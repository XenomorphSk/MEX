//! `EvidenceSink` em disco com finalização atômica.
//!
//! Layout do pacote (`<raiz>/<acquisition_id>/`):
//!
//! ```text
//! .staging/            temporários (*.part); removido no selo
//! artifacts/<caminho>  artefatos finalizados
//! SHA256SUMS           hashes dos artefatos (formato sha256sum)
//! manifest.json        manifesto
//! manifest.sha256      selo do manifesto — gravado por último
//! ```
//!
//! Um artefato só aparece em `artifacts/` depois de: gravação completa,
//! `fsync`, conferência de tamanho, releitura com hash (opcional, padrão
//! ligado) e publicação atômica sem sobrescrita. Qualquer falha remove o
//! temporário e registra o artefato como `Failed`.
//!
//! Todo acesso ao disco passa pelo módulo interno `pkgdir`: no Linux, ancorado em
//! descritores de diretório mantidos abertos (`openat`/`O_NOFOLLOW`,
//! `renameat2(RENAME_NOREPLACE)`), sem janela entre checagem e uso (M7).

use crate::manifest::{seal_line, Manifest, ManifestHeader, Termination, MANIFEST_FORMAT_V1};
use crate::pkgdir::PackageDir;
use crate::{MANIFEST_DIGEST_FILE, MANIFEST_FILE, SUMS_FILE};
use async_trait::async_trait;
use mex_core::ids::AcquisitionId;
use mex_core::integrity::{sha256_hex, Digest256, StreamHasher};
use mex_core::model::{AcquisitionOutcome, ArtifactRecord, ArtifactStatus};
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{AdapterReport, ArtifactSpec, ArtifactWriter, EvidenceSink};
use mex_core::{MexError, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Limites e opções do sink.
#[derive(Debug, Clone)]
pub struct SinkOptions {
    /// Tamanho máximo de um artefato.
    pub max_artifact_bytes: u64,
    /// Total máximo do pacote (`None` = sem limite além do disco).
    pub max_total_bytes: Option<u64>,
    /// Relê cada artefato e confere o hash antes de publicá-lo.
    pub verify_after_write: bool,
    /// Tamanho máximo do `manifest.json`. Deve ser no máximo
    /// [`crate::verify::MAX_MANIFEST_BYTES`], ou o pacote não poderá ser
    /// verificado. Novos artefatos são recusados antes de estourar o limite.
    pub max_manifest_bytes: u64,
}

/// Estimativa conservadora do custo de um registro no manifesto, além dos
/// caminhos (campos fixos, hash, timestamps, formatação).
const RECORD_OVERHEAD: u64 = 1024;
/// Reserva para o cabeçalho do manifesto (caso, autorização, limitações...).
const HEADER_RESERVE: u64 = 1024 * 1024;

impl Default for SinkOptions {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 1 << 40, // 1 TiB
            max_total_bytes: None,
            verify_after_write: true,
            max_manifest_bytes: crate::verify::MAX_MANIFEST_BYTES,
        }
    }
}

/// Pacote finalizado e selado.
#[derive(Debug, Clone)]
pub struct SealedPackage {
    /// Diretório do pacote.
    pub package_dir: PathBuf,
    /// Manifesto gravado.
    pub manifest: Manifest,
    /// SHA-256 exato de `manifest.json`.
    pub manifest_sha256: Digest256,
}

/// Dados para finalizar o pacote.
#[derive(Debug, Clone)]
pub struct FinalizeInput {
    /// Proveniência.
    pub header: ManifestHeader,
    /// Relato do adaptador (vazio se o adaptador terminou com erro).
    pub report: AdapterReport,
    /// Como a execução terminou.
    pub termination: Termination,
    /// Instante de término.
    pub finished_at: UtcTimestamp,
}

/// Sink de evidências em disco.
pub struct DiskEvidenceSink {
    acquisition_id: AcquisitionId,
    dir: PackageDir,
    options: SinkOptions,
    records: Vec<ArtifactRecord>,
    /// Caminhos finalizados, em minúsculas: impede colisões em sistemas de
    /// arquivos sem distinção de maiúsculas (NTFS, FAT, APFS padrão).
    taken: HashSet<String>,
    bytes_total: u64,
    /// Estimativa acumulada do tamanho do manifesto.
    manifest_budget: u64,
}

impl DiskEvidenceSink {
    /// Cria o pacote `<root>/<acquisition_id>/`. Falha se já existir.
    pub async fn create(
        root: &Path,
        acquisition_id: AcquisitionId,
        options: SinkOptions,
    ) -> Result<Self> {
        let dir = PackageDir::create(root, &acquisition_id.to_string()).await?;
        tracing::info!(package = %dir.path().display(), "pacote de evidências criado");
        Ok(Self {
            acquisition_id,
            dir,
            options,
            records: Vec::new(),
            taken: HashSet::new(),
            bytes_total: 0,
            manifest_budget: HEADER_RESERVE,
        })
    }

    /// Diretório do pacote.
    pub fn package_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Finaliza: limpa a área temporária, deriva o resultado, grava
    /// `SHA256SUMS`, `manifest.json` e, por último, o selo `manifest.sha256`.
    ///
    /// Se esta função falhar, o pacote fica sem selo e a verificação o
    /// classifica como `Incomplete`.
    pub async fn finalize(self, input: FinalizeInput) -> Result<SealedPackage> {
        self.dir.clear_staging().await?;

        let completed = self.records.iter().filter(|r| r.is_complete()).count();
        let failed = self.records.len() - completed + input.report.not_acquired.len();
        let outcome = AcquisitionOutcome::derive(
            input.termination == Termination::Cancelled,
            completed,
            failed,
            matches!(input.termination, Termination::Interrupted { .. }),
        );
        let h = input.header;
        let manifest = Manifest {
            format: MANIFEST_FORMAT_V1.into(),
            acquisition_id: self.acquisition_id,
            software: crate::manifest::SoftwareInfo::current(),
            case: h.case,
            operator: h.operator,
            authorization: h.authorization,
            device_id: h.device_id,
            device: h.device,
            adapter: h.adapter,
            started_at: h.started_at,
            finished_at: input.finished_at,
            outcome,
            termination: input.termination,
            limitations: input.report.limitations,
            modifying_operations: input.report.modifying_operations,
            totals: Manifest::compute_totals(&self.records, input.report.not_acquired.len()),
            not_acquired: input.report.not_acquired,
            artifacts: self.records,
        };
        let problems = manifest.consistency_problems();
        if !problems.is_empty() {
            return Err(MexError::InvalidInput(format!(
                "manifesto inconsistente: {}",
                problems.join("; ")
            )));
        }

        let bytes = manifest.to_bytes()?;
        if bytes.len() as u64 > self.options.max_manifest_bytes {
            return Err(MexError::InvalidInput(format!(
                "manifesto de {} bytes excede o limite verificável de {} bytes",
                bytes.len(),
                self.options.max_manifest_bytes
            )));
        }
        let digest = sha256_hex(&bytes);
        self.dir
            .write_control(SUMS_FILE, manifest.sha256sums().into_bytes())
            .await?;
        self.dir.write_control(MANIFEST_FILE, bytes).await?;
        self.dir
            .write_control(MANIFEST_DIGEST_FILE, seal_line(&digest).into_bytes())
            .await?;
        tracing::info!(
            package = %self.dir.path().display(),
            outcome = outcome.as_str(),
            manifest_sha256 = %digest.hex,
            "pacote selado"
        );
        Ok(SealedPackage {
            package_dir: self.dir.path().to_path_buf(),
            manifest,
            manifest_sha256: digest,
        })
    }
}

#[async_trait]
impl EvidenceSink for DiskEvidenceSink {
    async fn begin_artifact<'a>(
        &'a mut self,
        spec: ArtifactSpec,
    ) -> Result<Box<dyn ArtifactWriter + 'a>> {
        if self
            .taken
            .contains(&spec.stored_path.as_str().to_lowercase())
        {
            return Err(MexError::InvalidInput(format!(
                "caminho já finalizado (comparação sem distinção de maiúsculas): {}",
                spec.stored_path
            )));
        }
        if spec
            .expected_size
            .is_some_and(|n| n > self.options.max_artifact_bytes)
        {
            return Err(MexError::InvalidInput(format!(
                "artefato excede o limite de {} bytes",
                self.options.max_artifact_bytes
            )));
        }
        // Caminhos entram no JSON; caracteres de controle podem virar \uXXXX.
        let cost = RECORD_OVERHEAD
            + spec.stored_path.as_str().len() as u64
            + 2 * spec.source_path.as_ref().map_or(0, |s| s.len() as u64);
        if self.manifest_budget + cost > self.options.max_manifest_bytes {
            return Err(MexError::InvalidInput(format!(
                "limite do manifesto atingido ({} bytes): o pacote não aceita novos artefatos sem se tornar inverificável",
                self.options.max_manifest_bytes
            )));
        }
        let (file, temp_name) = self.dir.create_temp().await?;
        self.manifest_budget += cost;
        Ok(Box::new(DiskArtifactWriter {
            sink: self,
            spec,
            temp_name,
            file: Some(tokio::fs::File::from_std(file)),
            hasher: StreamHasher::new(),
            created_at: UtcTimestamp::now(),
            finished: false,
        }))
    }

    fn artifacts(&self) -> &[ArtifactRecord] {
        &self.records
    }

    fn destination(&self) -> Option<&Path> {
        Some(self.dir.path())
    }
}

struct DiskArtifactWriter<'a> {
    sink: &'a mut DiskEvidenceSink,
    spec: ArtifactSpec,
    temp_name: String,
    file: Option<tokio::fs::File>,
    hasher: StreamHasher,
    created_at: UtcTimestamp,
    finished: bool,
}

impl DiskArtifactWriter<'_> {
    fn temp_display(&self) -> PathBuf {
        self.sink
            .dir
            .path()
            .join(crate::STAGING_DIR)
            .join(&self.temp_name)
    }

    fn push_failed(&mut self, size: u64, reason: String) {
        let rec = self.spec.to_record(
            self.sink.acquisition_id,
            size,
            ArtifactStatus::Failed { reason },
            self.created_at,
        );
        self.sink.records.push(rec);
    }

    async fn publish(&mut self) -> Result<ArtifactRecord> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| MexError::InvalidInput("artefato já finalizado".into()))?;
        let tp = self.temp_display();
        file.flush().await.map_err(|e| MexError::io(&tp, e))?;
        file.sync_all().await.map_err(|e| MexError::io(&tp, e))?;
        drop(file);

        let written = self.hasher.bytes_hashed();
        if let Some(expected) = self.spec.expected_size {
            if expected != written {
                return Err(MexError::Adapter(format!(
                    "tamanho divergente: anunciado {expected}, gravado {written}"
                )));
            }
        }
        let digest = std::mem::take(&mut self.hasher).finalize();

        if self.sink.options.verify_after_write {
            let (reread, n) = self.sink.dir.hash_temp(&self.temp_name).await?;
            if n != written {
                return Err(MexError::Adapter(format!(
                    "releitura com tamanho divergente: gravado {written}, lido {n}"
                )));
            }
            reread.verify_eq(&digest)?;
        }

        self.sink
            .dir
            .publish(&self.temp_name, &self.spec.stored_path)
            .await?;

        let status = ArtifactStatus::Complete {
            digest,
            completed_at: UtcTimestamp::now(),
        };
        Ok(self
            .spec
            .to_record(self.sink.acquisition_id, written, status, self.created_at))
    }
}

#[async_trait]
impl ArtifactWriter for DiskArtifactWriter<'_> {
    async fn write(&mut self, chunk: &[u8]) -> Result<()> {
        let len = chunk.len() as u64;
        let opts = &self.sink.options;
        if self.hasher.bytes_hashed() + len > opts.max_artifact_bytes {
            return Err(MexError::InvalidInput(format!(
                "artefato excede o limite de {} bytes",
                opts.max_artifact_bytes
            )));
        }
        if opts
            .max_total_bytes
            .is_some_and(|max| self.sink.bytes_total + len > max)
        {
            return Err(MexError::InvalidInput(
                "pacote excede o limite total configurado".into(),
            ));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| MexError::InvalidInput("artefato já finalizado".into()))?;
        if let Err(e) = file.write_all(chunk).await {
            return Err(MexError::io(self.temp_display(), e));
        }
        self.hasher.update(chunk);
        self.sink.bytes_total += len;
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.hasher.bytes_hashed()
    }

    async fn commit(mut self: Box<Self>) -> Result<ArtifactRecord> {
        self.finished = true;
        let size = self.hasher.bytes_hashed();
        match self.publish().await {
            Ok(record) => {
                self.sink
                    .taken
                    .insert(record.stored_path.as_str().to_lowercase());
                self.sink.records.push(record.clone());
                Ok(record)
            }
            Err(e) => {
                self.file = None;
                self.sink.dir.remove_temp(&self.temp_name).await;
                self.push_failed(size, format!("falha na finalização: {e}"));
                Err(e)
            }
        }
    }

    async fn abort(mut self: Box<Self>, reason: &str) -> Result<()> {
        self.finished = true;
        self.file = None;
        self.sink.dir.remove_temp(&self.temp_name).await;
        let size = self.hasher.bytes_hashed();
        self.push_failed(size, format!("abortado: {reason}"));
        Ok(())
    }
}

impl Drop for DiskArtifactWriter<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.file = None;
            // Melhor esforço; se falhar, `finalize` remove o `.part`.
            self.sink.dir.remove_temp_now(&self.temp_name);
            let size = self.hasher.bytes_hashed();
            self.push_failed(size, "gravação interrompida sem commit".into());
        }
    }
}
