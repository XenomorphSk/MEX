//! `LocalEvidenceImporter`: importa backups/exportações já existentes no
//! host (diretório) para um pacote de evidências.
//!
//! Garantias:
//! - **Somente leitura** na origem: nada é criado, alterado ou removido.
//!   (O sistema operacional pode atualizar o *atime* dos arquivos lidos;
//!   recomenda-se montar a origem como somente leitura.)
//! - Links simbólicos **não** são seguidos; são relatados como não
//!   adquiridos, com o destino do link.
//! - Arquivos especiais (FIFO, socket, dispositivo) não são lidos.
//! - Em Unix, o arquivo aberto é conferido (dispositivo + inode) contra o
//!   inspecionado, impedindo troca por link entre a inspeção e a abertura.
//! - Ordem determinística (nomes ordenados por bytes).
//! - Nomes que não formam um [`EvidencePath`] válido (ex.: `:`, `CON`,
//!   bytes não UTF-8) e colisões sem distinção de maiúsculas são gravados
//!   em `unmapped/NNNNNN`, preservando o caminho original em `source_path`.
//! - Um arquivo que muda de tamanho durante a leitura falha no `commit` e
//!   é registrado como `Failed`.
//! - A origem não pode conter, nem estar contida, no pacote de destino.

use async_trait::async_trait;
use mex_core::cancel::CancellationToken;
use mex_core::capability::{Availability, Capability, CapabilityKind, ModificationRisk};
use mex_core::model::{ArtifactFailure, DeviceObservation, Platform};
use mex_core::path::EvidencePath;
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{
    AcquisitionAdapter, AcquisitionRequest, AdapterDescriptor, AdapterReport, ArtifactSpec,
    CapabilityResolver, EvidenceSink,
};
use mex_core::{MexError, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

/// Prefixo dos artefatos mapeados pelo caminho original.
pub const FILES_PREFIX: &str = "files";
/// Prefixo dos artefatos cujo nome não pôde ser mapeado.
pub const UNMAPPED_PREFIX: &str = "unmapped";

const CHUNK: usize = 1024 * 1024;
const MAX_DEPTH: usize = 128;

/// Importador de evidências locais.
pub struct LocalEvidenceImporter {
    source: PathBuf,
}

impl LocalEvidenceImporter {
    /// Cria o importador para o diretório de origem.
    pub fn new(source: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
        }
    }

    /// Diretório de origem.
    pub fn source(&self) -> &Path {
        &self.source
    }
}

impl CapabilityResolver for LocalEvidenceImporter {
    fn resolve(&self, device: &DeviceObservation) -> Vec<Capability> {
        let kind = CapabilityKind::LocalImport;
        if device.platform == Platform::Simulated {
            return vec![Capability::unavailable(
                kind,
                "importador real não opera dispositivos simulados",
            )];
        }
        match std::fs::metadata(&self.source) {
            Ok(m) if m.is_dir() => vec![Capability {
                kind,
                availability: Availability::Available,
                prerequisites: vec![
                    "autorização registrada que abranja o material importado".into(),
                    "origem montada somente leitura (recomendado)".into(),
                ],
                limitations: vec![
                    "integridade anterior à importação depende da cadeia de custódia da origem"
                        .into(),
                    "links simbólicos e arquivos especiais não são importados".into(),
                ],
                modification_risk: ModificationRisk::None,
            }],
            Ok(_) => vec![Capability::unavailable(kind, "origem não é um diretório")],
            Err(e) => vec![Capability::unavailable(
                kind,
                format!("origem inacessível: {e}"),
            )],
        }
    }
}

struct Walk<'a> {
    sink: &'a mut dyn EvidenceSink,
    cancel: &'a CancellationToken,
    taken: HashSet<String>,
    unmapped: usize,
    report: AdapterReport,
}

#[async_trait]
impl AcquisitionAdapter for LocalEvidenceImporter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            id: "local-import",
            version: env!("CARGO_PKG_VERSION"),
            platforms: &[Platform::Android, Platform::Ios],
            capabilities: &[CapabilityKind::LocalImport],
            prerequisites: &[
                "autorização registrada que abranja o material importado",
                "origem montada somente leitura (recomendado)",
            ],
            restrictions: &[
                "links simbólicos não são seguidos",
                "arquivos especiais não são importados",
                "nomes inválidos como caminho de evidência vão para unmapped/ com o caminho original preservado",
            ],
            modification_risk: ModificationRisk::None,
        }
    }

    async fn acquire(
        &self,
        request: &AcquisitionRequest,
        sink: &mut dyn EvidenceSink,
        cancel: &CancellationToken,
    ) -> Result<AdapterReport> {
        if request.capability != CapabilityKind::LocalImport {
            return Err(MexError::UnsupportedCapability(
                request.capability.as_str().into(),
            ));
        }
        let root = tokio::fs::canonicalize(&self.source)
            .await
            .map_err(|e| MexError::io(&self.source, e))?;
        if let Some(dest) = sink.destination() {
            let dest = tokio::fs::canonicalize(dest)
                .await
                .map_err(|e| MexError::io(dest, e))?;
            if dest.starts_with(&root) || root.starts_with(&dest) {
                return Err(MexError::PolicyDenied(
                    "a origem da importação não pode conter nem estar dentro do pacote de destino"
                        .into(),
                ));
            }
        }
        let mut w = Walk {
            sink,
            cancel,
            taken: HashSet::new(),
            unmapped: 0,
            report: AdapterReport::default(),
        };
        w.walk_dir(root, Vec::new()).await?;
        if w.unmapped > 0 {
            w.report.limitations.push(format!(
                "{} item(ns) gravado(s) em {UNMAPPED_PREFIX}/ por nome incompatível com caminho de evidência; caminho original em source_path",
                w.unmapped
            ));
        }
        w.report
            .limitations
            .push("importação de cópia existente: não houve contato com o dispositivo".into());
        Ok(w.report)
    }
}

impl Walk<'_> {
    fn not_acquired(&mut self, rel: &Path, reason: impl Into<String>) {
        self.report.not_acquired.push(ArtifactFailure {
            source_path: Some(provenance(rel)),
            reason: reason.into(),
        });
    }

    /// Percurso iterativo em profundidade, ordenado por nome.
    async fn walk_dir(&mut self, start: PathBuf, start_rel: Vec<std::ffi::OsString>) -> Result<()> {
        let mut stack = vec![(start, start_rel)];
        while let Some((dir, rel)) = stack.pop() {
            self.cancel.check()?;
            let rel_path: PathBuf = rel.iter().collect();
            let mut entries = Vec::new();
            match tokio::fs::read_dir(&dir).await {
                Ok(mut rd) => loop {
                    match rd.next_entry().await {
                        Ok(Some(e)) => entries.push(e),
                        Ok(None) => break,
                        Err(e) => {
                            self.not_acquired(
                                &rel_path,
                                format!("leitura de diretório interrompida: {e}"),
                            );
                            break;
                        }
                    }
                },
                Err(e) => {
                    self.not_acquired(&rel_path, format!("diretório ilegível: {e}"));
                    continue;
                }
            }
            entries.sort_by_key(|e| e.file_name());
            let mut subdirs = Vec::new();
            for entry in entries {
                let mut child_rel = rel.clone();
                child_rel.push(entry.file_name());
                let child_rel_path: PathBuf = child_rel.iter().collect();
                let ft = match entry.file_type().await {
                    Ok(t) => t,
                    Err(e) => {
                        self.not_acquired(
                            &child_rel_path,
                            format!("tipo de arquivo ilegível: {e}"),
                        );
                        continue;
                    }
                };
                if ft.is_symlink() {
                    let target = tokio::fs::read_link(entry.path())
                        .await
                        .map(|t| t.display().to_string())
                        .unwrap_or_else(|_| "?".into());
                    self.not_acquired(
                        &child_rel_path,
                        format!("link simbólico não seguido (destino: {target})"),
                    );
                } else if ft.is_dir() {
                    if child_rel.len() > MAX_DEPTH {
                        self.not_acquired(&child_rel_path, "profundidade máxima excedida");
                    } else {
                        subdirs.push((entry.path(), child_rel));
                    }
                } else if ft.is_file() {
                    self.import_file(&entry.path(), &child_rel_path, &child_rel)
                        .await?;
                } else {
                    self.not_acquired(
                        &child_rel_path,
                        "arquivo especial (FIFO, socket ou dispositivo) não importado",
                    );
                }
            }
            // Pilha: empilha em ordem reversa para visitar em ordem crescente.
            stack.extend(subdirs.into_iter().rev());
        }
        Ok(())
    }

    fn stored_path_for(&mut self, rel: &[std::ffi::OsString]) -> EvidencePath {
        let mapped = rel
            .iter()
            .map(|c| c.to_str())
            .collect::<Option<Vec<_>>>()
            .and_then(|parts| {
                EvidencePath::new(&format!("{FILES_PREFIX}/{}", parts.join("/"))).ok()
            })
            .filter(|p| !self.taken.contains(&p.as_str().to_lowercase()));
        let path = match mapped {
            Some(p) => p,
            None => {
                self.unmapped += 1;
                EvidencePath::new(&format!("{UNMAPPED_PREFIX}/{:06}", self.unmapped))
                    .expect("caminho gerado é sempre válido")
            }
        };
        self.taken.insert(path.as_str().to_lowercase());
        path
    }

    async fn import_file(
        &mut self,
        abs: &Path,
        rel: &Path,
        rel_parts: &[std::ffi::OsString],
    ) -> Result<()> {
        self.cancel.check()?;
        let before = match tokio::fs::symlink_metadata(abs).await {
            Ok(m) if m.file_type().is_file() => m,
            Ok(_) => {
                self.not_acquired(rel, "tipo de arquivo mudou durante a importação");
                return Ok(());
            }
            Err(e) => {
                self.not_acquired(rel, format!("metadados ilegíveis: {e}"));
                return Ok(());
            }
        };
        let mut file = match tokio::fs::File::open(abs).await {
            Ok(f) => f,
            Err(e) => {
                self.not_acquired(rel, format!("arquivo não pôde ser aberto: {e}"));
                return Ok(());
            }
        };
        match file.metadata().await {
            Ok(after) if same_file(&before, &after) => {}
            Ok(_) => {
                self.not_acquired(rel, "arquivo substituído entre a inspeção e a abertura");
                return Ok(());
            }
            Err(e) => {
                self.not_acquired(rel, format!("metadados ilegíveis após abertura: {e}"));
                return Ok(());
            }
        }

        let spec = ArtifactSpec {
            stored_path: self.stored_path_for(rel_parts),
            source_path: Some(provenance(rel)),
            source_modified: before.modified().ok().map(UtcTimestamp::from_system_time),
            expected_size: Some(before.len()),
        };
        let mut writer = self.sink.begin_artifact(spec).await?;
        let mut buf = vec![0u8; CHUNK];
        loop {
            if self.cancel.is_cancelled() {
                writer.abort("cancelado pelo operador").await?;
                return Err(MexError::Cancelled);
            }
            let n = match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    // Erro na origem: este artefato falha, a importação segue.
                    writer
                        .abort(&format!("erro de leitura na origem: {e}"))
                        .await?;
                    return Ok(());
                }
            };
            // Erro no destino é fatal: propaga (o writer é descartado e o
            // artefato registrado como falho).
            writer.write(&buf[..n]).await?;
        }
        // Falha de commit (ex.: tamanho mudou) já fica registrada no sink.
        // O nome do arquivo de origem não vai para o log (pode conter dado
        // pessoal); a falha fica registrada no pacote e no banco.
        if writer.commit().await.is_err() {
            tracing::warn!("artefato não finalizado; detalhes no inventário da aquisição");
        }
        Ok(())
    }
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    b.is_file() && a.len() == b.len()
}

/// Representação textual sem perdas do caminho de origem. Nomes não UTF-8
/// recebem o prefixo `<não-UTF-8>` e bytes fora do ASCII imprimível são
/// escapados como `\xNN`.
pub fn provenance(rel: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = rel.as_os_str().as_bytes();
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                let mut out = String::from("<não-UTF-8> ");
                for &b in bytes {
                    if (0x20..0x7f).contains(&b) && b != b'\\' {
                        out.push(b as char);
                    } else {
                        out.push_str(&format!("\\x{b:02x}"));
                    }
                }
                out
            }
        }
    }
    #[cfg(not(unix))]
    {
        rel.to_string_lossy().into_owned()
    }
}
