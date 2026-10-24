//! Implementações mock para testes e desenvolvimento da interface.
//!
//! **Nada aqui representa uma aquisição real.** O mock só aceita
//! dispositivos com [`Platform::Simulated`], e adaptadores reais nunca aceitam
//! essa plataforma; assim um resultado simulado não pode ser confundido com
//! evidência. O conteúdo gerado é determinístico ([`mock_content`]), o que
//! permite comparar hashes com valores de referência (golden).

use crate::cancel::CancellationToken;
use crate::capability::{Capability, CapabilityKind, ModificationRisk};
use crate::error::{MexError, Result};
use crate::ids::{AcquisitionId, ArtifactId};
use crate::integrity::StreamHasher;
use crate::model::{
    AdbState, ArtifactFailure, ArtifactRecord, ArtifactStatus, DeviceObservation, Platform,
};
use crate::path::EvidencePath;
use crate::timestamp::UtcTimestamp;
use crate::traits::{
    AcquisitionAdapter, AcquisitionRequest, AdapterDescriptor, AdapterReport, ArtifactSpec,
    ArtifactWriter, CapabilityResolver, DeviceProvider, EvidenceSink,
};
use async_trait::async_trait;
use std::collections::HashMap;

/// Byte `i` do conteúdo simulado com semente `seed`.
fn mock_byte(seed: u8, i: u64) -> u8 {
    (i.wrapping_mul(31)
        .wrapping_add(u64::from(seed).wrapping_mul(17))
        % 251) as u8
}

/// Conteúdo simulado completo (para conferência em testes).
pub fn mock_content(seed: u8, size: u64) -> Vec<u8> {
    (0..size).map(|i| mock_byte(seed, i)).collect()
}

/// Cria uma observação de dispositivo simulado.
pub fn simulated_device(serial: &str, adb_state: AdbState) -> DeviceObservation {
    DeviceObservation {
        platform: Platform::Simulated,
        serial: serial.to_owned(),
        manufacturer: Some("Simulado".into()),
        model: Some("SIM-1".into()),
        os_version: Some("0".into()),
        security_patch: None,
        adb_state: Some(adb_state),
        observed_at: UtcTimestamp::now(),
    }
}

/// Provedor de dispositivos simulados.
pub struct MockProvider {
    devices: Vec<DeviceObservation>,
}

impl MockProvider {
    /// Cria um provedor com observações fixas. Observações de plataformas
    /// reais são rejeitadas.
    pub fn new(devices: Vec<DeviceObservation>) -> Result<Self> {
        if devices.iter().any(|d| d.platform != Platform::Simulated) {
            return Err(MexError::PolicyDenied(
                "MockProvider só aceita dispositivos simulados".into(),
            ));
        }
        Ok(Self { devices })
    }
}

#[async_trait]
impl DeviceProvider for MockProvider {
    fn id(&self) -> &'static str {
        "mock"
    }

    async fn list_devices(&self) -> Result<Vec<DeviceObservation>> {
        Ok(self.devices.clone())
    }
}

/// Um artefato do cenário simulado.
#[derive(Debug, Clone)]
pub struct MockArtifact {
    /// Caminho lógico (validado no momento da gravação).
    pub path: String,
    /// Tamanho em bytes.
    pub size: u64,
    /// Semente do conteúdo determinístico.
    pub seed: u8,
}

/// Roteiro do adaptador mock.
#[derive(Debug, Clone)]
pub struct MockScenario {
    /// Artefatos a "adquirir", em ordem.
    pub artifacts: Vec<MockArtifact>,
    /// Tamanho dos blocos de escrita.
    pub chunk_size: usize,
    /// Simula desconexão abrupta após este total de bytes.
    pub disconnect_after_bytes: Option<u64>,
    /// Itens relatados como não adquiridos.
    pub not_acquired: Vec<ArtifactFailure>,
}

/// Adaptador mock.
pub struct MockAdapter {
    scenario: MockScenario,
}

impl MockAdapter {
    /// Cria o adaptador com um roteiro.
    pub fn new(scenario: MockScenario) -> Self {
        Self { scenario }
    }
}

impl CapabilityResolver for MockAdapter {
    fn resolve(&self, device: &DeviceObservation) -> Vec<Capability> {
        let kinds = [CapabilityKind::DeviceInfo, CapabilityKind::LocalImport];
        if device.platform != Platform::Simulated {
            return kinds
                .map(|k| {
                    Capability::unavailable(k, "adaptador mock só opera dispositivos simulados")
                })
                .to_vec();
        }
        if device.adb_state != Some(AdbState::Device) {
            return kinds
                .map(|k| Capability::unavailable(k, "depuração não autorizada no aparelho"))
                .to_vec();
        }
        kinds
            .map(|kind| Capability {
                kind,
                availability: crate::capability::Availability::Available,
                prerequisites: vec!["dispositivo simulado".into()],
                limitations: vec!["conteúdo sintético; não é evidência".into()],
                modification_risk: ModificationRisk::None,
            })
            .to_vec()
    }
}

#[async_trait]
impl AcquisitionAdapter for MockAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            id: "mock",
            version: crate::CORE_VERSION,
            platforms: &[Platform::Simulated],
            capabilities: &[CapabilityKind::DeviceInfo, CapabilityKind::LocalImport],
            prerequisites: &["dispositivo simulado"],
            restrictions: &["somente testes; nunca usar em caso real"],
            modification_risk: ModificationRisk::None,
        }
    }

    async fn acquire(
        &self,
        request: &AcquisitionRequest,
        sink: &mut dyn EvidenceSink,
        cancel: &CancellationToken,
    ) -> Result<AdapterReport> {
        let available = self
            .resolve(&request.device)
            .into_iter()
            .any(|c| c.kind == request.capability && c.is_available());
        if !available {
            return Err(MexError::UnsupportedCapability(
                request.capability.as_str().into(),
            ));
        }

        let mut total: u64 = 0;
        for art in &self.scenario.artifacts {
            cancel.check()?;
            let spec = ArtifactSpec {
                stored_path: EvidencePath::new(&art.path)?,
                source_path: Some(format!("/simulated/{}", art.path)),
                source_modified: None,
                expected_size: Some(art.size),
            };
            let mut writer = sink.begin_artifact(spec).await?;
            let mut offset = 0u64;
            while offset < art.size {
                if cancel.is_cancelled() {
                    writer.abort("cancelado pelo operador").await?;
                    return Err(MexError::Cancelled);
                }
                if let Some(limit) = self.scenario.disconnect_after_bytes {
                    if total >= limit {
                        // Desconexão abrupta: o writer é descartado sem commit.
                        return Err(MexError::DeviceDisconnected(request.device.serial.clone()));
                    }
                }
                let n = (self.scenario.chunk_size as u64).min(art.size - offset);
                let chunk: Vec<u8> = (offset..offset + n)
                    .map(|i| mock_byte(art.seed, i))
                    .collect();
                writer.write(&chunk).await?;
                offset += n;
                total += n;
            }
            writer.commit().await?;
        }

        Ok(AdapterReport {
            not_acquired: self.scenario.not_acquired.clone(),
            limitations: vec!["aquisição simulada".into()],
            modifying_operations: Vec::new(),
        })
    }
}

/// Sink de evidências em memória, para testes.
///
/// Implementa o mesmo contrato exigido de um sink real: nada é `Complete`
/// sem `commit`; `abort` e `drop` sem `commit` geram registro `Failed`.
pub struct InMemorySink {
    acquisition_id: AcquisitionId,
    records: Vec<ArtifactRecord>,
    blobs: HashMap<ArtifactId, Vec<u8>>,
    bytes_total: u64,
    cancel_at: Option<(u64, CancellationToken)>,
}

impl InMemorySink {
    /// Cria um sink vazio para a aquisição.
    pub fn new(acquisition_id: AcquisitionId) -> Self {
        Self {
            acquisition_id,
            records: Vec::new(),
            blobs: HashMap::new(),
            bytes_total: 0,
            cancel_at: None,
        }
    }

    /// Injeção de falha para testes: aciona `token` quando o total gravado
    /// atingir `bytes` (simula o operador cancelando durante a escrita).
    pub fn cancel_when_bytes_reach(mut self, bytes: u64, token: CancellationToken) -> Self {
        self.cancel_at = Some((bytes, token));
        self
    }

    /// Conteúdo de um artefato completo.
    pub fn content(&self, id: ArtifactId) -> Option<&[u8]> {
        self.blobs.get(&id).map(Vec::as_slice)
    }

    /// Total de bytes recebidos (inclusive de artefatos abortados).
    pub fn bytes_total(&self) -> u64 {
        self.bytes_total
    }

    fn push_failed(
        &mut self,
        spec: &ArtifactSpec,
        size: u64,
        created_at: UtcTimestamp,
        reason: String,
    ) {
        let record = spec.to_record(
            self.acquisition_id,
            size,
            ArtifactStatus::Failed { reason },
            created_at,
        );
        self.records.push(record);
    }
}

#[async_trait]
impl EvidenceSink for InMemorySink {
    async fn begin_artifact<'a>(
        &'a mut self,
        spec: ArtifactSpec,
    ) -> Result<Box<dyn ArtifactWriter + 'a>> {
        if self
            .records
            .iter()
            .any(|r| r.is_complete() && r.stored_path == spec.stored_path)
        {
            return Err(MexError::InvalidInput(format!(
                "artefato já finalizado não pode ser sobrescrito: {}",
                spec.stored_path
            )));
        }
        Ok(Box::new(InMemoryWriter {
            sink: self,
            spec,
            buf: Vec::new(),
            hasher: StreamHasher::new(),
            created_at: UtcTimestamp::now(),
            finished: false,
        }))
    }

    fn artifacts(&self) -> &[ArtifactRecord] {
        &self.records
    }
}

struct InMemoryWriter<'a> {
    sink: &'a mut InMemorySink,
    spec: ArtifactSpec,
    buf: Vec<u8>,
    hasher: StreamHasher,
    created_at: UtcTimestamp,
    finished: bool,
}

#[async_trait]
impl ArtifactWriter for InMemoryWriter<'_> {
    async fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(chunk);
        self.hasher.update(chunk);
        self.sink.bytes_total += chunk.len() as u64;
        if let Some((limit, token)) = &self.sink.cancel_at {
            if self.sink.bytes_total >= *limit {
                token.cancel();
            }
        }
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.hasher.bytes_hashed()
    }

    async fn commit(mut self: Box<Self>) -> Result<ArtifactRecord> {
        self.finished = true;
        let written = self.hasher.bytes_hashed();
        if let Some(expected) = self.spec.expected_size {
            if expected != written {
                let reason = format!("tamanho divergente: anunciado {expected}, gravado {written}");
                self.sink
                    .push_failed(&self.spec, written, self.created_at, reason.clone());
                return Err(MexError::Adapter(reason));
            }
        }
        let status = ArtifactStatus::Complete {
            digest: std::mem::take(&mut self.hasher).finalize(),
            completed_at: UtcTimestamp::now(),
        };
        let record =
            self.spec
                .to_record(self.sink.acquisition_id, written, status, self.created_at);
        let buf = std::mem::take(&mut self.buf);
        self.sink.blobs.insert(record.id, buf);
        self.sink.records.push(record.clone());
        Ok(record)
    }

    async fn abort(mut self: Box<Self>, reason: &str) -> Result<()> {
        self.finished = true;
        let size = self.hasher.bytes_hashed();
        self.sink.push_failed(
            &self.spec,
            size,
            self.created_at,
            format!("abortado: {reason}"),
        );
        Ok(())
    }
}

impl Drop for InMemoryWriter<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let size = self.hasher.bytes_hashed();
            let spec = self.spec.clone();
            self.sink.push_failed(
                &spec,
                size,
                self.created_at,
                "gravação interrompida sem commit".into(),
            );
        }
    }
}
