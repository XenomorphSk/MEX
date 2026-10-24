//! Traits fundamentais do motor de aquisição (plugins).
//!
//! Fronteiras de confiança:
//! - [`DeviceProvider`] **observa** dispositivos; não decide nada.
//! - [`CapabilityResolver`] decide o que é possível para cada observação.
//! - [`AcquisitionAdapter`] lê da origem e escreve em um [`EvidenceSink`].
//! - [`EvidenceSink`] é a única fonte de verdade sobre quais artefatos
//!   foram finalizados e com qual hash. Um adaptador não consegue declarar
//!   um artefato completo que o sink não tenha finalizado.
//!
//! O ciclo de vida do job (estados, progresso) pertence ao motor — ver
//! [`crate::job::AcquisitionJob`].

use crate::cancel::CancellationToken;
use crate::capability::{Capability, CapabilityKind, ModificationRisk};
use crate::error::Result;
use crate::ids::{AcquisitionId, ArtifactId};
use crate::model::{ArtifactFailure, ArtifactRecord, ArtifactStatus, DeviceObservation, Platform};
use crate::path::EvidencePath;
use crate::timestamp::UtcTimestamp;
use async_trait::async_trait;
use serde::Serialize;

/// Metadados declarados por um adaptador de aquisição. Entram no relatório.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdapterDescriptor {
    /// Identificador estável (ex.: "mock", "android-adb", "local-import").
    pub id: &'static str,
    /// Versão semântica do módulo.
    pub version: &'static str,
    /// Plataformas suportadas.
    pub platforms: &'static [Platform],
    /// Capacidades que o adaptador pode oferecer (sujeitas à resolução).
    pub capabilities: &'static [CapabilityKind],
    /// Pré-requisitos de acesso.
    pub prerequisites: &'static [&'static str],
    /// Restrições conhecidas.
    pub restrictions: &'static [&'static str],
    /// Maior risco de modificação do dispositivo que o adaptador pode causar.
    pub modification_risk: ModificationRisk,
}

/// Descobre dispositivos em um transporte (ADB, importador local, mock).
#[async_trait]
pub trait DeviceProvider: Send + Sync {
    /// Identificador do provedor, para diagnóstico.
    fn id(&self) -> &'static str;

    /// Lista os dispositivos atualmente visíveis.
    async fn list_devices(&self) -> Result<Vec<DeviceObservation>>;
}

/// Resolve quais capacidades estão disponíveis para um dispositivo concreto.
///
/// Regra forense: a presença do dispositivo nunca implica disponibilidade.
/// Cada capacidade é avaliada explicitamente e pode ser negada com motivo.
pub trait CapabilityResolver: Send + Sync {
    /// Resolve as capacidades para o dispositivo observado.
    fn resolve(&self, device: &DeviceObservation) -> Vec<Capability>;
}

/// Especificação de um artefato a ser gravado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSpec {
    /// Caminho lógico validado no pacote.
    pub stored_path: EvidencePath,
    /// Caminho como reportado pela origem (proveniência; não confiável).
    pub source_path: Option<String>,
    /// Data de modificação na origem, quando disponível.
    pub source_modified: Option<UtcTimestamp>,
    /// Tamanho anunciado pela origem, se conhecido. Se informado, o `commit`
    /// falha quando o total gravado divergir.
    pub expected_size: Option<u64>,
}

impl ArtifactSpec {
    /// Constrói o registro do artefato a partir desta especificação.
    /// Uso exclusivo de implementações de [`EvidenceSink`].
    pub fn to_record(
        &self,
        acquisition_id: AcquisitionId,
        size_bytes: u64,
        status: ArtifactStatus,
        created_at: UtcTimestamp,
    ) -> ArtifactRecord {
        ArtifactRecord {
            id: ArtifactId::new(),
            acquisition_id,
            stored_path: self.stored_path.clone(),
            source_path: self.source_path.clone(),
            source_modified: self.source_modified,
            size_bytes,
            status,
            created_at,
        }
    }
}

/// Escrita de um único artefato.
///
/// Contrato de implementação:
/// - os dados vão para área temporária até o `commit`;
/// - `commit` calcula/conclui o digest e torna o artefato visível
///   atomicamente; só então ele é `Complete`;
/// - `abort`, ou o `drop` sem `commit`, registra o artefato como `Failed`
///   — nunca como completo.
#[async_trait]
pub trait ArtifactWriter: Send {
    /// Acrescenta um bloco.
    async fn write(&mut self, chunk: &[u8]) -> Result<()>;

    /// Bytes gravados até agora.
    fn bytes_written(&self) -> u64;

    /// Finaliza atomicamente e devolve o registro completo.
    async fn commit(self: Box<Self>) -> Result<ArtifactRecord>;

    /// Descarta o artefato em curso, registrando o motivo.
    async fn abort(self: Box<Self>, reason: &str) -> Result<()>;
}

/// Destino de evidências de uma aquisição.
#[async_trait]
pub trait EvidenceSink: Send {
    /// Inicia a gravação de um artefato.
    async fn begin_artifact<'a>(
        &'a mut self,
        spec: ArtifactSpec,
    ) -> Result<Box<dyn ArtifactWriter + 'a>>;

    /// Artefatos registrados até agora (completos e falhos), na ordem.
    fn artifacts(&self) -> &[ArtifactRecord];

    /// Diretório do pacote no host, se o sink grava no sistema de arquivos
    /// local. Adaptadores que leem do host (ex.: importador) devem recusar
    /// origens que contenham ou estejam contidas neste diretório.
    fn destination(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Pedido de aquisição entregue ao adaptador pelo motor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionRequest {
    /// Aquisição em curso.
    pub acquisition_id: AcquisitionId,
    /// Capacidade a exercer (já resolvida como disponível).
    pub capability: CapabilityKind,
    /// Dispositivo-alvo.
    pub device: DeviceObservation,
}

/// O que o adaptador relata ao final. Note a ausência de "sucesso": o
/// resultado é derivado pelo motor a partir do sink
/// ([`crate::model::AcquisitionOutcome::derive`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdapterReport {
    /// Itens que não chegaram a ser gravados (ex.: permissão negada).
    pub not_acquired: Vec<ArtifactFailure>,
    /// Limitações observadas nesta execução.
    pub limitations: Vec<String>,
    /// Operações executadas que podem ter modificado o dispositivo.
    pub modifying_operations: Vec<String>,
}

/// Adaptador de aquisição.
#[async_trait]
pub trait AcquisitionAdapter: CapabilityResolver {
    /// Metadados do adaptador.
    fn descriptor(&self) -> AdapterDescriptor;

    /// Executa a aquisição, gravando no `sink`.
    ///
    /// Deve consultar `cancel` entre blocos e retornar
    /// [`crate::MexError::Cancelled`] quando solicitado, abortando o artefato
    /// em curso. Artefatos já finalizados permanecem válidos no sink.
    async fn acquire(
        &self,
        request: &AcquisitionRequest,
        sink: &mut dyn EvidenceSink,
        cancel: &CancellationToken,
    ) -> Result<AdapterReport>;
}
