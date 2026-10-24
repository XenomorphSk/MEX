//! Manifesto do pacote de evidências (formato `blackbit-mex/manifest/v1`).
//!
//! O manifesto descreve proveniência (caso, operador, autorização,
//! dispositivo, adaptador, versão do software), resultado e limitações da
//! aquisição, e o inventário de artefatos com seus hashes.
//!
//! O arquivo `manifest.json` é selado por `manifest.sha256`, no formato do
//! `sha256sum` (`<hex>  manifest.json`). O selo ao lado do manifesto detecta
//! alteração acidental ou parcial; contra quem reescreve manifesto **e**
//! selo, a defesa é comparar com o hash registrado no banco e na cadeia de
//! auditoria no momento da aquisição (ver `verify_package`).

use mex_core::capability::{CapabilityKind, ModificationRisk};
use mex_core::ids::{AcquisitionId, DeviceId};
use mex_core::integrity::Digest256;
use mex_core::model::{
    AcquisitionOutcome, ArtifactFailure, ArtifactRecord, Authorization, Case, DeviceObservation,
    Operator,
};
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::AdapterDescriptor;
use mex_core::{MexError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Identificador do formato do manifesto.
pub const MANIFEST_FORMAT_V1: &str = "blackbit-mex/manifest/v1";

/// Software que produziu o pacote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareInfo {
    /// Nome do produto.
    pub name: String,
    /// Versão.
    pub version: String,
}

impl SoftwareInfo {
    /// Este build.
    pub fn current() -> Self {
        Self {
            name: "BlackBit MEX".into(),
            version: mex_core::CORE_VERSION.into(),
        }
    }
}

/// Adaptador usado, como registrado no manifesto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterRecord {
    /// Identificador do adaptador.
    pub id: String,
    /// Versão do adaptador.
    pub version: String,
    /// Capacidade exercida.
    pub capability: CapabilityKind,
    /// Pré-requisitos declarados.
    pub prerequisites: Vec<String>,
    /// Restrições declaradas.
    pub restrictions: Vec<String>,
    /// Risco de modificação declarado.
    pub modification_risk: ModificationRisk,
}

impl AdapterRecord {
    /// Constrói a partir do descritor do adaptador.
    pub fn from_descriptor(d: &AdapterDescriptor, capability: CapabilityKind) -> Self {
        Self {
            id: d.id.into(),
            version: d.version.into(),
            capability,
            prerequisites: d.prerequisites.iter().map(|s| s.to_string()).collect(),
            restrictions: d.restrictions.iter().map(|s| s.to_string()).collect(),
            modification_risk: d.modification_risk,
        }
    }
}

/// Como a execução do adaptador terminou.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Termination {
    /// O adaptador retornou normalmente.
    Normal,
    /// Cancelada pelo operador.
    Cancelled,
    /// Interrompida por erro (desconexão, falha de E/S...).
    Interrupted {
        /// Motivo legível.
        reason: String,
    },
}

/// Dados de proveniência fornecidos pelo motor ao finalizar o pacote.
#[derive(Debug, Clone)]
pub struct ManifestHeader {
    /// Caso.
    pub case: Case,
    /// Operador executor.
    pub operator: Operator,
    /// Autorização invocada.
    pub authorization: Authorization,
    /// Dispositivo no inventário.
    pub device_id: DeviceId,
    /// Observação do dispositivo usada na aquisição.
    pub device: DeviceObservation,
    /// Adaptador.
    pub adapter: AdapterRecord,
    /// Início da aquisição.
    pub started_at: UtcTimestamp,
}

/// Totais do pacote (redundantes; conferidos na verificação).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Artefatos completos.
    pub artifacts_complete: usize,
    /// Artefatos que falharam durante a gravação.
    pub artifacts_failed: usize,
    /// Itens não adquiridos relatados pelo adaptador.
    pub not_acquired: usize,
    /// Soma dos tamanhos dos artefatos completos.
    pub bytes_complete: u64,
}

/// Manifesto do pacote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Formato (`blackbit-mex/manifest/v1`).
    pub format: String,
    /// Aquisição (também é o nome do diretório do pacote na criação).
    pub acquisition_id: AcquisitionId,
    /// Software.
    pub software: SoftwareInfo,
    /// Caso.
    pub case: Case,
    /// Operador.
    pub operator: Operator,
    /// Autorização.
    pub authorization: Authorization,
    /// Dispositivo no inventário.
    pub device_id: DeviceId,
    /// Observação do dispositivo.
    pub device: DeviceObservation,
    /// Adaptador.
    pub adapter: AdapterRecord,
    /// Início.
    pub started_at: UtcTimestamp,
    /// Fim.
    pub finished_at: UtcTimestamp,
    /// Resultado (derivado dos artefatos efetivamente finalizados).
    pub outcome: AcquisitionOutcome,
    /// Término da execução.
    pub termination: Termination,
    /// Limitações.
    pub limitations: Vec<String>,
    /// Operações potencialmente modificadoras do dispositivo.
    pub modifying_operations: Vec<String>,
    /// Itens não adquiridos.
    pub not_acquired: Vec<ArtifactFailure>,
    /// Inventário (completos e falhos, na ordem de gravação).
    pub artifacts: Vec<ArtifactRecord>,
    /// Totais.
    pub totals: Totals,
}

impl Manifest {
    /// Serialização canônica do arquivo `manifest.json`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut v = serde_json::to_vec_pretty(self)
            .map_err(|e| MexError::InvalidInput(format!("manifesto não serializável: {e}")))?;
        v.push(b'\n');
        Ok(v)
    }

    /// Recalcula os totais a partir do inventário.
    pub fn compute_totals(artifacts: &[ArtifactRecord], not_acquired: usize) -> Totals {
        let complete: Vec<_> = artifacts.iter().filter(|a| a.is_complete()).collect();
        Totals {
            artifacts_complete: complete.len(),
            artifacts_failed: artifacts.len() - complete.len(),
            not_acquired,
            bytes_complete: complete.iter().map(|a| a.size_bytes).sum(),
        }
    }

    /// Verifica a coerência interna do manifesto. Devolve as divergências.
    pub fn consistency_problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.format != MANIFEST_FORMAT_V1 {
            out.push(format!("formato desconhecido: {:?}", self.format));
        }
        if self.authorization.case_id != self.case.id {
            out.push("autorização não pertence ao caso".into());
        }
        if self.finished_at < self.started_at {
            out.push("finished_at anterior a started_at".into());
        }
        if Self::compute_totals(&self.artifacts, self.not_acquired.len()) != self.totals {
            out.push("totais não correspondem ao inventário".into());
        }
        let mut seen = HashSet::new();
        for a in &self.artifacts {
            if a.acquisition_id != self.acquisition_id {
                out.push(format!("artefato {} de outra aquisição", a.stored_path));
            }
            if a.is_complete() && !seen.insert(a.stored_path.as_str().to_lowercase()) {
                out.push(format!("caminho duplicado: {}", a.stored_path));
            }
        }
        out
    }

    /// Linhas do arquivo `SHA256SUMS` (formato `sha256sum`), ordenadas.
    pub fn sha256sums(&self) -> String {
        let mut lines: Vec<String> = self
            .artifacts
            .iter()
            .filter_map(|a| {
                a.digest()
                    .map(|d| format!("{}  {}/{}\n", d.hex, crate::ARTIFACTS_DIR, a.stored_path))
            })
            .collect();
        lines.sort();
        lines.concat()
    }
}

/// Conteúdo do selo `manifest.sha256`.
pub fn seal_line(digest: &Digest256) -> String {
    format!("{}  {}\n", digest.hex, crate::MANIFEST_FILE)
}

/// Lê o selo; aceita somente a forma exata produzida por [`seal_line`].
pub fn parse_seal(content: &str) -> Option<Digest256> {
    let hex = content
        .strip_suffix('\n')?
        .strip_suffix(crate::MANIFEST_FILE)?
        .strip_suffix("  ")?;
    if hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    Digest256::sha256_from_hex(hex).ok()
}
