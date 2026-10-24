//! Modelo do relatório técnico (`blackbit-mex/report/v1`).
//!
//! O relatório é uma **fotografia** no momento da emissão: inclui uma
//! verificação de integridade executada naquele instante e o estado da
//! cadeia de custódia (comprimento e hash do último evento). Impresso ou
//! arquivado fora do sistema, o hash da cabeça da cadeia serve de âncora
//! externa contra truncamento da auditoria.

use mex_core::audit::AuditEvent;
use mex_core::ids::{AcquisitionId, ReportId};
use mex_core::integrity::Digest256;
use mex_core::model::{Case, IntegrityStatus, Operator};
use mex_core::timestamp::UtcTimestamp;
use mex_evidence::{Finding, Manifest};
use serde::Serialize;

/// Identificador do formato.
pub const REPORT_FORMAT_V1: &str = "blackbit-mex/report/v1";

/// Versão de um módulo de software.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleVersion {
    /// Nome do módulo.
    pub name: String,
    /// Versão.
    pub version: String,
}

/// Resultado da verificação executada na emissão.
#[derive(Debug, Clone, Serialize)]
pub struct IntegritySection {
    /// Classificação.
    pub status: IntegrityStatus,
    /// SHA-256 do manifesto registrado na finalização da aquisição.
    pub registered_manifest_sha256: Digest256,
    /// SHA-256 calculado do `manifest.json` presente no pacote.
    pub computed_manifest_sha256: Option<Digest256>,
    /// Artefatos conferidos.
    pub artifacts_checked: usize,
    /// Bytes relidos.
    pub bytes_verified: u64,
    /// Divergências.
    pub findings: Vec<Finding>,
    /// Quando.
    pub verified_at: UtcTimestamp,
}

/// Cadeia de custódia.
#[derive(Debug, Clone, Serialize)]
pub struct CustodySection {
    /// Eventos do caso, em ordem de `seq`.
    pub events: Vec<AuditEvent>,
    /// Se a cadeia **completa** verificou sem divergência.
    pub chain_intact: bool,
    /// Descrição da primeira divergência, se houver.
    pub chain_problem: Option<String>,
    /// Comprimento da cadeia completa no momento da emissão.
    pub chain_length: u64,
    /// `entry_hash` do último evento (âncora externa).
    pub chain_head_hash: Option<String>,
}

/// Situação do registro de uma etapa no MEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    /// Registrado pelo MEX.
    Registered,
    /// Registrado apenas em parte.
    Partial,
    /// Não registrado pelo MEX; depende de documentação do perito.
    NotRegistered,
}

/// Etapa da cadeia de custódia e o que o MEX registra sobre ela.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StageCoverage {
    /// Nome da etapa.
    pub stage: &'static str,
    /// Situação.
    pub coverage: Coverage,
    /// O que é (ou não é) registrado.
    pub note: &'static str,
}

/// Considerações legais.
#[derive(Debug, Clone, Serialize)]
pub struct LegalSection {
    /// Aviso de não conformidade automática.
    pub notice: &'static str,
    /// Etapas do art. 158-B do CPP e o que o MEX registra.
    pub stages: Vec<StageCoverage>,
}

/// Aviso legal fixo.
pub const LEGAL_NOTICE: &str = "Este relatório organiza registros técnicos da aquisição considerando \
os requisitos de documentação da cadeia de custódia dos arts. 158-A a 158-F do Código de Processo \
Penal. Sua emissão NÃO constitui declaração de conformidade jurídica: a adequação do procedimento \
deve ser avaliada pelo perito responsável e pela autoridade competente. Etapas não registradas pelo \
MEX devem ser documentadas por outros meios.";

/// Cobertura das etapas do art. 158-B pelo MEX neste build.
pub fn stage_coverage() -> Vec<StageCoverage> {
    use Coverage::*;
    let s = |stage, coverage, note| StageCoverage {
        stage,
        coverage,
        note,
    };
    vec![
        s("Reconhecimento", NotRegistered, "Não registrado pelo MEX."),
        s("Isolamento", NotRegistered, "Não registrado pelo MEX."),
        s(
            "Fixação",
            Partial,
            "Identificação do dispositivo como auto-declarada pelo aparelho/origem; não substitui a descrição do vestígio pelo perito.",
        ),
        s(
            "Coleta",
            Registered,
            "Aquisição: método e versão, operador, autorização, início/fim, resultado, limitações e itens não adquiridos.",
        ),
        s(
            "Acondicionamento",
            Partial,
            "Pacote digital selado com SHA-256 por artefato e do manifesto. Acondicionamento físico do aparelho não é registrado.",
        ),
        s(
            "Transporte",
            Partial,
            "Exportações do pacote digital registradas e verificadas no destino. Transporte físico não é registrado.",
        ),
        s("Recebimento", NotRegistered, "Não registrado pelo MEX."),
        s(
            "Processamento",
            Partial,
            "Verificações de integridade registradas. Análise de conteúdo não é realizada pelo MEX.",
        ),
        s(
            "Armazenamento",
            Partial,
            "Local do pacote e hash do manifesto registrados. Condições de guarda não são registradas.",
        ),
        s("Descarte", NotRegistered, "Não registrado pelo MEX."),
    ]
}

/// Relatório técnico.
#[derive(Debug, Clone, Serialize)]
pub struct TechnicalReport {
    /// Formato.
    pub format: &'static str,
    /// Identificador.
    pub report_id: ReportId,
    /// Emissão.
    pub generated_at: UtcTimestamp,
    /// Operador emissor.
    pub generated_by: Operator,
    /// Versões dos módulos de software usados na emissão.
    pub software: Vec<ModuleVersion>,
    /// Caso (conforme banco).
    pub case: Case,
    /// Aquisição.
    pub acquisition_id: AcquisitionId,
    /// Diretório do pacote registrado.
    pub package_path: String,
    /// Manifesto lido do pacote; `None` se ausente/ilegível.
    pub manifest: Option<Manifest>,
    /// Motivo de o manifesto não estar disponível.
    pub manifest_problem: Option<String>,
    /// Verificação de integridade.
    pub integrity: IntegritySection,
    /// Cadeia de custódia.
    pub custody: CustodySection,
    /// Considerações legais.
    pub legal: LegalSection,
}

impl TechnicalReport {
    /// Serialização canônica do `report.json`.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).expect("relatório é sempre serializável");
        v.push(b'\n');
        v
    }
}
