//! Modelos de domínio do MEX.
//!
//! Entidades de negócio independentes de persistência. O mapeamento para
//! SQLite vive em `mex-storage`; aqui ficam os tipos e invariantes.

use crate::capability::CapabilityKind;
use crate::error::{MexError, Result};
use crate::ids::*;
use crate::integrity::Digest256;
use crate::path::EvidencePath;
use crate::timestamp::UtcTimestamp;
use serde::{Deserialize, Serialize};

/// Limite genérico para campos textuais curtos (nomes, números de caso...).
pub const MAX_SHORT_TEXT: usize = 256;
/// Limite para campos textuais longos (observações, escopo).
pub const MAX_LONG_TEXT: usize = 8 * 1024;

/// Valida um campo textual obrigatório: não vazio após `trim`, sem
/// caracteres de controle (exceto quebras de linha em textos longos) e
/// dentro do limite de bytes. Devolve o valor sem espaços nas pontas.
pub fn required_text(field: &'static str, value: &str, max: usize) -> Result<String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(MexError::InvalidInput(format!("{field} é obrigatório")));
    }
    optional_text(field, Some(v), max).map(|o| o.unwrap_or_default())
}

/// Valida um campo textual opcional; vazio vira `None`.
pub fn optional_text(
    field: &'static str,
    value: Option<&str>,
    max: usize,
) -> Result<Option<String>> {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if v.len() > max {
        return Err(MexError::InvalidInput(format!(
            "{field} excede {max} bytes"
        )));
    }
    let multiline_ok = max > MAX_SHORT_TEXT;
    if v.chars()
        .any(|c| c.is_control() && !(multiline_ok && (c == '\n' || c == '\r' || c == '\t')))
    {
        return Err(MexError::InvalidInput(format!(
            "{field} contém caracteres de controle"
        )));
    }
    Ok(Some(v.to_owned()))
}

/// Operador autorizado (perito/investigador).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operator {
    /// Identificador.
    pub id: OperatorId,
    /// Nome completo.
    pub full_name: String,
    /// Matrícula/identificação funcional.
    pub badge: String,
    /// Organização/unidade.
    pub organization: String,
    /// Criado em (UTC).
    pub created_at: UtcTimestamp,
}

impl Operator {
    /// Cria um operador validando os campos.
    pub fn new(full_name: &str, badge: &str, organization: &str, at: UtcTimestamp) -> Result<Self> {
        Ok(Self {
            id: OperatorId::new(),
            full_name: required_text("nome do operador", full_name, MAX_SHORT_TEXT)?,
            badge: required_text("matrícula", badge, MAX_SHORT_TEXT)?,
            organization: required_text("organização", organization, MAX_SHORT_TEXT)?,
            created_at: at,
        })
    }
}

/// Caso pericial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    /// Identificador.
    pub id: CaseId,
    /// Número do caso/procedimento (único).
    pub number: String,
    /// Título/descrição curta.
    pub title: String,
    /// Operador responsável pela criação.
    pub created_by: OperatorId,
    /// Criado em (UTC).
    pub created_at: UtcTimestamp,
}

impl Case {
    /// Cria um caso validando os campos.
    pub fn new(
        number: &str,
        title: &str,
        created_by: OperatorId,
        at: UtcTimestamp,
    ) -> Result<Self> {
        Ok(Self {
            id: CaseId::new(),
            number: required_text("número do caso", number, MAX_SHORT_TEXT)?,
            title: required_text("título do caso", title, MAX_SHORT_TEXT)?,
            created_by,
            created_at: at,
        })
    }
}

/// Natureza da autorização legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationKind {
    /// Decisão/mandado judicial.
    JudicialWarrant,
    /// Consentimento expresso do titular do dispositivo.
    OwnerConsent,
    /// Outra base legal, descrita em `kind_detail`.
    Other,
}

impl AuthorizationKind {
    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthorizationKind::JudicialWarrant => "judicial-warrant",
            AuthorizationKind::OwnerConsent => "owner-consent",
            AuthorizationKind::Other => "other",
        }
    }
}

/// Referência de autorização legal para a aquisição.
///
/// O MEX registra a autorização informada pelo operador; ele **não** avalia
/// sua validade jurídica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// Identificador.
    pub id: AuthorizationId,
    /// Caso ao qual pertence.
    pub case_id: CaseId,
    /// Natureza da autorização.
    pub kind: AuthorizationKind,
    /// Descrição da base legal quando `kind == Other`.
    pub kind_detail: Option<String>,
    /// Número/identificação do documento.
    pub reference: String,
    /// Autoridade emissora.
    pub issuer: String,
    /// Observações/escopo da autorização.
    pub scope_notes: Option<String>,
    /// SHA-256 da cópia digital do documento, se anexada.
    pub document_sha256: Option<Digest256>,
    /// Operador que registrou.
    pub recorded_by: OperatorId,
    /// Registrada em (UTC).
    pub recorded_at: UtcTimestamp,
}

/// Plataforma do dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Android.
    Android,
    /// iOS (suporte futuro).
    Ios,
    /// Dispositivo simulado (testes). Nunca é aceito por adaptadores reais,
    /// e o mock nunca aceita dispositivos reais.
    Simulated,
}

impl Platform {
    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Android => "android",
            Platform::Ios => "ios",
            Platform::Simulated => "simulated",
        }
    }
}

/// Estado do dispositivo no transporte ADB.
///
/// `Device` significa apenas que a depuração USB foi autorizada **no
/// aparelho** — não constitui autorização legal, que é registrada
/// separadamente em [`Authorization`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdbState {
    /// Conectado e com depuração autorizada.
    Device,
    /// Conectado, mas a depuração não foi autorizada no aparelho.
    Unauthorized,
    /// Visível mas offline/inacessível.
    Offline,
    /// Qualquer outro estado (bootloader, recovery, sideload, "no
    /// permissions"...). O rótulo original é preservado.
    Other(String),
}

impl AdbState {
    /// Interpreta o rótulo de estado reportado pelo `adb devices`.
    pub fn parse(label: &str) -> Self {
        match label.trim() {
            "device" => AdbState::Device,
            "unauthorized" => AdbState::Unauthorized,
            "offline" => AdbState::Offline,
            other => AdbState::Other(other.chars().take(MAX_SHORT_TEXT).collect()),
        }
    }

    /// Rótulo textual (o original, no caso de `Other`).
    pub fn label(&self) -> &str {
        match self {
            AdbState::Device => "device",
            AdbState::Unauthorized => "unauthorized",
            AdbState::Offline => "offline",
            AdbState::Other(s) => s,
        }
    }
}

/// O que um [`crate::traits::DeviceProvider`] observou num instante.
///
/// Todos os campos descritivos são **auto-declarados pelo aparelho** e não
/// confiáveis: o serial, por exemplo, pode ser um valor genérico repetido
/// entre unidades (ex.: `0123456789ABCDEF`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceObservation {
    /// Plataforma.
    pub platform: Platform,
    /// Serial reportado pelo transporte.
    pub serial: String,
    /// Fabricante, se acessível.
    pub manufacturer: Option<String>,
    /// Modelo, se acessível.
    pub model: Option<String>,
    /// Versão do sistema operacional, se acessível.
    pub os_version: Option<String>,
    /// Nível de patch de segurança, se acessível.
    pub security_patch: Option<String>,
    /// Estado ADB (apenas para transportes ADB).
    pub adb_state: Option<AdbState>,
    /// Momento da observação.
    pub observed_at: UtcTimestamp,
}

/// Dispositivo inventariado.
///
/// O inventário **não** usa o serial como chave única: dois aparelhos
/// distintos podem reportar o mesmo serial. A correlação de observações com
/// um `Device` existente é decisão explícita do operador/inventário.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Identificador interno.
    pub id: DeviceId,
    /// Observação mais recente.
    pub observed: DeviceObservation,
    /// Primeira vez visto (UTC).
    pub first_seen: UtcTimestamp,
}

impl Device {
    /// Novo dispositivo no inventário a partir da primeira observação.
    /// `first_seen` é o instante da observação, garantindo
    /// `first_seen <= last_seen` (também exigido pelo schema).
    pub fn new(observed: DeviceObservation) -> Self {
        Self {
            id: DeviceId::new(),
            first_seen: observed.observed_at,
            observed,
        }
    }
}

/// Resultado de uma aquisição.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionOutcome {
    /// Todos os artefatos planejados foram adquiridos e finalizados.
    Complete,
    /// Parte dos artefatos falhou ou a aquisição foi interrompida.
    Partial,
    /// Nenhum artefato foi adquirido.
    Failed,
    /// Cancelada pelo operador.
    Cancelled,
}

impl AcquisitionOutcome {
    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquisitionOutcome::Complete => "complete",
            AcquisitionOutcome::Partial => "partial",
            AcquisitionOutcome::Failed => "failed",
            AcquisitionOutcome::Cancelled => "cancelled",
        }
    }

    /// Deriva o resultado a partir do que o sink **efetivamente** finalizou.
    ///
    /// Regras conservadoras ("nunca simular sucesso"):
    /// - cancelamento prevalece sobre qualquer outro resultado;
    /// - `Complete` exige ao menos um artefato, nenhuma falha e nenhuma
    ///   interrupção;
    /// - zero artefatos finalizados é `Failed`, mesmo sem falhas explícitas;
    /// - qualquer falha ou interrupção com artefatos finalizados é `Partial`.
    pub fn derive(cancelled: bool, completed: usize, failed: usize, interrupted: bool) -> Self {
        if cancelled {
            AcquisitionOutcome::Cancelled
        } else if completed == 0 {
            AcquisitionOutcome::Failed
        } else if failed > 0 || interrupted {
            AcquisitionOutcome::Partial
        } else {
            AcquisitionOutcome::Complete
        }
    }
}

/// Registro de uma aquisição (vínculo caso/dispositivo/autorização + método).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acquisition {
    /// Identificador.
    pub id: AcquisitionId,
    /// Caso.
    pub case_id: CaseId,
    /// Dispositivo-alvo.
    pub device_id: DeviceId,
    /// Autorização invocada (deve pertencer ao mesmo caso).
    pub authorization_id: AuthorizationId,
    /// Operador executor.
    pub operator_id: OperatorId,
    /// Capacidade exercida.
    pub capability: CapabilityKind,
    /// Identificador do adaptador/método (ex.: "android-adb").
    pub adapter_id: String,
    /// Versão do adaptador no momento da execução.
    pub adapter_version: String,
    /// Versão do MEX no momento da execução.
    pub software_version: String,
    /// Resultado, preenchido ao finalizar.
    pub outcome: Option<AcquisitionOutcome>,
    /// Limitações conhecidas desta aquisição (para o relatório).
    pub limitations: Vec<String>,
    /// Início (UTC).
    pub started_at: UtcTimestamp,
    /// Fim (UTC), quando finalizada.
    pub finished_at: Option<UtcTimestamp>,
}

/// Estado de um artefato de evidência.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum ArtifactStatus {
    /// Gravação em andamento (área temporária).
    Pending,
    /// Finalizado atomicamente; o digest é obrigatório.
    Complete {
        /// Digest calculado durante a gravação.
        digest: Digest256,
        /// Momento da finalização.
        completed_at: UtcTimestamp,
    },
    /// Falhou ou foi abortado; nunca deve ser tratado como evidência íntegra.
    Failed {
        /// Motivo legível.
        reason: String,
    },
}

/// Artefato de evidência produzido por uma aquisição.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Identificador.
    pub id: ArtifactId,
    /// Aquisição de origem.
    pub acquisition_id: AcquisitionId,
    /// Caminho lógico validado dentro do pacote de evidências.
    pub stored_path: EvidencePath,
    /// Caminho como reportado pela origem (não confiável; só proveniência).
    pub source_path: Option<String>,
    /// Data de modificação na origem, quando disponível (proveniência).
    pub source_modified: Option<UtcTimestamp>,
    /// Bytes gravados.
    pub size_bytes: u64,
    /// Estado.
    pub status: ArtifactStatus,
    /// Criado em (UTC).
    pub created_at: UtcTimestamp,
}

impl ArtifactRecord {
    /// Indica se o artefato foi finalizado com digest.
    pub fn is_complete(&self) -> bool {
        matches!(self.status, ArtifactStatus::Complete { .. })
    }

    /// Digest, somente se completo.
    pub fn digest(&self) -> Option<&Digest256> {
        match &self.status {
            ArtifactStatus::Complete { digest, .. } => Some(digest),
            _ => None,
        }
    }
}

/// Resultado da verificação de integridade de um pacote de evidências.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityStatus {
    /// Manifesto selado e todos os artefatos conferem.
    Intact,
    /// Divergência detectada (hash, tamanho, arquivo ausente/extra, manifesto).
    Compromised,
    /// Pacote sem selo (finalização não concluída).
    Incomplete,
}

impl IntegrityStatus {
    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            IntegrityStatus::Intact => "intact",
            IntegrityStatus::Compromised => "compromised",
            IntegrityStatus::Incomplete => "incomplete",
        }
    }
}

/// Item que não pôde ser adquirido, para o relatório de limitações.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactFailure {
    /// Caminho/identificação na origem, como reportado.
    pub source_path: Option<String>,
    /// Motivo legível.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_validation() {
        assert_eq!(required_text("x", "  abc ", 10).unwrap(), "abc");
        assert!(required_text("x", "   ", 10).is_err());
        assert!(required_text("x", "a\u{0}b", 10).is_err());
        assert!(required_text("x", "abcdefghijk", 10).is_err());
        assert!(required_text("x", "a\nb", MAX_SHORT_TEXT).is_err());
        assert!(required_text("x", "a\nb", MAX_LONG_TEXT).is_ok());
        assert_eq!(optional_text("x", Some("  "), 10).unwrap(), None);
    }

    #[test]
    fn operator_and_case_constructors_validate() {
        let t = UtcTimestamp::now();
        let op =
            Operator::new("Perita Exemplo", "12345", "Instituto de Criminalística", t).unwrap();
        assert!(Operator::new("", "1", "org", t).is_err());
        assert!(Case::new("IP 001/2025", "Apreensão", op.id, t).is_ok());
        assert!(Case::new(" ", "Apreensão", op.id, t).is_err());
    }

    #[test]
    fn adb_state_preserves_unknown_label() {
        assert_eq!(AdbState::parse("device"), AdbState::Device);
        assert_eq!(AdbState::parse("unauthorized"), AdbState::Unauthorized);
        assert_eq!(AdbState::parse("offline"), AdbState::Offline);
        let s = AdbState::parse("recovery");
        assert_eq!(s, AdbState::Other("recovery".into()));
        assert_eq!(s.label(), "recovery");
    }

    #[test]
    fn outcome_derivation_never_overstates() {
        use AcquisitionOutcome::*;
        assert_eq!(AcquisitionOutcome::derive(false, 3, 0, false), Complete);
        assert_eq!(AcquisitionOutcome::derive(false, 3, 1, false), Partial);
        assert_eq!(AcquisitionOutcome::derive(false, 3, 0, true), Partial);
        assert_eq!(AcquisitionOutcome::derive(false, 0, 0, false), Failed);
        assert_eq!(AcquisitionOutcome::derive(false, 0, 2, true), Failed);
        assert_eq!(AcquisitionOutcome::derive(true, 3, 0, false), Cancelled);
    }
}
