//! Capacidades de aquisição.
//!
//! Uma capacidade descreve o que um adaptador consegue fazer com um
//! dispositivo específico, e os pré-requisitos/riscos associados. A presença
//! de um dispositivo nunca implica capacidade: cada uma é resolvida
//! explicitamente e pode ser negada.

use serde::{Deserialize, Serialize};

/// Tipos de capacidade de aquisição.
///
/// Apenas as marcadas por [`CapabilityKind::is_operational`] podem ser
/// oferecidas neste build. As demais existem para fixar a arquitetura e
/// **não** são funcionalidades disponíveis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    /// Leitura de propriedades/identificação do dispositivo.
    DeviceInfo,
    /// Aquisição lógica de dispositivo Android previamente autorizado.
    AndroidLogical,
    /// Importação de backup/arquivo forense já existente.
    LocalImport,
    /// (Planejado) Aquisição de sistema de arquivos.
    FileSystem,
    /// (Planejado) Aquisição privilegiada. Exigirá método VALIDATED.
    Privileged,
    /// (Planejado) Adaptador de pesquisa avançada (apenas laboratório).
    AdvancedResearch,
    /// (Planejado) Importação de backup iOS.
    IosBackup,
}

impl CapabilityKind {
    /// Todas as variantes (para validação de schema e UI).
    pub const ALL: [CapabilityKind; 7] = [
        CapabilityKind::DeviceInfo,
        CapabilityKind::AndroidLogical,
        CapabilityKind::LocalImport,
        CapabilityKind::FileSystem,
        CapabilityKind::Privileged,
        CapabilityKind::AdvancedResearch,
        CapabilityKind::IosBackup,
    ];

    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            CapabilityKind::DeviceInfo => "device-info",
            CapabilityKind::AndroidLogical => "android-logical",
            CapabilityKind::LocalImport => "local-import",
            CapabilityKind::FileSystem => "file-system",
            CapabilityKind::Privileged => "privileged",
            CapabilityKind::AdvancedResearch => "advanced-research",
            CapabilityKind::IosBackup => "ios-backup",
        }
    }

    /// Indica se a capacidade é operacional neste build.
    pub fn is_operational(&self) -> bool {
        matches!(
            self,
            CapabilityKind::DeviceInfo
                | CapabilityKind::AndroidLogical
                | CapabilityKind::LocalImport
        )
    }

    /// Capacidades que, quando existirem, só poderão ser usadas em caso real
    /// com um método de pesquisa em estado VALIDATED (ver `mex-research`).
    pub fn requires_validated_method(&self) -> bool {
        matches!(
            self,
            CapabilityKind::Privileged | CapabilityKind::AdvancedResearch
        )
    }
}

impl std::str::FromStr for CapabilityKind {
    type Err = crate::MexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| crate::MexError::InvalidInput(format!("capacidade desconhecida: {s:?}")))
    }
}

/// Disponibilidade resolvida de uma capacidade para um dispositivo concreto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum Availability {
    /// Disponível, sujeita aos pré-requisitos listados.
    Available,
    /// Indisponível, com motivo legível.
    Unavailable {
        /// Motivo pelo qual está indisponível (ex.: dispositivo não autorizado).
        reason: String,
    },
    /// Capacidade declarada mas não implementada neste build.
    NotImplemented,
}

/// Risco de que a operação modifique o dispositivo de origem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModificationRisk {
    /// Nenhuma escrita conhecida no dispositivo.
    None,
    /// Pode alterar estado volátil ou logs do sistema (ex.: sessão ADB).
    Low,
    /// Modifica o dispositivo de forma observável e persistente.
    High,
}

/// Descrição completa de uma capacidade resolvida.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Tipo da capacidade.
    pub kind: CapabilityKind,
    /// Disponibilidade resolvida para o dispositivo-alvo.
    pub availability: Availability,
    /// Pré-requisitos de acesso (ex.: "depuração USB autorizada").
    pub prerequisites: Vec<String>,
    /// Restrições/limitações conhecidas.
    pub limitations: Vec<String>,
    /// Risco de modificação do dispositivo.
    pub modification_risk: ModificationRisk,
}

impl Capability {
    /// Atalho para uma capacidade indisponível com motivo.
    pub fn unavailable(kind: CapabilityKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            availability: Availability::Unavailable {
                reason: reason.into(),
            },
            prerequisites: Vec::new(),
            limitations: Vec::new(),
            modification_risk: ModificationRisk::None,
        }
    }

    /// Atalho para uma capacidade planejada, ainda não implementada.
    pub fn not_implemented(kind: CapabilityKind) -> Self {
        Self {
            availability: Availability::NotImplemented,
            ..Self::unavailable(kind, "")
        }
    }

    /// Indica se a capacidade está disponível.
    pub fn is_available(&self) -> bool {
        matches!(self.availability, Availability::Available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_roundtrip_and_match_serde() {
        for k in CapabilityKind::ALL {
            assert_eq!(k.as_str().parse::<CapabilityKind>().unwrap(), k);
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
    }

    #[test]
    fn future_capabilities_are_not_operational() {
        for k in [
            CapabilityKind::FileSystem,
            CapabilityKind::Privileged,
            CapabilityKind::AdvancedResearch,
            CapabilityKind::IosBackup,
        ] {
            assert!(!k.is_operational(), "{k:?}");
        }
    }
}
