//! Identificadores tipados.
//!
//! Cada entidade tem um ID próprio para evitar troca acidental de chaves.
//! Internamente são UUIDv4 estáveis, serializados como string hifenizada
//! minúscula (36 caracteres), que é também a forma persistida no SQLite.

/// Define um identificador tipado baseado em UUID.
///
/// Exportado para que outros crates do workspace (ex.: `mex-research`)
/// definam seus próprios IDs com as mesmas garantias.
#[macro_export]
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            ::serde::Serialize, ::serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub ::uuid::Uuid);

        impl $name {
            /// Gera um novo identificador aleatório (UUIDv4).
            pub fn new() -> Self {
                Self(::uuid::Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                // Forma hifenizada minúscula: canônica para hash e persistência.
                write!(f, "{}", self.0.hyphenated())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::MexError;

            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                ::uuid::Uuid::parse_str(s).map(Self).map_err(|_| {
                    $crate::MexError::InvalidInput(format!(
                        "{} inválido: {s:?}",
                        stringify!($name)
                    ))
                })
            }
        }
    };
}

typed_id!(
    /// Identificador de caso pericial.
    CaseId
);
typed_id!(
    /// Identificador de operador (perito/investigador autorizado).
    OperatorId
);
typed_id!(
    /// Identificador de autorização (mandado/ordem/consentimento).
    AuthorizationId
);
typed_id!(
    /// Identificador de dispositivo inventariado.
    DeviceId
);
typed_id!(
    /// Identificador de aquisição.
    AcquisitionId
);
typed_id!(
    /// Identificador de job de aquisição.
    JobId
);
typed_id!(
    /// Identificador de artefato de evidência.
    ArtifactId
);
typed_id!(
    /// Identificador de evento de auditoria.
    AuditEventId
);
typed_id!(
    /// Identificador de relatório gerado.
    ReportId
);
typed_id!(
    /// Identificador de verificação de integridade.
    VerificationId
);
typed_id!(
    /// Identificador de exportação de pacote de evidências.
    ExportId
);

#[cfg(test)]
mod tests {
    use super::CaseId;

    #[test]
    fn display_and_parse_roundtrip() {
        let id = CaseId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36);
        assert_eq!(s, s.to_lowercase());
        assert_eq!(s.parse::<CaseId>().unwrap(), id);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!("not-a-uuid".parse::<CaseId>().is_err());
    }
}
