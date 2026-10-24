//! Erro serializável para a interface.
//!
//! A interface recebe uma categoria estável (`kind`) e uma mensagem legível
//! em português. Detalhes internos (pilha, SQL) não são expostos.

use serde::Serialize;

/// Erro exibível na interface.
#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct AppError {
    /// Categoria: `session`, `not-found`, `invalid`, `policy`, `integrity`,
    /// `io`, `storage`, `internal`.
    pub kind: &'static str,
    /// Mensagem legível.
    pub message: String,
}

/// Resultado da camada de aplicação.
pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    /// Sessão sem operador.
    pub fn session(msg: impl Into<String>) -> Self {
        Self {
            kind: "session",
            message: msg.into(),
        }
    }

    /// Registro inexistente.
    pub fn not_found(what: &str) -> Self {
        Self {
            kind: "not-found",
            message: format!("{what} não encontrado(a)"),
        }
    }

    /// Falha interna.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            kind: "internal",
            message: msg.into(),
        }
    }
}

impl From<mex_core::MexError> for AppError {
    fn from(e: mex_core::MexError) -> Self {
        use mex_core::MexError::*;
        let kind = match &e {
            InvalidInput(_)
            | InvalidPath { .. }
            | InvalidTransition { .. }
            | UnsupportedCapability(_) => "invalid",
            PolicyDenied(_) | Unauthorized => "policy",
            IntegrityMismatch { .. } | AuditChainBroken { .. } => "integrity",
            Io { .. } => "io",
            Cancelled | DeviceDisconnected(_) | Adapter(_) => "internal",
        };
        Self {
            kind,
            message: e.to_string(),
        }
    }
}

impl From<mex_storage::StorageError> for AppError {
    fn from(e: mex_storage::StorageError) -> Self {
        match e {
            mex_storage::StorageError::Domain(d) => d.into(),
            mex_storage::StorageError::Database(sqlx::Error::Database(db)) => Self {
                kind: "storage",
                message: format!("operação recusada pelo banco: {}", db.message()),
            },
            other => {
                tracing::error!(error = %other, "erro de banco");
                Self {
                    kind: "storage",
                    message: "erro de banco de dados (detalhes no log)".into(),
                }
            }
        }
    }
}

impl From<mex_acquisition::EngineError> for AppError {
    fn from(e: mex_acquisition::EngineError) -> Self {
        match e {
            mex_acquisition::EngineError::Domain(d) => d.into(),
            mex_acquisition::EngineError::Storage(s) => s.into(),
        }
    }
}

impl From<mex_reporting::ReportError> for AppError {
    fn from(e: mex_reporting::ReportError) -> Self {
        match e {
            mex_reporting::ReportError::Domain(d) => d.into(),
            mex_reporting::ReportError::Storage(s) => s.into(),
            mex_reporting::ReportError::Engine(x) => x.into(),
        }
    }
}
