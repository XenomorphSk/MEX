//! # mex-reporting
//!
//! Relatórios técnicos e exportação verificada do BlackBit MEX:
//!
//! - [`generate_report`]: relatório técnico em JSON (estruturado) e HTML
//!   (autocontido, para leitura e impressão), com verificação de
//!   integridade executada na emissão e o estado da cadeia de custódia;
//! - [`export_package`]: cópia do pacote para outro destino, verificada no
//!   destino contra o hash registrado na aquisição.
//!
//! Arquivos emitidos e exportações são registrados no banco com evento
//! `exported` na cadeia de custódia.

pub mod export;
pub mod generate;
pub mod html;
pub mod model;

pub use export::{export_package, ExportOutcome};
pub use generate::{generate_report, EmittedReport, ReportRequest};
pub use model::TechnicalReport;

/// Versão deste módulo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Erros de emissão/exportação.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// Erro de domínio ou de política.
    #[error(transparent)]
    Domain(#[from] mex_core::MexError),
    /// Erro de persistência.
    #[error(transparent)]
    Storage(#[from] mex_storage::StorageError),
    /// Erro do motor (verificação).
    #[error(transparent)]
    Engine(#[from] mex_acquisition::EngineError),
}
