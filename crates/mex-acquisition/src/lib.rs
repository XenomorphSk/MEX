//! # mex-acquisition
//!
//! Motor de aquisição do BlackBit MEX:
//!
//! - [`engine::run_acquisition`]: conduz o job, o pacote de evidências, a
//!   persistência e a auditoria de uma aquisição;
//! - [`engine::verify_acquisition`]: verificação posterior registrada;
//! - [`importer::LocalEvidenceImporter`]: importação de backups/exportações
//!   existentes no host.
//!
//! Aquisição de dispositivos via ADB entra no Milestone 3.

pub mod engine;
pub mod importer;

pub use engine::{
    run_acquisition, run_acquisition_as, verify_acquisition, AcquisitionPlan, AcquisitionSummary,
    EngineError,
};
pub use importer::LocalEvidenceImporter;

/// Versão deste módulo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
