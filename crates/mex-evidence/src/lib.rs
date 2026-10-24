//! # mex-evidence
//!
//! Evidence Engine do BlackBit MEX:
//!
//! - [`DiskEvidenceSink`]: gravação em streaming com SHA-256, área temporária,
//!   `fsync`, releitura e publicação atômica sem sobrescrita;
//! - [`Manifest`]: proveniência, resultado, limitações e inventário;
//! - selo `manifest.sha256` e `SHA256SUMS`, verificáveis com `sha256sum -c`;
//! - [`verify_package`]: verificação posterior, somente leitura.
//!
//! Este crate não conhece adaptadores concretos nem o módulo de pesquisa.

mod fsutil;
pub mod manifest;
mod pkgdir;
pub mod sink;
pub mod verify;

pub use manifest::{AdapterRecord, Manifest, ManifestHeader, Termination};
pub use sink::{DiskEvidenceSink, FinalizeInput, SealedPackage, SinkOptions};
pub use verify::{verify_package, Finding, FindingKind, VerificationReport};

/// Versão deste módulo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Grava um arquivo **novo** de forma atômica (temporário exclusivo,
/// `fsync`, `rename` sem sobrescrita, `fsync` do diretório).
pub async fn write_new_file_atomic(
    dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> mex_core::Result<std::path::PathBuf> {
    fsutil::write_atomic(dir, name, bytes).await
}

/// Subdiretório dos artefatos finalizados.
pub const ARTIFACTS_DIR: &str = "artifacts";
/// Área temporária (removida no selo).
pub const STAGING_DIR: &str = ".staging";
/// Manifesto.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Selo do manifesto (formato `sha256sum`).
pub const MANIFEST_DIGEST_FILE: &str = "manifest.sha256";
/// Hashes dos artefatos (formato `sha256sum`).
pub const SUMS_FILE: &str = "SHA256SUMS";
