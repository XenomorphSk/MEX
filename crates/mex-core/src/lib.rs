//! # mex-core
//!
//! Núcleo de domínio do **BlackBit MEX (Mobile Extraction Engine)**.
//!
//! Contém modelos de domínio, identificadores tipados, timestamps UTC
//! canônicos, caminhos de evidência validados, a máquina de estados de jobs,
//! integridade criptográfica (SHA-256), a cadeia de auditoria encadeada e os
//! traits fundamentais do motor de aquisição por plugins.
//!
//! ## Princípios forenses incorporados
//! - A presença de um dispositivo nunca implica autorização nem capacidade.
//! - O registro de um artefato como completo vem do [`traits::EvidenceSink`]
//!   (que calculou o hash), nunca da alegação de um adaptador.
//! - Nenhuma evidência é marcada como completa sem `commit` bem-sucedido.
//! - Transições de job inválidas são rejeitadas.
//! - A auditoria é append-only com encadeamento de hashes (limitações
//!   documentadas em [`audit`]).
//!
//! Este crate não implementa bypass de autenticação, exploração de
//! dispositivos de terceiros, quebra de senhas ou elevação de privilégios.

pub mod audit;
pub mod cancel;
pub mod capability;
pub mod error;
pub mod ids;
pub mod integrity;
pub mod job;
pub mod mock;
pub mod model;
pub mod path;
pub mod state;
pub mod timestamp;
pub mod traits;

pub use error::{MexError, Result};

/// Versão do núcleo (do Cargo.toml).
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
