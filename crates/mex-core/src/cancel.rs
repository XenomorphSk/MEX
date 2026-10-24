//! Cancelamento cooperativo.
//!
//! Adaptadores devem consultar o token entre blocos de I/O e encerrar
//! retornando [`MexError::Cancelled`]. O cancelamento nunca é forçado
//! no meio de uma escrita: o artefato em curso é abortado pelo
//! [`crate::traits::ArtifactWriter`] e jamais marcado como completo.

use crate::error::{MexError, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Token de cancelamento compartilhável entre threads/tarefas.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Cria um token não cancelado.
    pub fn new() -> Self {
        Self::default()
    }

    /// Solicita o cancelamento. Idempotente.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Indica se o cancelamento foi solicitado.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Retorna `Err(Cancelled)` se o cancelamento foi solicitado.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(MexError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_state() {
        let a = CancellationToken::new();
        let b = a.clone();
        assert!(b.check().is_ok());
        a.cancel();
        assert!(matches!(b.check(), Err(MexError::Cancelled)));
    }
}
