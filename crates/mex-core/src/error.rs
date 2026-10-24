//! Tipos de erro do núcleo de domínio.
//!
//! O núcleo usa `thiserror` para erros estruturados. Camadas de fronteira
//! (CLI, Tauri, adaptadores de I/O) podem envolvê-los com `anyhow`.

use thiserror::Error;

/// Erro de domínio do MEX.
#[derive(Debug, Error)]
pub enum MexError {
    /// Transição de estado inválida solicitada numa máquina de estados.
    #[error("transição inválida: {from} -> {to}")]
    InvalidTransition {
        /// Estado de origem.
        from: &'static str,
        /// Estado de destino solicitado.
        to: &'static str,
    },

    /// Entrada rejeitada pela validação de domínio.
    #[error("entrada inválida: {0}")]
    InvalidInput(String),

    /// Caminho de evidência rejeitado (path traversal, componente proibido...).
    #[error("caminho de evidência inválido ({path:?}): {reason}")]
    InvalidPath {
        /// Caminho recebido (não confiável; apenas para diagnóstico).
        path: String,
        /// Motivo da rejeição.
        reason: &'static str,
    },

    /// Falha de verificação de integridade (hash divergente).
    #[error("integridade divergente: esperado {expected}, obtido {actual}")]
    IntegrityMismatch {
        /// Hash esperado (hex).
        expected: String,
        /// Hash calculado (hex).
        actual: String,
    },

    /// A cadeia de auditoria foi violada no evento de sequência `seq`.
    #[error("cadeia de auditoria violada no evento seq={seq}: {reason}")]
    AuditChainBroken {
        /// Número de sequência do primeiro evento inconsistente.
        seq: u64,
        /// Descrição da inconsistência.
        reason: String,
    },

    /// Capacidade solicitada não é suportada pelo adaptador.
    #[error("capacidade não suportada: {0}")]
    UnsupportedCapability(String),

    /// Operação negada por política (ex.: método não validado em caso real).
    #[error("operação negada por política: {0}")]
    PolicyDenied(String),

    /// Operação negada por falta de autorização registrada.
    #[error("autorização ausente ou inválida para a operação")]
    Unauthorized,

    /// Operação interrompida por cancelamento cooperativo.
    #[error("operação cancelada pelo operador")]
    Cancelled,

    /// O dispositivo deixou de responder/foi desconectado.
    #[error("dispositivo desconectado: {0}")]
    DeviceDisconnected(String),

    /// Falha de entrada/saída no host (gravação de evidência, leitura de origem).
    #[error("falha de E/S em {path}: {source}")]
    Io {
        /// Caminho envolvido (do host).
        path: String,
        /// Erro original.
        #[source]
        source: std::io::Error,
    },

    /// Falha genérica de adaptador, com mensagem descritiva.
    #[error("falha de adaptador: {0}")]
    Adapter(String),
}

impl MexError {
    /// Atalho para construir [`MexError::Io`].
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        MexError::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

/// Alias de resultado do domínio.
pub type Result<T> = std::result::Result<T, MexError>;
