//! Gravação atômica de arquivos novos **fora** do pacote de evidências
//! (ex.: relatórios). Dentro do pacote, todo acesso passa por
//! [`crate::pkgdir`].
//!
//! Regras: nunca sobrescrever, `fsync` antes do `rename`, modo `0600` em Unix.

use mex_core::{MexError, Result};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Exige que nada exista em `path` (nem link simbólico quebrado).
pub(crate) async fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path).await {
        Ok(_) => Err(MexError::InvalidInput(format!(
            "destino já existe e não será sobrescrito: {}",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(MexError::io(path, e)),
    }
}

/// Sincroniza um diretório (persistência de criação/renomeação).
///
/// Em sistemas que não suportam `fsync` de diretório (ex.: Windows, alguns
/// sistemas FAT) a falha é registrada em log e não interrompe a operação.
pub(crate) async fn fsync_dir(dir: &Path) {
    let r = async {
        let f = fs::File::open(dir).await?;
        f.sync_all().await
    }
    .await;
    if let Err(e) = r {
        tracing::warn!(dir = %dir.display(), error = %e, "fsync de diretório indisponível");
    }
}

/// Grava `bytes` em `dir/name` de forma atômica: arquivo temporário
/// exclusivo, `fsync`, verificação de ausência do destino, `rename` e
/// `fsync` do diretório.
pub(crate) async fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let target = dir.join(name);
    require_absent(&target).await?;
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let r = async {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&tmp).await.map_err(|e| MexError::io(&tmp, e))?;
        f.write_all(bytes)
            .await
            .map_err(|e| MexError::io(&tmp, e))?;
        f.flush().await.map_err(|e| MexError::io(&tmp, e))?;
        f.sync_all().await.map_err(|e| MexError::io(&tmp, e))?;
        drop(f);
        require_absent(&target).await?;
        fs::rename(&tmp, &target)
            .await
            .map_err(|e| MexError::io(&target, e))
    }
    .await;
    if r.is_err() {
        let _ = fs::remove_file(&tmp).await;
    }
    r?;
    fsync_dir(dir).await;
    Ok(target)
}
