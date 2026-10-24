//! Diretório do pacote de evidências: única porta do sink para o disco.
//!
//! ## Linux (implementação ancorada em descritores)
//!
//! Os diretórios do pacote, de `artifacts/` e de `.staging/` são abertos
//! **uma vez**, na criação, e mantidos abertos. Toda operação posterior é
//! relativa a esses descritores (`openat`, `mkdirat`, `renameat2`,
//! `unlinkat`), nunca a caminhos textuais. Consequências:
//!
//! - trocar um diretório do pacote por um link simbólico, ou movê-lo, depois
//!   da criação não desvia nenhuma gravação: os descritores continuam
//!   apontando para os diretórios originais;
//! - cada subdiretório de um artefato é aberto com `O_NOFOLLOW` a partir do
//!   descritor do pai; um link no caminho é recusado (`ELOOP`/`ENOTDIR`);
//! - a publicação usa `renameat2(RENAME_NOREPLACE)`: atômica e incapaz de
//!   sobrescrever um destino existente, sem janela entre checar e renomear;
//! - arquivos são criados com `O_EXCL | O_NOFOLLOW` e modo `0600`;
//!   diretórios com modo `0700` (permissões mínimas).
//!
//! Se o sistema de arquivos não suportar `RENAME_NOREPLACE` (`EINVAL`), é
//! usado `statat` + `renameat` **no mesmo descritor de diretório**: a janela
//! residual só é explorável por quem já tem escrita naquele diretório
//! específico do pacote. O evento é registrado em log.
//!
//! ## Outras plataformas
//!
//! Implementação baseada em caminhos, com checagem de links antes de cada
//! operação (garantia mais fraca, documentada em `docs/threat-model.md`).

use crate::{ARTIFACTS_DIR, STAGING_DIR};
use mex_core::integrity::{hash_reader, Digest256};
use mex_core::path::EvidencePath;
use mex_core::{MexError, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Diretório de pacote (clonável; os descritores são compartilhados).
#[derive(Clone)]
pub(crate) struct PackageDir(Arc<imp::Inner>);

async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| MexError::Adapter(format!("tarefa de E/S falhou: {e}")))?
}

impl PackageDir {
    /// Cria `<root>/<name>/` com `artifacts/` e `.staging/`. Falha se existir.
    pub async fn create(root: &Path, name: &str) -> Result<Self> {
        let (root, name) = (root.to_path_buf(), name.to_owned());
        let inner = blocking(move || imp::Inner::create(&root, &name)).await?;
        Ok(Self(Arc::new(inner)))
    }

    /// Caminho do pacote (somente para exibição, registro e verificação).
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    /// Cria um temporário exclusivo em `.staging/`. Devolve o arquivo e o nome.
    pub async fn create_temp(&self) -> Result<(std::fs::File, String)> {
        let i = Arc::clone(&self.0);
        blocking(move || i.create_temp()).await
    }

    /// Relê o temporário e calcula seu SHA-256.
    pub async fn hash_temp(&self, name: &str) -> Result<(Digest256, u64)> {
        let (i, name) = (Arc::clone(&self.0), name.to_owned());
        blocking(move || {
            let f = i.open_temp(&name)?;
            hash_reader(f).map_err(|e| MexError::io(i.staging_display(&name), e))
        })
        .await
    }

    /// Remove um temporário (melhor esforço).
    pub async fn remove_temp(&self, name: &str) {
        let (i, name) = (Arc::clone(&self.0), name.to_owned());
        let _ = blocking(move || i.remove_temp(&name)).await;
    }

    /// Remove um temporário de forma síncrona (uso em `Drop`).
    pub fn remove_temp_now(&self, name: &str) {
        let _ = self.0.remove_temp(name);
    }

    /// Publica o temporário em `artifacts/<dest>`, sem sobrescrever.
    pub async fn publish(&self, temp: &str, dest: &EvidencePath) -> Result<()> {
        let (i, temp, dest) = (Arc::clone(&self.0), temp.to_owned(), dest.clone());
        blocking(move || i.publish(&temp, &dest)).await
    }

    /// Grava um arquivo de controle novo na raiz do pacote (atômico, sem
    /// sobrescrita).
    pub async fn write_control(&self, name: &str, bytes: Vec<u8>) -> Result<()> {
        let (i, name) = (Arc::clone(&self.0), name.to_owned());
        blocking(move || i.write_control(&name, &bytes)).await
    }

    /// Remove `*.part` remanescentes e a área temporária.
    pub async fn clear_staging(&self) -> Result<()> {
        let i = Arc::clone(&self.0);
        blocking(move || i.clear_staging()).await
    }
}

fn exists_error(p: &Path) -> MexError {
    MexError::InvalidInput(format!(
        "destino já existe e não será sobrescrito: {}",
        p.display()
    ))
}

fn not_real_dir(p: &Path) -> MexError {
    MexError::InvalidInput(format!(
        "{} existe e não é um diretório real (link simbólico ou arquivo)",
        p.display()
    ))
}

fn unexpected_staging(p: &Path) -> MexError {
    MexError::InvalidInput(format!(
        "conteúdo inesperado na área temporária: {}",
        p.display()
    ))
}

fn temp_name() -> String {
    format!("{}.part", uuid::Uuid::new_v4().simple())
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, RenameFlags, CWD};
    use rustix::io::Errno;
    use std::io::Write;
    use std::os::fd::OwnedFd;

    const DIR_MODE: Mode = Mode::RWXU;

    fn file_mode() -> Mode {
        Mode::RUSR | Mode::WUSR
    }

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn err(p: &Path, e: Errno) -> MexError {
        MexError::io(p, std::io::Error::from(e))
    }

    fn open_subdir(parent: &OwnedFd, name: &str, display: &Path) -> Result<OwnedFd> {
        rfs::openat(parent, name, dir_flags(), Mode::empty()).map_err(|e| match e {
            Errno::LOOP | Errno::NOTDIR => not_real_dir(display),
            e => err(display, e),
        })
    }

    fn sync_dir(fd: &OwnedFd) {
        if let Err(e) = rfs::fsync(fd) {
            tracing::warn!(error = %e, "fsync de diretório indisponível");
        }
    }

    /// `renameat2(NOREPLACE)`, com alternativa para sistemas de arquivos sem
    /// suporte, restrita ao mesmo descritor de diretório de destino.
    fn rename_noreplace(
        from_dir: &OwnedFd,
        from: &str,
        to_dir: &OwnedFd,
        to: &str,
        dest_path: &Path,
    ) -> Result<()> {
        match rfs::renameat_with(from_dir, from, to_dir, to, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) => Err(exists_error(dest_path)),
            Err(Errno::INVAL) | Err(Errno::NOSYS) => {
                tracing::warn!(
                    dest = %dest_path.display(),
                    "RENAME_NOREPLACE indisponível neste sistema de arquivos; usando statat + renameat no mesmo diretório"
                );
                match rfs::statat(to_dir, to, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(_) => Err(exists_error(dest_path)),
                    Err(Errno::NOENT) => {
                        rfs::renameat(from_dir, from, to_dir, to).map_err(|e| err(dest_path, e))
                    }
                    Err(e) => Err(err(dest_path, e)),
                }
            }
            Err(e) => Err(err(dest_path, e)),
        }
    }

    pub(crate) struct Inner {
        pub(crate) path: PathBuf,
        root: OwnedFd,
        artifacts: OwnedFd,
        staging: OwnedFd,
    }

    impl Inner {
        pub(crate) fn create(root: &Path, name: &str) -> Result<Self> {
            let root_c = std::fs::canonicalize(root).map_err(|e| MexError::io(root, e))?;
            let root_fd = rfs::openat(
                CWD,
                &root_c,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| err(&root_c, e))?;
            let path = root_c.join(name);
            rfs::mkdirat(&root_fd, name, DIR_MODE).map_err(|e| err(&path, e))?;
            let pkg = open_subdir(&root_fd, name, &path)?;
            let mut fds = Vec::new();
            for d in [ARTIFACTS_DIR, STAGING_DIR] {
                let p = path.join(d);
                rfs::mkdirat(&pkg, d, DIR_MODE).map_err(|e| err(&p, e))?;
                fds.push(open_subdir(&pkg, d, &p)?);
            }
            sync_dir(&pkg);
            sync_dir(&root_fd);
            let staging = fds.pop().expect("staging");
            let artifacts = fds.pop().expect("artifacts");
            Ok(Self {
                path,
                root: pkg,
                artifacts,
                staging,
            })
        }

        pub(crate) fn staging_display(&self, name: &str) -> PathBuf {
            self.path.join(STAGING_DIR).join(name)
        }

        pub(crate) fn create_temp(&self) -> Result<(std::fs::File, String)> {
            let name = temp_name();
            let flags =
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let fd = rfs::openat(&self.staging, name.as_str(), flags, file_mode())
                .map_err(|e| err(&self.staging_display(&name), e))?;
            Ok((std::fs::File::from(fd), name))
        }

        pub(crate) fn open_temp(&self, name: &str) -> Result<std::fs::File> {
            let fd = rfs::openat(
                &self.staging,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| err(&self.staging_display(name), e))?;
            Ok(std::fs::File::from(fd))
        }

        pub(crate) fn remove_temp(&self, name: &str) -> Result<()> {
            rfs::unlinkat(&self.staging, name, AtFlags::empty())
                .map_err(|e| err(&self.staging_display(name), e))
        }

        pub(crate) fn publish(&self, temp: &str, dest: &EvidencePath) -> Result<()> {
            let comps: Vec<&str> = dest.components().collect();
            let (name, parents) = comps.split_last().expect("EvidencePath nunca é vazio");
            let mut display = self.path.join(ARTIFACTS_DIR);
            let mut cur = self
                .artifacts
                .try_clone()
                .map_err(|e| MexError::io(&display, e))?;
            for c in parents {
                display.push(c);
                cur = match rfs::openat(&cur, *c, dir_flags(), Mode::empty()) {
                    Ok(fd) => fd,
                    Err(Errno::NOENT) => {
                        match rfs::mkdirat(&cur, *c, DIR_MODE) {
                            Ok(()) | Err(Errno::EXIST) => {}
                            Err(e) => return Err(err(&display, e)),
                        }
                        sync_dir(&cur);
                        open_subdir(&cur, c, &display)?
                    }
                    Err(Errno::LOOP) | Err(Errno::NOTDIR) => return Err(not_real_dir(&display)),
                    Err(e) => return Err(err(&display, e)),
                };
            }
            display.push(name);
            rename_noreplace(&self.staging, temp, &cur, name, &display)?;
            sync_dir(&cur);
            sync_dir(&self.staging);
            Ok(())
        }

        pub(crate) fn write_control(&self, name: &str, bytes: &[u8]) -> Result<()> {
            let target = self.path.join(name);
            let tmp = format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple());
            let r = (|| -> Result<()> {
                let flags = OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC;
                let fd = rfs::openat(&self.root, tmp.as_str(), flags, file_mode())
                    .map_err(|e| err(&target, e))?;
                let mut f = std::fs::File::from(fd);
                f.write_all(bytes).map_err(|e| MexError::io(&target, e))?;
                f.sync_all().map_err(|e| MexError::io(&target, e))?;
                rename_noreplace(&self.root, &tmp, &self.root, name, &target)
            })();
            if r.is_err() {
                let _ = rfs::unlinkat(&self.root, tmp.as_str(), AtFlags::empty());
            }
            r?;
            sync_dir(&self.root);
            Ok(())
        }

        pub(crate) fn clear_staging(&self) -> Result<()> {
            let staging_path = self.path.join(STAGING_DIR);
            let mut dir = rfs::Dir::read_from(&self.staging).map_err(|e| err(&staging_path, e))?;
            let mut names = Vec::new();
            while let Some(entry) = dir.read() {
                let entry = entry.map_err(|e| err(&staging_path, e))?;
                let n = entry.file_name().to_string_lossy().into_owned();
                if n != "." && n != ".." {
                    names.push(n);
                }
            }
            for n in names {
                let p = staging_path.join(&n);
                let st = rfs::statat(&self.staging, n.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| err(&p, e))?;
                if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                    || !n.ends_with(".part")
                {
                    return Err(unexpected_staging(&p));
                }
                rfs::unlinkat(&self.staging, n.as_str(), AtFlags::empty())
                    .map_err(|e| err(&p, e))?;
            }
            rfs::unlinkat(&self.root, STAGING_DIR, AtFlags::REMOVEDIR)
                .map_err(|e| err(&staging_path, e))?;
            sync_dir(&self.root);
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    //! Implementação baseada em caminhos (garantia mais fraca: há janela
    //! entre a checagem de links e cada operação).
    use super::*;
    use std::fs;
    use std::io::Write;

    fn require_real_dir(p: &Path) -> Result<()> {
        match fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_dir() => Ok(()),
            Ok(_) => Err(not_real_dir(p)),
            Err(e) => Err(MexError::io(p, e)),
        }
    }

    fn require_absent(p: &Path) -> Result<()> {
        match fs::symlink_metadata(p) {
            Ok(_) => Err(exists_error(p)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(MexError::io(p, e)),
        }
    }

    pub(crate) struct Inner {
        pub(crate) path: PathBuf,
    }

    impl Inner {
        pub(crate) fn create(root: &Path, name: &str) -> Result<Self> {
            let root = fs::canonicalize(root).map_err(|e| MexError::io(root, e))?;
            let path = root.join(name);
            fs::create_dir(&path).map_err(|e| MexError::io(&path, e))?;
            for d in [ARTIFACTS_DIR, STAGING_DIR] {
                let p = path.join(d);
                fs::create_dir(&p).map_err(|e| MexError::io(&p, e))?;
            }
            Ok(Self { path })
        }

        fn staging(&self) -> Result<PathBuf> {
            require_real_dir(&self.path)?;
            let s = self.path.join(STAGING_DIR);
            require_real_dir(&s)?;
            Ok(s)
        }

        pub(crate) fn staging_display(&self, name: &str) -> PathBuf {
            self.path.join(STAGING_DIR).join(name)
        }

        pub(crate) fn create_temp(&self) -> Result<(fs::File, String)> {
            let name = temp_name();
            let p = self.staging()?.join(&name);
            let f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
                .map_err(|e| MexError::io(&p, e))?;
            Ok((f, name))
        }

        pub(crate) fn open_temp(&self, name: &str) -> Result<fs::File> {
            let p = self.staging()?.join(name);
            fs::File::open(&p).map_err(|e| MexError::io(&p, e))
        }

        pub(crate) fn remove_temp(&self, name: &str) -> Result<()> {
            let p = self.staging_display(name);
            fs::remove_file(&p).map_err(|e| MexError::io(&p, e))
        }

        pub(crate) fn publish(&self, temp: &str, dest: &EvidencePath) -> Result<()> {
            let src = self.staging()?.join(temp);
            let mut cur = self.path.join(ARTIFACTS_DIR);
            require_real_dir(&cur)?;
            let comps: Vec<&str> = dest.components().collect();
            let (name, parents) = comps.split_last().expect("EvidencePath nunca é vazio");
            for c in parents {
                cur.push(c);
                match fs::symlink_metadata(&cur) {
                    Ok(m) if m.file_type().is_dir() => {}
                    Ok(_) => return Err(not_real_dir(&cur)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        fs::create_dir(&cur).map_err(|e| MexError::io(&cur, e))?
                    }
                    Err(e) => return Err(MexError::io(&cur, e)),
                }
            }
            let target = cur.join(name);
            require_absent(&target)?;
            fs::rename(&src, &target).map_err(|e| MexError::io(&target, e))
        }

        pub(crate) fn write_control(&self, name: &str, bytes: &[u8]) -> Result<()> {
            require_real_dir(&self.path)?;
            let target = self.path.join(name);
            require_absent(&target)?;
            let tmp = self
                .path
                .join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
            let r = (|| -> Result<()> {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
                    .map_err(|e| MexError::io(&tmp, e))?;
                f.write_all(bytes).map_err(|e| MexError::io(&tmp, e))?;
                f.sync_all().map_err(|e| MexError::io(&tmp, e))?;
                require_absent(&target)?;
                fs::rename(&tmp, &target).map_err(|e| MexError::io(&target, e))
            })();
            if r.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            r
        }

        pub(crate) fn clear_staging(&self) -> Result<()> {
            let s = self.staging()?;
            for entry in fs::read_dir(&s).map_err(|e| MexError::io(&s, e))? {
                let entry = entry.map_err(|e| MexError::io(&s, e))?;
                let p = entry.path();
                let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
                if !(is_file && p.extension().is_some_and(|e| e == "part")) {
                    return Err(unexpected_staging(&p));
                }
                fs::remove_file(&p).map_err(|e| MexError::io(&p, e))?;
            }
            fs::remove_dir(&s).map_err(|e| MexError::io(&s, e))
        }
    }
}
