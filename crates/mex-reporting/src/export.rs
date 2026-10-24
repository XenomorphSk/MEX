//! Exportação verificada de pacotes de evidência (ex.: para mídia externa).
//!
//! 1. A origem é verificada contra o hash registrado; **pacote não íntegro
//!    não é exportado** (evento `error`).
//! 2. A cópia vai para `<destino>/.<acquisition_id>.<aleatório>.partial`,
//!    só com arquivos regulares e diretórios, sem sobrescrita, com `fsync`.
//! 3. A cópia é verificada **no destino** contra o hash registrado.
//! 4. Íntegra ⇒ `rename` para `<destino>/<acquisition_id>`. Caso contrário
//!    a cópia temporária é removida.
//! 5. O resultado é registrado (`evidence_exports` + evento `exported`).
//!
//! Limitação: a verificação logo após a cópia pode ler do cache do sistema
//! operacional. Para atestar a mídia, verifique novamente após remontá-la.

use crate::ReportError;
use mex_acquisition::verify_acquisition;
use mex_core::audit::{AuditDraft, AuditKind};
use mex_core::ids::{AcquisitionId, ExportId};
use mex_core::model::{Case, IntegrityStatus, Operator};
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use mex_evidence::{verify_package, VerificationReport};
use mex_storage::reporting::ExportRecord;
use mex_storage::Storage;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Resultado de uma exportação.
#[derive(Debug, Clone)]
pub struct ExportOutcome {
    /// Registro gravado.
    pub record: ExportRecord,
    /// Verificação da cópia no destino.
    pub verification: VerificationReport,
    /// Diretório final, se a cópia foi aceita.
    pub destination: Option<PathBuf>,
}

/// Diretório novo com permissões mínimas (`0700` em Unix).
fn create_dir_private(p: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p)
}

fn copy_file(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut i = fs::File::open(src)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut o = opts.open(dst)?;
    let n = io::copy(&mut i, &mut o)?;
    o.sync_all()?;
    Ok(n)
}

/// Copia a árvore `src` para `dst` (novo). Recusa qualquer entrada que não
/// seja diretório ou arquivo regular. Devolve (arquivos, bytes).
fn copy_tree(src: &Path, dst: &Path) -> io::Result<(u64, u64)> {
    create_dir_private(dst)?;
    let (mut files, mut total) = (0u64, 0u64);
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&s)?.collect::<io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let ft = e.file_type()?;
            let target = d.join(e.file_name());
            if ft.is_dir() {
                create_dir_private(&target)?;
                stack.push((e.path(), target));
            } else if ft.is_file() {
                total += copy_file(&e.path(), &target)?;
                files += 1;
            } else {
                return Err(io::Error::other(format!(
                    "entrada não regular no pacote: {}",
                    e.path().display()
                )));
            }
        }
    }
    Ok((files, total))
}

async fn audit_error(
    storage: &Storage,
    case: &Case,
    op: &Operator,
    detail: String,
) -> Result<(), ReportError> {
    storage
        .append_audit_event(
            AuditDraft {
                case_id: Some(case.id),
                operator_id: Some(op.id),
                kind: AuditKind::Error,
                detail,
            },
            UtcTimestamp::now(),
        )
        .await?;
    Ok(())
}

/// Exporta o pacote da aquisição para `dest_root/<acquisition_id>`.
pub async fn export_package(
    storage: &Storage,
    acquisition_id: AcquisitionId,
    case: &Case,
    operator: &Operator,
    dest_root: &Path,
) -> Result<ExportOutcome, ReportError> {
    if storage.acquisition_case_id(acquisition_id).await? != Some(case.id) {
        return Err(MexError::InvalidInput(format!(
            "aquisição {acquisition_id} não pertence ao caso {}",
            case.number
        ))
        .into());
    }
    let registered = storage
        .registered_package(acquisition_id)
        .await?
        .ok_or_else(|| MexError::InvalidInput("aquisição sem pacote registrado".into()))?;

    let source_check = verify_acquisition(storage, acquisition_id, case.id, operator).await?;
    if source_check.status != IntegrityStatus::Intact {
        let msg = format!(
            "exportação da aquisição {acquisition_id} recusada: pacote de origem {}",
            source_check.status.as_str()
        );
        audit_error(storage, case, operator, msg.clone()).await?;
        return Err(MexError::PolicyDenied(msg).into());
    }

    let source = PathBuf::from(&registered.package_path);
    let dest_root = tokio::fs::canonicalize(dest_root)
        .await
        .map_err(|e| MexError::io(dest_root, e))?;
    let source_c = tokio::fs::canonicalize(&source)
        .await
        .map_err(|e| MexError::io(&source, e))?;
    if dest_root.starts_with(&source_c) {
        return Err(MexError::PolicyDenied(
            "o destino não pode estar dentro do pacote de origem".into(),
        )
        .into());
    }
    let final_dir = dest_root.join(acquisition_id.to_string());
    if fs::symlink_metadata(&final_dir).is_ok() {
        return Err(MexError::InvalidInput(format!(
            "destino já existe e não será sobrescrito: {}",
            final_dir.display()
        ))
        .into());
    }
    let partial = dest_root.join(format!(
        ".{acquisition_id}.{}.partial",
        uuid::Uuid::new_v4().simple()
    ));

    let expected = registered.manifest_sha256.clone();
    let (src2, part2, final2) = (source_c.clone(), partial.clone(), final_dir.clone());
    let copied = tokio::task::spawn_blocking(
        move || -> io::Result<(u64, u64, VerificationReport, bool)> {
            let (files, bytes) = match copy_tree(&src2, &part2) {
                Ok(v) => v,
                Err(e) => {
                    let _ = fs::remove_dir_all(&part2);
                    return Err(e);
                }
            };
            let report = verify_package(&part2, Some(&expected));
            if report.status == IntegrityStatus::Intact {
                if fs::symlink_metadata(&final2).is_ok() {
                    let _ = fs::remove_dir_all(&part2);
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "destino criado durante a cópia",
                    ));
                }
                fs::rename(&part2, &final2)?;
                if let Ok(d) = fs::File::open(final2.parent().unwrap_or(Path::new("."))) {
                    let _ = d.sync_all();
                }
                Ok((files, bytes, report, true))
            } else {
                let _ = fs::remove_dir_all(&part2);
                Ok((files, bytes, report, false))
            }
        },
    )
    .await
    .map_err(|e| MexError::Adapter(format!("tarefa de cópia falhou: {e}")))?;

    let (files, bytes, mut verification, accepted) = match copied {
        Ok(v) => v,
        Err(e) => {
            let msg =
                format!("exportação da aquisição {acquisition_id} falhou durante a cópia: {e}");
            audit_error(storage, case, operator, msg).await?;
            return Err(MexError::io(&final_dir, e).into());
        }
    };
    if accepted {
        verification.package_dir = final_dir.clone();
    }
    let record = ExportRecord {
        id: ExportId::new(),
        case_id: case.id,
        acquisition_id,
        destination: final_dir.display().to_string(),
        manifest_sha256: registered.manifest_sha256,
        status: verification.status,
        files_copied: files,
        bytes_copied: bytes,
        exported_by: operator.id,
        exported_at: UtcTimestamp::now(),
    };
    storage.record_export(&record).await?;
    Ok(ExportOutcome {
        record,
        verification,
        destination: accepted.then_some(final_dir),
    })
}
