//! Recuperação de aquisições interrompidas (ex.: aplicativo encerrado ou
//! queda de energia durante a execução).
//!
//! Uma aquisição sem resultado que não está em execução **neste processo**
//! é encerrada como `failed`, com motivo e eventos de auditoria
//! (`interrupted`, `job-state-changed`, `acquisition-finished`). Nenhum
//! pacote é registrado: um pacote eventualmente gravado em disco não foi
//! selado e a verificação o classificará como `incomplete`.

use crate::repo::draft;
use crate::{append_audit_in_tx, Result, Storage};
use mex_core::audit::AuditKind;
use mex_core::ids::{AcquisitionId, CaseId, OperatorId};
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use sqlx::Row;

/// Aquisição sem resultado registrado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAcquisition {
    /// Aquisição.
    pub id: AcquisitionId,
    /// Caso.
    pub case_id: CaseId,
    /// Operador que iniciou.
    pub operator_id: OperatorId,
}

impl Storage {
    /// Aquisições sem resultado.
    pub async fn open_acquisitions(&self) -> Result<Vec<OpenAcquisition>> {
        let rows =
            sqlx::query("SELECT id, case_id, operator_id FROM acquisitions WHERE outcome IS NULL")
                .fetch_all(&self.pool)
                .await?;
        rows.iter()
            .map(|r| {
                Ok(OpenAcquisition {
                    id: r.try_get::<String, _>("id")?.parse()?,
                    case_id: r.try_get::<String, _>("case_id")?.parse()?,
                    operator_id: r.try_get::<String, _>("operator_id")?.parse()?,
                })
            })
            .collect()
    }

    /// Encerra uma aquisição interrompida como `failed`.
    pub async fn close_interrupted_acquisition(
        &self,
        a: &OpenAcquisition,
        reason: &str,
    ) -> Result<()> {
        let at = UtcTimestamp::now();
        let mut tx = self.write_tx().await?;
        let job: Option<(String, String)> =
            sqlx::query_as("SELECT id, state FROM acquisition_jobs WHERE acquisition_id = ?")
                .bind(a.id.to_string())
                .fetch_optional(&mut *tx)
                .await?;

        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::Interrupted,
                Some(a.case_id),
                Some(a.operator_id),
                format!("aquisição {} interrompida: {reason}", a.id),
            ),
            at,
        )
        .await?;

        if let Some((job_id, state)) = job {
            let current: JobState = state.parse()?;
            if !current.is_terminal() {
                // Todo estado não terminal admite a transição para `failed`.
                current.transition_to(JobState::Failed)?;
                sqlx::query(
                    "UPDATE acquisition_jobs SET state = 'failed', updated_at = ? WHERE id = ?",
                )
                .bind(at.to_canonical())
                .bind(&job_id)
                .execute(&mut *tx)
                .await?;
                append_audit_in_tx(
                    &mut tx,
                    draft(
                        AuditKind::JobStateChanged,
                        Some(a.case_id),
                        Some(a.operator_id),
                        format!("job {job_id}: {state} -> failed ({reason})"),
                    ),
                    at,
                )
                .await?;
            }
        }

        let limitations = serde_json::to_string(&[reason]).expect("array de strings");
        sqlx::query(
            "UPDATE acquisitions SET outcome = 'failed', finished_at = ?, limitations_json = ?
              WHERE id = ? AND outcome IS NULL",
        )
        .bind(at.to_canonical())
        .bind(limitations)
        .bind(a.id.to_string())
        .execute(&mut *tx)
        .await?;
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::AcquisitionFinished,
                Some(a.case_id),
                Some(a.operator_id),
                format!(
                    "aquisição {} finalizada: failed; sem pacote de evidências ({reason})",
                    a.id
                ),
            ),
            at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
