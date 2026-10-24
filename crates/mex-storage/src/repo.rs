//! Repositórios com auditoria transacional.
//!
//! Cada método que altera dados abre uma transação de escrita, grava o dado
//! e o evento de auditoria correspondente, e confirma. Se qualquer parte
//! falhar (validação, CHECK, FK, trigger), nada é gravado — nem o evento.
//!
//! Decisão: artefatos individuais **não** geram evento de auditoria. Eles
//! são cobertos pelo SHA-256 do manifesto, registrado no evento
//! `acquisition-finished`; isso evita milhares de eventos por aquisição sem
//! perder rastreabilidade.

use crate::{append_audit_in_tx, Result, Storage};
use mex_core::audit::{AuditDraft, AuditKind};
use mex_core::ids::{AcquisitionId, CaseId, OperatorId, VerificationId};
use mex_core::integrity::Digest256;
use mex_core::job::AcquisitionJob;
use mex_core::model::{
    Acquisition, AcquisitionOutcome, ArtifactRecord, ArtifactStatus, Authorization, Case, Device,
    IntegrityStatus, Operator,
};
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use sqlx::{Row, SqliteConnection};

/// Dados de finalização de uma aquisição.
#[derive(Debug, Clone)]
pub struct AcquisitionFinish {
    /// Aquisição.
    pub acquisition_id: AcquisitionId,
    /// Caso (para o evento de auditoria).
    pub case_id: CaseId,
    /// Operador.
    pub operator_id: OperatorId,
    /// Resultado.
    pub outcome: AcquisitionOutcome,
    /// Limitações.
    pub limitations: Vec<String>,
    /// Fim.
    pub finished_at: UtcTimestamp,
    /// Diretório do pacote selado, se houve pacote.
    pub package_path: Option<String>,
    /// SHA-256 do manifesto, se houve pacote.
    pub manifest_sha256: Option<Digest256>,
}

/// Resultado de verificação a registrar.
#[derive(Debug, Clone)]
pub struct VerificationRecord {
    /// Aquisição verificada.
    pub acquisition_id: AcquisitionId,
    /// Caso (para o evento de auditoria).
    pub case_id: CaseId,
    /// Classificação.
    pub status: IntegrityStatus,
    /// Hash calculado do manifesto.
    pub manifest_sha256: Option<Digest256>,
    /// Artefatos conferidos.
    pub artifacts_checked: u64,
    /// Bytes conferidos.
    pub bytes_verified: u64,
    /// Divergências serializadas (array JSON).
    pub findings: Vec<serde_json::Value>,
    /// Operador que executou.
    pub verified_by: OperatorId,
    /// Quando.
    pub verified_at: UtcTimestamp,
}

/// Referência registrada do pacote de uma aquisição.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredPackage {
    /// Diretório do pacote.
    pub package_path: String,
    /// SHA-256 do manifesto registrado na finalização.
    pub manifest_sha256: Digest256,
}

pub(crate) fn draft(
    kind: AuditKind,
    case_id: Option<CaseId>,
    operator_id: Option<OperatorId>,
    detail: String,
) -> AuditDraft {
    AuditDraft {
        case_id,
        operator_id,
        kind,
        detail,
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v)
        .map_err(|e| MexError::InvalidInput(format!("serialização JSON: {e}")).into())
}

pub(crate) fn i64_of(n: u64, what: &str) -> Result<i64> {
    i64::try_from(n).map_err(|_| MexError::InvalidInput(format!("{what} excede i64")).into())
}

impl Storage {
    /// Cadastra um operador.
    pub async fn register_operator(&self, op: &Operator) -> Result<()> {
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO operators (id, full_name, badge, organization, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(op.id.to_string())
        .bind(&op.full_name)
        .bind(&op.badge)
        .bind(&op.organization)
        .bind(op.created_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!(
            "operador cadastrado: {} (matrícula {}, {})",
            op.full_name, op.badge, op.organization
        );
        append_audit_in_tx(
            &mut tx,
            draft(AuditKind::OperatorRegistered, None, Some(op.id), detail),
            op.created_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Cria um caso.
    pub async fn create_case(&self, case: &Case) -> Result<()> {
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO cases (id, number, title, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(case.id.to_string())
        .bind(&case.number)
        .bind(&case.title)
        .bind(case.created_by.to_string())
        .bind(case.created_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!("caso {} criado: {}", case.number, case.title);
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::CaseCreated,
                Some(case.id),
                Some(case.created_by),
                detail,
            ),
            case.created_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Registra uma autorização legal.
    pub async fn record_authorization(&self, a: &Authorization) -> Result<()> {
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO authorizations (id, case_id, kind, kind_detail, reference, issuer,
                 scope_notes, document_sha256, recorded_by, recorded_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(a.id.to_string())
        .bind(a.case_id.to_string())
        .bind(a.kind.as_str())
        .bind(&a.kind_detail)
        .bind(&a.reference)
        .bind(&a.issuer)
        .bind(&a.scope_notes)
        .bind(a.document_sha256.as_ref().map(|d| d.hex.clone()))
        .bind(a.recorded_by.to_string())
        .bind(a.recorded_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let mut detail = format!(
            "autorização registrada: {} {} ({})",
            a.kind.as_str(),
            a.reference,
            a.issuer
        );
        if let Some(d) = &a.document_sha256 {
            detail.push_str(&format!("; documento sha256 {}", d.hex));
        }
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::AuthorizationRecorded,
                Some(a.case_id),
                Some(a.recorded_by),
                detail,
            ),
            a.recorded_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Registra um dispositivo no inventário.
    pub async fn register_device(
        &self,
        d: &Device,
        case_id: Option<CaseId>,
        by: OperatorId,
    ) -> Result<()> {
        let o = &d.observed;
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO devices (id, platform, serial, manufacturer, model, os_version,
                 security_patch, adb_state, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(d.id.to_string())
        .bind(o.platform.as_str())
        .bind(&o.serial)
        .bind(&o.manufacturer)
        .bind(&o.model)
        .bind(&o.os_version)
        .bind(&o.security_patch)
        .bind(o.adb_state.as_ref().map(|s| s.label().to_owned()))
        .bind(d.first_seen.to_canonical())
        .bind(o.observed_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!(
            "dispositivo registrado: {} serial {:?} fabricante {:?} modelo {:?} (id {})",
            o.platform.as_str(),
            o.serial,
            o.manufacturer.as_deref().unwrap_or("?"),
            o.model.as_deref().unwrap_or("?"),
            d.id
        );
        append_audit_in_tx(
            &mut tx,
            draft(AuditKind::DeviceRegistered, case_id, Some(by), detail),
            d.first_seen,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Registra o início de uma aquisição.
    pub async fn start_acquisition(&self, a: &Acquisition) -> Result<()> {
        if a.outcome.is_some() || a.finished_at.is_some() {
            return Err(MexError::InvalidInput("aquisição iniciada já finalizada".into()).into());
        }
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO acquisitions (id, case_id, device_id, authorization_id, operator_id,
                 capability_kind, adapter_id, adapter_version, software_version,
                 limitations_json, started_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(a.id.to_string())
        .bind(a.case_id.to_string())
        .bind(a.device_id.to_string())
        .bind(a.authorization_id.to_string())
        .bind(a.operator_id.to_string())
        .bind(a.capability.as_str())
        .bind(&a.adapter_id)
        .bind(&a.adapter_version)
        .bind(&a.software_version)
        .bind(to_json(&a.limitations)?)
        .bind(a.started_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!(
            "aquisição {} iniciada: capacidade {}, adaptador {} {}, MEX {}, dispositivo {}, autorização {}",
            a.id,
            a.capability.as_str(),
            a.adapter_id,
            a.adapter_version,
            a.software_version,
            a.device_id,
            a.authorization_id
        );
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::AcquisitionStarted,
                Some(a.case_id),
                Some(a.operator_id),
                detail,
            ),
            a.started_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Grava o estado atual do job e audita a última transição (ou a criação).
    pub async fn save_job(
        &self,
        job: &AcquisitionJob,
        case_id: CaseId,
        operator_id: OperatorId,
    ) -> Result<()> {
        let completed = job.artifacts_completed();
        let failed = job.failures().len() as u64;
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO acquisition_jobs (id, acquisition_id, state, bytes_acquired, bytes_total,
                 artifacts_completed, artifacts_failed, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (id) DO UPDATE SET
                 state = excluded.state,
                 bytes_acquired = excluded.bytes_acquired,
                 bytes_total = excluded.bytes_total,
                 artifacts_completed = excluded.artifacts_completed,
                 artifacts_failed = excluded.artifacts_failed,
                 updated_at = excluded.updated_at",
        )
        .bind(job.id().to_string())
        .bind(job.acquisition_id().to_string())
        .bind(job.state().name())
        .bind(i64_of(job.bytes_acquired(), "bytes_acquired")?)
        .bind(
            job.bytes_total()
                .map(|n| i64_of(n, "bytes_total"))
                .transpose()?,
        )
        .bind(i64::from(completed))
        .bind(i64_of(failed, "artifacts_failed")?)
        .bind(job.created_at().to_canonical())
        .bind(job.updated_at().to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = match job.history().last() {
            None => format!(
                "job {} criado (aquisição {}, capacidade {})",
                job.id(),
                job.acquisition_id(),
                job.capability().as_str()
            ),
            Some(t) => {
                let mut d = format!("job {}: {} -> {}", job.id(), t.from.name(), t.to.name());
                if let Some(r) = &t.reason {
                    d.push_str(&format!(" ({r})"));
                }
                d
            }
        };
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::JobStateChanged,
                Some(case_id),
                Some(operator_id),
                detail,
            ),
            job.updated_at(),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Registra os artefatos de uma aquisição (completos e falhos).
    ///
    /// Completos seguem o fluxo imposto pelo schema: `pending` → hash →
    /// `complete`.
    pub async fn record_artifacts(&self, artifacts: &[ArtifactRecord]) -> Result<()> {
        let mut tx = self.write_tx().await?;
        for a in artifacts {
            insert_artifact(&mut tx, a).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Finaliza a aquisição, registrando resultado e hash do manifesto.
    pub async fn finish_acquisition(&self, f: &AcquisitionFinish) -> Result<()> {
        if f.package_path.is_some() != f.manifest_sha256.is_some() {
            return Err(MexError::InvalidInput(
                "pacote e hash do manifesto devem ser informados juntos".into(),
            )
            .into());
        }
        let mut tx = self.write_tx().await?;
        let r = sqlx::query(
            "UPDATE acquisitions
                SET outcome = ?, finished_at = ?, limitations_json = ?,
                    package_path = ?, manifest_sha256 = ?
              WHERE id = ?",
        )
        .bind(f.outcome.as_str())
        .bind(f.finished_at.to_canonical())
        .bind(to_json(&f.limitations)?)
        .bind(&f.package_path)
        .bind(f.manifest_sha256.as_ref().map(|d| d.hex.clone()))
        .bind(f.acquisition_id.to_string())
        .execute(&mut *tx)
        .await?;
        if r.rows_affected() != 1 {
            return Err(MexError::InvalidInput(format!(
                "aquisição inexistente: {}",
                f.acquisition_id
            ))
            .into());
        }
        let mut detail = format!(
            "aquisição {} finalizada: {}",
            f.acquisition_id,
            f.outcome.as_str()
        );
        match (&f.manifest_sha256, &f.package_path) {
            (Some(d), Some(p)) => {
                detail.push_str(&format!("; manifesto sha256 {}; pacote {p}", d.hex))
            }
            _ => detail.push_str("; sem pacote de evidências"),
        }
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::AcquisitionFinished,
                Some(f.case_id),
                Some(f.operator_id),
                detail,
            ),
            f.finished_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Pacote e hash de manifesto registrados para a aquisição.
    pub async fn registered_package(&self, id: AcquisitionId) -> Result<Option<RegisteredPackage>> {
        let row =
            sqlx::query("SELECT package_path, manifest_sha256 FROM acquisitions WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        let Some(row) = row else { return Ok(None) };
        let path: Option<String> = row.try_get("package_path")?;
        let hash: Option<String> = row.try_get("manifest_sha256")?;
        match (path, hash) {
            (Some(package_path), Some(h)) => Ok(Some(RegisteredPackage {
                package_path,
                manifest_sha256: Digest256::sha256_from_hex(&h)?,
            })),
            _ => Ok(None),
        }
    }

    /// Registra o resultado de uma verificação de integridade.
    pub async fn record_verification(&self, v: &VerificationRecord) -> Result<()> {
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO integrity_verifications (id, acquisition_id, status, manifest_sha256,
                 artifacts_checked, bytes_verified, findings_count, findings_json,
                 verified_by, verified_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(VerificationId::new().to_string())
        .bind(v.acquisition_id.to_string())
        .bind(v.status.as_str())
        .bind(v.manifest_sha256.as_ref().map(|d| d.hex.clone()))
        .bind(i64_of(v.artifacts_checked, "artifacts_checked")?)
        .bind(i64_of(v.bytes_verified, "bytes_verified")?)
        .bind(i64_of(v.findings.len() as u64, "findings")?)
        .bind(to_json(&v.findings)?)
        .bind(v.verified_by.to_string())
        .bind(v.verified_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!(
            "verificação de integridade da aquisição {}: {} ({} artefatos, {} divergências{})",
            v.acquisition_id,
            v.status.as_str(),
            v.artifacts_checked,
            v.findings.len(),
            v.manifest_sha256
                .as_ref()
                .map(|d| format!(", manifesto sha256 {}", d.hex))
                .unwrap_or_default()
        );
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::IntegrityVerified,
                Some(v.case_id),
                Some(v.verified_by),
                detail,
            ),
            v.verified_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn insert_artifact(conn: &mut SqliteConnection, a: &ArtifactRecord) -> Result<()> {
    let (status, reason) = match &a.status {
        ArtifactStatus::Complete { .. } | ArtifactStatus::Pending => ("pending", None),
        ArtifactStatus::Failed { reason } => ("failed", Some(reason.as_str())),
    };
    sqlx::query(
        "INSERT INTO artifacts (id, acquisition_id, stored_path, source_path, source_modified,
             size_bytes, status, failure_reason, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.id.to_string())
    .bind(a.acquisition_id.to_string())
    .bind(a.stored_path.as_str())
    .bind(&a.source_path)
    .bind(a.source_modified.map(|t| t.to_canonical()))
    .bind(i64_of(a.size_bytes, "size_bytes")?)
    .bind(status)
    .bind(reason)
    .bind(a.created_at.to_canonical())
    .execute(&mut *conn)
    .await?;

    if let ArtifactStatus::Complete {
        digest,
        completed_at,
    } = &a.status
    {
        sqlx::query(
            "INSERT INTO artifact_hashes (artifact_id, alg, hex, computed_at) VALUES (?, ?, ?, ?)",
        )
        .bind(a.id.to_string())
        .bind(digest.alg.as_str())
        .bind(&digest.hex)
        .bind(completed_at.to_canonical())
        .execute(&mut *conn)
        .await?;
        sqlx::query("UPDATE artifacts SET status = 'complete', completed_at = ? WHERE id = ?")
            .bind(completed_at.to_canonical())
            .bind(a.id.to_string())
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
