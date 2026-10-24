//! Consultas de leitura para a interface.
//!
//! Somente leitura: nenhuma função aqui altera o banco. Entidades de
//! domínio são reconstruídas e revalidadas (IDs, timestamps canônicos,
//! caminhos de evidência); dado persistido inválido vira erro, não é
//! silenciosamente aceito.

use crate::{Result, Storage};
use mex_core::ids::{AcquisitionId, AuthorizationId, CaseId, DeviceId, OperatorId};
use mex_core::integrity::Digest256;
use mex_core::model::{
    AdbState, Authorization, AuthorizationKind, Case, Device, DeviceObservation, Operator, Platform,
};
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;

fn ts(r: &SqliteRow, col: &str) -> Result<UtcTimestamp> {
    Ok(UtcTimestamp::parse_canonical(
        &r.try_get::<String, _>(col)?,
    )?)
}

fn opt_ts(r: &SqliteRow, col: &str) -> Result<Option<UtcTimestamp>> {
    r.try_get::<Option<String>, _>(col)?
        .map(|s| UtcTimestamp::parse_canonical(&s).map_err(Into::into))
        .transpose()
}

fn id<T: std::str::FromStr<Err = MexError>>(r: &SqliteRow, col: &str) -> Result<T> {
    Ok(r.try_get::<String, _>(col)?.parse()?)
}

fn u64_of(r: &SqliteRow, col: &str) -> Result<u64> {
    let v: i64 = r.try_get(col)?;
    u64::try_from(v).map_err(|_| MexError::InvalidInput(format!("{col} negativo")).into())
}

fn platform(s: &str) -> Result<Platform> {
    match s {
        "android" => Ok(Platform::Android),
        "ios" => Ok(Platform::Ios),
        "simulated" => Ok(Platform::Simulated),
        o => Err(MexError::InvalidInput(format!("plataforma desconhecida: {o}")).into()),
    }
}

fn auth_kind(s: &str) -> Result<AuthorizationKind> {
    match s {
        "judicial-warrant" => Ok(AuthorizationKind::JudicialWarrant),
        "owner-consent" => Ok(AuthorizationKind::OwnerConsent),
        "other" => Ok(AuthorizationKind::Other),
        o => Err(MexError::InvalidInput(format!("tipo de autorização desconhecido: {o}")).into()),
    }
}

fn operator_from(r: &SqliteRow) -> Result<Operator> {
    Ok(Operator {
        id: id(r, "id")?,
        full_name: r.try_get("full_name")?,
        badge: r.try_get("badge")?,
        organization: r.try_get("organization")?,
        created_at: ts(r, "created_at")?,
    })
}

fn case_from(r: &SqliteRow) -> Result<Case> {
    Ok(Case {
        id: id(r, "id")?,
        number: r.try_get("number")?,
        title: r.try_get("title")?,
        created_by: id(r, "created_by")?,
        created_at: ts(r, "created_at")?,
    })
}

fn authorization_from(r: &SqliteRow) -> Result<Authorization> {
    let doc: Option<String> = r.try_get("document_sha256")?;
    Ok(Authorization {
        id: id(r, "id")?,
        case_id: id(r, "case_id")?,
        kind: auth_kind(&r.try_get::<String, _>("kind")?)?,
        kind_detail: r.try_get("kind_detail")?,
        reference: r.try_get("reference")?,
        issuer: r.try_get("issuer")?,
        scope_notes: r.try_get("scope_notes")?,
        document_sha256: doc.map(|h| Digest256::sha256_from_hex(&h)).transpose()?,
        recorded_by: id(r, "recorded_by")?,
        recorded_at: ts(r, "recorded_at")?,
    })
}

fn device_from(r: &SqliteRow) -> Result<Device> {
    let adb: Option<String> = r.try_get("adb_state")?;
    Ok(Device {
        id: id(r, "id")?,
        first_seen: ts(r, "first_seen")?,
        observed: DeviceObservation {
            platform: platform(&r.try_get::<String, _>("platform")?)?,
            serial: r.try_get("serial")?,
            manufacturer: r.try_get("manufacturer")?,
            model: r.try_get("model")?,
            os_version: r.try_get("os_version")?,
            security_patch: r.try_get("security_patch")?,
            adb_state: adb.map(|s| AdbState::parse(&s)),
            observed_at: ts(r, "last_seen")?,
        },
    })
}

/// Caso com contadores.
#[derive(Debug, Clone, Serialize)]
pub struct CaseSummary {
    /// Caso.
    pub case: Case,
    /// Situação (`open`/`closed`).
    pub status: String,
    /// Autorizações registradas.
    pub authorizations: u64,
    /// Aquisições registradas.
    pub acquisitions: u64,
}

/// Aquisição com estado do job e do pacote.
#[derive(Debug, Clone, Serialize)]
pub struct AcquisitionView {
    /// Aquisição.
    pub id: AcquisitionId,
    /// Caso.
    pub case_id: CaseId,
    /// Dispositivo.
    pub device_id: DeviceId,
    /// Autorização.
    pub authorization_id: AuthorizationId,
    /// Operador.
    pub operator_id: OperatorId,
    /// Capacidade.
    pub capability: String,
    /// Adaptador.
    pub adapter_id: String,
    /// Versão do adaptador.
    pub adapter_version: String,
    /// Versão do MEX.
    pub software_version: String,
    /// Resultado (ausente enquanto em curso).
    pub outcome: Option<String>,
    /// Limitações registradas.
    pub limitations: Vec<String>,
    /// Início.
    pub started_at: UtcTimestamp,
    /// Fim.
    pub finished_at: Option<UtcTimestamp>,
    /// Pacote.
    pub package_path: Option<String>,
    /// SHA-256 do manifesto.
    pub manifest_sha256: Option<String>,
    /// Estado do job (o mais recente).
    pub job_state: Option<String>,
    /// Bytes gravados (registrados ao fim da execução do adaptador).
    pub bytes_acquired: u64,
    /// Artefatos completos.
    pub artifacts_completed: u64,
    /// Falhas.
    pub artifacts_failed: u64,
    /// Última verificação de integridade, se houver.
    pub last_verification: Option<String>,
}

/// Artefato para listagem.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactView {
    /// Caminho no pacote.
    pub stored_path: String,
    /// Caminho na origem.
    pub source_path: Option<String>,
    /// Modificação na origem.
    pub source_modified: Option<UtcTimestamp>,
    /// Tamanho.
    pub size_bytes: u64,
    /// Estado.
    pub status: String,
    /// Motivo de falha.
    pub failure_reason: Option<String>,
    /// SHA-256.
    pub sha256: Option<String>,
}

/// Verificação registrada.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationView {
    /// Resultado.
    pub status: String,
    /// Hash do manifesto calculado.
    pub manifest_sha256: Option<String>,
    /// Artefatos conferidos.
    pub artifacts_checked: u64,
    /// Bytes relidos.
    pub bytes_verified: u64,
    /// Divergências.
    pub findings: serde_json::Value,
    /// Operador.
    pub verified_by: OperatorId,
    /// Quando.
    pub verified_at: UtcTimestamp,
}

/// Arquivo de relatório emitido.
#[derive(Debug, Clone, Serialize)]
pub struct ReportView {
    /// Aquisição.
    pub acquisition_id: Option<AcquisitionId>,
    /// Formato.
    pub format: String,
    /// Caminho.
    pub stored_path: String,
    /// SHA-256 do arquivo.
    pub sha256: String,
    /// Emissor.
    pub generated_by: OperatorId,
    /// Quando.
    pub generated_at: UtcTimestamp,
}

/// Exportação registrada.
#[derive(Debug, Clone, Serialize)]
pub struct ExportView {
    /// Destino.
    pub destination: String,
    /// Resultado da verificação da cópia.
    pub status: String,
    /// Arquivos.
    pub files_copied: u64,
    /// Bytes.
    pub bytes_copied: u64,
    /// Operador.
    pub exported_by: OperatorId,
    /// Quando.
    pub exported_at: UtcTimestamp,
}

/// Contadores gerais.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    /// Casos.
    pub cases: u64,
    /// Dispositivos.
    pub devices: u64,
    /// Aquisições.
    pub acquisitions: u64,
    /// Aquisições sem resultado (em curso ou interrompidas sem finalização).
    pub acquisitions_open: u64,
    /// Artefatos completos.
    pub artifacts_complete: u64,
    /// Eventos de auditoria.
    pub audit_events: u64,
}

impl Storage {
    /// Operadores cadastrados.
    pub async fn list_operators(&self) -> Result<Vec<Operator>> {
        sqlx::query("SELECT * FROM operators WHERE active = 1 ORDER BY full_name")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(operator_from)
            .collect()
    }

    /// Operador por ID.
    pub async fn get_operator(&self, id: OperatorId) -> Result<Option<Operator>> {
        sqlx::query("SELECT * FROM operators WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(operator_from)
            .transpose()
    }

    /// Casos com contadores, mais recentes primeiro.
    pub async fn list_cases(&self) -> Result<Vec<CaseSummary>> {
        let rows = sqlx::query(
            "SELECT c.*,
                    (SELECT count(*) FROM authorizations a WHERE a.case_id = c.id) AS n_auth,
                    (SELECT count(*) FROM acquisitions q WHERE q.case_id = c.id) AS n_acq
               FROM cases c ORDER BY c.created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(CaseSummary {
                    case: case_from(r)?,
                    status: r.try_get("status")?,
                    authorizations: u64_of(r, "n_auth")?,
                    acquisitions: u64_of(r, "n_acq")?,
                })
            })
            .collect()
    }

    /// Caso por ID.
    pub async fn get_case(&self, id: CaseId) -> Result<Option<Case>> {
        sqlx::query("SELECT * FROM cases WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(case_from)
            .transpose()
    }

    /// Autorizações do caso.
    pub async fn list_authorizations(&self, case_id: CaseId) -> Result<Vec<Authorization>> {
        sqlx::query("SELECT * FROM authorizations WHERE case_id = ? ORDER BY recorded_at")
            .bind(case_id.to_string())
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(authorization_from)
            .collect()
    }

    /// Autorização por ID.
    pub async fn get_authorization(&self, id: AuthorizationId) -> Result<Option<Authorization>> {
        sqlx::query("SELECT * FROM authorizations WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(authorization_from)
            .transpose()
    }

    /// Inventário de dispositivos.
    pub async fn list_devices(&self) -> Result<Vec<Device>> {
        sqlx::query("SELECT * FROM devices ORDER BY first_seen DESC")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(device_from)
            .collect()
    }

    /// Dispositivo por ID.
    pub async fn get_device(&self, id: DeviceId) -> Result<Option<Device>> {
        sqlx::query("SELECT * FROM devices WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(device_from)
            .transpose()
    }

    /// Aquisições, filtradas por caso e/ou dispositivo, mais recentes primeiro.
    pub async fn list_acquisitions(
        &self,
        case_id: Option<CaseId>,
        device_id: Option<DeviceId>,
    ) -> Result<Vec<AcquisitionView>> {
        let rows = sqlx::query(
            "SELECT q.*,
                    j.state AS job_state, j.bytes_acquired, j.artifacts_completed, j.artifacts_failed,
                    (SELECT v.status FROM integrity_verifications v
                      WHERE v.acquisition_id = q.id
                      ORDER BY v.verified_at DESC LIMIT 1) AS last_verification
               FROM acquisitions q
               LEFT JOIN acquisition_jobs j ON j.acquisition_id = q.id
              WHERE (?1 IS NULL OR q.case_id = ?1)
                AND (?2 IS NULL OR q.device_id = ?2)
              ORDER BY q.started_at DESC",
        )
        .bind(case_id.map(|c| c.to_string()))
        .bind(device_id.map(|d| d.to_string()))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let lim: String = r.try_get("limitations_json")?;
                let opt_u64 = |c: &str| -> Result<u64> {
                    Ok(r.try_get::<Option<i64>, _>(c)?.unwrap_or(0).max(0) as u64)
                };
                Ok(AcquisitionView {
                    id: id(r, "id")?,
                    case_id: id(r, "case_id")?,
                    device_id: id(r, "device_id")?,
                    authorization_id: id(r, "authorization_id")?,
                    operator_id: id(r, "operator_id")?,
                    capability: r.try_get("capability_kind")?,
                    adapter_id: r.try_get("adapter_id")?,
                    adapter_version: r.try_get("adapter_version")?,
                    software_version: r.try_get("software_version")?,
                    outcome: r.try_get("outcome")?,
                    limitations: serde_json::from_str(&lim)
                        .map_err(|e| MexError::InvalidInput(format!("limitations_json: {e}")))?,
                    started_at: ts(r, "started_at")?,
                    finished_at: opt_ts(r, "finished_at")?,
                    package_path: r.try_get("package_path")?,
                    manifest_sha256: r.try_get("manifest_sha256")?,
                    job_state: r.try_get("job_state")?,
                    bytes_acquired: opt_u64("bytes_acquired")?,
                    artifacts_completed: opt_u64("artifacts_completed")?,
                    artifacts_failed: opt_u64("artifacts_failed")?,
                    last_verification: r.try_get("last_verification")?,
                })
            })
            .collect()
    }

    /// Artefatos de uma aquisição, na ordem de registro.
    pub async fn list_artifacts(&self, acquisition_id: AcquisitionId) -> Result<Vec<ArtifactView>> {
        let rows = sqlx::query(
            "SELECT a.*, h.hex FROM artifacts a
               LEFT JOIN artifact_hashes h ON h.artifact_id = a.id AND h.alg = 'sha-256'
              WHERE a.acquisition_id = ? ORDER BY a.rowid",
        )
        .bind(acquisition_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(ArtifactView {
                    stored_path: r.try_get("stored_path")?,
                    source_path: r.try_get("source_path")?,
                    source_modified: opt_ts(r, "source_modified")?,
                    size_bytes: u64_of(r, "size_bytes")?,
                    status: r.try_get("status")?,
                    failure_reason: r.try_get("failure_reason")?,
                    sha256: r.try_get("hex")?,
                })
            })
            .collect()
    }

    /// Verificações de uma aquisição, mais recentes primeiro.
    pub async fn list_verifications(
        &self,
        acquisition_id: AcquisitionId,
    ) -> Result<Vec<VerificationView>> {
        let rows = sqlx::query(
            "SELECT * FROM integrity_verifications WHERE acquisition_id = ? ORDER BY verified_at DESC",
        )
        .bind(acquisition_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let f: String = r.try_get("findings_json")?;
                Ok(VerificationView {
                    status: r.try_get("status")?,
                    manifest_sha256: r.try_get("manifest_sha256")?,
                    artifacts_checked: u64_of(r, "artifacts_checked")?,
                    bytes_verified: u64_of(r, "bytes_verified")?,
                    findings: serde_json::from_str(&f)
                        .map_err(|e| MexError::InvalidInput(format!("findings_json: {e}")))?,
                    verified_by: id(r, "verified_by")?,
                    verified_at: ts(r, "verified_at")?,
                })
            })
            .collect()
    }

    /// Relatórios emitidos para o caso.
    pub async fn list_reports(&self, case_id: CaseId) -> Result<Vec<ReportView>> {
        let rows = sqlx::query(
            "SELECT * FROM reports WHERE case_id = ? ORDER BY generated_at DESC, format",
        )
        .bind(case_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let acq: Option<String> = r.try_get("acquisition_id")?;
                Ok(ReportView {
                    acquisition_id: acq.map(|s| s.parse()).transpose()?,
                    format: r.try_get("format")?,
                    stored_path: r.try_get("stored_path")?,
                    sha256: r.try_get("sha256")?,
                    generated_by: id(r, "generated_by")?,
                    generated_at: ts(r, "generated_at")?,
                })
            })
            .collect()
    }

    /// Exportações da aquisição.
    pub async fn list_exports(&self, acquisition_id: AcquisitionId) -> Result<Vec<ExportView>> {
        let rows = sqlx::query(
            "SELECT * FROM evidence_exports WHERE acquisition_id = ? ORDER BY exported_at DESC",
        )
        .bind(acquisition_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(ExportView {
                    destination: r.try_get("destination")?,
                    status: r.try_get("status")?,
                    files_copied: u64_of(r, "files_copied")?,
                    bytes_copied: u64_of(r, "bytes_copied")?,
                    exported_by: id(r, "exported_by")?,
                    exported_at: ts(r, "exported_at")?,
                })
            })
            .collect()
    }

    /// Contadores gerais.
    pub async fn stats(&self) -> Result<Stats> {
        let r = sqlx::query(
            "SELECT (SELECT count(*) FROM cases) AS cases,
                    (SELECT count(*) FROM devices) AS devices,
                    (SELECT count(*) FROM acquisitions) AS acquisitions,
                    (SELECT count(*) FROM acquisitions WHERE outcome IS NULL) AS acquisitions_open,
                    (SELECT count(*) FROM artifacts WHERE status = 'complete') AS artifacts_complete,
                    (SELECT count(*) FROM audit_events) AS audit_events",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(Stats {
            cases: u64_of(&r, "cases")?,
            devices: u64_of(&r, "devices")?,
            acquisitions: u64_of(&r, "acquisitions")?,
            acquisitions_open: u64_of(&r, "acquisitions_open")?,
            artifacts_complete: u64_of(&r, "artifacts_complete")?,
            audit_events: u64_of(&r, "audit_events")?,
        })
    }
}
