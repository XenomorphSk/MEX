//! Repositórios: dado + evento de auditoria na mesma transação.

use mex_core::audit::{AuditDraft, AuditKind};
use mex_core::capability::CapabilityKind;
use mex_core::ids::{AcquisitionId, AuthorizationId, DeviceId};
use mex_core::integrity::sha256_hex;
use mex_core::job::AcquisitionJob;
use mex_core::mock::simulated_device;
use mex_core::model::{
    Acquisition, AcquisitionOutcome, AdbState, ArtifactRecord, ArtifactStatus, Authorization,
    AuthorizationKind, Case, Device, IntegrityStatus, Operator,
};
use mex_core::path::EvidencePath;
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use mex_storage::repo::{AcquisitionFinish, VerificationRecord};
use mex_storage::Storage;

struct World {
    op: Operator,
    case: Case,
    auth: Authorization,
    device: Device,
    acq: Acquisition,
}

async fn world(s: &Storage) -> World {
    let t = UtcTimestamp::now();
    let op = Operator::new("Perito Teste", "777", "IC", t).unwrap();
    s.register_operator(&op).await.unwrap();
    let case = Case::new("IP 42/2025", "Caso de teste", op.id, t).unwrap();
    s.create_case(&case).await.unwrap();
    let auth = Authorization {
        id: AuthorizationId::new(),
        case_id: case.id,
        kind: AuthorizationKind::JudicialWarrant,
        kind_detail: None,
        reference: "Mandado 1".into(),
        issuer: "1ª Vara Criminal".into(),
        scope_notes: Some("dados do aparelho apreendido".into()),
        document_sha256: Some(sha256_hex(b"pdf do mandado")),
        recorded_by: op.id,
        recorded_at: t,
    };
    s.record_authorization(&auth).await.unwrap();
    let device = Device {
        id: DeviceId::new(),
        observed: simulated_device("SIM1", AdbState::Device),
        first_seen: t,
    };
    s.register_device(&device, Some(case.id), op.id)
        .await
        .unwrap();
    let acq = Acquisition {
        id: AcquisitionId::new(),
        case_id: case.id,
        device_id: device.id,
        authorization_id: auth.id,
        operator_id: op.id,
        capability: CapabilityKind::LocalImport,
        adapter_id: "mock".into(),
        adapter_version: "0.1.0".into(),
        software_version: mex_core::CORE_VERSION.into(),
        outcome: None,
        limitations: vec![],
        started_at: t,
        finished_at: None,
    };
    s.start_acquisition(&acq).await.unwrap();
    World {
        op,
        case,
        auth,
        device,
        acq,
    }
}

fn artifact(acq: AcquisitionId, path: &str, complete: bool) -> ArtifactRecord {
    let status = if complete {
        ArtifactStatus::Complete {
            digest: sha256_hex(path.as_bytes()),
            completed_at: UtcTimestamp::now(),
        }
    } else {
        ArtifactStatus::Failed {
            reason: "desconectado".into(),
        }
    };
    ArtifactRecord {
        id: mex_core::ids::ArtifactId::new(),
        acquisition_id: acq,
        stored_path: EvidencePath::new(path).unwrap(),
        source_path: Some(format!("/sdcard/{path}")),
        source_modified: Some(UtcTimestamp::now()),
        size_bytes: 10,
        status,
        created_at: UtcTimestamp::now(),
    }
}

async fn kinds(s: &Storage) -> Vec<AuditKind> {
    s.load_audit_chain()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

fn finish(w: &World, hash: bool) -> AcquisitionFinish {
    AcquisitionFinish {
        acquisition_id: w.acq.id,
        case_id: w.case.id,
        operator_id: w.op.id,
        outcome: AcquisitionOutcome::Partial,
        limitations: vec!["um artefato não adquirido".into()],
        finished_at: UtcTimestamp::now(),
        package_path: hash.then(|| "/evidencias/pkg".into()),
        manifest_sha256: hash.then(|| sha256_hex(b"manifest")),
    }
}

#[tokio::test]
async fn full_flow_produces_ordered_verifiable_audit() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;

    let t = UtcTimestamp::now();
    let mut job = AcquisitionJob::new(w.acq.id, CapabilityKind::LocalImport, t);
    s.save_job(&job, w.case.id, w.op.id).await.unwrap();
    for st in [JobState::Validating, JobState::Ready, JobState::Running] {
        job.transition(st, None, t).unwrap();
        s.save_job(&job, w.case.id, w.op.id).await.unwrap();
    }
    s.record_artifacts(&[
        artifact(w.acq.id, "a.bin", true),
        artifact(w.acq.id, "b.bin", false),
    ])
    .await
    .unwrap();
    s.finish_acquisition(&finish(&w, true)).await.unwrap();

    use AuditKind::*;
    assert_eq!(
        kinds(&s).await,
        vec![
            OperatorRegistered,
            CaseCreated,
            AuthorizationRecorded,
            DeviceRegistered,
            AcquisitionStarted,
            JobStateChanged,
            JobStateChanged,
            JobStateChanged,
            JobStateChanged,
            AcquisitionFinished,
        ]
    );
    assert_eq!(s.verify_audit_chain().await.unwrap(), 10);

    let chain = s.load_audit_chain().await.unwrap();
    let fin = chain.last().unwrap();
    assert!(
        fin.detail.contains(&sha256_hex(b"manifest").hex),
        "{}",
        fin.detail
    );
    assert_eq!(fin.case_id, Some(w.case.id));
    assert_eq!(fin.operator_id, Some(w.op.id));

    let reg = s.registered_package(w.acq.id).await.unwrap().unwrap();
    assert_eq!(reg.manifest_sha256, sha256_hex(b"manifest"));

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE status = 'complete'")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(n, 1);
    let state: String = sqlx::query_scalar("SELECT state FROM acquisition_jobs")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(state, "running");
    let _ = (&w.auth, &w.device);
}

#[tokio::test]
async fn failed_write_leaves_no_audit_event() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;
    let before = kinds(&s).await.len();

    // Número de caso duplicado: viola UNIQUE.
    let dup = Case::new("IP 42/2025", "Outro", w.op.id, UtcTimestamp::now()).unwrap();
    assert!(s.create_case(&dup).await.is_err());
    // Autorização de caso inexistente: viola FK.
    let mut orphan = w.auth.clone();
    orphan.id = AuthorizationId::new();
    orphan.case_id = mex_core::ids::CaseId::new();
    assert!(s.record_authorization(&orphan).await.is_err());

    assert_eq!(kinds(&s).await.len(), before);
    s.verify_audit_chain().await.unwrap();
}

#[tokio::test]
async fn artifact_batch_is_all_or_nothing() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;
    let r = s
        .record_artifacts(&[
            artifact(w.acq.id, "x.bin", true),
            artifact(w.acq.id, "x.bin", true),
        ])
        .await;
    assert!(r.is_err());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn finished_acquisition_is_immutable() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;
    s.finish_acquisition(&finish(&w, true)).await.unwrap();
    let before = kinds(&s).await.len();

    let mut again = finish(&w, true);
    again.manifest_sha256 = Some(sha256_hex(b"outro manifesto"));
    let e = s.finish_acquisition(&again).await.unwrap_err();
    assert!(e.to_string().contains("imutável"), "{e}");
    assert_eq!(kinds(&s).await.len(), before);
    assert_eq!(
        s.registered_package(w.acq.id)
            .await
            .unwrap()
            .unwrap()
            .manifest_sha256,
        sha256_hex(b"manifest")
    );
}

#[tokio::test]
async fn manifest_cannot_be_registered_before_finish() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;
    let e = sqlx::query("UPDATE acquisitions SET manifest_sha256 = ? WHERE id = ?")
        .bind(sha256_hex(b"x").hex)
        .bind(w.acq.id.to_string())
        .execute(s.pool())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("finalização"), "{e}");

    let mut bad = finish(&w, true);
    bad.manifest_sha256 = None;
    assert!(s.finish_acquisition(&bad).await.is_err());
}

#[tokio::test]
async fn acquisition_without_package_can_finish_failed() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;
    let mut f = finish(&w, false);
    f.outcome = AcquisitionOutcome::Failed;
    s.finish_acquisition(&f).await.unwrap();
    assert!(s.registered_package(w.acq.id).await.unwrap().is_none());
    let last = s.load_audit_chain().await.unwrap().pop().unwrap();
    assert!(last.detail.contains("sem pacote"));
}

#[tokio::test]
async fn verifications_are_recorded_append_only() {
    let s = Storage::open_in_memory().await.unwrap();
    let w = world(&s).await;
    s.finish_acquisition(&finish(&w, true)).await.unwrap();
    let rec = |status, findings: Vec<serde_json::Value>| VerificationRecord {
        acquisition_id: w.acq.id,
        case_id: w.case.id,
        status,
        manifest_sha256: Some(sha256_hex(b"manifest")),
        artifacts_checked: 1,
        bytes_verified: 10,
        findings,
        verified_by: w.op.id,
        verified_at: UtcTimestamp::now(),
    };
    s.record_verification(&rec(IntegrityStatus::Intact, vec![]))
        .await
        .unwrap();
    s.record_verification(&rec(
        IntegrityStatus::Compromised,
        vec![serde_json::json!({"subject": "artifacts/a.bin", "kind": "hash-mismatch"})],
    ))
    .await
    .unwrap();
    // Incoerente: "intact" com divergências.
    assert!(s
        .record_verification(&rec(IntegrityStatus::Intact, vec![serde_json::json!({})]))
        .await
        .is_err());

    assert!(
        sqlx::query("UPDATE integrity_verifications SET status = 'intact'")
            .execute(s.pool())
            .await
            .is_err()
    );
    assert!(sqlx::query("DELETE FROM integrity_verifications")
        .execute(s.pool())
        .await
        .is_err());
    let k = kinds(&s).await;
    assert_eq!(
        k.iter()
            .filter(|k| **k == AuditKind::IntegrityVerified)
            .count(),
        2
    );
    s.verify_audit_chain().await.unwrap();
}

/// Escritas concorrentes em banco de arquivo: `BEGIN IMMEDIATE` serializa
/// os escritores; nenhuma falha e a cadeia continua linear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_audit_appends_are_serialized() {
    let dir = tempfile::tempdir().unwrap();
    let s = Storage::open(&dir.path().join("mex.db")).await.unwrap();
    let mut handles = Vec::new();
    for i in 0..32 {
        let s = s.clone();
        handles.push(tokio::spawn(async move {
            s.append_audit_event(
                AuditDraft {
                    case_id: None,
                    operator_id: None,
                    kind: AuditKind::OperationExecuted,
                    detail: format!("operação concorrente {i}"),
                },
                UtcTimestamp::now(),
            )
            .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }
    assert_eq!(s.verify_audit_chain().await.unwrap(), 32);
    s.close().await;
}
