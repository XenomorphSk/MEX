//! Testes do schema SQLite (migration 0001) contra um SQLite real.

use mex_core::audit::{AuditDraft, AuditKind};
use mex_core::capability::CapabilityKind;
use mex_core::ids::{CaseId, OperatorId};
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use mex_research::MethodStatus;
use mex_storage::{Storage, StorageError, MIGRATOR};
use sqlx::Row;

fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn ts() -> String {
    UtcTimestamp::now().to_canonical()
}

async fn db() -> Storage {
    Storage::open_in_memory()
        .await
        .expect("abrir banco em memória")
}

async fn exec(s: &Storage, sql: &str, binds: &[&str]) -> Result<(), sqlx::Error> {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(s.pool()).await.map(|_| ())
}

async fn operator(s: &Storage) -> String {
    let i = id();
    exec(
        s,
        "INSERT INTO operators (id, full_name, badge, organization, created_at) VALUES (?, 'Perita', ?, 'IC', ?)",
        &[&i, &i, &ts()],
    )
    .await
    .unwrap();
    i
}

async fn case(s: &Storage, op: &str) -> String {
    let i = id();
    exec(
        s,
        "INSERT INTO cases (id, number, title, created_by, created_at) VALUES (?, ?, 'Título', ?, ?)",
        &[&i, &i, op, &ts()],
    )
    .await
    .unwrap();
    i
}

async fn authorization(s: &Storage, case: &str, op: &str) -> String {
    let i = id();
    exec(
        s,
        "INSERT INTO authorizations (id, case_id, kind, reference, issuer, recorded_by, recorded_at)
         VALUES (?, ?, 'judicial-warrant', 'Mandado 1', 'Vara Criminal', ?, ?)",
        &[&i, case, op, &ts()],
    )
    .await
    .unwrap();
    i
}

async fn device(s: &Storage, serial: &str) -> String {
    let i = id();
    let t = ts();
    exec(
        s,
        "INSERT INTO devices (id, platform, serial, adb_state, first_seen, last_seen)
         VALUES (?, 'simulated', ?, 'device', ?, ?)",
        &[&i, serial, &t, &t],
    )
    .await
    .unwrap();
    i
}

async fn try_acquisition(
    s: &Storage,
    case: &str,
    dev: &str,
    auth: &str,
    op: &str,
) -> Result<String, sqlx::Error> {
    let i = id();
    exec(
        s,
        "INSERT INTO acquisitions (id, case_id, device_id, authorization_id, operator_id,
             capability_kind, adapter_id, adapter_version, software_version, started_at)
         VALUES (?, ?, ?, ?, ?, 'local-import', 'mock', '0.1.0', '0.1.0', ?)",
        &[&i, case, dev, auth, op, &ts()],
    )
    .await
    .map(|_| i)
}

/// Caso completo pronto para receber aquisições: (op, case, auth, device, acquisition).
async fn fixture(s: &Storage) -> (String, String, String, String, String) {
    let op = operator(s).await;
    let c = case(s, &op).await;
    let a = authorization(s, &c, &op).await;
    let d = device(s, "SIM123").await;
    let acq = try_acquisition(s, &c, &d, &a, &op).await.unwrap();
    (op, c, a, d, acq)
}

async fn pending_artifact(s: &Storage, acq: &str, path: &str) -> String {
    let i = id();
    exec(
        s,
        "INSERT INTO artifacts (id, acquisition_id, stored_path, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
        &[&i, acq, path, &ts()],
    )
    .await
    .unwrap();
    i
}

fn is_constraint_error(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(_))
}

// ------------------------------------------------------------- migrations

#[tokio::test]
async fn migrations_create_all_tables() {
    let s = db().await;
    let rows = sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .fetch_all(s.pool())
        .await
        .unwrap();
    let tables: Vec<String> = rows.iter().map(|r| r.get("name")).collect();
    for t in [
        "cases",
        "operators",
        "authorizations",
        "devices",
        "acquisitions",
        "acquisition_jobs",
        "artifacts",
        "artifact_hashes",
        "audit_events",
        "research_devices",
        "research_methods",
        "research_method_status_history",
        "compatibility_results",
        "reports",
    ] {
        assert!(tables.contains(&t.to_string()), "tabela ausente: {t}");
    }
}

#[tokio::test]
async fn migrations_are_idempotent_and_versioned() {
    let s = db().await;
    MIGRATOR.run(s.pool()).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success = 1")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(n, MIGRATOR.iter().count() as i64);
    assert!(n >= 1);
}

#[tokio::test]
async fn foreign_keys_are_enforced_on_connection() {
    let s = db().await;
    let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(fk, 1);
    let e = exec(
        &s,
        "INSERT INTO cases (id, number, title, created_by, created_at) VALUES (?, 'N1', 'T', ?, ?)",
        &[&id(), &id(), &ts()],
    )
    .await
    .unwrap_err();
    assert!(is_constraint_error(&e));
}

#[tokio::test]
async fn file_database_persists_across_reopen() {
    let dir = std::env::temp_dir().join(format!("mex-storage-test-{}", id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mex.db");
    {
        let s = Storage::open(&path).await.unwrap();
        for k in [AuditKind::OperatorRegistered, AuditKind::CaseCreated] {
            s.append_audit_event(draft(k, "evento persistente"), UtcTimestamp::now())
                .await
                .unwrap();
        }
        s.close().await;
    }
    let s = Storage::open(&path).await.unwrap();
    assert_eq!(s.verify_audit_chain().await.unwrap(), 2);
    s.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

// -------------------------------------------- enums: Rust <-> CHECK do SQL

#[tokio::test]
async fn every_job_state_is_accepted_and_unknown_rejected() {
    let s = db().await;
    let (.., acq) = fixture(&s).await;
    let sql = "INSERT INTO acquisition_jobs (id, acquisition_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?)";
    for st in JobState::ALL {
        exec(&s, sql, &[&id(), &acq, st.name(), &ts(), &ts()])
            .await
            .unwrap();
    }
    assert!(exec(&s, sql, &[&id(), &acq, "done", &ts(), &ts()])
        .await
        .is_err());
}

#[tokio::test]
async fn every_capability_kind_is_accepted() {
    let s = db().await;
    let op = operator(&s).await;
    let c = case(&s, &op).await;
    let a = authorization(&s, &c, &op).await;
    let d = device(&s, "X").await;
    let sql = "INSERT INTO acquisitions (id, case_id, device_id, authorization_id, operator_id,
                   capability_kind, adapter_id, adapter_version, software_version, started_at)
               VALUES (?, ?, ?, ?, ?, ?, 'mock', '1', '1', ?)";
    for k in CapabilityKind::ALL {
        exec(&s, sql, &[&id(), &c, &d, &a, &op, k.as_str(), &ts()])
            .await
            .unwrap();
    }
    assert!(exec(&s, sql, &[&id(), &c, &d, &a, &op, "root", &ts()])
        .await
        .is_err());
}

#[tokio::test]
async fn every_audit_kind_is_accepted() {
    let s = db().await;
    for k in AuditKind::ALL {
        s.append_audit_event(draft(k, k.as_str()), UtcTimestamp::now())
            .await
            .unwrap();
    }
    assert_eq!(s.verify_audit_chain().await.unwrap(), AuditKind::ALL.len());
}

#[tokio::test]
async fn research_status_values_match_and_methods_start_experimental() {
    let s = db().await;
    let insert = "INSERT INTO research_methods (id, name, version, capability_kind, hypothesis, status, created_at, updated_at)
                  VALUES (?, ?, '1', 'file-system', 'h', ?, ?, ?)";
    let m = id();
    exec(&s, insert, &[&m, &m, "EXPERIMENTAL", &ts(), &ts()])
        .await
        .unwrap();
    let e = exec(&s, insert, &[&id(), "outro", "VALIDATED", &ts(), &ts()])
        .await
        .unwrap_err();
    assert!(e.to_string().contains("EXPERIMENTAL"), "{e}");

    for st in MethodStatus::ALL {
        exec(
            &s,
            "UPDATE research_methods SET status = ? WHERE id = ?",
            &[st.as_str(), &m],
        )
        .await
        .unwrap();
    }
    assert!(exec(
        &s,
        "UPDATE research_methods SET status = 'validated' WHERE id = ?",
        &[&m]
    )
    .await
    .is_err());
}

// --------------------------------------------------- integridade referencial

#[tokio::test]
async fn authorization_must_belong_to_the_same_case() {
    let s = db().await;
    let op = operator(&s).await;
    let case_a = case(&s, &op).await;
    let case_b = case(&s, &op).await;
    let auth_b = authorization(&s, &case_b, &op).await;
    let d = device(&s, "X").await;
    let e = try_acquisition(&s, &case_a, &d, &auth_b, &op)
        .await
        .unwrap_err();
    assert!(is_constraint_error(&e));
    assert!(try_acquisition(&s, &case_b, &d, &auth_b, &op).await.is_ok());
}

#[tokio::test]
async fn duplicate_serials_are_distinct_devices() {
    let s = db().await;
    let a = device(&s, "0123456789ABCDEF").await;
    let b = device(&s, "0123456789ABCDEF").await;
    assert_ne!(a, b);
}

#[tokio::test]
async fn outcome_and_finish_time_go_together() {
    let s = db().await;
    let (.., acq) = fixture(&s).await;
    assert!(exec(
        &s,
        "UPDATE acquisitions SET outcome = 'complete' WHERE id = ?",
        &[&acq]
    )
    .await
    .is_err());
    exec(
        &s,
        "UPDATE acquisitions SET outcome = 'partial', finished_at = ? WHERE id = ?",
        &[&ts(), &acq],
    )
    .await
    .unwrap();
}

// ----------------------------------------------------------- artefatos

#[tokio::test]
async fn artifact_cannot_be_inserted_as_complete() {
    let s = db().await;
    let (.., acq) = fixture(&s).await;
    let e = exec(
        &s,
        "INSERT INTO artifacts (id, acquisition_id, stored_path, status, created_at, completed_at)
         VALUES (?, ?, 'a.bin', 'complete', ?, ?)",
        &[&id(), &acq, &ts(), &ts()],
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("proibido"), "{e}");
}

#[tokio::test]
async fn artifact_complete_requires_hash_then_becomes_immutable() {
    let s = db().await;
    let (.., acq) = fixture(&s).await;
    let art = pending_artifact(&s, &acq, "files/a.bin").await;
    let complete = "UPDATE artifacts SET status = 'complete', completed_at = ? WHERE id = ?";

    let e = exec(&s, complete, &[&ts(), &art]).await.unwrap_err();
    assert!(e.to_string().contains("hash"), "{e}");

    exec(
        &s,
        "INSERT INTO artifact_hashes (artifact_id, alg, hex, computed_at) VALUES (?, 'sha-256', ?, ?)",
        &[&art, &"ab".repeat(32), &ts()],
    )
    .await
    .unwrap();
    exec(&s, complete, &[&ts(), &art]).await.unwrap();

    assert!(exec(
        &s,
        "UPDATE artifacts SET size_bytes = 1 WHERE id = ?",
        &[&art]
    )
    .await
    .is_err());
    assert!(exec(&s, "DELETE FROM artifacts WHERE id = ?", &[&art])
        .await
        .is_err());
    assert!(exec(
        &s,
        "UPDATE artifact_hashes SET hex = ? WHERE artifact_id = ?",
        &[&"00".repeat(32), &art]
    )
    .await
    .is_err());
    assert!(exec(
        &s,
        "DELETE FROM artifact_hashes WHERE artifact_id = ?",
        &[&art]
    )
    .await
    .is_err());
}

#[tokio::test]
async fn hash_format_is_checked() {
    let s = db().await;
    let (.., acq) = fixture(&s).await;
    let art = pending_artifact(&s, &acq, "a.bin").await;
    let sql = "INSERT INTO artifact_hashes (artifact_id, alg, hex, computed_at) VALUES (?, 'sha-256', ?, ?)";
    for bad in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
        assert!(exec(&s, sql, &[&art, &bad, &ts()]).await.is_err(), "{bad}");
    }
}

#[tokio::test]
async fn failed_artifact_requires_reason_and_paths_are_relative() {
    let s = db().await;
    let (.., acq) = fixture(&s).await;
    let sql = "INSERT INTO artifacts (id, acquisition_id, stored_path, status, failure_reason, created_at)
               VALUES (?, ?, ?, ?, ?, ?)";
    let mut q = sqlx::query(sql)
        .bind(id())
        .bind(&acq)
        .bind("x.bin")
        .bind("failed")
        .bind(None::<String>)
        .bind(ts());
    assert!(q.execute(s.pool()).await.is_err());
    q = sqlx::query(sql)
        .bind(id())
        .bind(&acq)
        .bind("/etc/passwd")
        .bind("pending")
        .bind(None::<String>)
        .bind(ts());
    assert!(q.execute(s.pool()).await.is_err());
}

// ---------------------------------------------------- cadeia de custódia

fn draft(kind: AuditKind, detail: &str) -> AuditDraft {
    AuditDraft {
        case_id: None,
        operator_id: None,
        kind,
        detail: detail.into(),
    }
}

#[tokio::test]
async fn audit_chain_roundtrips_through_sqlite() {
    let s = db().await;
    let op = operator(&s).await;
    let c = case(&s, &op).await;
    let op_id: OperatorId = op.parse().unwrap();
    let case_id: CaseId = c.parse().unwrap();
    let mut written = Vec::new();
    for (k, d) in [
        (AuditKind::CaseCreated, "caso criado"),
        (AuditKind::AuthorizationRecorded, "mandado registrado"),
        (AuditKind::Interrupted, "dispositivo desconectado"),
    ] {
        let ev = s
            .append_audit_event(
                AuditDraft {
                    case_id: Some(case_id),
                    operator_id: Some(op_id),
                    kind: k,
                    detail: d.into(),
                },
                UtcTimestamp::now(),
            )
            .await
            .unwrap();
        written.push(ev);
    }
    let loaded = s.load_audit_chain().await.unwrap();
    assert_eq!(loaded, written);
    assert_eq!(s.verify_audit_chain().await.unwrap(), 3);
}

#[tokio::test]
async fn audit_events_are_append_only() {
    let s = db().await;
    s.append_audit_event(draft(AuditKind::CaseCreated, "a"), UtcTimestamp::now())
        .await
        .unwrap();
    let e = exec(
        &s,
        "UPDATE audit_events SET detail = 'x' WHERE seq = 0",
        &[],
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("append-only"), "{e}");
    let e = exec(&s, "DELETE FROM audit_events", &[]).await.unwrap_err();
    assert!(e.to_string().contains("append-only"), "{e}");
}

#[tokio::test]
async fn out_of_sequence_insert_is_rejected() {
    let s = db().await;
    let first = s
        .append_audit_event(draft(AuditKind::CaseCreated, "a"), UtcTimestamp::now())
        .await
        .unwrap();
    let sql = "INSERT INTO audit_events (seq, id, kind, detail, at, prev_hash, entry_hash) VALUES (?, ?, 'error', 'x', ?, ?, ?)";
    // seq pulado
    let e = sqlx::query(sql)
        .bind(5_i64)
        .bind(id())
        .bind(ts())
        .bind(&first.entry_hash)
        .bind("cd".repeat(32))
        .execute(s.pool())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("sequência"), "{e}");
    // prev_hash errado
    let e = sqlx::query(sql)
        .bind(1_i64)
        .bind(id())
        .bind(ts())
        .bind("ef".repeat(32))
        .bind("cd".repeat(32))
        .execute(s.pool())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("sequência"), "{e}");
}

/// Adversário com acesso direto ao arquivo remove os triggers e altera um
/// evento: a verificação criptográfica da cadeia ainda detecta.
#[tokio::test]
async fn tampering_after_dropping_triggers_is_detected_by_verification() {
    let s = db().await;
    for d in ["um", "dois", "três"] {
        s.append_audit_event(draft(AuditKind::OperationExecuted, d), UtcTimestamp::now())
            .await
            .unwrap();
    }
    exec(&s, "DROP TRIGGER audit_events_no_update", &[])
        .await
        .unwrap();
    exec(
        &s,
        "UPDATE audit_events SET detail = 'adulterado' WHERE seq = 1",
        &[],
    )
    .await
    .unwrap();

    match s.verify_audit_chain().await {
        Err(StorageError::Domain(MexError::AuditChainBroken { seq, .. })) => assert_eq!(seq, 1),
        other => panic!("adulteração não detectada: {other:?}"),
    }
}

#[tokio::test]
async fn non_canonical_timestamp_in_db_is_rejected_on_load() {
    let s = db().await;
    s.append_audit_event(draft(AuditKind::CaseCreated, "a"), UtcTimestamp::now())
        .await
        .unwrap();
    exec(&s, "DROP TRIGGER audit_events_no_update", &[])
        .await
        .unwrap();
    // Mesma largura (27), formato diferente.
    exec(
        &s,
        "UPDATE audit_events SET at = '2025-01-01 12:00:00.000000Z' WHERE seq = 0",
        &[],
    )
    .await
    .unwrap();
    assert!(matches!(
        s.load_audit_chain().await,
        Err(StorageError::Domain(MexError::InvalidInput(_)))
    ));
}
