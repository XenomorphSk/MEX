//! Fluxo completo da camada de aplicação (o que a interface desktop executa).

use mex_app::{
    App, AppConfig, ImportRequest, NewAuthorization, NewCase, NewDevice, NewOperator, RunStatus,
    RunView,
};
use mex_core::audit::AuditKind;
use mex_core::capability::CapabilityKind;
use mex_core::ids::{AcquisitionId, CaseId, DeviceId};
use mex_core::integrity::sha256_hex;
use mex_core::job::AcquisitionJob;
use mex_core::model::{Acquisition, AuthorizationKind, Platform};
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/local_import_v1"
);
const ORACLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/local_import_v1.sha256"
);

async fn open(dir: &std::path::Path) -> Arc<App> {
    App::open(AppConfig {
        data_dir: dir.to_path_buf(),
    })
    .await
    .unwrap()
}

/// Operador + sessão + caso + autorização + dispositivo.
async fn setup(app: &App) -> (CaseId, mex_core::ids::AuthorizationId, DeviceId) {
    let op = app
        .register_operator(NewOperator {
            full_name: "Perita Interface".into(),
            badge: "0101".into(),
            organization: "IC".into(),
        })
        .await
        .unwrap();
    app.select_operator(op.id).await.unwrap();
    let case = app
        .create_case(NewCase {
            number: "IP 0700/2025".into(),
            title: "Teste da interface".into(),
        })
        .await
        .unwrap();
    let auth = app
        .record_authorization(NewAuthorization {
            case_id: case.id,
            kind: AuthorizationKind::JudicialWarrant,
            kind_detail: None,
            reference: "Mandado 700/2025".into(),
            issuer: "Vara Criminal".into(),
            scope_notes: None,
            document_path: None,
        })
        .await
        .unwrap();
    let dev = app
        .register_device(NewDevice {
            case_id: Some(case.id),
            platform: Platform::Android,
            serial: "SERIAL-UI".into(),
            manufacturer: Some("Exemplo".into()),
            model: None,
            os_version: None,
            security_patch: None,
        })
        .await
        .unwrap();
    (case.id, auth.id, dev.id)
}

async fn wait(app: &App, id: AcquisitionId) -> RunView {
    for _ in 0..600 {
        let r = app
            .list_runs()
            .into_iter()
            .find(|r| r.acquisition_id == id)
            .unwrap();
        if !matches!(r.status, RunStatus::Running) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("execução não terminou em 12 s");
}

fn import(
    case: CaseId,
    auth: mex_core::ids::AuthorizationId,
    dev: DeviceId,
    src: &str,
    ok: bool,
) -> ImportRequest {
    ImportRequest {
        case_id: case,
        authorization_id: auth,
        device_id: dev,
        source_dir: src.into(),
        operator_confirmed: ok,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutations_require_an_identified_operator() {
    let dir = tempfile::tempdir().unwrap();
    let app = open(dir.path()).await;
    let e = app
        .create_case(NewCase {
            number: "X".into(),
            title: "Y".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.kind, "session");
    assert!(app.info().session.is_none());

    // Diretórios de dados com permissões mínimas (Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in ["", "evidencias", "relatorios"] {
            let m = std::fs::metadata(dir.path().join(d))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o077, 0, "{d:?}: {m:o}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_flow_import_verify_report_export() {
    let dir = tempfile::tempdir().unwrap();
    let app = open(dir.path()).await;
    let (case, auth, dev) = setup(&app).await;

    // Prévia do assistente.
    let p = app
        .preview_import(case, auth, dev, FIXTURE.into())
        .await
        .unwrap();
    assert!(p.capability.is_available());
    assert_eq!(p.adapter.id, "local-import");
    assert!(!p.adapter.prerequisites.is_empty());
    assert!(!p.capability.limitations.is_empty());

    // Sem confirmação explícita: recusado.
    let e = app
        .start_import(import(case, auth, dev, FIXTURE, false))
        .await
        .unwrap_err();
    assert_eq!(e.kind, "policy");

    let run = app
        .start_import(import(case, auth, dev, FIXTURE, true))
        .await
        .unwrap();
    let done = wait(&app, run.acquisition_id).await;
    assert!(
        matches!(&done.status, RunStatus::Finished { outcome, .. } if outcome == "complete"),
        "{:?}",
        done.status
    );

    // Estado persistido.
    let acqs = app.list_acquisitions(Some(case), None).await.unwrap();
    assert_eq!(acqs.len(), 1);
    let a = &acqs[0];
    assert_eq!(a.id, run.acquisition_id);
    assert_eq!(a.outcome.as_deref(), Some("complete"));
    assert_eq!(a.job_state.as_deref(), Some("completed"));
    assert_eq!(a.artifacts_completed, 5);
    assert!(a.manifest_sha256.is_some());
    assert_eq!(
        app.list_acquisitions(None, Some(dev)).await.unwrap().len(),
        1
    );

    // Inventário confere com o oráculo independente (sha256sum).
    let oracle: BTreeMap<String, String> = std::fs::read_to_string(ORACLE)
        .unwrap()
        .lines()
        .map(|l| {
            let (h, p) = l.split_once("  ").unwrap();
            (format!("files/{p}"), h.to_owned())
        })
        .collect();
    let arts: BTreeMap<String, String> = app
        .list_artifacts(a.id)
        .await
        .unwrap()
        .into_iter()
        .map(|x| (x.stored_path, x.sha256.unwrap()))
        .collect();
    assert_eq!(arts, oracle);

    // Verificação, relatório, exportação.
    let v = app.verify(a.id).await.unwrap();
    assert_eq!(v.status.as_str(), "intact");
    assert_eq!(app.list_verifications(a.id).await.unwrap().len(), 1);
    let r = app.generate_report(a.id).await.unwrap();
    assert_eq!(r.integrity, "intact");
    assert!(std::path::Path::new(&r.html_path).starts_with(dir.path()));
    assert_eq!(
        sha256_hex(&std::fs::read(&r.html_path).unwrap()).hex,
        r.html_sha256
    );
    assert_eq!(app.list_reports(case).await.unwrap().len(), 2);
    let dest = tempfile::tempdir().unwrap();
    let x = app
        .export(a.id, dest.path().display().to_string())
        .await
        .unwrap();
    assert_eq!(x.status, "intact");
    assert!(x.destination.is_some());
    assert_eq!(app.list_exports(a.id).await.unwrap().len(), 1);

    // Cadeia de custódia.
    let c = app.custody(case).await.unwrap();
    assert!(c.chain_intact);
    let kinds: Vec<AuditKind> = c.events.iter().map(|e| e.kind).collect();
    for k in [
        AuditKind::CaseCreated,
        AuditKind::AuthorizationRecorded,
        AuditKind::DeviceRegistered,
        AuditKind::AcquisitionStarted,
        AuditKind::AcquisitionFinished,
        AuditKind::IntegrityVerified,
        AuditKind::Exported,
    ] {
        assert!(kinds.contains(&k), "{k:?}");
    }
    let s = app.stats().await.unwrap();
    assert_eq!(
        (s.cases, s.devices, s.acquisitions, s.acquisitions_open),
        (1, 1, 1, 0)
    );

    // Execução terminada não pode ser cancelada.
    assert!(app.cancel_run(a.id).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn document_hash_is_recorded_and_inputs_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let app = open(dir.path()).await;
    let (case, _, _) = setup(&app).await;
    let doc = dir.path().join("mandado.pdf");
    std::fs::write(&doc, b"%PDF-1.7 documento de teste").unwrap();
    let a = app
        .record_authorization(NewAuthorization {
            case_id: case,
            kind: AuthorizationKind::OwnerConsent,
            kind_detail: None,
            reference: "Termo 1".into(),
            issuer: "Titular".into(),
            scope_notes: Some("Somente fotos".into()),
            document_path: Some(doc.display().to_string()),
        })
        .await
        .unwrap();
    assert_eq!(
        a.document_sha256.unwrap(),
        sha256_hex(b"%PDF-1.7 documento de teste")
    );
    assert_eq!(
        std::fs::read(&doc).unwrap(),
        b"%PDF-1.7 documento de teste",
        "documento intacto"
    );

    let other = NewAuthorization {
        case_id: case,
        kind: AuthorizationKind::Other,
        kind_detail: None,
        reference: "R".into(),
        issuer: "I".into(),
        scope_notes: None,
        document_path: None,
    };
    assert_eq!(
        app.record_authorization(other).await.unwrap_err().kind,
        "invalid"
    );

    let sim = NewDevice {
        case_id: None,
        platform: Platform::Simulated,
        serial: "SIM".into(),
        manufacturer: None,
        model: None,
        os_version: None,
        security_patch: None,
    };
    assert_eq!(app.register_device(sim).await.unwrap_err().kind, "policy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_from_another_case_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let app = open(dir.path()).await;
    let (_, auth, dev) = setup(&app).await;
    let other = app
        .create_case(NewCase {
            number: "IP 0701/2025".into(),
            title: "Outro".into(),
        })
        .await
        .unwrap();
    let e = app
        .preview_import(other.id, auth, dev, FIXTURE.into())
        .await
        .unwrap_err();
    assert_eq!(e.kind, "policy");
    assert!(app
        .start_import(import(other.id, auth, dev, FIXTURE, true))
        .await
        .is_err());
    assert!(app.list_runs().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_from_the_interface() {
    let dir = tempfile::tempdir().unwrap();
    let app = open(dir.path()).await;
    let (case, auth, dev) = setup(&app).await;
    let src = tempfile::tempdir().unwrap();
    let block = vec![0x5Au8; 256 * 1024];
    for i in 0..200 {
        std::fs::write(src.path().join(format!("f{i:03}.bin")), &block).unwrap();
    }
    let run = app
        .start_import(import(
            case,
            auth,
            dev,
            &src.path().display().to_string(),
            true,
        ))
        .await
        .unwrap();
    app.cancel_run(run.acquisition_id).unwrap();
    let done = wait(&app, run.acquisition_id).await;
    assert!(done.cancel_requested);
    assert!(
        matches!(&done.status, RunStatus::Finished { outcome, .. } if outcome == "cancelled"),
        "{:?}",
        done.status
    );
    let a = &app.list_acquisitions(Some(case), None).await.unwrap()[0];
    assert_eq!(a.outcome.as_deref(), Some("cancelled"));
    assert_eq!(a.job_state.as_deref(), Some("cancelled"));
    assert!(app.custody(case).await.unwrap().chain_intact);
}

/// Aplicativo encerrado durante uma aquisição: na próxima abertura ela é
/// encerrada como `failed`, com auditoria.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_acquisition_is_closed_on_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let acq_id;
    let case_id;
    {
        let app = open(dir.path()).await;
        let (case, auth, dev) = setup(&app).await;
        case_id = case;
        let op = app.info().session.unwrap();
        let acq = Acquisition {
            id: AcquisitionId::new(),
            case_id: case,
            device_id: dev,
            authorization_id: auth,
            operator_id: op.id,
            capability: CapabilityKind::LocalImport,
            adapter_id: "local-import".into(),
            adapter_version: "0.1.0".into(),
            software_version: "0.1.0".into(),
            outcome: None,
            limitations: vec![],
            started_at: UtcTimestamp::now(),
            finished_at: None,
        };
        acq_id = acq.id;
        app.storage().start_acquisition(&acq).await.unwrap();
        let mut job = AcquisitionJob::new(acq.id, CapabilityKind::LocalImport, UtcTimestamp::now());
        for s in [JobState::Validating, JobState::Ready, JobState::Running] {
            job.transition(s, None, UtcTimestamp::now()).unwrap();
        }
        app.storage().save_job(&job, case, op.id).await.unwrap();
        app.storage().clone().close().await;
    }
    let app = open(dir.path()).await;
    assert_eq!(app.info().recovered_on_open, 1);
    let a = &app.list_acquisitions(Some(case_id), None).await.unwrap()[0];
    assert_eq!(a.id, acq_id);
    assert_eq!(a.outcome.as_deref(), Some("failed"));
    assert_eq!(a.job_state.as_deref(), Some("failed"));
    assert!(a.limitations[0].contains("encerrado durante a execução"));
    let c = app.custody(case_id).await.unwrap();
    assert!(c.chain_intact);
    assert!(c.events.iter().any(|e| e.kind == AuditKind::Interrupted));
    // Uma segunda abertura não encontra mais nada a recuperar.
    drop(app);
    assert_eq!(open(dir.path()).await.info().recovered_on_open, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_validated_methods_are_allowed_in_cases() {
    let dir = tempfile::tempdir().unwrap();
    let app = open(dir.path()).await;
    let p = app.research_policy();
    assert_eq!(p.len(), 5);
    for m in p {
        assert_eq!(m.allowed_in_case, m.status == "VALIDATED", "{}", m.status);
    }
}
