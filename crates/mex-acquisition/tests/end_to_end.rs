//! Testes ponta a ponta: motor + Evidence Engine + SQLite + auditoria.

use async_trait::async_trait;
use mex_acquisition::{
    run_acquisition, verify_acquisition, AcquisitionPlan, EngineError, LocalEvidenceImporter,
};
use mex_core::audit::AuditKind;
use mex_core::cancel::CancellationToken;
use mex_core::capability::{Availability, Capability, CapabilityKind, ModificationRisk};
use mex_core::ids::{AuthorizationId, DeviceId};
use mex_core::mock::{simulated_device, MockAdapter, MockArtifact, MockScenario};
use mex_core::model::{
    AcquisitionOutcome, AdbState, Authorization, AuthorizationKind, Case, Device,
    DeviceObservation, IntegrityStatus, Operator, Platform,
};
use mex_core::path::EvidencePath;
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{
    AcquisitionAdapter, AcquisitionRequest, AdapterDescriptor, AdapterReport, ArtifactSpec,
    CapabilityResolver, EvidenceSink,
};
use mex_core::{MexError, Result};
use mex_evidence::{FindingKind, SinkOptions};
use mex_storage::Storage;
use std::collections::BTreeMap;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/local_import_v1"
);
const ORACLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/local_import_v1.sha256"
);

struct Ctx {
    storage: Storage,
    operator: Operator,
    case: Case,
    authorization: Authorization,
    evidence: tempfile::TempDir,
}

async fn ctx() -> Ctx {
    let storage = Storage::open_in_memory().await.unwrap();
    let t = UtcTimestamp::now();
    let operator = Operator::new("Perita Teste", "0042", "Instituto de Criminalística", t).unwrap();
    storage.register_operator(&operator).await.unwrap();
    let case = Case::new(
        &format!("IP {}", uuid_like()),
        "Teste ponta a ponta",
        operator.id,
        t,
    )
    .unwrap();
    storage.create_case(&case).await.unwrap();
    let authorization = Authorization {
        id: AuthorizationId::new(),
        case_id: case.id,
        kind: AuthorizationKind::JudicialWarrant,
        kind_detail: None,
        reference: "Mandado 77/2025".into(),
        issuer: "2ª Vara Criminal".into(),
        scope_notes: None,
        document_sha256: None,
        recorded_by: operator.id,
        recorded_at: t,
    };
    storage.record_authorization(&authorization).await.unwrap();
    Ctx {
        storage,
        operator,
        case,
        authorization,
        evidence: tempfile::tempdir().unwrap(),
    }
}

fn uuid_like() -> String {
    DeviceId::new().to_string()
}

fn android_backup_device() -> DeviceObservation {
    DeviceObservation {
        platform: Platform::Android,
        serial: "R58M123ABC".into(),
        manufacturer: Some("Exemplo".into()),
        model: Some("Modelo X".into()),
        os_version: Some("14".into()),
        security_patch: None,
        adb_state: None,
        observed_at: UtcTimestamp::now(),
    }
}

async fn plan(c: &Ctx, observed: DeviceObservation, capability: CapabilityKind) -> AcquisitionPlan {
    let device = Device::new(observed);
    c.storage
        .register_device(&device, Some(c.case.id), c.operator.id)
        .await
        .unwrap();
    AcquisitionPlan {
        case: c.case.clone(),
        operator: c.operator.clone(),
        authorization: c.authorization.clone(),
        device,
        capability,
        evidence_root: c.evidence.path().to_path_buf(),
        sink_options: SinkOptions::default(),
    }
}

async fn audit_kinds(s: &Storage) -> Vec<AuditKind> {
    s.load_audit_chain()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

fn oracle() -> BTreeMap<String, String> {
    std::fs::read_to_string(ORACLE)
        .unwrap()
        .lines()
        .map(|l| {
            let (h, p) = l.split_once("  ").unwrap();
            (format!("files/{p}"), h.to_owned())
        })
        .collect()
}

// ---------------------------------------------------------- importação

/// Importação da fixture: hashes conferidos contra `sha256sum` (coreutils),
/// gerado de forma independente do MEX.
#[tokio::test]
async fn fixture_import_matches_independent_oracle() {
    let c = ctx().await;
    let importer = LocalEvidenceImporter::new(FIXTURE);
    let p = plan(&c, android_backup_device(), CapabilityKind::LocalImport).await;
    let s = run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(s.outcome, AcquisitionOutcome::Complete, "{:?}", s.reason);
    assert_eq!(s.job.state(), JobState::Completed);
    let pkg = s.package.as_ref().unwrap();
    let got: BTreeMap<String, String> = pkg
        .manifest
        .artifacts
        .iter()
        .map(|a| (a.stored_path.to_string(), a.digest().unwrap().hex.clone()))
        .collect();
    assert_eq!(got, oracle());
    assert!(pkg
        .manifest
        .artifacts
        .iter()
        .all(|a| a.source_modified.is_some()));
    assert_eq!(s.job.artifacts_completed(), 5);

    // Persistência e auditoria.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE status = 'complete'")
        .fetch_one(c.storage.pool())
        .await
        .unwrap();
    assert_eq!(n, 5);
    c.storage.verify_audit_chain().await.unwrap();
    let kinds = audit_kinds(&c.storage).await;
    assert_eq!(kinds.last(), Some(&AuditKind::AcquisitionFinished));
    assert!(kinds.contains(&AuditKind::AcquisitionStarted));
    let reg = c
        .storage
        .registered_package(s.acquisition_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reg.manifest_sha256, pkg.manifest_sha256);

    // Verificação registrada.
    let r = verify_acquisition(&c.storage, s.acquisition_id, c.case.id, &c.operator)
        .await
        .unwrap();
    assert_eq!(r.status, IntegrityStatus::Intact, "{:?}", r.findings);
    assert_eq!(
        audit_kinds(&c.storage).await.last(),
        Some(&AuditKind::IntegrityVerified)
    );
}

#[tokio::test]
async fn tampering_after_acquisition_is_detected_and_recorded() {
    let c = ctx().await;
    let importer = LocalEvidenceImporter::new(FIXTURE);
    let p = plan(&c, android_backup_device(), CapabilityKind::LocalImport).await;
    let s = run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
        .await
        .unwrap();
    let pkg = s.package.unwrap();

    // Adulteração de um artefato + "re-selo" consistente do pacote inteiro.
    let target = pkg
        .package_dir
        .join("artifacts/files/sdcard/DCIM/foto_0001.bin");
    std::fs::write(&target, b"imagem SUBSTITUIDA\n").unwrap();
    let mut forged = pkg.manifest.clone();
    for a in &mut forged.artifacts {
        if a.stored_path.as_str().ends_with("foto_0001.bin") {
            let d = mex_core::integrity::sha256_hex(b"imagem SUBSTITUIDA\n");
            a.size_bytes = 19;
            if let mex_core::model::ArtifactStatus::Complete { digest, .. } = &mut a.status {
                *digest = d;
            }
        }
    }
    forged.totals =
        mex_evidence::Manifest::compute_totals(&forged.artifacts, forged.not_acquired.len());
    let bytes = forged.to_bytes().unwrap();
    for (name, content) in [
        ("SHA256SUMS", forged.sha256sums().into_bytes()),
        ("manifest.json", bytes.clone()),
        (
            "manifest.sha256",
            mex_evidence::manifest::seal_line(&mex_core::integrity::sha256_hex(&bytes))
                .into_bytes(),
        ),
    ] {
        std::fs::write(pkg.package_dir.join(name), content).unwrap();
    }

    // Localmente o pacote parece íntegro...
    assert_eq!(
        mex_evidence::verify_package(&pkg.package_dir, None).status,
        IntegrityStatus::Intact
    );
    // ...mas o hash registrado no banco/auditoria denuncia a adulteração.
    let r = verify_acquisition(&c.storage, s.acquisition_id, c.case.id, &c.operator)
        .await
        .unwrap();
    assert_eq!(r.status, IntegrityStatus::Compromised);
    assert!(matches!(
        r.findings[0].kind,
        FindingKind::RegisteredHashMismatch { .. }
    ));
    let (status, count): (String, i64) = sqlx::query_as(
        "SELECT status, findings_count FROM integrity_verifications WHERE acquisition_id = ?",
    )
    .bind(s.acquisition_id.to_string())
    .fetch_one(c.storage.pool())
    .await
    .unwrap();
    assert_eq!((status.as_str(), count), ("compromised", 1));
}

/// Origem com casos difíceis, criada em tempo de teste (Unix).
#[cfg(unix)]
fn hostile_source() -> (tempfile::TempDir, bool) {
    use std::os::unix::ffi::OsStrExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    std::fs::write(p.join("ok.txt"), b"ok").unwrap();
    std::fs::write(p.join("nome:dois-pontos.txt"), b"dois pontos").unwrap();
    std::fs::write(p.join("CON"), b"reservado no Windows").unwrap();
    std::fs::write(p.join("A.txt"), b"maiuscula").unwrap();
    std::fs::write(p.join("a.txt"), b"minuscula").unwrap();
    std::fs::write(
        p.join(std::ffi::OsStr::from_bytes(b"\xff\xfe.bin")),
        b"nao utf8",
    )
    .unwrap();
    std::fs::create_dir(p.join("sub")).unwrap();
    std::fs::write(p.join("sub/deep.txt"), b"profundo").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", p.join("link")).unwrap();
    let fifo = std::process::Command::new("mkfifo")
        .arg(p.join("fifo"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    (d, fifo)
}

#[cfg(unix)]
#[tokio::test]
async fn hostile_source_is_handled_without_following_links() {
    let c = ctx().await;
    let (src, has_fifo) = hostile_source();
    let importer = LocalEvidenceImporter::new(src.path());
    let p = plan(&c, android_backup_device(), CapabilityKind::LocalImport).await;
    let s = run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
        .await
        .unwrap();
    let m = &s.package.as_ref().unwrap().manifest;

    // Links/FIFOs não adquiridos ⇒ parcial, nunca "completo".
    assert_eq!(s.outcome, AcquisitionOutcome::Partial);
    let not: Vec<_> = m
        .not_acquired
        .iter()
        .map(|f| f.source_path.clone().unwrap())
        .collect();
    assert!(not.contains(&"link".to_string()));
    assert!(m
        .not_acquired
        .iter()
        .any(|f| f.reason.contains("/etc/hostname")));
    if has_fifo {
        assert!(not.contains(&"fifo".to_string()));
    }

    let by_source: BTreeMap<String, String> = m
        .artifacts
        .iter()
        .map(|a| (a.source_path.clone().unwrap(), a.stored_path.to_string()))
        .collect();
    assert_eq!(by_source["ok.txt"], "files/ok.txt");
    assert_eq!(by_source["A.txt"], "files/A.txt");
    assert_eq!(by_source["sub/deep.txt"], "files/sub/deep.txt");
    for name in [
        "nome:dois-pontos.txt",
        "CON",
        "a.txt",
        "<não-UTF-8> \\xff\\xfe.bin",
    ] {
        assert!(
            by_source[name].starts_with("unmapped/"),
            "{name} -> {}",
            by_source[name]
        );
    }
    assert!(!by_source.contains_key("link"));
    assert!(m.limitations.iter().any(|l| l.contains("unmapped/")));

    let r = verify_acquisition(&c.storage, s.acquisition_id, c.case.id, &c.operator)
        .await
        .unwrap();
    assert_eq!(r.status, IntegrityStatus::Intact, "{:?}", r.findings);
}

#[tokio::test]
async fn importing_from_inside_the_evidence_root_is_refused() {
    let c = ctx().await;
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("x.txt"), b"x").unwrap();
    let mut p = plan(&c, android_backup_device(), CapabilityKind::LocalImport).await;
    p.evidence_root = src.path().join("evidencias");
    std::fs::create_dir(&p.evidence_root).unwrap();
    let importer = LocalEvidenceImporter::new(src.path());
    let s = run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(s.outcome, AcquisitionOutcome::Failed);
    assert!(s.reason.unwrap().contains("não pode conter"));
    assert!(s.package.unwrap().manifest.artifacts.is_empty());
}

// ----------------------------------------------------- política e validação

#[tokio::test]
async fn authorization_from_another_case_is_refused_before_start() {
    let c = ctx().await;
    let mut p = plan(&c, android_backup_device(), CapabilityKind::LocalImport).await;
    p.authorization.case_id = mex_core::ids::CaseId::new();
    let importer = LocalEvidenceImporter::new(FIXTURE);
    let e = run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(e, EngineError::Domain(MexError::PolicyDenied(_))));
    assert_eq!(
        audit_kinds(&c.storage).await.last(),
        Some(&AuditKind::Error)
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM acquisitions")
        .fetch_one(c.storage.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn non_operational_capability_is_refused() {
    let c = ctx().await;
    let p = plan(&c, android_backup_device(), CapabilityKind::Privileged).await;
    let importer = LocalEvidenceImporter::new(FIXTURE);
    assert!(
        run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unavailable_capability_fails_without_creating_a_package() {
    let c = ctx().await;
    let p = plan(&c, android_backup_device(), CapabilityKind::LocalImport).await;
    let importer = LocalEvidenceImporter::new("/caminho/que/nao/existe");
    let s = run_acquisition(&c.storage, &importer, p, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(s.outcome, AcquisitionOutcome::Failed);
    assert_eq!(s.job.state(), JobState::Failed);
    assert!(s.package.is_none());
    assert_eq!(std::fs::read_dir(c.evidence.path()).unwrap().count(), 0);
    assert!(c
        .storage
        .registered_package(s.acquisition_id)
        .await
        .unwrap()
        .is_none());
    c.storage.verify_audit_chain().await.unwrap();
}

// ------------------------------------------- cancelamento e desconexão

/// Adaptador de teste: grava um artefato, inicia o segundo e então o
/// "operador" cancela — de forma determinística.
struct CancelsMidway;

impl CapabilityResolver for CancelsMidway {
    fn resolve(&self, _: &DeviceObservation) -> Vec<Capability> {
        vec![Capability {
            kind: CapabilityKind::LocalImport,
            availability: Availability::Available,
            prerequisites: vec![],
            limitations: vec![],
            modification_risk: ModificationRisk::None,
        }]
    }
}

#[async_trait]
impl AcquisitionAdapter for CancelsMidway {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            id: "test-cancels-midway",
            version: "0.0.0",
            platforms: &[Platform::Simulated],
            capabilities: &[CapabilityKind::LocalImport],
            prerequisites: &[],
            restrictions: &["somente testes"],
            modification_risk: ModificationRisk::None,
        }
    }

    async fn acquire(
        &self,
        _: &AcquisitionRequest,
        sink: &mut dyn EvidenceSink,
        cancel: &CancellationToken,
    ) -> Result<AdapterReport> {
        let spec = |p: &str| ArtifactSpec {
            stored_path: EvidencePath::new(p).unwrap(),
            source_path: None,
            source_modified: None,
            expected_size: None,
        };
        let mut w = sink.begin_artifact(spec("primeiro.bin")).await?;
        w.write(b"completo").await?;
        w.commit().await?;
        let mut w = sink.begin_artifact(spec("segundo.bin")).await?;
        w.write(b"parcial").await?;
        cancel.cancel(); // operador cancela durante a gravação
        if cancel.is_cancelled() {
            w.abort("cancelado pelo operador").await?;
            return Err(MexError::Cancelled);
        }
        unreachable!()
    }
}

#[tokio::test]
async fn cancellation_through_engine() {
    let c = ctx().await;
    let p = plan(
        &c,
        simulated_device("SIM", AdbState::Device),
        CapabilityKind::LocalImport,
    )
    .await;
    let s = run_acquisition(&c.storage, &CancelsMidway, p, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(s.outcome, AcquisitionOutcome::Cancelled);
    assert_eq!(s.job.state(), JobState::Cancelled);
    let pkg = s.package.unwrap();
    assert!(pkg.package_dir.join("artifacts/primeiro.bin").is_file());
    assert!(!pkg.package_dir.join("artifacts/segundo.bin").exists());
    let kinds = audit_kinds(&c.storage).await;
    assert!(kinds.contains(&AuditKind::Interrupted));
    assert_eq!(kinds.last(), Some(&AuditKind::AcquisitionFinished));
    let outcome: String = sqlx::query_scalar("SELECT outcome FROM acquisitions WHERE id = ?")
        .bind(s.acquisition_id.to_string())
        .fetch_one(c.storage.pool())
        .await
        .unwrap();
    assert_eq!(outcome, "cancelled");
}

#[tokio::test]
async fn disconnection_through_engine_is_partial() {
    let c = ctx().await;
    let adapter = MockAdapter::new(MockScenario {
        artifacts: vec![
            MockArtifact {
                path: "a.bin".into(),
                size: 5_000,
                seed: 1,
            },
            MockArtifact {
                path: "b.bin".into(),
                size: 500_000,
                seed: 2,
            },
        ],
        chunk_size: 4096,
        disconnect_after_bytes: Some(100_000),
        not_acquired: vec![],
    });
    let p = plan(
        &c,
        simulated_device("SIM", AdbState::Device),
        CapabilityKind::LocalImport,
    )
    .await;
    let s = run_acquisition(&c.storage, &adapter, p, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(s.outcome, AcquisitionOutcome::Partial);
    assert_eq!(s.job.state(), JobState::Partial);
    assert_eq!(s.job.artifacts_completed(), 1);
    assert_eq!(s.job.failures().len(), 1);
    assert!(s.reason.unwrap().contains("desconectado"));
    let r = verify_acquisition(&c.storage, s.acquisition_id, c.case.id, &c.operator)
        .await
        .unwrap();
    assert_eq!(r.status, IntegrityStatus::Intact);
    c.storage.verify_audit_chain().await.unwrap();
}
