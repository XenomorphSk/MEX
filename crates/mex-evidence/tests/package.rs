//! Testes do Evidence Engine em disco real (diretório temporário).

use mex_core::cancel::CancellationToken;
use mex_core::capability::CapabilityKind;
use mex_core::ids::{AcquisitionId, AuthorizationId, DeviceId};
use mex_core::integrity::sha256_hex;
use mex_core::mock::{mock_content, simulated_device, MockAdapter, MockArtifact, MockScenario};
use mex_core::model::{
    AcquisitionOutcome, AdbState, ArtifactStatus, Authorization, AuthorizationKind, Case,
    IntegrityStatus, Operator,
};
use mex_core::path::EvidencePath;
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{
    AcquisitionAdapter, AcquisitionRequest, AdapterReport, ArtifactSpec, EvidenceSink,
};
use mex_core::MexError;
use mex_evidence::manifest::{parse_seal, seal_line};
use mex_evidence::{
    verify_package, AdapterRecord, DiskEvidenceSink, FinalizeInput, FindingKind, Manifest,
    ManifestHeader, SealedPackage, SinkOptions, Termination,
};
use std::path::Path;

fn header(adapter: &MockAdapter) -> ManifestHeader {
    let t = UtcTimestamp::now();
    let operator = Operator::new("Perita Teste", "0001", "Instituto de Criminalística", t).unwrap();
    let case = Case::new("IP 0001/2025", "Teste do Evidence Engine", operator.id, t).unwrap();
    let authorization = Authorization {
        id: AuthorizationId::new(),
        case_id: case.id,
        kind: AuthorizationKind::JudicialWarrant,
        kind_detail: None,
        reference: "Mandado 123/2025".into(),
        issuer: "Vara Criminal".into(),
        scope_notes: None,
        document_sha256: None,
        recorded_by: operator.id,
        recorded_at: t,
    };
    ManifestHeader {
        case,
        operator,
        authorization,
        device_id: DeviceId::new(),
        device: simulated_device("SIM123", AdbState::Device),
        adapter: AdapterRecord::from_descriptor(&adapter.descriptor(), CapabilityKind::LocalImport),
        started_at: t,
    }
}

fn scenario() -> MockScenario {
    MockScenario {
        artifacts: vec![
            MockArtifact {
                path: "device/info.json".into(),
                size: 1_000,
                seed: 1,
            },
            MockArtifact {
                path: "files/sdcard/a.bin".into(),
                size: 2 * 1024 * 1024 + 3,
                seed: 2,
            },
            MockArtifact {
                path: "files/sdcard/b.bin".into(),
                size: 0,
                seed: 3,
            },
            MockArtifact {
                path: "files/c.bin".into(),
                size: 70_000,
                seed: 4,
            },
        ],
        chunk_size: 64 * 1024,
        disconnect_after_bytes: None,
        not_acquired: Vec::new(),
    }
}

/// Grava o primeiro artefato, inicia o segundo e então o "operador" cancela.
/// Determinístico: não depende de em qual suspensão o escalonador interrompe
/// o adaptador (cancelar entre dois artefatos é legítimo e não aborta nenhum).
async fn cancel_midway(
    sink: &mut DiskEvidenceSink,
    cancel: &CancellationToken,
) -> Result<AdapterReport, MexError> {
    let mut w = sink.begin_artifact(spec("device/info.json", None)).await?;
    w.write(&mock_content(1, 1_000)).await?;
    w.commit().await?;
    let mut w = sink
        .begin_artifact(spec("files/sdcard/a.bin", None))
        .await?;
    w.write(&mock_content(2, 4096)).await?;
    cancel.cancel();
    if cancel.is_cancelled() {
        w.abort("cancelado pelo operador").await?;
        return Err(MexError::Cancelled);
    }
    unreachable!("o cancelamento foi solicitado acima")
}

/// Executa o mock contra um sink em disco e sela o pacote. Com
/// `cancel_early`, usa [`cancel_midway`] no lugar do mock.
async fn acquire(root: &Path, sc: MockScenario, cancel_early: bool) -> SealedPackage {
    let acq = AcquisitionId::new();
    let adapter = MockAdapter::new(sc);
    let mut sink = DiskEvidenceSink::create(root, acq, SinkOptions::default())
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let request = AcquisitionRequest {
        acquisition_id: acq,
        capability: CapabilityKind::LocalImport,
        device: simulated_device("SIM123", AdbState::Device),
    };
    let result = if cancel_early {
        cancel_midway(&mut sink, &cancel).await
    } else {
        adapter.acquire(&request, &mut sink, &cancel).await
    };
    let (report, termination) = match result {
        Ok(r) => (r, Termination::Normal),
        Err(MexError::Cancelled) => (AdapterReport::default(), Termination::Cancelled),
        Err(e) => (
            AdapterReport::default(),
            Termination::Interrupted {
                reason: e.to_string(),
            },
        ),
    };
    sink.finalize(FinalizeInput {
        header: header(&adapter),
        report,
        termination,
        finished_at: UtcTimestamp::now(),
    })
    .await
    .unwrap()
}

fn kinds(r: &mex_evidence::VerificationReport) -> Vec<FindingKind> {
    r.findings.iter().map(|f| f.kind.clone()).collect()
}

// --------------------------------------------------------- fluxo nominal

#[tokio::test]
async fn sealed_package_has_expected_layout_and_verifies_intact() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;

    assert_eq!(pkg.manifest.outcome, AcquisitionOutcome::Complete);
    assert_eq!(pkg.manifest.totals.artifacts_complete, 4);
    let dir = &pkg.package_dir;
    assert!(dir.join("manifest.json").is_file());
    assert!(dir.join("manifest.sha256").is_file());
    assert!(dir.join("SHA256SUMS").is_file());
    assert!(
        !dir.join(".staging").exists(),
        "área temporária deve ser removida"
    );

    for (art, spec) in pkg.manifest.artifacts.iter().zip(&scenario().artifacts) {
        let on_disk = std::fs::read(dir.join("artifacts").join(&spec.path)).unwrap();
        assert_eq!(on_disk, mock_content(spec.seed, spec.size));
        assert_eq!(art.digest().unwrap(), &sha256_hex(&on_disk));
    }

    let seal = std::fs::read_to_string(dir.join("manifest.sha256")).unwrap();
    assert_eq!(parse_seal(&seal).unwrap(), pkg.manifest_sha256);
    let bytes = std::fs::read(dir.join("manifest.json")).unwrap();
    assert_eq!(sha256_hex(&bytes), pkg.manifest_sha256);
    let parsed: Manifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, pkg.manifest);

    let r = verify_package(dir, Some(&pkg.manifest_sha256));
    assert_eq!(r.status, IntegrityStatus::Intact, "{:?}", r.findings);
    assert_eq!(r.artifacts_checked, 4);
    assert_eq!(r.bytes_verified, pkg.manifest.totals.bytes_complete);
}

/// Conferência independente com o `sha256sum` do sistema (coreutils).
#[tokio::test]
async fn package_is_verifiable_with_coreutils_sha256sum() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    for file in ["manifest.sha256", "SHA256SUMS"] {
        let out = match std::process::Command::new("sha256sum")
            .arg("--check")
            .arg("--strict")
            .arg(file)
            .current_dir(&pkg.package_dir)
            .output()
        {
            Ok(o) => o,
            Err(_) => {
                eprintln!("sha256sum indisponível; verificação independente ignorada");
                return;
            }
        };
        assert!(
            out.status.success(),
            "{file}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[tokio::test]
async fn cancellation_is_recorded_and_partial_file_is_not_published() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), true).await;
    assert_eq!(pkg.manifest.outcome, AcquisitionOutcome::Cancelled);
    assert_eq!(pkg.manifest.termination, Termination::Cancelled);
    assert_eq!(pkg.manifest.totals.artifacts_complete, 1);
    assert_eq!(
        pkg.manifest.totals.artifacts_failed, 1,
        "artefato em curso deve ser abortado"
    );
    assert!(pkg.package_dir.join("artifacts/device/info.json").is_file());
    for a in pkg.manifest.artifacts.iter().filter(|a| !a.is_complete()) {
        assert!(matches!(a.status, ArtifactStatus::Failed { .. }));
        assert!(!a
            .stored_path
            .resolve_under(&pkg.package_dir.join("artifacts"))
            .exists());
    }
    let r = verify_package(&pkg.package_dir, Some(&pkg.manifest_sha256));
    assert_eq!(r.status, IntegrityStatus::Intact, "{:?}", r.findings);
}

#[tokio::test]
async fn disconnection_yields_partial_package() {
    let tmp = tempfile::tempdir().unwrap();
    let mut sc = scenario();
    sc.disconnect_after_bytes = Some(1_000 + 1024 * 1024);
    let pkg = acquire(tmp.path(), sc, false).await;
    assert_eq!(pkg.manifest.outcome, AcquisitionOutcome::Partial);
    assert!(matches!(
        pkg.manifest.termination,
        Termination::Interrupted { .. }
    ));
    assert_eq!(pkg.manifest.totals.artifacts_complete, 1);
    assert_eq!(pkg.manifest.totals.artifacts_failed, 1);
    let failed = &pkg.manifest.artifacts[1];
    assert!(!failed.is_complete());
    assert!(failed.size_bytes > 0, "tamanho parcial é registrado");
    assert!(!pkg
        .package_dir
        .join("artifacts/files/sdcard/a.bin")
        .exists());
    assert_eq!(
        verify_package(&pkg.package_dir, None).status,
        IntegrityStatus::Intact
    );
}

// ------------------------------------------------------------ adulteração

#[tokio::test]
async fn flipped_bit_in_artifact_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    let p = pkg.package_dir.join("artifacts/files/sdcard/a.bin");
    let mut b = std::fs::read(&p).unwrap();
    b[1_000_000] ^= 0x01;
    std::fs::write(&p, b).unwrap();

    let r = verify_package(&pkg.package_dir, Some(&pkg.manifest_sha256));
    assert_eq!(r.status, IntegrityStatus::Compromised);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].subject, "artifacts/files/sdcard/a.bin");
    assert!(matches!(
        r.findings[0].kind,
        FindingKind::HashMismatch { .. }
    ));
}

#[tokio::test]
async fn truncated_missing_and_extra_files_are_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    let a = pkg.package_dir.join("artifacts");
    std::fs::OpenOptions::new()
        .write(true)
        .open(a.join("files/c.bin"))
        .unwrap()
        .set_len(10)
        .unwrap();
    std::fs::remove_file(a.join("device/info.json")).unwrap();
    std::fs::write(a.join("files/plantado.bin"), b"x").unwrap();

    let r = verify_package(&pkg.package_dir, None);
    assert_eq!(r.status, IntegrityStatus::Compromised);
    let k = kinds(&r);
    assert!(k.contains(&FindingKind::SizeMismatch {
        expected: 70_000,
        actual: 10
    }));
    assert!(k.contains(&FindingKind::ArtifactMissing));
    assert!(k.contains(&FindingKind::UnexpectedEntry));
}

#[cfg(unix)]
#[tokio::test]
async fn artifact_replaced_by_symlink_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    let p = pkg.package_dir.join("artifacts/files/c.bin");
    let copy = tmp.path().join("copia.bin");
    std::fs::copy(&p, &copy).unwrap();
    std::fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink(&copy, &p).unwrap();
    let r = verify_package(&pkg.package_dir, None);
    assert!(kinds(&r).contains(&FindingKind::NotRegularFile));
}

#[tokio::test]
async fn edited_manifest_breaks_the_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    let p = pkg.package_dir.join("manifest.json");
    let s = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, s.replace("Mandado 123/2025", "Mandado 999/2025")).unwrap();
    let r = verify_package(&pkg.package_dir, None);
    assert_eq!(r.status, IntegrityStatus::Compromised);
    assert!(matches!(
        r.findings[0].kind,
        FindingKind::SealMismatch { .. }
    ));
}

/// Quem reescreve manifesto **e** selo passa pela verificação local, mas
/// não pelo hash registrado no momento da aquisição (banco/auditoria).
#[tokio::test]
async fn resealed_manifest_is_caught_only_by_registered_hash() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    let mut forged = pkg.manifest.clone();
    forged.authorization.reference = "Mandado forjado".into();
    let bytes = forged.to_bytes().unwrap();
    std::fs::write(pkg.package_dir.join("manifest.json"), &bytes).unwrap();
    std::fs::write(
        pkg.package_dir.join("manifest.sha256"),
        seal_line(&sha256_hex(&bytes)),
    )
    .unwrap();

    assert_eq!(
        verify_package(&pkg.package_dir, None).status,
        IntegrityStatus::Intact
    );
    let r = verify_package(&pkg.package_dir, Some(&pkg.manifest_sha256));
    assert_eq!(r.status, IntegrityStatus::Compromised);
    assert!(matches!(
        r.findings[0].kind,
        FindingKind::RegisteredHashMismatch { .. }
    ));
}

#[tokio::test]
async fn path_traversal_injected_in_manifest_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    let p = pkg.package_dir.join("manifest.json");
    let s = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"files/c.bin\"", "\"../../../etc/passwd\"");
    std::fs::write(&p, &s).unwrap();
    std::fs::write(
        pkg.package_dir.join("manifest.sha256"),
        seal_line(&sha256_hex(s.as_bytes())),
    )
    .unwrap();
    let r = verify_package(&pkg.package_dir, None);
    assert_eq!(r.status, IntegrityStatus::Compromised);
    assert!(matches!(
        r.findings[0].kind,
        FindingKind::ManifestInvalid { .. }
    ));
}

#[tokio::test]
async fn sums_file_tampering_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    std::fs::write(pkg.package_dir.join("SHA256SUMS"), "").unwrap();
    let r = verify_package(&pkg.package_dir, None);
    assert_eq!(kinds(&r), vec![FindingKind::SumsMismatch]);
}

#[tokio::test]
async fn unsealed_package_is_incomplete() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = acquire(tmp.path(), scenario(), false).await;
    std::fs::remove_file(pkg.package_dir.join("manifest.sha256")).unwrap();
    assert_eq!(
        verify_package(&pkg.package_dir, None).status,
        IntegrityStatus::Incomplete
    );

    // Pacote abandonado antes de finalize (ex.: queda de energia).
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    let mut w = sink.begin_artifact(spec("x.bin", None)).await.unwrap();
    w.write(b"dados").await.unwrap();
    w.commit().await.unwrap();
    let dir = sink.package_dir().to_path_buf();
    drop(sink);
    let r = verify_package(&dir, None);
    assert_eq!(r.status, IntegrityStatus::Incomplete);
    assert!(kinds(&r).contains(&FindingKind::StagingLeftover));
}

// -------------------------------------------------------- contrato do sink

fn spec(path: &str, expected_size: Option<u64>) -> ArtifactSpec {
    ArtifactSpec {
        stored_path: EvidencePath::new(path).unwrap(),
        source_path: None,
        source_modified: None,
        expected_size,
    }
}

#[tokio::test]
async fn existing_package_directory_is_never_reused() {
    let tmp = tempfile::tempdir().unwrap();
    let acq = AcquisitionId::new();
    let _first = DiskEvidenceSink::create(tmp.path(), acq, SinkOptions::default())
        .await
        .unwrap();
    assert!(
        DiskEvidenceSink::create(tmp.path(), acq, SinkOptions::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn case_insensitive_collision_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    let mut w = sink
        .begin_artifact(spec("Fotos/IMG.jpg", None))
        .await
        .unwrap();
    w.write(b"1").await.unwrap();
    w.commit().await.unwrap();
    assert!(sink
        .begin_artifact(spec("fotos/img.JPG", None))
        .await
        .is_err());
}

#[tokio::test]
async fn size_mismatch_and_limits_fail_without_publishing() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = SinkOptions {
        max_artifact_bytes: 8,
        ..SinkOptions::default()
    };
    let mut sink = DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), opts)
        .await
        .unwrap();

    let mut w = sink.begin_artifact(spec("a.bin", Some(5))).await.unwrap();
    w.write(b"123").await.unwrap();
    assert!(w.commit().await.is_err());

    let mut w = sink.begin_artifact(spec("b.bin", None)).await.unwrap();
    w.write(b"12345678").await.unwrap();
    assert!(w.write(b"9").await.is_err());
    w.abort("limite").await.unwrap();

    assert!(sink.begin_artifact(spec("c.bin", Some(9))).await.is_err());

    let dir = sink.package_dir().join("artifacts");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    assert_eq!(sink.artifacts().len(), 2);
    assert!(sink.artifacts().iter().all(|a| !a.is_complete()));
    let staging = sink.package_dir().join(".staging");
    assert_eq!(
        std::fs::read_dir(staging).unwrap().count(),
        0,
        "temporários removidos"
    );
}

/// Um link simbólico plantado dentro do pacote não desvia a gravação.
#[cfg(unix)]
#[tokio::test]
async fn planted_symlink_in_package_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    std::os::unix::fs::symlink(outside.path(), sink.package_dir().join("artifacts/files")).unwrap();

    let mut w = sink
        .begin_artifact(spec("files/x.bin", None))
        .await
        .unwrap();
    w.write(b"segredo").await.unwrap();
    let e = w.commit().await.unwrap_err();
    assert!(e.to_string().contains("não é um diretório real"), "{e}");
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert!(!sink.artifacts()[0].is_complete());
}

/// O sink nunca produz um manifesto maior do que a verificação aceita:
/// ao atingir o orçamento, novos artefatos são recusados e o pacote selado
/// continua verificável.
#[tokio::test]
async fn manifest_budget_keeps_package_verifiable() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = SinkOptions {
        max_manifest_bytes: 1024 * 1024 + 4 * 1100,
        ..SinkOptions::default()
    };
    let mut sink = DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), opts)
        .await
        .unwrap();
    let mut accepted = 0;
    let mut refused = None;
    for i in 0..10 {
        match sink.begin_artifact(spec(&format!("f{i}.bin"), None)).await {
            Ok(mut w) => {
                w.write(b"x").await.unwrap();
                w.commit().await.unwrap();
                accepted += 1;
            }
            Err(e) => {
                refused = Some(e.to_string());
                break;
            }
        }
    }
    assert!((1..10).contains(&accepted), "aceitos: {accepted}");
    assert!(refused.unwrap().contains("limite do manifesto"));

    let adapter = MockAdapter::new(scenario());
    let pkg = sink
        .finalize(FinalizeInput {
            header: header(&adapter),
            report: AdapterReport::default(),
            termination: Termination::Interrupted {
                reason: "limite do manifesto atingido".into(),
            },
            finished_at: UtcTimestamp::now(),
        })
        .await
        .unwrap();
    assert_eq!(pkg.manifest.outcome, AcquisitionOutcome::Partial);
    let r = verify_package(&pkg.package_dir, Some(&pkg.manifest_sha256));
    assert_eq!(r.status, IntegrityStatus::Intact, "{:?}", r.findings);
}
