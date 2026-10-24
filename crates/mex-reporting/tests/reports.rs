//! Relatórios e exportação, sobre aquisições reais da fixture.

use mex_acquisition::{run_acquisition, AcquisitionPlan, LocalEvidenceImporter};
use mex_core::audit::AuditKind;
use mex_core::cancel::CancellationToken;
use mex_core::capability::CapabilityKind;
use mex_core::ids::{AcquisitionId, AuthorizationId};
use mex_core::integrity::{hash_reader, sha256_hex};
use mex_core::model::{
    Authorization, AuthorizationKind, Case, Device, DeviceObservation, IntegrityStatus, Operator,
    Platform,
};
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use mex_evidence::{verify_package, SinkOptions};
use mex_reporting::{export_package, generate_report, ReportError, ReportRequest};
use mex_storage::Storage;
use std::path::{Path, PathBuf};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/local_import_v1"
);

struct World {
    storage: Storage,
    operator: Operator,
    case: Case,
    authorization: Authorization,
    evidence: tempfile::TempDir,
    out: tempfile::TempDir,
}

async fn world() -> World {
    let storage = Storage::open_in_memory().await.unwrap();
    let t = UtcTimestamp::now();
    let operator =
        Operator::new("Perita Relatora", "0099", "Instituto de Criminalística", t).unwrap();
    storage.register_operator(&operator).await.unwrap();
    let case = Case::new("IP 0500/2025", "Teste de relatórios", operator.id, t).unwrap();
    storage.create_case(&case).await.unwrap();
    let authorization = Authorization {
        id: AuthorizationId::new(),
        case_id: case.id,
        kind: AuthorizationKind::JudicialWarrant,
        kind_detail: None,
        reference: "Mandado 500/2025".into(),
        issuer: "3ª Vara Criminal".into(),
        scope_notes: Some("Dados do backup apreendido".into()),
        document_sha256: Some(sha256_hex(b"documento")),
        recorded_by: operator.id,
        recorded_at: t,
    };
    storage.record_authorization(&authorization).await.unwrap();
    World {
        storage,
        operator,
        case,
        authorization,
        evidence: tempfile::tempdir().unwrap(),
        out: tempfile::tempdir().unwrap(),
    }
}

async fn import(w: &World, source: &Path) -> (AcquisitionId, PathBuf) {
    let device = Device::new(DeviceObservation {
        platform: Platform::Android,
        serial: "R58M000TEST".into(),
        manufacturer: Some("Exemplo".into()),
        model: Some("Modelo Y".into()),
        os_version: Some("13".into()),
        security_patch: None,
        adb_state: None,
        observed_at: UtcTimestamp::now(),
    });
    w.storage
        .register_device(&device, Some(w.case.id), w.operator.id)
        .await
        .unwrap();
    let plan = AcquisitionPlan {
        case: w.case.clone(),
        operator: w.operator.clone(),
        authorization: w.authorization.clone(),
        device,
        capability: CapabilityKind::LocalImport,
        evidence_root: w.evidence.path().to_path_buf(),
        sink_options: SinkOptions::default(),
    };
    let s = run_acquisition(
        &w.storage,
        &LocalEvidenceImporter::new(source),
        plan,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    (s.acquisition_id, s.package.unwrap().package_dir)
}

fn request(w: &World, acq: AcquisitionId) -> ReportRequest {
    ReportRequest {
        acquisition_id: acq,
        case: w.case.clone(),
        operator: w.operator.clone(),
        output_dir: w.out.path().to_path_buf(),
    }
}

fn file_sha(p: &Path) -> String {
    hash_reader(std::fs::File::open(p).unwrap()).unwrap().0.hex
}

// ------------------------------------------------------------ relatório

#[tokio::test]
async fn report_is_emitted_hashed_and_recorded() {
    let w = world().await;
    let (acq, _) = import(&w, Path::new(FIXTURE)).await;
    let r = generate_report(&w.storage, &request(&w, acq))
        .await
        .unwrap();

    // Hash dos arquivos = hash registrado no banco.
    assert_eq!(file_sha(&r.json_path), r.json_sha256.hex);
    assert_eq!(file_sha(&r.html_path), r.html_sha256.hex);
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT format, stored_path, sha256 FROM reports ORDER BY format")
            .fetch_all(w.storage.pool())
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        (
            "html".into(),
            r.html_path.display().to_string(),
            r.html_sha256.hex.clone()
        )
    );
    assert_eq!(
        rows[1],
        (
            "json".into(),
            r.json_path.display().to_string(),
            r.json_sha256.hex.clone()
        )
    );

    // Conteúdo estruturado.
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&r.json_path).unwrap()).unwrap();
    assert_eq!(v["format"], "blackbit-mex/report/v1");
    assert_eq!(v["integrity"]["status"], "intact");
    assert_eq!(v["manifest"]["artifacts"].as_array().unwrap().len(), 5);
    assert_eq!(v["legal"]["stages"].as_array().unwrap().len(), 10);
    assert!(v["software"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["name"] == "schema SQLite"));
    assert!(r.report.custody.chain_intact);

    // A cadeia no relatório termina na verificação feita na emissão; depois
    // vêm os dois eventos `exported` (JSON e HTML).
    let chain = w.storage.load_audit_chain().await.unwrap();
    let n = chain.len();
    assert_eq!(chain[n - 1].kind, AuditKind::Exported);
    assert_eq!(chain[n - 2].kind, AuditKind::Exported);
    assert_eq!(chain[n - 3].kind, AuditKind::IntegrityVerified);
    assert_eq!(
        r.report.custody.chain_head_hash.as_deref(),
        Some(chain[n - 3].entry_hash.as_str())
    );
    assert!(
        chain[n - 1].detail.contains(&r.html_sha256.hex)
            || chain[n - 1].detail.contains(&r.json_sha256.hex)
    );
    w.storage.verify_audit_chain().await.unwrap();

    // Relatórios são imutáveis.
    assert!(sqlx::query("UPDATE reports SET sha256 = ?")
        .bind("00".repeat(32))
        .execute(w.storage.pool())
        .await
        .is_err());
}

#[tokio::test]
async fn html_is_self_contained_and_complete() {
    let w = world().await;
    let (acq, _) = import(&w, Path::new(FIXTURE)).await;
    let r = generate_report(&w.storage, &request(&w, acq))
        .await
        .unwrap();
    let html = std::fs::read_to_string(&r.html_path).unwrap();

    for forbidden in [
        "http://", "https://", "<script", "<link", "src=", "@import", "url(",
    ] {
        assert!(
            !html.contains(forbidden),
            "recurso externo/ativo encontrado: {forbidden}"
        );
    }
    for section in [
        "1. Identificação",
        "2. Autorização",
        "3. Dispositivo e aquisição",
        "4. Versões de software",
        "5. Verificação de integridade",
        "6. Inventário de artefatos",
        "7. Limitações, falhas e operações potencialmente modificadoras",
        "8. Cadeia de custódia",
        "9. Considerações sobre a cadeia de custódia",
    ] {
        assert!(html.contains(section), "seção ausente: {section}");
    }
    assert!(html.contains("ÍNTEGRO"));
    assert!(html.contains("NÃO constitui declaração de conformidade jurídica"));
    for a in &r.report.manifest.as_ref().unwrap().artifacts {
        assert!(html.contains(&a.digest().unwrap().hex));
    }
    assert!(html.contains(r.report.custody.chain_head_hash.as_deref().unwrap()));
    assert_eq!(
        mex_reporting::html::render(&r.report),
        html,
        "renderização determinística"
    );
}

/// Nomes de arquivo hostis vindos da origem são escapados.
#[cfg(unix)]
#[tokio::test]
async fn hostile_names_are_escaped_in_html() {
    let w = world().await;
    let src = tempfile::tempdir().unwrap();
    // Nomes de arquivo não podem conter "/", mas podem conter "<", ">" e aspas.
    std::fs::write(src.path().join("<script>alert(1)<script>.txt"), b"x").unwrap();
    std::fs::write(src.path().join("<img onerror=alert(2) src=x>"), b"y").unwrap();
    std::fs::write(src.path().join("aspas\"&'.txt"), b"z").unwrap();
    let (acq, _) = import(&w, src.path()).await;
    let r = generate_report(&w.storage, &request(&w, acq))
        .await
        .unwrap();
    let html = std::fs::read_to_string(&r.html_path).unwrap();
    assert!(!html.contains("<script>alert"));
    assert!(!html.contains("<img"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;script&gt;.txt"));
    assert!(html.contains("aspas&quot;&amp;&#39;.txt"));
}

#[tokio::test]
async fn compromised_package_is_reported_as_such() {
    let w = world().await;
    let (acq, pkg) = import(&w, Path::new(FIXTURE)).await;
    std::fs::write(
        pkg.join("artifacts/files/sdcard/DCIM/foto_0001.bin"),
        b"alterado\n",
    )
    .unwrap();
    let r = generate_report(&w.storage, &request(&w, acq))
        .await
        .unwrap();
    assert_eq!(r.report.integrity.status, IntegrityStatus::Compromised);
    let html = std::fs::read_to_string(&r.html_path).unwrap();
    assert!(html.contains("COMPROMETIDO"));
    assert!(html.contains("Tamanho divergente"));
    assert!(html.contains("Atenção:</strong> o pacote não está íntegro"));
    let status: String = sqlx::query_scalar(
        "SELECT status FROM integrity_verifications ORDER BY verified_at DESC LIMIT 1",
    )
    .fetch_one(w.storage.pool())
    .await
    .unwrap();
    assert_eq!(status, "compromised");
}

#[tokio::test]
async fn missing_manifest_is_reported_not_hidden() {
    let w = world().await;
    let (acq, pkg) = import(&w, Path::new(FIXTURE)).await;
    std::fs::remove_file(pkg.join("manifest.json")).unwrap();
    let r = generate_report(&w.storage, &request(&w, acq))
        .await
        .unwrap();
    assert_eq!(r.report.integrity.status, IntegrityStatus::Incomplete);
    assert!(r.report.manifest.is_none());
    assert!(r.report.manifest_problem.is_some());
    let html = std::fs::read_to_string(&r.html_path).unwrap();
    assert!(html.contains("Manifesto indisponível"));
    assert!(!html.contains("6. Inventário de artefatos"));
}

#[tokio::test]
async fn report_inside_package_or_for_other_case_is_refused() {
    let w = world().await;
    let (acq, pkg) = import(&w, Path::new(FIXTURE)).await;

    let mut inside = request(&w, acq);
    inside.output_dir = pkg.clone();
    assert!(matches!(
        generate_report(&w.storage, &inside).await,
        Err(ReportError::Domain(MexError::PolicyDenied(_)))
    ));

    let other = Case::new(
        "IP 9999/2025",
        "Outro caso",
        w.operator.id,
        UtcTimestamp::now(),
    )
    .unwrap();
    w.storage.create_case(&other).await.unwrap();
    let mut wrong = request(&w, acq);
    wrong.case = other;
    assert!(generate_report(&w.storage, &wrong).await.is_err());

    // Nenhum arquivo foi gravado e o pacote segue íntegro.
    assert_eq!(std::fs::read_dir(w.out.path()).unwrap().count(), 0);
    let reg = w.storage.registered_package(acq).await.unwrap().unwrap();
    assert_eq!(
        verify_package(&pkg, Some(&reg.manifest_sha256)).status,
        IntegrityStatus::Intact
    );
}

// ------------------------------------------------------------ exportação

#[tokio::test]
async fn export_copies_verifies_and_records() {
    let w = world().await;
    let (acq, _) = import(&w, Path::new(FIXTURE)).await;
    let dest = tempfile::tempdir().unwrap();
    let e = export_package(&w.storage, acq, &w.case, &w.operator, dest.path())
        .await
        .unwrap();

    let final_dir = e.destination.clone().unwrap();
    assert_eq!(
        final_dir,
        dest.path().canonicalize().unwrap().join(acq.to_string())
    );
    assert_eq!(e.record.status, IntegrityStatus::Intact);
    assert_eq!(e.record.files_copied, 8); // 5 artefatos + 3 arquivos de controle
    let reg = w.storage.registered_package(acq).await.unwrap().unwrap();
    assert_eq!(
        verify_package(&final_dir, Some(&reg.manifest_sha256)).status,
        IntegrityStatus::Intact
    );

    // Nenhuma cópia temporária remanescente.
    let names: Vec<String> = std::fs::read_dir(dest.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec![acq.to_string()]);

    // Conferência independente na cópia, com coreutils.
    for f in ["manifest.sha256", "SHA256SUMS"] {
        if let Ok(o) = std::process::Command::new("sha256sum")
            .args(["--check", "--strict", f])
            .current_dir(&final_dir)
            .output()
        {
            assert!(
                o.status.success(),
                "{f}: {}",
                String::from_utf8_lossy(&o.stdout)
            );
        }
    }

    let row: (String, i64) = sqlx::query_as("SELECT status, files_copied FROM evidence_exports")
        .fetch_one(w.storage.pool())
        .await
        .unwrap();
    assert_eq!(row, ("intact".into(), 8));
    let last = w.storage.load_audit_chain().await.unwrap().pop().unwrap();
    assert_eq!(last.kind, AuditKind::Exported);
    assert!(last.detail.contains(&reg.manifest_sha256.hex));

    // Permissões mínimas na cópia (Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o077;
        assert_eq!(mode(&final_dir), 0);
        assert_eq!(mode(&final_dir.join("manifest.json")), 0);
        assert_eq!(
            mode(&final_dir.join("artifacts/files/sdcard/DCIM/foto_0001.bin")),
            0
        );
    }

    // Exportar de novo para o mesmo destino não sobrescreve.
    assert!(
        export_package(&w.storage, acq, &w.case, &w.operator, dest.path())
            .await
            .is_err()
    );
    assert!(sqlx::query("DELETE FROM evidence_exports")
        .execute(w.storage.pool())
        .await
        .is_err());
}

#[tokio::test]
async fn compromised_package_is_not_exported() {
    let w = world().await;
    let (acq, pkg) = import(&w, Path::new(FIXTURE)).await;
    std::fs::write(pkg.join("artifacts/extra.bin"), b"plantado").unwrap();
    let dest = tempfile::tempdir().unwrap();
    let e = export_package(&w.storage, acq, &w.case, &w.operator, dest.path())
        .await
        .unwrap_err();
    assert!(matches!(e, ReportError::Domain(MexError::PolicyDenied(_))));
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
    let last = w.storage.load_audit_chain().await.unwrap().pop().unwrap();
    assert_eq!(last.kind, AuditKind::Error);
    assert!(last.detail.contains("recusada"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_exports")
        .fetch_one(w.storage.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn export_into_the_package_is_refused() {
    let w = world().await;
    let (acq, pkg) = import(&w, Path::new(FIXTURE)).await;
    let inside = pkg.join("artifacts");
    assert!(
        export_package(&w.storage, acq, &w.case, &w.operator, &inside)
            .await
            .is_err()
    );
    let reg = w.storage.registered_package(acq).await.unwrap().unwrap();
    assert_eq!(
        verify_package(&pkg, Some(&reg.manifest_sha256)).status,
        IntegrityStatus::Intact
    );
}
