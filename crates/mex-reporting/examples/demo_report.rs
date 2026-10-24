//! Demonstração: importa a fixture `tests/fixtures/local_import_v1` para um
//! diretório de trabalho e emite o relatório técnico (JSON + HTML).
//!
//! Dados sintéticos; NÃO é evidência real.
//!
//! Uso: cargo run -p mex-reporting --example demo_report -- <diretório-vazio>

use mex_acquisition::{run_acquisition, AcquisitionPlan, LocalEvidenceImporter};
use mex_core::cancel::CancellationToken;
use mex_core::capability::CapabilityKind;
use mex_core::ids::AuthorizationId;
use mex_core::model::{
    Authorization, AuthorizationKind, Case, Device, DeviceObservation, Operator, Platform,
};
use mex_core::timestamp::UtcTimestamp;
use mex_evidence::SinkOptions;
use mex_reporting::{generate_report, ReportRequest};
use mex_storage::Storage;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("informe um diretório de trabalho vazio")?,
    );
    std::fs::create_dir_all(&work)?;
    if std::fs::read_dir(&work)?.next().is_some() {
        return Err("o diretório de trabalho deve estar vazio".into());
    }
    let evidence = work.join("evidencias");
    let reports = work.join("relatorios");
    std::fs::create_dir(&evidence)?;
    std::fs::create_dir(&reports)?;
    let storage = Storage::open(&work.join("mex.db")).await?;

    let t = UtcTimestamp::now();
    let operator = Operator::new(
        "Perito(a) de Demonstração",
        "DEMO-001",
        "Laboratório de Demonstração",
        t,
    )?;
    storage.register_operator(&operator).await?;
    let case = Case::new(
        "DEMO 0001/2025",
        "Demonstração com dados sintéticos",
        operator.id,
        t,
    )?;
    storage.create_case(&case).await?;
    let authorization = Authorization {
        id: AuthorizationId::new(),
        case_id: case.id,
        kind: AuthorizationKind::Other,
        kind_detail: Some("Demonstração — dados sintéticos, sem valor legal".into()),
        reference: "DEMO".into(),
        issuer: "N/A".into(),
        scope_notes: None,
        document_sha256: None,
        recorded_by: operator.id,
        recorded_at: t,
    };
    storage.record_authorization(&authorization).await?;
    let device = Device::new(DeviceObservation {
        platform: Platform::Android,
        serial: "DEMO-SERIAL".into(),
        manufacturer: Some("Fixture".into()),
        model: Some("local_import_v1".into()),
        os_version: None,
        security_patch: None,
        adb_state: None,
        observed_at: UtcTimestamp::now(),
    });
    storage
        .register_device(&device, Some(case.id), operator.id)
        .await?;

    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/local_import_v1");
    let summary = run_acquisition(
        &storage,
        &LocalEvidenceImporter::new(fixture),
        AcquisitionPlan {
            case: case.clone(),
            operator: operator.clone(),
            authorization,
            device,
            capability: CapabilityKind::LocalImport,
            evidence_root: evidence,
            sink_options: SinkOptions::default(),
        },
        &CancellationToken::new(),
    )
    .await?;
    let r = generate_report(
        &storage,
        &ReportRequest {
            acquisition_id: summary.acquisition_id,
            case,
            operator,
            output_dir: reports,
        },
    )
    .await?;
    println!("resultado: {}", summary.outcome.as_str());
    println!("integridade: {}", r.report.integrity.status.as_str());
    println!(
        "HTML: {}  sha256 {}",
        r.html_path.display(),
        r.html_sha256.hex
    );
    println!(
        "JSON: {}  sha256 {}",
        r.json_path.display(),
        r.json_sha256.hex
    );
    Ok(())
}
