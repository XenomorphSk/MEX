//! Emissão do relatório técnico.
//!
//! 1. Confere que a aquisição pertence ao caso.
//! 2. Executa e **registra** uma verificação de integridade do pacote contra
//!    o hash de manifesto registrado na aquisição.
//! 3. Lê o manifesto do pacote (somente leitura, sem seguir links).
//! 4. Verifica a cadeia de auditoria completa e coleta os eventos do caso.
//! 5. Grava `<report_id>.json` e `<report_id>.html` como arquivos novos
//!    (atômicos, sem sobrescrita) fora do pacote.
//! 6. Registra o SHA-256 de cada arquivo no banco, com evento `exported`.

use crate::model::{
    stage_coverage, CustodySection, IntegritySection, LegalSection, ModuleVersion, TechnicalReport,
    LEGAL_NOTICE, REPORT_FORMAT_V1,
};
use crate::ReportError;
use mex_acquisition::verify_acquisition;
use mex_core::audit::verify_chain;
use mex_core::ids::{AcquisitionId, ReportId};
use mex_core::integrity::{sha256_hex, Digest256};
use mex_core::model::{Case, Operator};
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use mex_evidence::verify::MAX_MANIFEST_BYTES;
use mex_evidence::{write_new_file_atomic, Manifest, MANIFEST_FILE};
use mex_storage::reporting::{ReportFormat, ReportRecord};
use mex_storage::Storage;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Pedido de emissão.
#[derive(Debug, Clone)]
pub struct ReportRequest {
    /// Aquisição.
    pub acquisition_id: AcquisitionId,
    /// Caso.
    pub case: Case,
    /// Operador emissor.
    pub operator: Operator,
    /// Diretório onde os arquivos serão gravados (fora do pacote).
    pub output_dir: PathBuf,
}

/// Relatório emitido.
#[derive(Debug, Clone)]
pub struct EmittedReport {
    /// Conteúdo.
    pub report: TechnicalReport,
    /// Arquivo JSON.
    pub json_path: PathBuf,
    /// SHA-256 do JSON.
    pub json_sha256: Digest256,
    /// Arquivo HTML.
    pub html_path: PathBuf,
    /// SHA-256 do HTML.
    pub html_sha256: Digest256,
}

/// Versões dos módulos usados na emissão.
pub fn software_versions() -> Vec<ModuleVersion> {
    let m = |name: &str, version: String| ModuleVersion {
        name: name.into(),
        version,
    };
    vec![
        m("mex-core", mex_core::CORE_VERSION.into()),
        m("mex-evidence", mex_evidence::VERSION.into()),
        m("mex-storage", mex_storage::VERSION.into()),
        m("mex-acquisition", mex_acquisition::VERSION.into()),
        m("mex-reporting", crate::VERSION.into()),
        m("schema SQLite", mex_storage::schema_version().to_string()),
    ]
}

/// Lê e interpreta o manifesto sem seguir links e com limite de tamanho.
fn read_manifest(package: &Path, acquisition_id: AcquisitionId) -> Result<Manifest, String> {
    let p = package.join(MANIFEST_FILE);
    let meta = std::fs::symlink_metadata(&p).map_err(|e| format!("manifesto inacessível: {e}"))?;
    if !meta.file_type().is_file() {
        return Err("manifest.json não é um arquivo regular".into());
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err("manifest.json excede o tamanho máximo".into());
    }
    let mut buf = Vec::new();
    std::fs::File::open(&p)
        .and_then(|f| f.take(MAX_MANIFEST_BYTES).read_to_end(&mut buf))
        .map_err(|e| format!("manifesto ilegível: {e}"))?;
    let m: Manifest =
        serde_json::from_slice(&buf).map_err(|e| format!("manifesto inválido: {e}"))?;
    if m.acquisition_id != acquisition_id {
        return Err(format!(
            "manifesto pertence a outra aquisição ({})",
            m.acquisition_id
        ));
    }
    Ok(m)
}

/// Emite o relatório técnico (JSON + HTML).
pub async fn generate_report(
    storage: &Storage,
    req: &ReportRequest,
) -> Result<EmittedReport, ReportError> {
    if storage.acquisition_case_id(req.acquisition_id).await? != Some(req.case.id) {
        return Err(MexError::InvalidInput(format!(
            "aquisição {} não pertence ao caso {}",
            req.acquisition_id, req.case.number
        ))
        .into());
    }
    let registered = storage
        .registered_package(req.acquisition_id)
        .await?
        .ok_or_else(|| {
            MexError::InvalidInput("aquisição sem pacote de evidências registrado".into())
        })?;
    let package = PathBuf::from(&registered.package_path);

    let out_dir = tokio::fs::canonicalize(&req.output_dir)
        .await
        .map_err(|e| MexError::io(&req.output_dir, e))?;
    if let Ok(pkg) = tokio::fs::canonicalize(&package).await {
        if out_dir.starts_with(&pkg) {
            return Err(MexError::PolicyDenied(
                "relatórios não podem ser gravados dentro do pacote de evidências".into(),
            )
            .into());
        }
    }

    // Verificação registrada (gera evento integrity-verified).
    let verification =
        verify_acquisition(storage, req.acquisition_id, req.case.id, &req.operator).await?;

    let (manifest, manifest_problem) = {
        let pkg = package.clone();
        let acq = req.acquisition_id;
        match tokio::task::spawn_blocking(move || read_manifest(&pkg, acq))
            .await
            .map_err(|e| MexError::Adapter(format!("tarefa de leitura falhou: {e}")))?
        {
            Ok(m) => (Some(m), None),
            Err(p) => (None, Some(p)),
        }
    };

    let chain = storage.load_audit_chain().await?;
    let chain_check = verify_chain(&chain);
    let custody = CustodySection {
        chain_intact: chain_check.is_ok(),
        chain_problem: chain_check.err().map(|e| e.to_string()),
        chain_length: chain.len() as u64,
        chain_head_hash: chain.last().map(|e| e.entry_hash.clone()),
        events: chain
            .into_iter()
            .filter(|e| e.case_id == Some(req.case.id))
            .collect(),
    };

    let report = TechnicalReport {
        format: REPORT_FORMAT_V1,
        report_id: ReportId::new(),
        generated_at: UtcTimestamp::now(),
        generated_by: req.operator.clone(),
        software: software_versions(),
        case: req.case.clone(),
        acquisition_id: req.acquisition_id,
        package_path: registered.package_path.clone(),
        manifest,
        manifest_problem,
        integrity: IntegritySection {
            status: verification.status,
            registered_manifest_sha256: registered.manifest_sha256.clone(),
            computed_manifest_sha256: verification.manifest_sha256.clone(),
            artifacts_checked: verification.artifacts_checked,
            bytes_verified: verification.bytes_verified,
            findings: verification.findings.clone(),
            verified_at: verification.verified_at,
        },
        custody,
        legal: LegalSection {
            notice: LEGAL_NOTICE,
            stages: stage_coverage(),
        },
    };

    let json = report.to_json_bytes();
    let html = crate::html::render(&report).into_bytes();
    let json_sha256 = sha256_hex(&json);
    let html_sha256 = sha256_hex(&html);
    let json_path =
        write_new_file_atomic(&out_dir, &format!("{}.json", report.report_id), &json).await?;
    let html_path =
        write_new_file_atomic(&out_dir, &format!("{}.html", report.report_id), &html).await?;

    for (format, path, sha) in [
        (ReportFormat::Json, &json_path, &json_sha256),
        (ReportFormat::Html, &html_path, &html_sha256),
    ] {
        storage
            .record_report(&ReportRecord {
                report_id: report.report_id,
                file_id: ReportId::new(),
                case_id: req.case.id,
                acquisition_id: req.acquisition_id,
                format,
                stored_path: path.display().to_string(),
                sha256: sha.clone(),
                generated_by: req.operator.id,
                generated_at: report.generated_at,
            })
            .await?;
    }
    tracing::info!(report = %report.report_id, status = report.integrity.status.as_str(), "relatório emitido");
    Ok(EmittedReport {
        report,
        json_path,
        json_sha256,
        html_path,
        html_sha256,
    })
}
