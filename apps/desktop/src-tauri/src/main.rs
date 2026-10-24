//! BlackBit MEX — aplicação desktop (Tauri 2).
//!
//! Cada comando é um invólucro fino sobre `mex_app::App`, onde ficam todas
//! as regras (sessão do operador, confirmação, políticas). Nenhum comando
//! acessa o sistema de arquivos ou processos por conta própria.
//!
//! Diretório de dados: `MEX_DATA_DIR`, se definido; senão o diretório de
//! dados do aplicativo do sistema (ex.: `~/.local/share/br.com.blackbit.mex`).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use mex_app::{
    App, AppConfig, AppError, AppInfo, CustodyView, ExportOutput, ImportPreview, ImportRequest,
    MethodPolicy, NewAuthorization, NewCase, NewDevice, NewOperator, ReportOutput, RunView,
};
use mex_core::ids::{AcquisitionId, AuthorizationId, CaseId, DeviceId, OperatorId};
use mex_core::model::{Authorization, Case, Device, Operator};
use std::sync::Arc;
use tauri::{Manager, State};

type S<'a> = State<'a, Arc<App>>;
type R<T> = Result<T, AppError>;

#[tauri::command]
fn app_info(app: S<'_>) -> AppInfo {
    app.info()
}

#[tauri::command]
async fn stats(app: S<'_>) -> R<mex_app::Stats> {
    app.stats().await
}

#[tauri::command]
async fn list_operators(app: S<'_>) -> R<Vec<Operator>> {
    app.list_operators().await
}

#[tauri::command]
async fn register_operator(app: S<'_>, input: NewOperator) -> R<Operator> {
    app.register_operator(input).await
}

#[tauri::command]
async fn select_operator(app: S<'_>, id: OperatorId) -> R<Operator> {
    app.select_operator(id).await
}

#[tauri::command]
fn end_session(app: S<'_>) {
    app.end_session()
}

#[tauri::command]
async fn list_cases(app: S<'_>) -> R<Vec<mex_app::CaseSummary>> {
    app.list_cases().await
}

#[tauri::command]
async fn get_case(app: S<'_>, id: CaseId) -> R<Case> {
    app.get_case(id).await
}

#[tauri::command]
async fn create_case(app: S<'_>, input: NewCase) -> R<Case> {
    app.create_case(input).await
}

#[tauri::command]
async fn list_authorizations(app: S<'_>, case_id: CaseId) -> R<Vec<Authorization>> {
    app.list_authorizations(case_id).await
}

#[tauri::command]
async fn record_authorization(app: S<'_>, input: NewAuthorization) -> R<Authorization> {
    app.record_authorization(input).await
}

#[tauri::command]
async fn list_devices(app: S<'_>) -> R<Vec<Device>> {
    app.list_devices().await
}

#[tauri::command]
async fn get_device(app: S<'_>, id: DeviceId) -> R<Device> {
    app.get_device(id).await
}

#[tauri::command]
async fn register_device(app: S<'_>, input: NewDevice) -> R<Device> {
    app.register_device(input).await
}

#[tauri::command]
async fn preview_import(
    app: S<'_>,
    case_id: CaseId,
    authorization_id: AuthorizationId,
    device_id: DeviceId,
    source_dir: String,
) -> R<ImportPreview> {
    app.preview_import(case_id, authorization_id, device_id, source_dir)
        .await
}

#[tauri::command]
async fn start_import(app: S<'_>, input: ImportRequest) -> R<RunView> {
    app.start_import(input).await
}

#[tauri::command]
fn list_runs(app: S<'_>) -> Vec<RunView> {
    app.list_runs()
}

#[tauri::command]
fn cancel_run(app: S<'_>, acquisition_id: AcquisitionId) -> R<()> {
    app.cancel_run(acquisition_id)
}

#[tauri::command]
async fn list_acquisitions(
    app: S<'_>,
    case_id: Option<CaseId>,
    device_id: Option<DeviceId>,
) -> R<Vec<mex_app::AcquisitionView>> {
    app.list_acquisitions(case_id, device_id).await
}

#[tauri::command]
async fn list_artifacts(
    app: S<'_>,
    acquisition_id: AcquisitionId,
) -> R<Vec<mex_app::ArtifactView>> {
    app.list_artifacts(acquisition_id).await
}

#[tauri::command]
async fn verify(app: S<'_>, acquisition_id: AcquisitionId) -> R<mex_app::VerificationReport> {
    app.verify(acquisition_id).await
}

#[tauri::command]
async fn list_verifications(
    app: S<'_>,
    acquisition_id: AcquisitionId,
) -> R<Vec<mex_app::VerificationView>> {
    app.list_verifications(acquisition_id).await
}

#[tauri::command]
async fn generate_report(app: S<'_>, acquisition_id: AcquisitionId) -> R<ReportOutput> {
    app.generate_report(acquisition_id).await
}

#[tauri::command]
async fn list_reports(app: S<'_>, case_id: CaseId) -> R<Vec<mex_app::ReportView>> {
    app.list_reports(case_id).await
}

#[tauri::command]
async fn export_package(
    app: S<'_>,
    acquisition_id: AcquisitionId,
    dest_dir: String,
) -> R<ExportOutput> {
    app.export(acquisition_id, dest_dir).await
}

#[tauri::command]
async fn list_exports(app: S<'_>, acquisition_id: AcquisitionId) -> R<Vec<mex_app::ExportView>> {
    app.list_exports(acquisition_id).await
}

#[tauri::command]
async fn custody(app: S<'_>, case_id: CaseId) -> R<CustodyView> {
    app.custody(case_id).await
}

#[tauri::command]
fn research_policy(app: S<'_>) -> Vec<MethodPolicy> {
    app.research_policy()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|handle| {
            let data_dir = match std::env::var_os("MEX_DATA_DIR") {
                Some(d) => std::path::PathBuf::from(d),
                None => handle.path().app_data_dir()?,
            };
            tracing::info!(data_dir = %data_dir.display(), "abrindo dados do MEX");
            let app = tauri::async_runtime::block_on(App::open(AppConfig { data_dir }))
                .map_err(|e| format!("não foi possível abrir os dados do MEX: {e}"))?;
            handle.manage(app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            stats,
            list_operators,
            register_operator,
            select_operator,
            end_session,
            list_cases,
            get_case,
            create_case,
            list_authorizations,
            record_authorization,
            list_devices,
            get_device,
            register_device,
            preview_import,
            start_import,
            list_runs,
            cancel_run,
            list_acquisitions,
            list_artifacts,
            verify,
            list_verifications,
            generate_report,
            list_reports,
            export_package,
            list_exports,
            custody,
            research_policy,
        ])
        .run(tauri::generate_context!())
        .expect("falha ao iniciar a aplicação");
}
