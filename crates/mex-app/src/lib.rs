//! # mex-app
//!
//! Camada de serviço da aplicação desktop do BlackBit MEX. Não depende do
//! Tauri: os comandos da interface são invólucros finos sobre [`App`], o que
//! permite testar todo o fluxo com `cargo test`.
//!
//! Regras aplicadas aqui (além das já impostas pelos crates de domínio):
//! - toda operação que altera dados exige um **operador identificado** na
//!   sessão;
//! - a importação exige **confirmação explícita do operador** e uma
//!   autorização do mesmo caso;
//! - dispositivos `simulated` não podem ser cadastrados pela interface;
//! - aquisições que ficaram abertas (aplicativo encerrado durante a
//!   execução) são encerradas como `failed` na abertura.

mod error;

pub use error::{AppError, AppResult};
pub use mex_evidence::VerificationReport;
pub use mex_storage::query::{
    AcquisitionView, ArtifactView, CaseSummary, ExportView, ReportView, Stats, VerificationView,
};

use mex_acquisition::{run_acquisition_as, AcquisitionPlan, LocalEvidenceImporter};
use mex_core::audit::{verify_chain, AuditEvent};
use mex_core::cancel::CancellationToken;
use mex_core::capability::{Capability, CapabilityKind};
use mex_core::ids::{AcquisitionId, AuthorizationId, CaseId, DeviceId, OperatorId};
use mex_core::integrity::{hash_reader, Digest256};
use mex_core::model::{
    optional_text, required_text, Authorization, AuthorizationKind, Case, Device,
    DeviceObservation, Operator, Platform, MAX_LONG_TEXT, MAX_SHORT_TEXT,
};
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{AcquisitionAdapter, AdapterDescriptor, CapabilityResolver};
use mex_core::MexError;
use mex_evidence::SinkOptions;
use mex_reporting::{export_package, generate_report, ReportRequest};
use mex_research::{case_usage, CaseUsage, MethodStatus};
use mex_storage::Storage;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

/// Versão deste módulo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Diretórios da aplicação.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Diretório de dados (banco, evidências, relatórios).
    pub data_dir: PathBuf,
}

/// Informações exibidas em Configurações.
#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    /// Diretório de dados.
    pub data_dir: String,
    /// Arquivo do banco.
    pub database: String,
    /// Raiz dos pacotes de evidência.
    pub evidence_root: String,
    /// Diretório dos relatórios.
    pub reports_root: String,
    /// Versões.
    pub versions: Vec<(String, String)>,
    /// Operador da sessão.
    pub session: Option<Operator>,
    /// Aquisições encerradas como interrompidas na abertura.
    pub recovered_on_open: usize,
}

/// Novo operador.
#[derive(Debug, Clone, Deserialize)]
pub struct NewOperator {
    /// Nome completo.
    pub full_name: String,
    /// Matrícula.
    pub badge: String,
    /// Organização.
    pub organization: String,
}

/// Novo caso.
#[derive(Debug, Clone, Deserialize)]
pub struct NewCase {
    /// Número do procedimento.
    pub number: String,
    /// Título.
    pub title: String,
}

/// Nova autorização.
#[derive(Debug, Clone, Deserialize)]
pub struct NewAuthorization {
    /// Caso.
    pub case_id: CaseId,
    /// Natureza.
    pub kind: AuthorizationKind,
    /// Descrição da base legal (obrigatória para `other`).
    pub kind_detail: Option<String>,
    /// Número/identificação do documento.
    pub reference: String,
    /// Autoridade emissora.
    pub issuer: String,
    /// Escopo/observações.
    pub scope_notes: Option<String>,
    /// Cópia digital do documento: apenas o SHA-256 é registrado.
    pub document_path: Option<String>,
}

/// Novo dispositivo (cadastro manual).
#[derive(Debug, Clone, Deserialize)]
pub struct NewDevice {
    /// Caso relacionado (para a auditoria).
    pub case_id: Option<CaseId>,
    /// Plataforma.
    pub platform: Platform,
    /// Serial.
    pub serial: String,
    /// Fabricante.
    pub manufacturer: Option<String>,
    /// Modelo.
    pub model: Option<String>,
    /// Versão do sistema.
    pub os_version: Option<String>,
    /// Patch de segurança.
    pub security_patch: Option<String>,
}

/// Pedido de importação.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportRequest {
    /// Caso.
    pub case_id: CaseId,
    /// Autorização invocada.
    pub authorization_id: AuthorizationId,
    /// Dispositivo de origem do material.
    pub device_id: DeviceId,
    /// Diretório de origem.
    pub source_dir: String,
    /// Confirmação explícita do operador.
    pub operator_confirmed: bool,
}

/// O que o assistente mostra antes da confirmação.
#[derive(Debug, Clone, Serialize)]
pub struct ImportPreview {
    /// Caso.
    pub case: Case,
    /// Autorização.
    pub authorization: Authorization,
    /// Dispositivo.
    pub device: Device,
    /// Método.
    pub adapter: AdapterDescriptor,
    /// Capacidade resolvida para este dispositivo e origem.
    pub capability: Capability,
    /// Diretório de origem.
    pub source_dir: String,
    /// Onde o pacote será criado.
    pub evidence_root: String,
}

/// Situação de uma execução iniciada nesta sessão.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum RunStatus {
    /// Em execução.
    Running,
    /// Terminou (qualquer resultado).
    Finished {
        /// Resultado.
        outcome: String,
        /// Motivo, quando não completa.
        reason: Option<String>,
    },
    /// Recusada ou falhou antes/fora da aquisição.
    Error {
        /// Mensagem.
        message: String,
    },
}

/// Execução iniciada nesta sessão do aplicativo.
#[derive(Debug, Clone, Serialize)]
pub struct RunView {
    /// Aquisição (também identifica a execução).
    pub acquisition_id: AcquisitionId,
    /// Caso.
    pub case_id: CaseId,
    /// Origem.
    pub source_dir: String,
    /// Início.
    pub started_at: UtcTimestamp,
    /// Fim.
    pub finished_at: Option<UtcTimestamp>,
    /// Cancelamento solicitado.
    pub cancel_requested: bool,
    /// Situação.
    pub status: RunStatus,
}

struct Run {
    view: RunView,
    cancel: CancellationToken,
}

/// Resultado da cadeia de custódia de um caso.
#[derive(Debug, Clone, Serialize)]
pub struct CustodyView {
    /// Eventos do caso.
    pub events: Vec<AuditEvent>,
    /// Cadeia completa íntegra.
    pub chain_intact: bool,
    /// Primeira divergência.
    pub chain_problem: Option<String>,
    /// Comprimento da cadeia completa.
    pub chain_length: u64,
    /// Hash do último evento.
    pub chain_head_hash: Option<String>,
}

/// Política de uso de métodos de pesquisa (informativo).
#[derive(Debug, Clone, Serialize)]
pub struct MethodPolicy {
    /// Estado.
    pub status: &'static str,
    /// Permitido em caso real.
    pub allowed_in_case: bool,
    /// Explicação.
    pub reason: Option<String>,
}

/// Relatório emitido.
#[derive(Debug, Clone, Serialize)]
pub struct ReportOutput {
    /// Integridade na emissão.
    pub integrity: String,
    /// HTML.
    pub html_path: String,
    /// SHA-256 do HTML.
    pub html_sha256: String,
    /// JSON.
    pub json_path: String,
    /// SHA-256 do JSON.
    pub json_sha256: String,
}

/// Exportação concluída.
#[derive(Debug, Clone, Serialize)]
pub struct ExportOutput {
    /// Resultado da verificação da cópia.
    pub status: String,
    /// Diretório final (ausente se a cópia foi descartada).
    pub destination: Option<String>,
    /// Arquivos.
    pub files_copied: u64,
    /// Bytes.
    pub bytes_copied: u64,
}

/// Aplicação.
pub struct App {
    storage: Storage,
    config: AppConfig,
    evidence_root: PathBuf,
    reports_root: PathBuf,
    session: RwLock<Option<Operator>>,
    runs: Mutex<Vec<Run>>,
    recovered_on_open: usize,
}

const INTERRUPTED_REASON: &str =
    "aplicativo encerrado durante a execução; pacote não selado (se existir, será classificado como incompleto)";

impl App {
    /// Abre (ou cria) os diretórios e o banco, e encerra aquisições
    /// interrompidas de sessões anteriores.
    pub async fn open(config: AppConfig) -> AppResult<Arc<Self>> {
        let evidence_root = config.data_dir.join("evidencias");
        let reports_root = config.data_dir.join("relatorios");
        for d in [&config.data_dir, &evidence_root, &reports_root] {
            std::fs::create_dir_all(d).map_err(|e| MexError::io(d, e))?;
            restrict_dir(d);
        }
        let storage = Storage::open(&config.data_dir.join("mex.db")).await?;
        let open = storage.open_acquisitions().await?;
        for a in &open {
            storage
                .close_interrupted_acquisition(a, INTERRUPTED_REASON)
                .await?;
        }
        if !open.is_empty() {
            tracing::warn!(
                n = open.len(),
                "aquisições interrompidas encerradas como failed"
            );
        }
        Ok(Arc::new(Self {
            storage,
            config,
            evidence_root,
            reports_root,
            session: RwLock::new(None),
            runs: Mutex::new(Vec::new()),
            recovered_on_open: open.len(),
        }))
    }

    /// Acesso ao banco (somente para testes e diagnóstico).
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    fn operator(&self) -> AppResult<Operator> {
        self.session
            .read()
            .expect("lock de sessão")
            .clone()
            .ok_or_else(|| AppError::session("nenhum operador identificado nesta sessão"))
    }

    // ------------------------------------------------------------ sessão

    /// Informações gerais.
    pub fn info(&self) -> AppInfo {
        AppInfo {
            data_dir: self.config.data_dir.display().to_string(),
            database: self.config.data_dir.join("mex.db").display().to_string(),
            evidence_root: self.evidence_root.display().to_string(),
            reports_root: self.reports_root.display().to_string(),
            versions: vec![
                ("mex-app".into(), VERSION.into()),
                ("mex-core".into(), mex_core::CORE_VERSION.into()),
                ("mex-evidence".into(), mex_evidence::VERSION.into()),
                ("mex-storage".into(), mex_storage::VERSION.into()),
                ("mex-acquisition".into(), mex_acquisition::VERSION.into()),
                ("mex-reporting".into(), mex_reporting::VERSION.into()),
                (
                    "schema SQLite".into(),
                    mex_storage::schema_version().to_string(),
                ),
            ],
            session: self.session.read().expect("lock de sessão").clone(),
            recovered_on_open: self.recovered_on_open,
        }
    }

    /// Operadores cadastrados.
    pub async fn list_operators(&self) -> AppResult<Vec<Operator>> {
        Ok(self.storage.list_operators().await?)
    }

    /// Cadastra um operador (não altera a sessão).
    pub async fn register_operator(&self, input: NewOperator) -> AppResult<Operator> {
        let op = Operator::new(
            &input.full_name,
            &input.badge,
            &input.organization,
            UtcTimestamp::now(),
        )?;
        self.storage.register_operator(&op).await?;
        Ok(op)
    }

    /// Identifica o operador da sessão.
    pub async fn select_operator(&self, id: OperatorId) -> AppResult<Operator> {
        let op = self
            .storage
            .get_operator(id)
            .await?
            .ok_or_else(|| AppError::not_found("operador"))?;
        *self.session.write().expect("lock de sessão") = Some(op.clone());
        Ok(op)
    }

    /// Encerra a sessão.
    pub fn end_session(&self) {
        *self.session.write().expect("lock de sessão") = None;
    }

    // ------------------------------------------------------- casos

    /// Contadores gerais.
    pub async fn stats(&self) -> AppResult<Stats> {
        Ok(self.storage.stats().await?)
    }

    /// Casos.
    pub async fn list_cases(&self) -> AppResult<Vec<CaseSummary>> {
        Ok(self.storage.list_cases().await?)
    }

    /// Caso.
    pub async fn get_case(&self, id: CaseId) -> AppResult<Case> {
        self.storage
            .get_case(id)
            .await?
            .ok_or_else(|| AppError::not_found("caso"))
    }

    /// Cria um caso.
    pub async fn create_case(&self, input: NewCase) -> AppResult<Case> {
        let op = self.operator()?;
        let case = Case::new(&input.number, &input.title, op.id, UtcTimestamp::now())?;
        self.storage.create_case(&case).await?;
        Ok(case)
    }

    /// Autorizações do caso.
    pub async fn list_authorizations(&self, case_id: CaseId) -> AppResult<Vec<Authorization>> {
        Ok(self.storage.list_authorizations(case_id).await?)
    }

    /// Registra uma autorização. Se um documento for indicado, apenas o seu
    /// SHA-256 é registrado (o arquivo não é copiado nem alterado).
    pub async fn record_authorization(&self, input: NewAuthorization) -> AppResult<Authorization> {
        let op = self.operator()?;
        self.get_case(input.case_id).await?;
        let kind_detail = optional_text(
            "descrição da base legal",
            input.kind_detail.as_deref(),
            MAX_SHORT_TEXT,
        )?;
        if input.kind == AuthorizationKind::Other && kind_detail.is_none() {
            return Err(MexError::InvalidInput(
                "autorização do tipo 'outra' exige a descrição da base legal".into(),
            )
            .into());
        }
        let document_sha256 = match input
            .document_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            None => None,
            Some(p) => Some(hash_document(Path::new(p)).await?),
        };
        let a = Authorization {
            id: AuthorizationId::new(),
            case_id: input.case_id,
            kind: input.kind,
            kind_detail,
            reference: required_text("referência", &input.reference, MAX_SHORT_TEXT)?,
            issuer: required_text("autoridade emissora", &input.issuer, MAX_SHORT_TEXT)?,
            scope_notes: optional_text("escopo", input.scope_notes.as_deref(), MAX_LONG_TEXT)?,
            document_sha256,
            recorded_by: op.id,
            recorded_at: UtcTimestamp::now(),
        };
        self.storage.record_authorization(&a).await?;
        Ok(a)
    }

    // ------------------------------------------------- dispositivos

    /// Inventário.
    pub async fn list_devices(&self) -> AppResult<Vec<Device>> {
        Ok(self.storage.list_devices().await?)
    }

    /// Dispositivo.
    pub async fn get_device(&self, id: DeviceId) -> AppResult<Device> {
        self.storage
            .get_device(id)
            .await?
            .ok_or_else(|| AppError::not_found("dispositivo"))
    }

    /// Cadastro manual (identificação informada pelo operador).
    pub async fn register_device(&self, input: NewDevice) -> AppResult<Device> {
        let op = self.operator()?;
        if input.platform == Platform::Simulated {
            return Err(MexError::PolicyDenied(
                "dispositivos simulados não podem ser cadastrados".into(),
            )
            .into());
        }
        if let Some(c) = input.case_id {
            self.get_case(c).await?;
        }
        let o = |f, v: Option<String>| optional_text(f, v.as_deref(), MAX_SHORT_TEXT);
        let device = Device::new(DeviceObservation {
            platform: input.platform,
            serial: required_text("serial", &input.serial, MAX_SHORT_TEXT)?,
            manufacturer: o("fabricante", input.manufacturer)?,
            model: o("modelo", input.model)?,
            os_version: o("versão do sistema", input.os_version)?,
            security_patch: o("patch de segurança", input.security_patch)?,
            adb_state: None,
            observed_at: UtcTimestamp::now(),
        });
        self.storage
            .register_device(&device, input.case_id, op.id)
            .await?;
        Ok(device)
    }

    // ---------------------------------------------------- importação

    async fn load_import(
        &self,
        case_id: CaseId,
        auth_id: AuthorizationId,
        device_id: DeviceId,
    ) -> AppResult<(Case, Authorization, Device)> {
        let case = self.get_case(case_id).await?;
        let auth = self
            .storage
            .get_authorization(auth_id)
            .await?
            .ok_or_else(|| AppError::not_found("autorização"))?;
        if auth.case_id != case.id {
            return Err(MexError::PolicyDenied(
                "a autorização selecionada não pertence ao caso".into(),
            )
            .into());
        }
        let device = self.get_device(device_id).await?;
        Ok((case, auth, device))
    }

    /// Prévia exibida pelo assistente antes da confirmação.
    pub async fn preview_import(
        &self,
        case_id: CaseId,
        authorization_id: AuthorizationId,
        device_id: DeviceId,
        source_dir: String,
    ) -> AppResult<ImportPreview> {
        let (case, authorization, device) = self
            .load_import(case_id, authorization_id, device_id)
            .await?;
        let importer = LocalEvidenceImporter::new(&source_dir);
        let capability = importer
            .resolve(&device.observed)
            .into_iter()
            .find(|c| c.kind == CapabilityKind::LocalImport)
            .ok_or_else(|| AppError::internal("importador não declarou a capacidade"))?;
        Ok(ImportPreview {
            case,
            authorization,
            device,
            adapter: importer.descriptor(),
            capability,
            source_dir,
            evidence_root: self.evidence_root.display().to_string(),
        })
    }

    /// Inicia uma importação em segundo plano.
    pub async fn start_import(self: &Arc<Self>, req: ImportRequest) -> AppResult<RunView> {
        let operator = self.operator()?;
        if !req.operator_confirmed {
            return Err(MexError::PolicyDenied(
                "a importação exige confirmação explícita do operador".into(),
            )
            .into());
        }
        let preview = self
            .preview_import(
                req.case_id,
                req.authorization_id,
                req.device_id,
                req.source_dir.clone(),
            )
            .await?;
        if !preview.capability.is_available() {
            return Err(MexError::PolicyDenied(format!(
                "importação indisponível: {:?}",
                preview.capability.availability
            ))
            .into());
        }

        let acquisition_id = AcquisitionId::new();
        let cancel = CancellationToken::new();
        let view = RunView {
            acquisition_id,
            case_id: req.case_id,
            source_dir: req.source_dir.clone(),
            started_at: UtcTimestamp::now(),
            finished_at: None,
            cancel_requested: false,
            status: RunStatus::Running,
        };
        self.runs.lock().expect("lock de execuções").push(Run {
            view: view.clone(),
            cancel: cancel.clone(),
        });

        let plan = AcquisitionPlan {
            case: preview.case,
            operator,
            authorization: preview.authorization,
            device: preview.device,
            capability: CapabilityKind::LocalImport,
            evidence_root: self.evidence_root.clone(),
            sink_options: SinkOptions::default(),
        };
        let app = Arc::clone(self);
        let source = req.source_dir;
        tokio::spawn(async move {
            let importer = LocalEvidenceImporter::new(source);
            let result =
                run_acquisition_as(&app.storage, &importer, plan, &cancel, acquisition_id).await;
            let status = match result {
                Ok(s) => RunStatus::Finished {
                    outcome: s.outcome.as_str().into(),
                    reason: s.reason,
                },
                Err(e) => RunStatus::Error {
                    message: e.to_string(),
                },
            };
            let mut runs = app.runs.lock().expect("lock de execuções");
            if let Some(r) = runs
                .iter_mut()
                .find(|r| r.view.acquisition_id == acquisition_id)
            {
                r.view.status = status;
                r.view.finished_at = Some(UtcTimestamp::now());
            }
        });
        Ok(view)
    }

    /// Execuções iniciadas nesta sessão, mais recentes primeiro.
    pub fn list_runs(&self) -> Vec<RunView> {
        let runs = self.runs.lock().expect("lock de execuções");
        runs.iter().rev().map(|r| r.view.clone()).collect()
    }

    /// Solicita cancelamento cooperativo.
    pub fn cancel_run(&self, acquisition_id: AcquisitionId) -> AppResult<()> {
        self.operator()?;
        let mut runs = self.runs.lock().expect("lock de execuções");
        let r = runs
            .iter_mut()
            .find(|r| r.view.acquisition_id == acquisition_id)
            .ok_or_else(|| AppError::not_found("execução"))?;
        if !matches!(r.view.status, RunStatus::Running) {
            return Err(MexError::InvalidInput("a execução já terminou".into()).into());
        }
        r.cancel.cancel();
        r.view.cancel_requested = true;
        Ok(())
    }

    // ----------------------------------------------- evidências

    /// Aquisições (filtros opcionais).
    pub async fn list_acquisitions(
        &self,
        case_id: Option<CaseId>,
        device_id: Option<DeviceId>,
    ) -> AppResult<Vec<AcquisitionView>> {
        Ok(self.storage.list_acquisitions(case_id, device_id).await?)
    }

    /// Artefatos.
    pub async fn list_artifacts(
        &self,
        acquisition_id: AcquisitionId,
    ) -> AppResult<Vec<ArtifactView>> {
        Ok(self.storage.list_artifacts(acquisition_id).await?)
    }

    async fn case_of(&self, acquisition_id: AcquisitionId) -> AppResult<Case> {
        let case_id = self
            .storage
            .acquisition_case_id(acquisition_id)
            .await?
            .ok_or_else(|| AppError::not_found("aquisição"))?;
        self.get_case(case_id).await
    }

    /// Verifica e registra a integridade do pacote.
    pub async fn verify(&self, acquisition_id: AcquisitionId) -> AppResult<VerificationReport> {
        let op = self.operator()?;
        let case = self.case_of(acquisition_id).await?;
        Ok(
            mex_acquisition::verify_acquisition(&self.storage, acquisition_id, case.id, &op)
                .await?,
        )
    }

    /// Histórico de verificações.
    pub async fn list_verifications(
        &self,
        acquisition_id: AcquisitionId,
    ) -> AppResult<Vec<VerificationView>> {
        Ok(self.storage.list_verifications(acquisition_id).await?)
    }

    /// Emite o relatório técnico.
    pub async fn generate_report(&self, acquisition_id: AcquisitionId) -> AppResult<ReportOutput> {
        let op = self.operator()?;
        let case = self.case_of(acquisition_id).await?;
        let r = generate_report(
            &self.storage,
            &ReportRequest {
                acquisition_id,
                case,
                operator: op,
                output_dir: self.reports_root.clone(),
            },
        )
        .await?;
        Ok(ReportOutput {
            integrity: r.report.integrity.status.as_str().into(),
            html_path: r.html_path.display().to_string(),
            html_sha256: r.html_sha256.hex,
            json_path: r.json_path.display().to_string(),
            json_sha256: r.json_sha256.hex,
        })
    }

    /// Relatórios do caso.
    pub async fn list_reports(&self, case_id: CaseId) -> AppResult<Vec<ReportView>> {
        Ok(self.storage.list_reports(case_id).await?)
    }

    /// Exporta o pacote para `dest_dir/<acquisition_id>`.
    pub async fn export(
        &self,
        acquisition_id: AcquisitionId,
        dest_dir: String,
    ) -> AppResult<ExportOutput> {
        let op = self.operator()?;
        let case = self.case_of(acquisition_id).await?;
        let e = export_package(
            &self.storage,
            acquisition_id,
            &case,
            &op,
            Path::new(&dest_dir),
        )
        .await?;
        Ok(ExportOutput {
            status: e.record.status.as_str().into(),
            destination: e.destination.map(|d| d.display().to_string()),
            files_copied: e.record.files_copied,
            bytes_copied: e.record.bytes_copied,
        })
    }

    /// Exportações da aquisição.
    pub async fn list_exports(&self, acquisition_id: AcquisitionId) -> AppResult<Vec<ExportView>> {
        Ok(self.storage.list_exports(acquisition_id).await?)
    }

    /// Cadeia de custódia do caso, com verificação da cadeia completa.
    pub async fn custody(&self, case_id: CaseId) -> AppResult<CustodyView> {
        let chain = self.storage.load_audit_chain().await?;
        let check = verify_chain(&chain);
        Ok(CustodyView {
            chain_intact: check.is_ok(),
            chain_problem: check.err().map(|e| e.to_string()),
            chain_length: chain.len() as u64,
            chain_head_hash: chain.last().map(|e| e.entry_hash.clone()),
            events: chain
                .into_iter()
                .filter(|e| e.case_id == Some(case_id))
                .collect(),
        })
    }

    /// Política de uso de métodos de pesquisa em casos reais.
    pub fn research_policy(&self) -> Vec<MethodPolicy> {
        MethodStatus::ALL
            .into_iter()
            .map(|s| match case_usage(s) {
                CaseUsage::Allowed => MethodPolicy {
                    status: s.as_str(),
                    allowed_in_case: true,
                    reason: None,
                },
                CaseUsage::Denied { reason } => MethodPolicy {
                    status: s.as_str(),
                    allowed_in_case: false,
                    reason: Some(reason),
                },
            })
            .collect()
    }
}

/// Permissões mínimas (`0700`) nos diretórios de dados. Em sistemas de
/// arquivos sem permissões Unix (FAT/exFAT) a tentativa falha e é registrada
/// em log: nesse caso o controle de acesso depende da montagem da mídia.
fn restrict_dir(d: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(dir = %d.display(), error = %e, "não foi possível restringir permissões do diretório");
        }
    }
    #[cfg(not(unix))]
    let _ = d;
}

/// SHA-256 de um documento (arquivo regular), lido em streaming.
async fn hash_document(path: &Path) -> AppResult<Digest256> {
    let p = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&p).map_err(|e| MexError::io(&p, e))?;
        if !meta.is_file() {
            return Err(MexError::InvalidInput(format!(
                "{} não é um arquivo",
                p.display()
            )));
        }
        std::fs::File::open(&p)
            .and_then(hash_reader)
            .map(|(d, _)| d)
            .map_err(|e| MexError::io(&p, e))
    })
    .await
    .map_err(|e| AppError::internal(format!("tarefa de hash falhou: {e}")))?
    .map_err(Into::into)
}
