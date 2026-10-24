//! Motor de aquisição: conduz um job do início ao selo do pacote.
//!
//! Sequência (cada passo persistido e auditado por `mex-storage`):
//!
//! 1. Pré-condições de política — autorização do mesmo caso, capacidade
//!    operacional, adaptador compatível com a plataforma. Recusa ⇒ evento
//!    `error` e nenhuma aquisição criada.
//! 2. `acquisition-started`; job `created → validating`.
//! 3. Resolução de capacidade **para este dispositivo**; indisponível ⇒
//!    `failed` sem pacote.
//! 4. `ready → running`; criação do pacote; execução do adaptador.
//! 5. Contadores do job a partir do sink; `finalizing` (ou `cancelled`).
//! 6. Selo do pacote; registro dos artefatos; estado terminal;
//!    `acquisition-finished` com o SHA-256 do manifesto.
//!
//! Uma vez registrada, a aquisição **sempre** é finalizada no banco, mesmo
//! em erro. O resultado nunca vem do adaptador: é derivado pelo sink.

use mex_core::audit::{AuditDraft, AuditKind};
use mex_core::cancel::CancellationToken;
use mex_core::capability::CapabilityKind;
use mex_core::ids::AcquisitionId;
use mex_core::job::AcquisitionJob;
use mex_core::model::{
    Acquisition, AcquisitionOutcome, ArtifactFailure, Authorization, Case, Device, Operator,
};
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{AcquisitionAdapter, AcquisitionRequest, AdapterReport, EvidenceSink};
use mex_core::MexError;
use mex_evidence::{
    verify_package, AdapterRecord, DiskEvidenceSink, FinalizeInput, ManifestHeader, SealedPackage,
    SinkOptions, Termination, VerificationReport,
};
use mex_storage::repo::{AcquisitionFinish, VerificationRecord};
use mex_storage::{Storage, StorageError};
use std::path::PathBuf;
use thiserror::Error;

/// Erros do motor.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Recusa de domínio/política (nenhuma aquisição foi criada).
    #[error(transparent)]
    Domain(#[from] MexError),
    /// Falha de persistência.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Resultado do motor.
pub type EngineResult<T> = std::result::Result<T, EngineError>;

/// O que executar.
#[derive(Debug, Clone)]
pub struct AcquisitionPlan {
    /// Caso (já registrado).
    pub case: Case,
    /// Operador executor (já registrado).
    pub operator: Operator,
    /// Autorização (já registrada, do mesmo caso).
    pub authorization: Authorization,
    /// Dispositivo (já registrado).
    pub device: Device,
    /// Capacidade a exercer.
    pub capability: CapabilityKind,
    /// Diretório raiz onde o pacote será criado.
    pub evidence_root: PathBuf,
    /// Opções do sink.
    pub sink_options: SinkOptions,
}

/// Resumo de uma execução.
#[derive(Debug, Clone)]
pub struct AcquisitionSummary {
    /// Aquisição registrada.
    pub acquisition_id: AcquisitionId,
    /// Resultado.
    pub outcome: AcquisitionOutcome,
    /// Job no estado final.
    pub job: AcquisitionJob,
    /// Pacote selado, se a execução chegou a produzir um.
    pub package: Option<SealedPackage>,
    /// Motivo, quando o resultado não é `Complete`.
    pub reason: Option<String>,
}

struct Run<'a> {
    storage: &'a Storage,
    plan: &'a AcquisitionPlan,
    acquisition_id: AcquisitionId,
    job: AcquisitionJob,
}

impl Run<'_> {
    async fn step(&mut self, to: JobState, reason: Option<&str>) -> EngineResult<()> {
        self.job.transition(to, reason, UtcTimestamp::now())?;
        self.storage
            .save_job(&self.job, self.plan.case.id, self.plan.operator.id)
            .await?;
        Ok(())
    }

    async fn audit(&self, kind: AuditKind, detail: String) -> EngineResult<()> {
        self.storage
            .append_audit_event(
                AuditDraft {
                    case_id: Some(self.plan.case.id),
                    operator_id: Some(self.plan.operator.id),
                    kind,
                    detail,
                },
                UtcTimestamp::now(),
            )
            .await?;
        Ok(())
    }

    /// Encerra sem pacote (falha antes de gravar evidência).
    async fn end_without_package(
        mut self,
        terminal: JobState,
        outcome: AcquisitionOutcome,
        reason: String,
    ) -> EngineResult<AcquisitionSummary> {
        self.step(terminal, Some(&reason)).await?;
        self.storage
            .finish_acquisition(&AcquisitionFinish {
                acquisition_id: self.acquisition_id,
                case_id: self.plan.case.id,
                operator_id: self.plan.operator.id,
                outcome,
                limitations: vec![reason.clone()],
                finished_at: UtcTimestamp::now(),
                package_path: None,
                manifest_sha256: None,
            })
            .await?;
        Ok(AcquisitionSummary {
            acquisition_id: self.acquisition_id,
            outcome,
            job: self.job,
            package: None,
            reason: Some(reason),
        })
    }
}

/// Executa uma aquisição completa.
pub async fn run_acquisition(
    storage: &Storage,
    adapter: &dyn AcquisitionAdapter,
    plan: AcquisitionPlan,
    cancel: &CancellationToken,
) -> EngineResult<AcquisitionSummary> {
    run_acquisition_as(storage, adapter, plan, cancel, AcquisitionId::new()).await
}

/// Como [`run_acquisition`], com o ID da aquisição definido pelo chamador
/// (permite à interface acompanhar a aquisição enquanto ela executa).
/// Um ID já usado é rejeitado pelo banco.
pub async fn run_acquisition_as(
    storage: &Storage,
    adapter: &dyn AcquisitionAdapter,
    plan: AcquisitionPlan,
    cancel: &CancellationToken,
    acquisition_id: AcquisitionId,
) -> EngineResult<AcquisitionSummary> {
    let descriptor = adapter.descriptor();

    // 1. Política.
    if let Err(reason) = check_policy(&plan, &descriptor) {
        storage
            .append_audit_event(
                AuditDraft {
                    case_id: Some(plan.case.id),
                    operator_id: Some(plan.operator.id),
                    kind: AuditKind::Error,
                    detail: format!("aquisição recusada antes do início: {reason}"),
                },
                UtcTimestamp::now(),
            )
            .await?;
        return Err(MexError::PolicyDenied(reason).into());
    }

    // 2. Registro da aquisição e do job.
    let started_at = UtcTimestamp::now();
    let acquisition = Acquisition {
        id: acquisition_id,
        case_id: plan.case.id,
        device_id: plan.device.id,
        authorization_id: plan.authorization.id,
        operator_id: plan.operator.id,
        capability: plan.capability,
        adapter_id: descriptor.id.into(),
        adapter_version: descriptor.version.into(),
        software_version: mex_core::CORE_VERSION.into(),
        outcome: None,
        limitations: Vec::new(),
        started_at,
        finished_at: None,
    };
    storage.start_acquisition(&acquisition).await?;
    let job = AcquisitionJob::new(acquisition.id, plan.capability, started_at);
    storage
        .save_job(&job, plan.case.id, plan.operator.id)
        .await?;
    let mut run = Run {
        storage,
        plan: &plan,
        acquisition_id: acquisition.id,
        job,
    };

    // 3. Validação de capacidade para este dispositivo.
    run.step(JobState::Validating, None).await?;
    let resolved = adapter
        .resolve(&plan.device.observed)
        .into_iter()
        .find(|c| c.kind == plan.capability);
    match resolved {
        Some(c) if c.is_available() => {}
        other => {
            let reason = match other.map(|c| c.availability) {
                Some(mex_core::capability::Availability::Unavailable { reason }) => {
                    format!("capacidade indisponível: {reason}")
                }
                Some(_) => "capacidade não implementada neste build".into(),
                None => "adaptador não oferece a capacidade".into(),
            };
            return run
                .end_without_package(JobState::Failed, AcquisitionOutcome::Failed, reason)
                .await;
        }
    }
    if cancel.is_cancelled() {
        return run
            .end_without_package(
                JobState::Cancelled,
                AcquisitionOutcome::Cancelled,
                "cancelado pelo operador antes do início".into(),
            )
            .await;
    }
    run.step(JobState::Ready, None).await?;

    // 4. Pacote + execução.
    let mut sink = match DiskEvidenceSink::create(
        &plan.evidence_root,
        acquisition.id,
        plan.sink_options.clone(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return run
                .end_without_package(
                    JobState::Failed,
                    AcquisitionOutcome::Failed,
                    format!("não foi possível criar o pacote: {e}"),
                )
                .await
        }
    };
    run.step(JobState::Running, None).await?;
    let request = AcquisitionRequest {
        acquisition_id: acquisition.id,
        capability: plan.capability,
        device: plan.device.observed.clone(),
    };
    let result = adapter.acquire(&request, &mut sink, cancel).await;
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

    // 5. Contadores e transição.
    let now = UtcTimestamp::now();
    for a in sink.artifacts() {
        run.job.record_bytes(a.size_bytes, now)?;
        if a.is_complete() {
            run.job.record_artifact_completed(now)?;
        } else if let mex_core::model::ArtifactStatus::Failed { reason } = &a.status {
            run.job.record_artifact_failure(
                ArtifactFailure {
                    source_path: a.source_path.clone(),
                    reason: reason.clone(),
                },
                now,
            )?;
        }
    }
    for f in &report.not_acquired {
        run.job.record_artifact_failure(f.clone(), now)?;
    }
    match &termination {
        Termination::Cancelled => {
            run.audit(
                AuditKind::Interrupted,
                format!("aquisição {} cancelada pelo operador", acquisition.id),
            )
            .await?;
            run.step(JobState::Cancelled, Some("cancelado pelo operador"))
                .await?;
        }
        Termination::Interrupted { reason } => {
            run.audit(
                AuditKind::Interrupted,
                format!("aquisição {} interrompida: {reason}", acquisition.id),
            )
            .await?;
            run.step(JobState::Finalizing, None).await?;
        }
        Termination::Normal => run.step(JobState::Finalizing, None).await?,
    }

    // 6. Selo, artefatos, estado terminal, finalização.
    let header = ManifestHeader {
        case: plan.case.clone(),
        operator: plan.operator.clone(),
        authorization: plan.authorization.clone(),
        device_id: plan.device.id,
        device: plan.device.observed.clone(),
        adapter: AdapterRecord::from_descriptor(&descriptor, plan.capability),
        started_at,
    };
    let reason = match &termination {
        Termination::Normal => None,
        Termination::Cancelled => Some("cancelado pelo operador".to_owned()),
        Termination::Interrupted { reason } => Some(reason.clone()),
    };
    let sealed = sink
        .finalize(FinalizeInput {
            header,
            report,
            termination: termination.clone(),
            finished_at: UtcTimestamp::now(),
        })
        .await;
    let sealed = match sealed {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("falha ao selar o pacote: {e}");
            run.audit(AuditKind::Error, msg.clone()).await?;
            let (terminal, outcome) = if termination == Termination::Cancelled {
                (None, AcquisitionOutcome::Cancelled)
            } else {
                (Some(JobState::Failed), AcquisitionOutcome::Failed)
            };
            if let Some(t) = terminal {
                run.step(t, Some(&msg)).await?;
            }
            storage
                .finish_acquisition(&AcquisitionFinish {
                    acquisition_id: acquisition.id,
                    case_id: plan.case.id,
                    operator_id: plan.operator.id,
                    outcome,
                    limitations: vec![msg.clone()],
                    finished_at: UtcTimestamp::now(),
                    package_path: None,
                    manifest_sha256: None,
                })
                .await?;
            return Ok(AcquisitionSummary {
                acquisition_id: acquisition.id,
                outcome,
                job: run.job,
                package: None,
                reason: Some(msg),
            });
        }
    };

    storage.record_artifacts(&sealed.manifest.artifacts).await?;
    let outcome = sealed.manifest.outcome;
    if termination != Termination::Cancelled {
        let why = (outcome == AcquisitionOutcome::Failed).then(|| {
            reason
                .clone()
                .unwrap_or_else(|| "nenhum artefato adquirido".into())
        });
        run.step(JobState::terminal_for(outcome), why.as_deref())
            .await?;
    }
    let mut limitations = sealed.manifest.limitations.clone();
    limitations.extend(sealed.manifest.not_acquired.iter().map(|f| {
        format!(
            "não adquirido: {} — {}",
            f.source_path.as_deref().unwrap_or("?"),
            f.reason
        )
    }));
    storage
        .finish_acquisition(&AcquisitionFinish {
            acquisition_id: acquisition.id,
            case_id: plan.case.id,
            operator_id: plan.operator.id,
            outcome,
            limitations,
            finished_at: sealed.manifest.finished_at,
            package_path: Some(sealed.package_dir.display().to_string()),
            manifest_sha256: Some(sealed.manifest_sha256.clone()),
        })
        .await?;
    tracing::info!(acquisition = %acquisition.id, outcome = outcome.as_str(), "aquisição finalizada");
    Ok(AcquisitionSummary {
        acquisition_id: acquisition.id,
        outcome,
        job: run.job,
        package: Some(sealed),
        reason,
    })
}

fn check_policy(
    plan: &AcquisitionPlan,
    d: &mex_core::traits::AdapterDescriptor,
) -> std::result::Result<(), String> {
    if plan.authorization.case_id != plan.case.id {
        return Err("a autorização informada não pertence ao caso".into());
    }
    if !plan.capability.is_operational() {
        return Err(format!(
            "capacidade {} não é operacional neste build",
            plan.capability.as_str()
        ));
    }
    if !d.capabilities.contains(&plan.capability) {
        return Err(format!(
            "adaptador {} não declara a capacidade {}",
            d.id,
            plan.capability.as_str()
        ));
    }
    if !d.platforms.contains(&plan.device.observed.platform) {
        return Err(format!(
            "adaptador {} não suporta a plataforma {}",
            d.id,
            plan.device.observed.platform.as_str()
        ));
    }
    Ok(())
}

/// Verifica o pacote de uma aquisição contra o hash de manifesto registrado
/// na finalização, e registra o resultado (tabela + auditoria).
pub async fn verify_acquisition(
    storage: &Storage,
    acquisition_id: AcquisitionId,
    case_id: mex_core::ids::CaseId,
    operator: &Operator,
) -> EngineResult<VerificationReport> {
    let reg = storage
        .registered_package(acquisition_id)
        .await?
        .ok_or_else(|| {
            MexError::InvalidInput(format!(
                "aquisição {acquisition_id} não possui pacote registrado"
            ))
        })?;
    let path = PathBuf::from(&reg.package_path);
    let expected = reg.manifest_sha256.clone();
    let report = tokio::task::spawn_blocking(move || verify_package(&path, Some(&expected)))
        .await
        .map_err(|e| MexError::Adapter(format!("tarefa de verificação falhou: {e}")))?;
    let findings = report
        .findings
        .iter()
        .map(|f| serde_json::to_value(f).expect("Finding é serializável"))
        .collect();
    storage
        .record_verification(&VerificationRecord {
            acquisition_id,
            case_id,
            status: report.status,
            manifest_sha256: report.manifest_sha256.clone(),
            artifacts_checked: report.artifacts_checked as u64,
            bytes_verified: report.bytes_verified,
            findings,
            verified_by: operator.id,
            verified_at: report.verified_at,
        })
        .await?;
    Ok(report)
}
