//! Job de aquisição: unidade de execução com estado e progresso.
//!
//! Decisão de arquitetura: `AcquisitionJob` é um tipo concreto do núcleo, e
//! não um trait de plugin. O ciclo de vida do job (estados, contadores,
//! histórico de transições) é responsabilidade do motor, não dos
//! adaptadores — assim nenhum adaptador consegue pular estados ou declarar
//! o próprio sucesso. Adaptadores implementam [`crate::traits::AcquisitionAdapter`].

use crate::capability::CapabilityKind;
use crate::error::{MexError, Result};
use crate::ids::{AcquisitionId, JobId};
use crate::model::ArtifactFailure;
use crate::state::JobState;
use crate::timestamp::UtcTimestamp;
use serde::{Deserialize, Serialize};

/// Uma transição registrada no histórico do job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobTransition {
    /// Estado anterior.
    pub from: JobState,
    /// Novo estado.
    pub to: JobState,
    /// Momento da transição.
    pub at: UtcTimestamp,
    /// Motivo (obrigatório para Failed/Cancelled).
    pub reason: Option<String>,
}

/// Job de aquisição.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionJob {
    id: JobId,
    acquisition_id: AcquisitionId,
    capability: CapabilityKind,
    state: JobState,
    bytes_acquired: u64,
    bytes_total: Option<u64>,
    artifacts_completed: u32,
    failures: Vec<ArtifactFailure>,
    history: Vec<JobTransition>,
    created_at: UtcTimestamp,
    updated_at: UtcTimestamp,
}

impl AcquisitionJob {
    /// Cria um job no estado `Created`.
    pub fn new(
        acquisition_id: AcquisitionId,
        capability: CapabilityKind,
        at: UtcTimestamp,
    ) -> Self {
        Self {
            id: JobId::new(),
            acquisition_id,
            capability,
            state: JobState::Created,
            bytes_acquired: 0,
            bytes_total: None,
            artifacts_completed: 0,
            failures: Vec::new(),
            history: Vec::new(),
            created_at: at,
            updated_at: at,
        }
    }

    /// Aplica uma transição validada pela máquina de estados.
    ///
    /// Transições para `Failed`/`Cancelled` exigem motivo.
    pub fn transition(
        &mut self,
        to: JobState,
        reason: Option<&str>,
        at: UtcTimestamp,
    ) -> Result<()> {
        let reason = reason.map(str::trim).filter(|r| !r.is_empty());
        if matches!(to, JobState::Failed | JobState::Cancelled) && reason.is_none() {
            return Err(MexError::InvalidInput(format!(
                "transição para {} exige motivo",
                to.name()
            )));
        }
        let next = self.state.transition_to(to)?;
        self.history.push(JobTransition {
            from: self.state,
            to: next,
            at,
            reason: reason.map(str::to_owned),
        });
        self.state = next;
        self.updated_at = at;
        Ok(())
    }

    /// Registra bytes adquiridos. Só permitido em `Running`.
    pub fn record_bytes(&mut self, n: u64, at: UtcTimestamp) -> Result<()> {
        self.require_running()?;
        self.bytes_acquired = self.bytes_acquired.saturating_add(n);
        self.updated_at = at;
        Ok(())
    }

    /// Define o total conhecido de bytes (quando a origem informa).
    pub fn set_bytes_total(&mut self, total: Option<u64>) {
        self.bytes_total = total;
    }

    /// Registra um artefato finalizado com sucesso. Só em `Running`.
    pub fn record_artifact_completed(&mut self, at: UtcTimestamp) -> Result<()> {
        self.require_running()?;
        self.artifacts_completed += 1;
        self.updated_at = at;
        Ok(())
    }

    /// Registra a falha de um artefato. Permitido em `Running` e `Finalizing`.
    pub fn record_artifact_failure(
        &mut self,
        failure: ArtifactFailure,
        at: UtcTimestamp,
    ) -> Result<()> {
        if !matches!(self.state, JobState::Running | JobState::Finalizing) {
            return Err(MexError::InvalidInput(format!(
                "falha de artefato não pode ser registrada em {}",
                self.state.name()
            )));
        }
        self.failures.push(failure);
        self.updated_at = at;
        Ok(())
    }

    fn require_running(&self) -> Result<()> {
        if self.state == JobState::Running {
            Ok(())
        } else {
            Err(MexError::InvalidInput(format!(
                "progresso só pode ser registrado em running (atual: {})",
                self.state.name()
            )))
        }
    }

    /// Identificador.
    pub fn id(&self) -> JobId {
        self.id
    }
    /// Aquisição.
    pub fn acquisition_id(&self) -> AcquisitionId {
        self.acquisition_id
    }
    /// Capacidade exercida.
    pub fn capability(&self) -> CapabilityKind {
        self.capability
    }
    /// Estado atual.
    pub fn state(&self) -> JobState {
        self.state
    }
    /// Bytes adquiridos.
    pub fn bytes_acquired(&self) -> u64 {
        self.bytes_acquired
    }
    /// Total conhecido de bytes.
    pub fn bytes_total(&self) -> Option<u64> {
        self.bytes_total
    }
    /// Artefatos finalizados.
    pub fn artifacts_completed(&self) -> u32 {
        self.artifacts_completed
    }
    /// Falhas por artefato.
    pub fn failures(&self) -> &[ArtifactFailure] {
        &self.failures
    }
    /// Histórico de transições.
    pub fn history(&self) -> &[JobTransition] {
        &self.history
    }
    /// Criado em.
    pub fn created_at(&self) -> UtcTimestamp {
        self.created_at
    }
    /// Última atualização.
    pub fn updated_at(&self) -> UtcTimestamp {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> AcquisitionJob {
        AcquisitionJob::new(
            AcquisitionId::new(),
            CapabilityKind::LocalImport,
            UtcTimestamp::now(),
        )
    }

    #[test]
    fn nominal_lifecycle_records_history() {
        let mut j = job();
        let t = UtcTimestamp::now();
        for s in [JobState::Validating, JobState::Ready, JobState::Running] {
            j.transition(s, None, t).unwrap();
        }
        j.record_bytes(100, t).unwrap();
        j.record_artifact_completed(t).unwrap();
        j.transition(JobState::Finalizing, None, t).unwrap();
        j.transition(JobState::Completed, None, t).unwrap();
        assert_eq!(j.history().len(), 5);
        assert_eq!(j.bytes_acquired(), 100);
        assert_eq!(j.artifacts_completed(), 1);
    }

    #[test]
    fn invalid_transition_leaves_state_unchanged() {
        let mut j = job();
        assert!(j
            .transition(JobState::Running, None, UtcTimestamp::now())
            .is_err());
        assert_eq!(j.state(), JobState::Created);
        assert!(j.history().is_empty());
    }

    #[test]
    fn failure_and_cancel_require_reason() {
        let mut j = job();
        let t = UtcTimestamp::now();
        assert!(j.transition(JobState::Cancelled, None, t).is_err());
        assert!(j.transition(JobState::Cancelled, Some("  "), t).is_err());
        j.transition(JobState::Cancelled, Some("operador cancelou"), t)
            .unwrap();
        assert_eq!(j.history()[0].reason.as_deref(), Some("operador cancelou"));
    }

    #[test]
    fn progress_outside_running_is_rejected() {
        let mut j = job();
        let t = UtcTimestamp::now();
        assert!(j.record_bytes(1, t).is_err());
        assert!(j.record_artifact_completed(t).is_err());
        assert!(j
            .record_artifact_failure(
                ArtifactFailure {
                    source_path: None,
                    reason: "x".into()
                },
                t
            )
            .is_err());
    }
}
