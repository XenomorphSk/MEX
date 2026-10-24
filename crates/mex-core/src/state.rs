//! Máquina de estados de jobs de aquisição.
//!
//! Fluxo nominal:
//! `Created -> Validating -> Ready -> Running -> Finalizing -> Completed`
//!
//! Estados terminais adicionais: `Failed`, `Cancelled`, `Partial`.
//! Transições inválidas são rejeitadas com [`MexError::InvalidTransition`].

use crate::error::{MexError, Result};
use crate::model::AcquisitionOutcome;
use serde::{Deserialize, Serialize};

/// Estado de um job de aquisição.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobState {
    /// Criado, ainda não validado.
    Created,
    /// Validando pré-requisitos e autorização.
    Validating,
    /// Pronto para executar.
    Ready,
    /// Em execução (adquirindo).
    Running,
    /// Finalizando: fechando artefatos, calculando manifesto.
    Finalizing,
    /// Concluído com sucesso.
    Completed,
    /// Concluído parcialmente (alguns artefatos falharam).
    Partial,
    /// Falhou.
    Failed,
    /// Cancelado cooperativamente.
    Cancelled,
}

impl JobState {
    /// Todas as variantes (para validação de schema).
    pub const ALL: [JobState; 9] = [
        JobState::Created,
        JobState::Validating,
        JobState::Ready,
        JobState::Running,
        JobState::Finalizing,
        JobState::Completed,
        JobState::Partial,
        JobState::Failed,
        JobState::Cancelled,
    ];

    /// Nome estável (também persistido no banco).
    pub fn name(&self) -> &'static str {
        match self {
            JobState::Created => "created",
            JobState::Validating => "validating",
            JobState::Ready => "ready",
            JobState::Running => "running",
            JobState::Finalizing => "finalizing",
            JobState::Completed => "completed",
            JobState::Partial => "partial",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }

    /// Estado terminal: não admite mais transições.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JobState::Completed | JobState::Partial | JobState::Failed | JobState::Cancelled
        )
    }

    /// Indica se `self -> next` é uma transição permitida.
    pub fn can_transition_to(&self, next: JobState) -> bool {
        use JobState::*;
        match self {
            Created => matches!(next, Validating | Cancelled | Failed),
            Validating => matches!(next, Ready | Cancelled | Failed),
            Ready => matches!(next, Running | Cancelled | Failed),
            Running => matches!(next, Finalizing | Cancelled | Failed),
            // Finalização pode concluir totalmente, parcialmente ou falhar.
            // Não é cancelável: interromper a gravação do manifesto deixaria
            // o pacote inconsistente; o cancelamento é verificado antes.
            Finalizing => matches!(next, Completed | Partial | Failed),
            // Terminais não transicionam.
            Completed | Partial | Failed | Cancelled => false,
        }
    }

    /// Aplica a transição, retornando o novo estado ou erro se inválida.
    pub fn transition_to(self, next: JobState) -> Result<JobState> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(MexError::InvalidTransition {
                from: self.name(),
                to: next.name(),
            })
        }
    }

    /// Estado terminal correspondente a um resultado de aquisição.
    pub fn terminal_for(outcome: AcquisitionOutcome) -> JobState {
        match outcome {
            AcquisitionOutcome::Complete => JobState::Completed,
            AcquisitionOutcome::Partial => JobState::Partial,
            AcquisitionOutcome::Failed => JobState::Failed,
            AcquisitionOutcome::Cancelled => JobState::Cancelled,
        }
    }
}

impl std::str::FromStr for JobState {
    type Err = MexError;

    fn from_str(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|st| st.name() == s)
            .ok_or_else(|| MexError::InvalidInput(format!("estado de job desconhecido: {s:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::JobState;
    use super::JobState::*;

    #[test]
    fn nominal_flow_is_allowed() {
        let mut s = Created;
        for next in [Validating, Ready, Running, Finalizing, Completed] {
            s = s.transition_to(next).expect("transição nominal deve valer");
        }
        assert!(s.is_terminal());
    }

    #[test]
    fn invalid_skips_are_rejected() {
        assert!(Created.transition_to(Running).is_err());
        assert!(Ready.transition_to(Completed).is_err());
        assert!(Running.transition_to(Completed).is_err());
    }

    #[test]
    fn terminal_states_do_not_transition() {
        for t in [Completed, Partial, Failed, Cancelled] {
            assert!(t.is_terminal());
            assert!(t.transition_to(Running).is_err());
        }
    }

    #[test]
    fn cancel_and_fail_available_before_finalize() {
        for s in [Created, Validating, Ready, Running] {
            assert!(s.can_transition_to(super::JobState::Cancelled));
            assert!(s.can_transition_to(super::JobState::Failed));
        }
    }

    #[test]
    fn finalize_can_be_partial() {
        assert!(Finalizing.transition_to(Partial).is_ok());
        assert!(Finalizing.transition_to(Cancelled).is_err());
    }

    #[test]
    fn names_roundtrip_and_match_serde() {
        for s in JobState::ALL {
            assert_eq!(s.name().parse::<JobState>().unwrap(), s);
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.name())
            );
        }
    }

    /// Verificação exaustiva: só as transições listadas na especificação
    /// são aceitas (9 x 9 pares).
    #[test]
    fn transition_table_is_exactly_the_specified_one() {
        let allowed: &[(JobState, JobState)] = &[
            (Created, Validating),
            (Created, Cancelled),
            (Created, Failed),
            (Validating, Ready),
            (Validating, Cancelled),
            (Validating, Failed),
            (Ready, Running),
            (Ready, Cancelled),
            (Ready, Failed),
            (Running, Finalizing),
            (Running, Cancelled),
            (Running, Failed),
            (Finalizing, Completed),
            (Finalizing, Partial),
            (Finalizing, Failed),
        ];
        for from in JobState::ALL {
            for to in JobState::ALL {
                assert_eq!(
                    from.can_transition_to(to),
                    allowed.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }
}
