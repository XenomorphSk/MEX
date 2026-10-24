//! # mex-research
//!
//! Organização da pesquisa de segurança mobile em **dispositivos de
//! laboratório autorizados**: catálogo de dispositivos e firmware, hipóteses
//! de aquisição, pré-condições, resultados experimentais, modificações
//! observadas e a matriz de compatibilidade.
//!
//! Este crate **não contém técnicas de aquisição**. Ele registra e governa a
//! maturidade de métodos implementados em outros módulos.
//!
//! ## Regra central
//! Somente um método em [`MethodStatus::Validated`] pode ser usado em um
//! caso real ([`case_usage`]). Nenhum outro estado é habilitado
//! automaticamente, e não existe "override" neste build: liberar métodos
//! não validados exigirá uma decisão de política documentada.
//!
//! Dependência unidirecional: `mex-research` depende de `mex-core`; o
//! Evidence Engine não depende deste crate.

use mex_core::capability::CapabilityKind;
use mex_core::ids::OperatorId;
use mex_core::model::{optional_text, required_text, MAX_LONG_TEXT, MAX_SHORT_TEXT};
use mex_core::timestamp::UtcTimestamp;
use mex_core::{typed_id, MexError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

typed_id!(
    /// Identificador de dispositivo de laboratório.
    ResearchDeviceId
);
typed_id!(
    /// Identificador de método de pesquisa.
    ResearchMethodId
);
typed_id!(
    /// Identificador de resultado de compatibilidade.
    CompatibilityResultId
);

/// Estado de maturidade de um método.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MethodStatus {
    /// Hipótese em investigação. Nunca usado em caso real.
    Experimental,
    /// Em execução do protocolo de validação forense.
    UnderValidation,
    /// Validado conforme `docs/forensic-validation.md`.
    Validated,
    /// Retirado de uso (terminal).
    Deprecated,
    /// Comprovadamente não funciona no escopo testado.
    Unsupported,
}

impl MethodStatus {
    /// Todas as variantes.
    pub const ALL: [MethodStatus; 5] = [
        MethodStatus::Experimental,
        MethodStatus::UnderValidation,
        MethodStatus::Validated,
        MethodStatus::Deprecated,
        MethodStatus::Unsupported,
    ];

    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            MethodStatus::Experimental => "EXPERIMENTAL",
            MethodStatus::UnderValidation => "UNDER_VALIDATION",
            MethodStatus::Validated => "VALIDATED",
            MethodStatus::Deprecated => "DEPRECATED",
            MethodStatus::Unsupported => "UNSUPPORTED",
        }
    }

    /// Transições permitidas.
    ///
    /// - `Validated` só é alcançável a partir de `UnderValidation`;
    /// - `Validated -> UnderValidation` permite revalidar (ex.: novo firmware);
    /// - `Deprecated` é terminal;
    /// - `Unsupported -> Experimental` permite reabrir com nova hipótese.
    pub fn can_transition_to(&self, next: MethodStatus) -> bool {
        use MethodStatus::*;
        match self {
            Experimental => matches!(next, UnderValidation | Unsupported | Deprecated),
            UnderValidation => matches!(next, Validated | Experimental | Unsupported | Deprecated),
            Validated => matches!(next, UnderValidation | Deprecated),
            Deprecated => false,
            Unsupported => matches!(next, Experimental | Deprecated),
        }
    }
}

/// Decisão sobre o uso de um método em um caso real.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CaseUsage {
    /// Permitido.
    Allowed,
    /// Negado, com motivo para exibição e auditoria.
    Denied {
        /// Motivo.
        reason: String,
    },
}

/// Política de uso em caso real: somente `Validated`.
pub fn case_usage(status: MethodStatus) -> CaseUsage {
    match status {
        MethodStatus::Validated => CaseUsage::Allowed,
        other => CaseUsage::Denied {
            reason: format!(
                "método em estado {} não pode ser usado em caso real; apenas VALIDATED",
                other.as_str()
            ),
        },
    }
}

/// Dispositivo de laboratório.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchDevice {
    /// Identificador.
    pub id: ResearchDeviceId,
    /// Rótulo interno do laboratório (etiqueta patrimonial).
    pub label: String,
    /// Fabricante.
    pub manufacturer: Option<String>,
    /// Modelo.
    pub model: Option<String>,
    /// Revisão de hardware.
    pub hardware_revision: Option<String>,
    /// Firmware/build instalado.
    pub firmware: Option<String>,
    /// Versão do SO.
    pub os_version: Option<String>,
    /// Patch de segurança.
    pub security_patch: Option<String>,
    /// Observações.
    pub notes: Option<String>,
    /// Cadastrado em.
    pub created_at: UtcTimestamp,
}

/// Registro de mudança de estado de um método.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusChange {
    /// Estado anterior.
    pub from: MethodStatus,
    /// Novo estado.
    pub to: MethodStatus,
    /// Quem decidiu.
    pub by: OperatorId,
    /// Justificativa (obrigatória).
    pub justification: String,
    /// Referência ao relatório de validação (obrigatória para VALIDATED).
    pub validation_reference: Option<String>,
    /// Quando.
    pub at: UtcTimestamp,
}

/// Método (hipótese) de aquisição catalogado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchMethod {
    id: ResearchMethodId,
    name: String,
    version: String,
    capability: CapabilityKind,
    hypothesis: String,
    preconditions: Vec<String>,
    known_modifications: Vec<String>,
    status: MethodStatus,
    history: Vec<StatusChange>,
    created_at: UtcTimestamp,
}

impl ResearchMethod {
    /// Cadastra um método. Todo método nasce `Experimental`.
    pub fn new(
        name: &str,
        version: &str,
        capability: CapabilityKind,
        hypothesis: &str,
        preconditions: Vec<String>,
        at: UtcTimestamp,
    ) -> Result<Self> {
        Ok(Self {
            id: ResearchMethodId::new(),
            name: required_text("nome do método", name, MAX_SHORT_TEXT)?,
            version: required_text("versão do método", version, MAX_SHORT_TEXT)?,
            capability,
            hypothesis: required_text("hipótese", hypothesis, MAX_LONG_TEXT)?,
            preconditions,
            known_modifications: Vec::new(),
            status: MethodStatus::Experimental,
            history: Vec::new(),
            created_at: at,
        })
    }

    /// Altera o estado, com justificativa obrigatória. A transição para
    /// `Validated` exige referência ao relatório de validação.
    pub fn change_status(
        &mut self,
        to: MethodStatus,
        by: OperatorId,
        justification: &str,
        validation_reference: Option<&str>,
        at: UtcTimestamp,
    ) -> Result<()> {
        if !self.status.can_transition_to(to) {
            return Err(MexError::InvalidTransition {
                from: self.status.as_str(),
                to: to.as_str(),
            });
        }
        let justification = required_text("justificativa", justification, MAX_LONG_TEXT)?;
        let validation_reference = optional_text(
            "referência de validação",
            validation_reference,
            MAX_SHORT_TEXT,
        )?;
        if to == MethodStatus::Validated && validation_reference.is_none() {
            return Err(MexError::InvalidInput(
                "VALIDATED exige referência ao relatório de validação forense".into(),
            ));
        }
        self.history.push(StatusChange {
            from: self.status,
            to,
            by,
            justification,
            validation_reference,
            at,
        });
        self.status = to;
        Ok(())
    }

    /// Registra uma modificação de dispositivo observada em experimentos.
    pub fn record_known_modification(&mut self, description: &str) -> Result<()> {
        self.known_modifications.push(required_text(
            "modificação observada",
            description,
            MAX_LONG_TEXT,
        )?);
        Ok(())
    }

    /// Identificador.
    pub fn id(&self) -> ResearchMethodId {
        self.id
    }
    /// Nome.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Versão.
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Capacidade que o método pretende oferecer.
    pub fn capability(&self) -> CapabilityKind {
        self.capability
    }
    /// Hipótese.
    pub fn hypothesis(&self) -> &str {
        &self.hypothesis
    }
    /// Pré-condições.
    pub fn preconditions(&self) -> &[String] {
        &self.preconditions
    }
    /// Modificações conhecidas.
    pub fn known_modifications(&self) -> &[String] {
        &self.known_modifications
    }
    /// Estado atual.
    pub fn status(&self) -> MethodStatus {
        self.status
    }
    /// Histórico de estados.
    pub fn history(&self) -> &[StatusChange] {
        &self.history
    }
    /// Cadastrado em.
    pub fn created_at(&self) -> UtcTimestamp {
        self.created_at
    }
}

/// Resultado de um experimento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExperimentOutcome {
    /// Funcionou conforme a hipótese.
    Success,
    /// Funcionou parcialmente.
    Partial,
    /// Não funcionou.
    Failure,
    /// Resultado não conclusivo.
    Inconclusive,
}

impl ExperimentOutcome {
    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            ExperimentOutcome::Success => "success",
            ExperimentOutcome::Partial => "partial",
            ExperimentOutcome::Failure => "failure",
            ExperimentOutcome::Inconclusive => "inconclusive",
        }
    }
}

/// Resultado de um experimento de um método em um dispositivo de laboratório.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityResult {
    /// Identificador.
    pub id: CompatibilityResultId,
    /// Dispositivo.
    pub research_device_id: ResearchDeviceId,
    /// Método.
    pub research_method_id: ResearchMethodId,
    /// Versão do método testada.
    pub method_version: String,
    /// Firmware no momento do teste.
    pub firmware_tested: Option<String>,
    /// Versão do SO no momento do teste.
    pub os_version_tested: Option<String>,
    /// Resultado.
    pub outcome: ExperimentOutcome,
    /// Modificações observadas no dispositivo.
    pub observed_modifications: Vec<String>,
    /// Observações.
    pub notes: Option<String>,
    /// Pesquisador.
    pub tested_by: OperatorId,
    /// Quando.
    pub tested_at: UtcTimestamp,
}

/// Linha da matriz de compatibilidade: o resultado mais recente de cada
/// combinação (dispositivo, método, versão do método, firmware).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixRow {
    /// Dispositivo.
    pub research_device_id: ResearchDeviceId,
    /// Método.
    pub research_method_id: ResearchMethodId,
    /// Versão do método.
    pub method_version: String,
    /// Firmware.
    pub firmware_tested: Option<String>,
    /// Resultado mais recente.
    pub latest: ExperimentOutcome,
    /// Quantidade de experimentos registrados para a combinação.
    pub runs: usize,
}

/// Monta a matriz de compatibilidade a partir dos resultados registrados.
///
/// A matriz só reflete experimentos registrados; ausência de linha significa
/// "não testado", nunca "compatível".
pub fn compatibility_matrix(results: &[CompatibilityResult]) -> Vec<MatrixRow> {
    type Key = (ResearchDeviceId, ResearchMethodId, String, Option<String>);
    let mut acc: BTreeMap<Key, (UtcTimestamp, ExperimentOutcome, usize)> = BTreeMap::new();
    for r in results {
        let key = (
            r.research_device_id,
            r.research_method_id,
            r.method_version.clone(),
            r.firmware_tested.clone(),
        );
        acc.entry(key)
            .and_modify(|(at, out, n)| {
                *n += 1;
                if r.tested_at >= *at {
                    *at = r.tested_at;
                    *out = r.outcome;
                }
            })
            .or_insert((r.tested_at, r.outcome, 1));
    }
    acc.into_iter()
        .map(|((d, m, v, f), (_, latest, runs))| MatrixRow {
            research_device_id: d,
            research_method_id: m,
            method_version: v,
            firmware_tested: f,
            latest,
            runs,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method() -> ResearchMethod {
        ResearchMethod::new(
            "Hipótese de teste",
            "0.1.0",
            CapabilityKind::FileSystem,
            "Descrição da hipótese a investigar em laboratório.",
            vec!["dispositivo de laboratório".into()],
            UtcTimestamp::now(),
        )
        .unwrap()
    }

    #[test]
    fn new_methods_are_experimental_and_denied_in_cases() {
        let m = method();
        assert_eq!(m.status(), MethodStatus::Experimental);
        assert!(matches!(case_usage(m.status()), CaseUsage::Denied { .. }));
    }

    #[test]
    fn only_validated_is_allowed_in_cases() {
        for s in MethodStatus::ALL {
            let allowed = matches!(case_usage(s), CaseUsage::Allowed);
            assert_eq!(allowed, s == MethodStatus::Validated, "{s:?}");
        }
    }

    #[test]
    fn cannot_jump_from_experimental_to_validated() {
        let mut m = method();
        let op = OperatorId::new();
        let t = UtcTimestamp::now();
        assert!(m
            .change_status(MethodStatus::Validated, op, "pulo", Some("VAL-1"), t)
            .is_err());
        assert_eq!(m.status(), MethodStatus::Experimental);
    }

    #[test]
    fn validation_requires_reference_and_justification() {
        let mut m = method();
        let op = OperatorId::new();
        let t = UtcTimestamp::now();
        assert!(m
            .change_status(MethodStatus::UnderValidation, op, " ", None, t)
            .is_err());
        m.change_status(
            MethodStatus::UnderValidation,
            op,
            "início do protocolo",
            None,
            t,
        )
        .unwrap();
        assert!(m
            .change_status(MethodStatus::Validated, op, "protocolo concluído", None, t)
            .is_err());
        m.change_status(
            MethodStatus::Validated,
            op,
            "protocolo concluído",
            Some("VAL-2025-001"),
            t,
        )
        .unwrap();
        assert_eq!(m.history().len(), 2);
        assert!(matches!(case_usage(m.status()), CaseUsage::Allowed));
    }

    #[test]
    fn deprecated_is_terminal() {
        for s in MethodStatus::ALL {
            assert!(!MethodStatus::Deprecated.can_transition_to(s));
        }
    }

    #[test]
    fn status_names_match_serde_and_spec() {
        let names: Vec<_> = MethodStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            names,
            [
                "EXPERIMENTAL",
                "UNDER_VALIDATION",
                "VALIDATED",
                "DEPRECATED",
                "UNSUPPORTED"
            ]
        );
        for s in MethodStatus::ALL {
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.as_str())
            );
        }
    }

    #[test]
    fn matrix_keeps_latest_result_per_combination() {
        let dev = ResearchDeviceId::new();
        let m = ResearchMethodId::new();
        let op = OperatorId::new();
        let mk = |micros, outcome| CompatibilityResult {
            id: CompatibilityResultId::new(),
            research_device_id: dev,
            research_method_id: m,
            method_version: "0.1.0".into(),
            firmware_tested: Some("FW-A".into()),
            os_version_tested: None,
            outcome,
            observed_modifications: vec![],
            notes: None,
            tested_by: op,
            tested_at: UtcTimestamp::from_unix_micros(micros).unwrap(),
        };
        let rows = compatibility_matrix(&[
            mk(2, ExperimentOutcome::Success),
            mk(1, ExperimentOutcome::Failure),
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].latest, ExperimentOutcome::Success);
        assert_eq!(rows[0].runs, 2);
        assert!(compatibility_matrix(&[]).is_empty());
    }
}
