//! Cadeia de auditoria (cadeia de custódia) append-only.
//!
//! Cada evento carrega `seq` (0, 1, 2, ...), o `entry_hash` do evento
//! anterior (`prev_hash`) e o seu próprio `entry_hash`, calculado sobre uma
//! **codificação canônica versionada** de *todos* os campos:
//!
//! ```text
//! SHA-256( "BLACKBIT-MEX/AUDIT/V1"
//!          || u64be(seq)
//!          || bytes(id) || opt(case_id) || opt(operator_id)
//!          || bytes(kind) || bytes(detail) || bytes(at canônico)
//!          || opt(prev_hash) )
//!
//! bytes(x) = u64be(len(x)) || x
//! opt(x)   = 0x00                 se ausente
//!          | 0x01 || bytes(x)     se presente
//! ```
//!
//! O prefixo de tamanho elimina ambiguidades de concatenação (nenhum valor
//! de `detail` consegue "deslocar" bytes para outro campo) e o marcador de
//! presença distingue campo ausente de campo vazio.
//!
//! **Esta codificação é um formato persistido.** Alterá-la invalida todas as
//! cadeias existentes; qualquer mudança exige um novo domínio (`.../V2`) e
//! verificação dos dois formatos. O teste golden em
//! `tests/golden/audit_chain_v1.json` protege contra alterações acidentais.
//!
//! ## O que a cadeia detecta
//! Alteração de qualquer campo de qualquer evento, remoção ou inserção de
//! eventos no meio da cadeia e reordenação.
//!
//! ## O que a cadeia **não** detecta (limitações documentadas)
//! - Remoção dos *últimos* eventos (truncamento) — exige ancorar
//!   periodicamente o hash mais recente fora do sistema (relatório impresso,
//!   carimbo de tempo RFC 3161, armazenamento WORM).
//! - Reescrita completa da cadeia por quem controla o banco: um hash chain
//!   isolado não é assinatura. Assinaturas digitais por operador e carimbo
//!   de tempo confiável estão previstos (ver `docs/threat-model.md`).

use crate::error::{MexError, Result};
use crate::ids::{AuditEventId, CaseId, OperatorId};
use crate::integrity::StreamHasher;
use crate::model::required_text;
use crate::timestamp::UtcTimestamp;
use serde::{Deserialize, Serialize};

/// Separador de domínio da codificação canônica, versão 1.
pub const AUDIT_HASH_DOMAIN_V1: &[u8] = b"BLACKBIT-MEX/AUDIT/V1";

/// Tamanho máximo do campo `detail`, em bytes.
pub const MAX_AUDIT_DETAIL: usize = 4096;

/// Tipo de evento de auditoria (cadeia de custódia).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditKind {
    /// Operador cadastrado/identificado.
    OperatorRegistered,
    /// Caso criado.
    CaseCreated,
    /// Autorização registrada.
    AuthorizationRecorded,
    /// Dispositivo registrado/atualizado no inventário.
    DeviceRegistered,
    /// Aquisição iniciada.
    AcquisitionStarted,
    /// Operação executada contra o dispositivo ou a evidência.
    OperationExecuted,
    /// Transição de estado de job.
    JobStateChanged,
    /// Aquisição finalizada (qualquer resultado).
    AcquisitionFinished,
    /// Erro.
    Error,
    /// Interrupção (desconexão, cancelamento, queda de energia detectada).
    Interrupted,
    /// Verificação de integridade executada.
    IntegrityVerified,
    /// Exportação de evidências ou relatório.
    Exported,
    /// Transferência de custódia/mídia.
    Transferred,
}

impl AuditKind {
    /// Todas as variantes (para validação de schema).
    pub const ALL: [AuditKind; 13] = [
        AuditKind::OperatorRegistered,
        AuditKind::CaseCreated,
        AuditKind::AuthorizationRecorded,
        AuditKind::DeviceRegistered,
        AuditKind::AcquisitionStarted,
        AuditKind::OperationExecuted,
        AuditKind::JobStateChanged,
        AuditKind::AcquisitionFinished,
        AuditKind::Error,
        AuditKind::Interrupted,
        AuditKind::IntegrityVerified,
        AuditKind::Exported,
        AuditKind::Transferred,
    ];

    /// Rótulo estável. Faz parte da codificação canônica: não renomear.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditKind::OperatorRegistered => "operator-registered",
            AuditKind::CaseCreated => "case-created",
            AuditKind::AuthorizationRecorded => "authorization-recorded",
            AuditKind::DeviceRegistered => "device-registered",
            AuditKind::AcquisitionStarted => "acquisition-started",
            AuditKind::OperationExecuted => "operation-executed",
            AuditKind::JobStateChanged => "job-state-changed",
            AuditKind::AcquisitionFinished => "acquisition-finished",
            AuditKind::Error => "error",
            AuditKind::Interrupted => "interrupted",
            AuditKind::IntegrityVerified => "integrity-verified",
            AuditKind::Exported => "exported",
            AuditKind::Transferred => "transferred",
        }
    }
}

impl std::str::FromStr for AuditKind {
    type Err = MexError;

    fn from_str(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| MexError::InvalidInput(format!("tipo de evento desconhecido: {s:?}")))
    }
}

/// Dados de um evento ainda não encadeado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDraft {
    /// Caso relacionado, quando aplicável.
    pub case_id: Option<CaseId>,
    /// Operador que originou o evento, quando aplicável.
    pub operator_id: Option<OperatorId>,
    /// Tipo do evento.
    pub kind: AuditKind,
    /// Detalhe legível. **Nunca** incluir conteúdo de evidência.
    pub detail: String,
}

/// Evento de auditoria encadeado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Posição na cadeia (0 para o primeiro evento).
    pub seq: u64,
    /// Identificador.
    pub id: AuditEventId,
    /// Caso relacionado.
    pub case_id: Option<CaseId>,
    /// Operador.
    pub operator_id: Option<OperatorId>,
    /// Tipo.
    pub kind: AuditKind,
    /// Detalhe legível.
    pub detail: String,
    /// Momento (UTC, microssegundos).
    pub at: UtcTimestamp,
    /// `entry_hash` do evento anterior; `None` somente para `seq == 0`.
    pub prev_hash: Option<String>,
    /// Hash deste evento (hex minúsculo).
    pub entry_hash: String,
}

impl AuditEvent {
    /// Encadeia um novo evento após `prev` (ou como primeiro, se `None`).
    pub fn append(prev: Option<&AuditEvent>, draft: AuditDraft, at: UtcTimestamp) -> Result<Self> {
        Self::append_with_id(prev, AuditEventId::new(), draft, at)
    }

    /// Como [`AuditEvent::append`], com ID explícito (fixtures determinísticas).
    pub fn append_with_id(
        prev: Option<&AuditEvent>,
        id: AuditEventId,
        draft: AuditDraft,
        at: UtcTimestamp,
    ) -> Result<Self> {
        let detail = required_text("detalhe do evento", &draft.detail, MAX_AUDIT_DETAIL)?;
        let mut ev = AuditEvent {
            seq: prev.map_or(0, |p| p.seq + 1),
            id,
            case_id: draft.case_id,
            operator_id: draft.operator_id,
            kind: draft.kind,
            detail,
            at,
            prev_hash: prev.map(|p| p.entry_hash.clone()),
            entry_hash: String::new(),
        };
        ev.entry_hash = ev.compute_hash();
        Ok(ev)
    }

    /// Recalcula o hash canônico a partir dos campos atuais.
    pub fn compute_hash(&self) -> String {
        let mut h = StreamHasher::new();
        h.update(AUDIT_HASH_DOMAIN_V1);
        h.update(&self.seq.to_be_bytes());
        put_bytes(&mut h, self.id.to_string().as_bytes());
        put_opt(&mut h, self.case_id.map(|c| c.to_string()).as_deref());
        put_opt(&mut h, self.operator_id.map(|o| o.to_string()).as_deref());
        put_bytes(&mut h, self.kind.as_str().as_bytes());
        put_bytes(&mut h, self.detail.as_bytes());
        put_bytes(&mut h, self.at.to_canonical().as_bytes());
        put_opt(&mut h, self.prev_hash.as_deref());
        h.finalize().hex
    }
}

fn put_bytes(h: &mut StreamHasher, b: &[u8]) {
    h.update(&(b.len() as u64).to_be_bytes());
    h.update(b);
}

fn put_opt(h: &mut StreamHasher, v: Option<&str>) {
    match v {
        None => h.update(&[0x00]),
        Some(s) => {
            h.update(&[0x01]);
            put_bytes(h, s.as_bytes());
        }
    }
}

/// Verifica uma cadeia completa, que deve começar em `seq == 0`.
///
/// Retorna [`MexError::AuditChainBroken`] apontando o primeiro evento
/// inconsistente.
pub fn verify_chain(events: &[AuditEvent]) -> Result<()> {
    let mut prev: Option<&AuditEvent> = None;
    for (i, ev) in events.iter().enumerate() {
        let broken = |reason: String| MexError::AuditChainBroken {
            seq: ev.seq,
            reason,
        };
        if ev.seq != i as u64 {
            return Err(broken(format!(
                "sequência esperada {i}, encontrada {} (evento removido ou inserido)",
                ev.seq
            )));
        }
        let expected_prev = prev.map(|p| p.entry_hash.as_str());
        if ev.prev_hash.as_deref() != expected_prev {
            return Err(broken(
                "prev_hash não corresponde ao evento anterior".into(),
            ));
        }
        if ev.compute_hash() != ev.entry_hash {
            return Err(broken(
                "entry_hash não corresponde ao conteúdo do evento".into(),
            ));
        }
        prev = Some(ev);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(kind: AuditKind, detail: &str) -> AuditDraft {
        AuditDraft {
            case_id: Some(CaseId::new()),
            operator_id: Some(OperatorId::new()),
            kind,
            detail: detail.into(),
        }
    }

    fn chain(n: usize) -> Vec<AuditEvent> {
        let mut out: Vec<AuditEvent> = Vec::new();
        for i in 0..n {
            let ev = AuditEvent::append(
                out.last(),
                draft(AuditKind::OperationExecuted, &format!("op {i}")),
                UtcTimestamp::now(),
            )
            .unwrap();
            out.push(ev);
        }
        out
    }

    #[test]
    fn intact_chain_verifies() {
        let c = chain(5);
        assert_eq!(c[0].seq, 0);
        assert!(c[0].prev_hash.is_none());
        verify_chain(&c).unwrap();
    }

    type Mutation = (&'static str, Box<dyn Fn(&mut AuditEvent)>);

    #[test]
    fn every_field_is_covered_by_the_hash() {
        let base = chain(3);
        let mutations: Vec<Mutation> = vec![
            ("id", Box::new(|e| e.id = AuditEventId::new())),
            ("case_id", Box::new(|e| e.case_id = Some(CaseId::new()))),
            ("case_id->None", Box::new(|e| e.case_id = None)),
            (
                "operator_id",
                Box::new(|e| e.operator_id = Some(OperatorId::new())),
            ),
            ("kind", Box::new(|e| e.kind = AuditKind::Exported)),
            ("detail", Box::new(|e| e.detail.push('!'))),
            (
                "at",
                Box::new(|e| e.at = UtcTimestamp::from_unix_micros(0).unwrap()),
            ),
        ];
        for (name, mutate) in mutations {
            let mut c = base.clone();
            mutate(&mut c[1]);
            let err = verify_chain(&c).expect_err(name);
            assert!(
                matches!(err, MexError::AuditChainBroken { seq: 1, .. }),
                "{name}: {err}"
            );
        }
    }

    #[test]
    fn deletion_insertion_and_reorder_are_detected() {
        let base = chain(4);

        let mut deleted = base.clone();
        deleted.remove(1);
        assert!(verify_chain(&deleted).is_err());

        let mut reordered = base.clone();
        reordered.swap(1, 2);
        assert!(verify_chain(&reordered).is_err());

        let mut first_removed = base.clone();
        first_removed.remove(0);
        assert!(verify_chain(&first_removed).is_err());
    }

    #[test]
    fn recomputed_tamper_is_still_caught_by_successor() {
        // Adversário altera um evento e recalcula seu hash, mas não o resto.
        let mut c = chain(3);
        c[1].detail = "adulterado".into();
        c[1].entry_hash = c[1].compute_hash();
        let err = verify_chain(&c).unwrap_err();
        assert!(matches!(err, MexError::AuditChainBroken { seq: 2, .. }));
    }

    #[test]
    fn truncation_is_a_documented_limitation() {
        // Remover o último evento NÃO é detectável sem âncora externa.
        let mut c = chain(3);
        c.pop();
        assert!(verify_chain(&c).is_ok());
    }

    #[test]
    fn control_characters_in_detail_are_rejected() {
        // Defesa em profundidade além do prefixo de tamanho: separadores e
        // NUL nunca chegam à cadeia.
        for d in ["a\u{1f}b", "a\u{0}b", "a\u{1b}[31mb"] {
            assert!(
                AuditEvent::append(None, draft(AuditKind::Error, d), UtcTimestamp::now()).is_err(),
                "{d:?}"
            );
        }
        assert!(AuditEvent::append(
            None,
            draft(AuditKind::Error, "linha 1\nlinha 2"),
            UtcTimestamp::now()
        )
        .is_ok());
    }

    #[test]
    fn empty_or_oversized_detail_is_rejected() {
        assert!(
            AuditEvent::append(None, draft(AuditKind::Error, "  "), UtcTimestamp::now()).is_err()
        );
        let big = "x".repeat(MAX_AUDIT_DETAIL + 1);
        assert!(
            AuditEvent::append(None, draft(AuditKind::Error, &big), UtcTimestamp::now()).is_err()
        );
    }

    #[test]
    fn kind_names_roundtrip_and_match_serde() {
        for k in AuditKind::ALL {
            assert_eq!(k.as_str().parse::<AuditKind>().unwrap(), k);
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
    }
}
