//! Golden tests: protegem formatos persistidos contra alterações acidentais.
//!
//! Os hashes de `tests/golden/audit_chain_v1.json` foram conferidos de forma
//! independente por `tests/golden/verify_audit_v1.sh` (printf + sha256sum,
//! sem código do MEX). Se este teste falhar, a codificação canônica mudou:
//! isso invalidaria todas as cadeias existentes e exige um novo domínio
//! (`BLACKBIT-MEX/AUDIT/V2`), não a atualização do arquivo golden.

use mex_core::audit::{verify_chain, AuditDraft, AuditEvent};

const GOLDEN: &str = include_str!("../../../tests/golden/audit_chain_v1.json");

fn golden() -> Vec<AuditEvent> {
    serde_json::from_str(GOLDEN).expect("golden JSON válido")
}

#[test]
fn golden_chain_verifies() {
    let chain = golden();
    assert_eq!(chain.len(), 3);
    verify_chain(&chain).unwrap();
}

#[test]
fn rebuilding_from_inputs_reproduces_golden_hashes() {
    let expected = golden();
    let mut rebuilt: Vec<AuditEvent> = Vec::new();
    for g in &expected {
        let ev = AuditEvent::append_with_id(
            rebuilt.last(),
            g.id,
            AuditDraft {
                case_id: g.case_id,
                operator_id: g.operator_id,
                kind: g.kind,
                detail: g.detail.clone(),
            },
            g.at,
        )
        .unwrap();
        rebuilt.push(ev);
    }
    assert_eq!(rebuilt, expected);
}
