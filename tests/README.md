# Testes do workspace

- `golden/` — valores de referência de formatos persistidos.
  - `audit_chain_v1.json`: cadeia de auditoria V1 com entradas fixas;
    consumida por `crates/mex-core/tests/golden.rs`.
  - `verify_audit_v1.sh`: verificação independente (printf + sha256sum).
- `fixtures/local_import_v1/` — árvore determinística para importação.
- `fixtures/local_import_v1.sha256` — oráculo gerado com `sha256sum`
  (coreutils), independente do MEX. Para regenerar após alterar a fixture:
  `cd tests/fixtures/local_import_v1 && find . -type f | LC_ALL=C sort | sed 's|^\./||' | xargs -d '\n' sha256sum > ../local_import_v1.sha256`
- Testes ponta a ponta: `crates/mex-acquisition/tests/end_to_end.rs`
  (o diretório `integration/` fica reservado para cenários com dispositivos
  reais de laboratório).

Testes de cada crate ficam em `crates/<crate>/tests/` e nos módulos
`#[cfg(test)]`.
