# Requisitos — BlackBit MEX

## Funcionais (MVP)
- RF1. Identificar dispositivos Android conectados via ADB.
- RF2. Reconhecer serial, fabricante, modelo, versão e patch (quando acessíveis).
- RF3. Reconhecer estados ADB: device, unauthorized, offline e outros (rótulo original preservado).
- RF4. Realizar aquisição lógica de dispositivos previamente autorizados.
- RF5. Importar backups/imagens forenses existentes (LocalEvidenceImporter).
- RF6. Preservar evidências com SHA-256 por artefato e manifesto do pacote.
- RF7. Registrar cadeia de custódia append-only com encadeamento de hashes.
- RF8. Exportar relatórios técnicos (JSON/HTML) verificáveis.
- RF9. Catalogar pesquisa de laboratório, isolada do Evidence Engine.

## Não-funcionais
- RNF1. Operação offline; sem telemetria obrigatória.
- RNF2. Sem processamento de evidências em serviços externos.
- RNF3. Execução de processos sem shell interpolation; timeouts e limites.
- RNF4. Proteção contra path traversal; caminhos de arquivo controlados.
- RNF5. Finalização atômica: falha/cancelamento nunca gera evidência "completa".
- RNF6. Migrations SQLite versionadas; integridade referencial.
- RNF7. Linux primeiro; Windows como compatibilidade futura.

## Rastreabilidade — Milestone 1

| Requisito | Implementação | Teste |
|---|---|---|
| RF3 | `mex_core::model::AdbState` | `model::tests::adb_state_preserves_unknown_label` |
| RF6 (hash) | `mex_core::integrity`, `ArtifactWriter::commit` | `foundation.rs` (vetores FIPS, streaming, corrupção) |
| RF7 | `mex_core::audit`, `mex_storage::append_audit_event` | `audit::tests`, `golden.rs`, `schema.rs` |
| RF9 | `mex_research` | `mex_research::tests` |
| RNF4 | `mex_core::path::EvidencePath` | `path::tests` |
| RNF5 | `InMemorySink`, triggers de `artifacts` | `foundation.rs` (cancelamento/desconexão), `schema.rs` |
| RNF6 | `migrations/0001_initial.sql`, `mex_storage::MIGRATOR` | `schema.rs` |

## Rastreabilidade — Milestone 2

| Requisito | Implementação | Teste |
|---|---|---|
| RF5 | `mex_acquisition::LocalEvidenceImporter` | `end_to_end.rs` (fixture + oráculo, origem hostil) |
| RF6 (manifesto) | `mex_evidence::{DiskEvidenceSink, Manifest}` | `package.rs` |
| RF6 (verificação) | `verify_package`, `verify_acquisition` | `package.rs`, `end_to_end.rs` |
| RF7 | `mex_storage::repo` (auditoria transacional) | `repo.rs` |
| RNF4 | Sink sem seguir links; importador sem seguir links | `planted_symlink_in_package_is_not_followed`, `hostile_source_*` |
| RNF5 | Staging + `fsync` + releitura + `rename`; selo por último | `package.rs` (cancelamento, desconexão, pacote sem selo) |

## Rastreabilidade — Milestone 5

| Requisito | Implementação | Teste |
|---|---|---|
| RF8 (relatório) | `mex_reporting::generate_report`, `html::render` | `reports.rs` (`report_is_emitted_hashed_and_recorded`, `html_is_self_contained_and_complete`) |
| RF8 (exportação) | `mex_reporting::export_package` | `reports.rs` (`export_*`, `compromised_package_is_not_exported`) |
| RF7 (exportação/transferência na custódia) | `mex_storage::reporting` (evento `exported`) | `reports.rs` |
| Referência CPP 158-A–F | `model::stage_coverage`, `LEGAL_NOTICE` | `report_is_emitted_hashed_and_recorded` |

## Rastreabilidade — Milestone 7 (parcial) e Milestone 4 (parcial)

| Requisito | Implementação | Teste |
|---|---|---|
| RNF4 (path traversal / caminhos controlados) | `mex_evidence::pkgdir` (descritores, `O_NOFOLLOW`, `RENAME_NOREPLACE`); verificação com `O_NOFOLLOW` | `hardening.rs` |
| Permissões mínimas | `0600`/`0700` em pacote, exportação, relatórios e dados do app | `hardening.rs`, `reports.rs`, `app_flow.rs` |
| Limites de recursos | Orçamento do manifesto no sink | `manifest_budget_keeps_package_verifiable` |
| Identificação do operador / confirmação | `mex_app::App` (sessão obrigatória, `operator_confirmed`) | `app_flow.rs` |
| Falhas não marcadas como completas (app encerrado) | `Storage::close_interrupted_acquisition` | `interrupted_acquisition_is_closed_on_next_open` |

## Fora de escopo (MVP, explicitamente não implementado)
- Bypass de autenticação, quebra de senhas, elevação de privilégios.
- Exploração de dispositivos de terceiros.
- Apresentar capacidades futuras/experimentais como operacionais.

## Referência jurídica
Considerar a documentação de cadeia de custódia dos arts. 158-A a 158-F do
CPP brasileiro, SEM declarar conformidade jurídica automática.
