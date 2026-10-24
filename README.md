# BlackBit MEX — Mobile Extraction Engine

Ferramenta de **aquisição forense autorizada** de dispositivos móveis, para
laboratórios periciais e investigadores autorizados. Construída em Rust com
ênfase em integridade de evidências, cadeia de custódia e rastreabilidade.

> **Escopo e ética.** O MEX realiza apenas aquisições **autorizadas** de
> dispositivos previamente autorizados e importação de backups existentes.
> **Não** implementa bypass de autenticação, quebra de senhas, exploração de
> dispositivos de terceiros ou elevação de privilégios. A presença física de
> um dispositivo nunca é tratada como autorização legal; autorizações são
> registradas explicitamente. Métodos de pesquisa são isolados, marcados por
> estado de maturidade e só podem ser usados em caso real quando VALIDATED.

## Estado atual

| Milestone | Situação |
|---|---|
| M1 Foundation, M2 Evidence Core, M5 Reporting | Concluídos |
| M4 Desktop | **Parcial:** camada de serviço (`mex-app`), casca Tauri 2 e base do frontend prontas; **telas pendentes** |
| M7 Hardening | **Parcial:** Evidence Engine ancorado em descritores (sem TOCTOU no Linux), permissões mínimas, limites coerentes, revisão de logs |
| M3 Android, M6 Research Lab | Não implementados |

| Componente | Conteúdo |
|---|---|
| `crates/mex-core` | Modelos de domínio com validação, IDs tipados, `UtcTimestamp` canônico, `EvidencePath` (anti path traversal), máquina de estados + `AcquisitionJob`, SHA-256 em streaming, cadeia de auditoria V1, traits assíncronos de plugin, cancelamento cooperativo, mock (somente dispositivos simulados) |
| `crates/mex-storage` | SQLite via SQLx, migrations embutidas, repositórios com auditoria na mesma transação |
| `crates/mex-evidence` | Gravação atômica em disco, manifesto selado, `SHA256SUMS`, verificação de integridade |
| `crates/mex-acquisition` | Motor de aquisição (job → pacote → banco → auditoria), verificação registrada, `LocalEvidenceImporter` |
| `crates/mex-reporting` | Relatório técnico JSON + HTML autocontido (verificação na emissão, custódia, art. 158-B), exportação verificada de pacotes |
| `crates/mex-app` | Camada de serviço da aplicação desktop (sessão do operador, validação, execuções em segundo plano com cancelamento, recuperação de aquisições interrompidas) |
| `apps/desktop` | Tauri 2 (comandos, CSP, capabilities mínimas), base React/TS (`api.ts`, `format.ts`); telas ainda não implementadas |
| `crates/mex-research` | Estados EXPERIMENTAL…UNSUPPORTED, política de uso em caso, matriz de compatibilidade |
| `migrations/` | 0001: 14 tabelas STRICT, CHECKs, FKs, triggers; 0002: pacote/manifesto, verificações, imutabilidade; 0003: exportações, relatórios imutáveis |
| `tests/golden` | Golden da auditoria + verificador independente em shell |

**Já é possível:** importar um backup/exportação existente (diretório) para
um pacote de evidências selado, com registro no banco, cadeia de custódia e
verificação posterior; emitir o relatório técnico (JSON/HTML) e exportar o
pacote com verificação no destino.

Demonstração com dados sintéticos (importa a fixture e emite o relatório):

```bash
cargo run -p mex-reporting --example demo_report -- /tmp/mex-demo
```

**Não implementado ainda:** ADB (M3), telas da interface desktop (M4). Nenhuma aquisição direta de dispositivo é possível ainda.

### Conferir um pacote sem o MEX

```bash
cd <raiz-de-evidências>/<acquisition_id>
sha256sum -c manifest.sha256 && sha256sum -c SHA256SUMS
```

## Build e testes

Requisitos: Rust estável ≥ 1.82. Dependências nativas: nenhuma (SQLite é
compilado junto pelo SQLx).

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
bash tests/golden/verify_audit_v1.sh
```

> **Mídia FAT/exFAT/`noexec`.** Em pendrives FAT o Cargo não consegue
> executar build scripts dentro de `target/` (sem bit de execução). Use um
> diretório de build em outro sistema de arquivos:
>
> ```bash
> export CARGO_TARGET_DIR="$HOME/.cache/blackbit-mex/target"
> ```
>
> O frontend (`apps/desktop`) usa `npm install --no-bin-links` em FAT (sem
> links simbólicos); os scripts chamam as ferramentas via `node node_modules/...`.
> Frontend: `npm test` (vitest) e `npm run build`.
>
> Em FAT a resolução de mtime é de 2 s; após editar migrations, se o teste
> parecer usar a versão antiga, rode `cargo clean -p mex-storage`.

## Estrutura

```
blackbit-mex/
├── apps/desktop/          # Tauri 2 + React (Milestone 4)
├── crates/
│   ├── mex-core/          # domínio, contratos, integridade, auditoria
│   ├── mex-storage/       # SQLite / SQLx
│   ├── mex-evidence/      # Evidence Engine (pacote, selo, verificação)
│   ├── mex-acquisition/   # motor + importador local
│   ├── mex-reporting/     # relatórios JSON/HTML + exportação verificada
│   ├── mex-app/           # camada de serviço da aplicação desktop
│   └── mex-research/      # governança de métodos de pesquisa
├── migrations/            # schema SQLite versionado
├── docs/                  # arquitetura, requisitos, ameaças, validação
└── tests/                 # golden / fixtures / integração
```

## Documentação

- `docs/architecture.md` — crates, contratos e decisões (ADRs).
- `docs/requirements.md` — requisitos e rastreabilidade.
- `docs/threat-model.md` — ameaças, mitigações e **limitações**.
- `docs/forensic-validation.md` — protocolo de validação forense.
- `docs/compatibility-matrix.md` — matriz de compatibilidade (pesquisa).

## Referência jurídica

A documentação de cadeia de custódia considera os arts. 158-A a 158-F do
CPP brasileiro. O MEX **não** declara conformidade jurídica automática: a
adequação de cada procedimento é responsabilidade do perito e da instituição.
