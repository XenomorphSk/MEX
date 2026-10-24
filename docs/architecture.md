# Arquitetura — BlackBit MEX

## Visão geral

O MEX é um workspace Rust de crates desacoplados. O núcleo (`mex-core`)
concentra domínio e contratos; os demais crates implementam transporte,
aquisição, persistência, relatórios e pesquisa dependendo apenas das
abstrações do núcleo.

```
            ┌──────────────┐
            │ apps/desktop │ (M4)
            └──────┬───────┘
   ┌───────────┬───┴────────┬──────────────┬───────────────┐
   ▼           ▼            ▼              ▼               ▼
mex-android  mex-acquisition  mex-evidence  mex-reporting  mex-research
 (M3)         (M2 ✔)           (M2 ✔)        (M5 ✔)         (M1 ✔)
   │           │   └── consulta mex-research p/ política ──┘
   └───────────┴────────────┬──────────────┘
                            ▼
              mex-core (M1 ✔)   ◄──   mex-storage (M1 ✔)
```

Regra de dependência: o Evidence Engine (`mex-evidence`) **não** depende de
`mex-research` nem de adaptadores concretos. Novos métodos de pesquisa entram
como novos adaptadores sem alterar o Evidence Engine.

## Crates

| Crate             | Responsabilidade                                              | Status          |
|-------------------|---------------------------------------------------------------|-----------------|
| `mex-core`        | Domínio, IDs, timestamps, caminhos, estado, integridade, auditoria, traits, mock | Implementado (M1) |
| `mex-storage`     | SQLite via SQLx, migrations, repositórios com auditoria transacional | Implementado (M1/M2) |
| `mex-research`    | Maturidade de métodos, política de uso, matriz de compatibilidade | Implementado (M1, modelo de domínio) |
| `mex-evidence`    | `DiskEvidenceSink`, manifesto selado, `SHA256SUMS`, `verify_package` | Implementado (M2) |
| `mex-acquisition` | Motor (`run_acquisition`, `verify_acquisition`), `LocalEvidenceImporter` | Implementado (M2) |
| `mex-devices`     | Inventário, detecção de conexão/desconexão                    | Planejado (M3)  |
| `mex-android`     | ADB: descoberta, identificação, aquisição lógica autorizada   | Planejado (M3)  |
| `mex-reporting`   | Relatório técnico JSON/HTML, exportação verificada de pacotes | Implementado (M5) |
| `mex-app`         | Camada de serviço da aplicação (sessão, validação, execuções em segundo plano, recuperação) | Implementado (M4) |
| `mex-ios`         | Importação de backup iOS                                      | Futuro          |
| `apps/desktop`    | Tauri 2 (28 comandos, CSP restrita, capabilities mínimas) + base React/TS | Parcial (M4): telas pendentes |

Crates planejados **não** existem no workspace até terem código real.

## Contratos (`mex-core::traits`)

| Trait                | Papel                                                         |
|----------------------|---------------------------------------------------------------|
| `DeviceProvider`     | Observa dispositivos (`DeviceObservation`). Não decide nada.  |
| `CapabilityResolver` | Resolve capacidades por dispositivo, com motivo quando negadas. |
| `AcquisitionAdapter` | Declara `AdapterDescriptor` (plataformas, pré-requisitos, restrições, risco, versão) e executa `acquire` gravando num `EvidenceSink`. |
| `EvidenceSink` / `ArtifactWriter` | Única fonte de verdade sobre artefatos finalizados: `commit` atômico com hash; `abort`/`drop` ⇒ `Failed`. |

`AcquisitionJob` é um **tipo concreto** (`mex-core::job`), não um trait.

## Decisões de arquitetura (ADR resumidos)

**ADR-001 — Sink é a fonte de verdade.** O adaptador não informa "sucesso";
devolve um `AdapterReport` (itens não adquiridos, limitações, operações
modificadoras). O resultado é derivado por `AcquisitionOutcome::derive` a
partir do que o sink efetivamente finalizou. Um adaptador defeituoso ou
malicioso não consegue declarar evidência completa inexistente.

**ADR-002 — Job é do motor, não do plugin.** Estados, contadores e histórico
pertencem a `AcquisitionJob`; adaptadores não pulam estados.

**ADR-003 — Timestamps com precisão fixa de microssegundos.** Formato único
`YYYY-MM-DDTHH:MM:SS.ffffffZ`. Necessário para que o hash da auditoria
sobreviva à persistência e à troca de plataforma.

**ADR-004 — Codificação canônica versionada da auditoria.** Domínio
`BLACKBIT-MEX/AUDIT/V1`, campos com prefixo de tamanho e marcador de presença,
cobrindo **todos** os campos (inclusive `seq`, `case_id`, `operator_id`).
Formato protegido por golden test e verificável de forma independente
(`tests/golden/verify_audit_v1.sh`). Mudança ⇒ novo domínio `V2`.

**ADR-005 — Dois caminhos por artefato.** `source_path` (como reportado,
não confiável, só proveniência) e `EvidencePath` (validado, único usado no
sistema de arquivos do host).

**ADR-006 — Serial não é identidade.** `devices.serial` não é único; aparelhos
distintos podem reportar o mesmo serial.

**ADR-007 — Regras forenses também no banco.** Triggers garantem auditoria
append-only e sequencial, artefato `complete` só com hash, registros finais
imutáveis e método de pesquisa nascendo `EXPERIMENTAL`. É defesa em
profundidade, não substitui a verificação criptográfica.

**ADR-008 — Plataforma `Simulated`.** O mock só aceita dispositivos simulados;
adaptadores reais devem recusá-los. Resultados simulados não se confundem com
evidência.

**ADR-009 — Somente VALIDATED em caso real.** `mex_research::case_usage`
nega qualquer outro estado. Não há override neste build.

**ADR-010 — Traits assíncronos via `async-trait`.** Necessário para objetos
de trait (`dyn AcquisitionAdapter`) em registro de plugins. O núcleo não
depende de Tokio; apenas os testes.

**ADR-011 — Dado e auditoria na mesma transação.** Todo repositório de
`mex-storage` grava o registro e o evento de auditoria numa única transação
`BEGIN IMMEDIATE`. Ou ambos persistem, ou nenhum. `BEGIN IMMEDIATE`
serializa escritores (com `BEGIN` simples, escritas concorrentes falhavam
com `database is locked` — defeito latente do M1, coberto por teste).

**ADR-012 — Pacote auto-verificável com ferramentas padrão.** `SHA256SUMS`
e `manifest.sha256` usam o formato do `sha256sum`; qualquer perito confere o
pacote com `sha256sum -c`, sem o MEX.

**ADR-013 — Selo local + hash registrado.** O selo ao lado do manifesto não
resiste a quem reescreve ambos; por isso o SHA-256 do manifesto é gravado no
banco (`acquisitions.manifest_sha256`, imutável após a finalização) e no
evento `acquisition-finished`, e `verify_acquisition` sempre compara com ele.

**ADR-014 — Artefatos não geram eventos individuais.** São cobertos pelo
hash do manifesto, auditado na finalização.

**ADR-015 — Importação preserva, não "corrige", nomes.** Nomes inválidos
como `EvidencePath` vão para `unmapped/NNNNNN`, com o caminho original
(sem perdas, inclusive bytes não UTF-8) em `source_path`.

**ADR-016 — Relatório sempre com verificação nova.** Emitir um relatório
executa e registra uma verificação de integridade naquele instante; o
relatório nunca reaproveita um resultado antigo.

**ADR-017 — Relatório como âncora externa.** O relatório traz o comprimento
da cadeia de auditoria e o hash do último evento. Impresso/assinado ou
arquivado fora do sistema, ele permite detectar truncamento posterior da
cadeia (limitação 2 do modelo de ameaças).

**ADR-018 — HTML autocontido e inerte.** Sem recursos externos, sem scripts,
com `Content-Security-Policy: default-src 'none'` e escape de todo texto.
Nomes vindos da origem são tratados como hostis.

**ADR-019 — Exportação só de pacote íntegro, verificada no destino.** A
cópia é feita em diretório temporário, verificada contra o hash registrado e
só então renomeada; pacote de origem não íntegro não é exportado.

**ADR-020 — Mapeamento do art. 158-B sem declaração de conformidade.** O
relatório indica, por etapa, o que o MEX registra, registra parcialmente ou
não registra; a avaliação jurídica fica com o perito e a autoridade.

**ADR-021 — Evidence Engine ancorado em descritores (M7).** No Linux,
todo acesso ao pacote passa por `pkgdir`, que mantém abertos os
descritores do pacote, de `artifacts/` e de `.staging/` e usa `openat`
com `O_NOFOLLOW`, `mkdirat` e `renameat2(RENAME_NOREPLACE)` via `rustix`
(API segura; `unsafe_code = forbid` preservado).

**ADR-022 — Limites coerentes entre gravação e verificação (M7).** O sink
nunca produz manifesto maior do que `verify_package` aceita.

**ADR-023 — Camada de serviço independente da interface (M4).** `mex-app`
concentra regras da aplicação e é testada sem interface gráfica; os comandos
Tauri são invólucros finos.

**ADR-024 — Recuperação de aquisições interrompidas (M4).** Ao abrir, o app
encerra como `failed` (com auditoria) aquisições sem resultado; o pacote
eventualmente gravado fica sem selo e é classificado como `incomplete`.

## Fluxo de uma aquisição (M2)

```
política ─► acquisition-started ─► job created/validating ─► resolve capacidade
   │ (recusa: evento error,              │ indisponível: failed, sem pacote
   │  nada criado)                       ▼
   │                         ready ─► pacote criado ─► running ─► adapter.acquire
   │                                                         │
   │            contadores do job a partir do SINK ◄─────────┘
   │            finalizing | cancelled (+ evento interrupted)
   │            selo: SHA256SUMS → manifest.json → manifest.sha256
   │            artefatos no banco → estado terminal
   └──────────► acquisition-finished (outcome + SHA-256 do manifesto)
```

## Máquina de estados de jobs

```
Created → Validating → Ready → Running → Finalizing → Completed
   │           │          │        │           ├────→ Partial
   └───────────┴──────────┴────────┴──→ Failed ←┘
   └───────────┴──────────┴────────┴──→ Cancelled
```

`Finalizing` não é cancelável (interromper a gravação do manifesto deixaria
o pacote inconsistente). `Failed`/`Cancelled` exigem motivo. A tabela de
transições é testada exaustivamente (9×9 pares).
