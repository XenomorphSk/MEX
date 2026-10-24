# Modelo de ameaças — BlackBit MEX

## Ativos
- Evidências adquiridas e seus hashes.
- Cadeia de custódia (`audit_events`).
- Metadados de caso, autorização e operador.
- Catálogo de pesquisa (métodos e seus estados de maturidade).

## Ameaças e mitigações

| Ameaça | Mitigação | Estado |
|---|---|---|
| Adulteração de artefato | SHA-256 por artefato no `commit`; re-verificação posterior | Núcleo (M1); verificação em disco no M2 |
| Evidência parcial marcada como completa | `ArtifactWriter`: `abort`/`drop` ⇒ `Failed`; trigger exige hash para `complete`; `AcquisitionOutcome::derive` conservador; pacote sem selo ⇒ `Incomplete` | M1/M2 |
| Adaptador declara sucesso falso | Resultado derivado do sink, não do adaptador (ADR-001) | M1 |
| Sobrescrita de artefato finalizado | Sink recusa caminho já finalizado; `UNIQUE(acquisition_id, stored_path)`; trigger de imutabilidade | M1 |
| Adulteração de evento de auditoria | Hash encadeado sobre **todos** os campos; triggers append-only | M1 |
| Reatribuição de evento a outro operador/caso | `case_id`/`operator_id` dentro do hash (corrigido no M1; a versão anterior não os cobria) | M1 |
| Remoção/inserção/reordenação de eventos | `seq` + `prev_hash` no hash; trigger sequencial | M1 |
| Path traversal / escrita fora do pacote | `EvidencePath` (rejeita `..`, absolutos, `\`, `:`, nomes reservados do Windows, controle) | M1 |
| Escrita do pacote desviada por link simbólico plantado | M2: checagem por caminho. **M7 (Linux): operações ancoradas em descritores mantidos abertos, `openat(O_NOFOLLOW)` por componente, `renameat2(RENAME_NOREPLACE)`** — teste de corrida real com mutação | M2/M7 |
| Pacote grande demais para ser verificado | Orçamento do manifesto no sink (≤ limite do verificador); `finalize` recusa manifesto acima do limite | M7 |
| Acesso de outros usuários do host às evidências | Arquivos `0600`, diretórios `0700` (pacote, cópias exportadas, relatórios, diretório de dados do app) | M7 |
| Nomes de arquivos da origem vazando para logs | Removidos do log; registrados apenas no inventário | M7 |
| Artefato trocado por link durante a verificação | Leitura com `O_NOFOLLOW`; tipo e tamanho conferidos no descritor que é lido | M7 |
| Artefato publicado com conteúdo diferente do hash | `fsync` + releitura com hash antes do `rename` | M2 |
| Colisão de nomes sem distinção de maiúsculas (NTFS/FAT) | Sink recusa; importador grava em `unmapped/` | M2 |
| Manifesto e selo reescritos juntos | Comparação com o hash registrado no banco/auditoria (`verify_acquisition`) | M2 |
| Importação segue link para fora da origem | Links não seguidos; conferência dev+inode após abrir | M2 |
| Importar o próprio pacote (recursão) | Origem e destino não podem conter um ao outro | M2 |
| Dado gravado sem evento de auditoria (ou vice-versa) | Mesma transação (ADR-011) | M2 |
| Injeção de HTML/script via nomes de arquivo da origem | Escape de todo texto; CSP `default-src 'none'`; sem recursos externos (teste com mutação) | M5 |
| Relatório adulterado após emissão | SHA-256 de cada arquivo registrado no banco e no evento `exported` | M5 |
| Exportação de pacote já adulterado / cópia corrompida | Origem verificada antes; cópia verificada no destino contra o hash registrado antes do `rename` | M5 |
| Relatório gravado dentro do pacote selado | Recusado | M5 |
| Injeção de comando | Processos sem shell, argumentos explícitos | Requisito para M3 (ADB) |
| Método experimental usado em caso | `case_usage` só permite VALIDATED; método nasce EXPERIMENTAL (também no banco) | M1 |
| Confusão de dispositivos com mesmo serial | Serial não é chave única | M1 |
| Vazamento de conteúdo sensível em logs | `detail` de auditoria é texto do operador/sistema; conteúdo de evidência nunca vai ao banco | Política; revisar no M7 |

## Limitações conhecidas (documentadas)

1. **Hash chain não é assinatura.** Quem controla o arquivo do banco pode
   remover os triggers e **reescrever a cadeia inteira**, recalculando todos
   os hashes. A cadeia detecta adulteração parcial, não reescrita completa.
   Evolução prevista: assinatura por operador (chave em token/smartcard),
   carimbo de tempo confiável (RFC 3161) e cópia em armazenamento WORM.
2. **Truncamento não é detectável sozinho.** Remover os últimos eventos
   produz uma cadeia válida mais curta. Mitigação disponível (M5): o
   relatório técnico registra comprimento e hash da cabeça da cadeia; se
   arquivado fora do sistema, serve de âncora. Mitigação prevista: ancorar
   periodicamente o `entry_hash` mais recente fora do sistema (relatório
   impresso/assinado, carimbo de tempo).
3. **Concorrência de escrita na auditoria.** Escritas são serializadas por
   `BEGIN IMMEDIATE` + `busy_timeout` de 5 s (M2). Sob contenção maior que
   esse tempo, a escrita falha com erro — a cadeia nunca bifurca (PK `seq` +
   trigger) e nenhum dado fica sem seu evento.
4. **Identificação do dispositivo é auto-declarada.** Fabricante, modelo,
   versão e serial vêm do próprio aparelho.
5. **"device" no ADB não é autorização legal.** Indica apenas depuração
   autorizada no aparelho. A autorização legal é registrada à parte; o MEX
   não avalia sua validade jurídica.
6. **Colisão de nomes sem distinção de maiúsculas.** Resolvido no M2 por
   comparação em minúsculas (Unicode simples). Normalização Unicode
   (NFC/NFD, relevante no macOS) ainda não é tratada.
7. **Relógio do host.** Timestamps vêm do relógio local, sem fonte confiável.
   A ordem da cadeia é dada por `seq`, não por `at`.
8. **TOCTOU no diretório do pacote — resolvido no Linux (M7).** Operações
   relativas a descritores abertos na criação do pacote. Residual: (a) em
   sistemas de arquivos sem `RENAME_NOREPLACE` usa-se `statat` + `renameat`
   no mesmo descritor (janela só para quem escreve naquele diretório);
   `RENAME_NOREPLACE` foi confirmado em tmpfs e vfat neste ambiente; (b) em
   outras plataformas permanece a implementação por caminhos.
9. **Releitura após gravação usa o cache do SO.** Detecta erros de software
   (truncamento, bug de sistema de arquivos, modificação concorrente), não
   necessariamente defeitos da mídia. Para mídia, verificar o pacote após
   desmontar/remontar (`verify_package`).
10. **`fsync` de diretório** pode não existir (Windows, alguns FAT); a falha
    é registrada em log e não interrompe a gravação.
11. **atime da origem.** O importador abre a origem só para leitura, mas o
    SO pode atualizar o *atime*. Recomenda-se montar a origem somente leitura.
12. **Selo não é assinatura.** Ver item 1; a assinatura do manifesto entra
    junto com a assinatura da auditoria.
13. **Relatório não é assinado digitalmente.** Seu hash fica no banco e na
    cadeia, sujeitos às limitações 1 e 2; há campo para assinatura manual.
14. **Verificação da exportação usa o cache do SO** (como o item 9);
    verificar novamente após remontar a mídia de destino.
15. **Permissões em FAT/exFAT.** Esses sistemas de arquivos não têm
    permissões Unix; o controle de acesso depende das opções de montagem.
    A tentativa de restringir é registrada em log quando falha.
16. **Auditoria de dependências Rust** (`cargo audit`) não foi executada:
    a ferramenta não está instalada. `npm audit`: 0 vulnerabilidades (M7).
