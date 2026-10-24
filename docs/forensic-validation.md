# Protocolo de validação forense — BlackBit MEX

## Objetivo
Comparar resultados de aquisição com conjuntos de dados conhecidos e
registrar desvios **antes** de qualquer uso pericial de um método.

## Procedimento
1. Preparar fixture determinística com conteúdo e hashes conhecidos
   (ex.: `mex_core::mock::mock_content`, ou dispositivo de laboratório com
   conjunto de arquivos semeado e inventariado).
2. Executar a aquisição/importação com o método em teste.
3. Comparar artefatos e hashes com a referência (golden).
4. Registrar, por execução:
   - itens corretos (hash idêntico);
   - **falsos positivos** (artefato relatado que não existe na referência);
   - **falsos negativos** (item da referência ausente sem registro de falha);
   - **dados não adquiridos** (ausentes, mas declarados em `not_acquired`);
   - modificações observadas no dispositivo.
5. Classificar o método: EXPERIMENTAL → UNDER_VALIDATION → VALIDATED. A
   transição para VALIDATED exige referência ao relatório desta validação
   (imposto em código e no banco).

## Regras
- Método EXPERIMENTAL nunca é habilitado automaticamente em caso judicial.
- Toda limitação observada é documentada no relatório do caso.
- Um valor golden só é aceito se tiver sido conferido por meio independente
  do código que o produziu.

## Verificação independente do formato da auditoria
`tests/golden/verify_audit_v1.sh` reimplementa a codificação canônica V1 com
`printf` e `sha256sum`, sem código do MEX, e confere os eventos de
`tests/golden/audit_chain_v1.json`. Qualquer perito pode executá-lo:

```bash
bash tests/golden/verify_audit_v1.sh
```

## Fixtures e oráculos independentes
- `tests/fixtures/local_import_v1/` — árvore determinística (nomes UTF-8,
  arquivo vazio, binário, arquivo de 1,5 MiB que exige vários blocos).
- `tests/fixtures/local_import_v1.sha256` — gerado com o `sha256sum` do
  coreutils, **não** pelo MEX. O teste
  `fixture_import_matches_independent_oracle` exige igualdade exata do
  inventário e de cada hash.
- O pacote produzido é conferido com `sha256sum --check --strict`
  (`package_is_verifiable_with_coreutils_sha256sum`).

Para conferir manualmente um pacote:

```bash
cd <raiz>/<acquisition_id>
sha256sum -c manifest.sha256 && sha256sum -c SHA256SUMS
```

E comparar o hash de `manifest.json` com o registrado no evento
`acquisition-finished` da cadeia de auditoria.

## Hardening (Milestone 7)
- Corrida real: outra thread alterna um diretório do pacote entre diretório
  e link simbólico para fora enquanto artefatos são publicados; em todas as
  execuções, 0 arquivos fora do pacote. Mutação (remover `O_NOFOLLOW`)
  detectada em 3/3 execuções.
- Fluxo do sink executado com a raiz de evidências em mídia **vfat**
  (`MEX_TEST_EVIDENCE_ROOT`); `RENAME_NOREPLACE` suportado nativamente.
- Um teste do M2 dependia do escalonador (cancelamento "após a primeira
  suspensão") e falhou 1 vez em 8 após o M7 aumentar os pontos de
  suspensão; foi reescrito de forma determinística (20/20 e 6 rodadas
  completas da suíte sem falhas).

## Relatórios (Milestone 5)
- Cada relatório executa uma verificação nova; o resultado e as divergências
  aparecem no relatório (íntegro, comprometido ou incompleto), nunca omitidos.
- Manifesto ausente ⇒ relatório emitido assim mesmo, declarando a ausência.
- O SHA-256 dos arquivos emitidos é conferido contra o registro do banco.
- A cópia exportada é conferida com `sha256sum --check --strict`.
- Não há oráculo independente para o *layout* do HTML; os testes conferem
  conteúdo, escape, ausência de recursos externos e determinismo.

## Cobertura do Milestone 2
- Importação local comparada com oráculo independente: 0 falsos positivos,
  0 falsos negativos na fixture `local_import_v1`.
- Itens não adquiridos (links, FIFOs, ilegíveis) aparecem em
  `not_acquired` e tornam o resultado `partial` — nunca silenciosos.
- Adulteração: bit invertido, truncamento, remoção, arquivo extra, link no
  lugar de artefato, manifesto editado, `SHA256SUMS` editado, path traversal
  injetado no manifesto e re-selo completo do pacote — todos detectados (o
  último somente contra o hash registrado, como esperado).

## Cobertura do Milestone 1
- Vetores SHA-256 conhecidos (FIPS 180-2: "abc", vazio, 1.000.000 × "a").
- Equivalência de hash em streaming com blocos distintos (256 MiB).
- Aquisição simulada: hash de cada artefato = hash do conteúdo de referência.
- Cancelamento, desconexão, itens não adquiridos ⇒ resultado nunca superestimado.
- Golden da cadeia de auditoria V1, conferido de forma independente.

Ainda **não** há validação com dispositivos reais: a aquisição via ADB
entra no Milestone 3. O único adaptador real (importador local) foi validado
apenas contra a fixture `local_import_v1` e a árvore hostil gerada nos testes.
