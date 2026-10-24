#!/usr/bin/env bash
# Verificação independente do formato de hash da cadeia de auditoria V1.
#
# Reimplementa a codificação canônica (ver crates/mex-core/src/audit.rs)
# apenas com printf + sha256sum, sem nenhum código do MEX, e confere os
# eventos de tests/golden/audit_chain_v1.json. Serve como referência para
# peritos/auditores validarem o algoritmo de forma independente.
#
# Uso: bash tests/golden/verify_audit_v1.sh
set -euo pipefail
export LC_ALL=C

u64be() { printf "$(printf '%016x' "$1" | sed 's/../\\x&/g')"; }
field() { u64be "$(printf '%s' "$1" | wc -c)"; printf '%s' "$1"; }
opt()   { if [ -z "$1" ]; then printf '\x00'; else printf '\x01'; field "$1"; fi; }
# ev SEQ ID CASE_ID OPERATOR_ID KIND DETAIL AT PREV_HASH  (vazio = ausente)
ev() {
  printf 'BLACKBIT-MEX/AUDIT/V1'; u64be "$1"; field "$2"; opt "$3"; opt "$4"
  field "$5"; field "$6"; field "$7"; opt "$8"
}
check() {
  local expected="$1"; shift
  local got; got=$(ev "$@" | sha256sum | cut -d' ' -f1)
  if [ "$got" = "$expected" ]; then echo "OK    seq=$1 $got"; else echo "FALHA seq=$1 esperado=$expected obtido=$got"; return 1; fi
}

C=11111111-1111-4111-8111-111111111111
O=22222222-2222-4222-8222-222222222222
H0=da9203dec4d54b1fa67da6d20e9c6ef86340f51ccdab30c5ec404bcf1b593780
H1=ddb8ec856f9b2357a46968f472a3537f51dfb913a30b6f1fb8b300085125042f
H2=c59f71624840ee854355aa139c2d52e3502528ca866ed1098b0ed14fb7d2d032

check "$H0" 0 00000000-0000-4000-8000-000000000001 "$C" "$O" case-created \
  "Caso IP 0001/2025 aberto" 2025-01-01T12:00:00.000000Z ""
check "$H1" 1 00000000-0000-4000-8000-000000000002 "$C" "$O" authorization-recorded \
  "Mandado nº 123/2025 registrado" 2025-01-01T12:05:00.250000Z "$H0"
check "$H2" 2 00000000-0000-4000-8000-000000000003 "" "" error \
  "Falha simulada" 2025-01-01T12:06:00.000001Z "$H1"
