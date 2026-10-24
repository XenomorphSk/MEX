// Formatação e rótulos (funções puras, testadas em format.test.ts).

import type { AdbState, Availability, AuthorizationKind, ModificationRisk, Platform } from "./api";

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const digits = i === 0 ? 0 : v < 10 ? 2 : 1;
  return `${v.toFixed(digits).replace(".", ",")} ${units[i]}`;
}

/** Timestamp canônico UTC → "AAAA-MM-DD HH:MM:SS UTC" (sem converter fuso). */
export function formatUtc(ts: string | null | undefined): string {
  if (!ts) return "—";
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\.\d{6}Z$/.exec(ts);
  return m ? `${m[1]} ${m[2]} UTC` : ts;
}

export function shortHash(hex: string | null | undefined, n = 12): string {
  if (!hex) return "—";
  return hex.length <= n ? hex : `${hex.slice(0, n)}…`;
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

const OUTCOME: Record<string, string> = {
  complete: "Completa",
  partial: "Parcial",
  failed: "Falhou",
  cancelled: "Cancelada",
};

export function outcomeLabel(o: string | null | undefined): string {
  if (!o) return "Em curso / sem resultado";
  return OUTCOME[o] ?? o;
}

const JOB: Record<string, string> = {
  created: "Criado",
  validating: "Validando",
  ready: "Pronto",
  running: "Executando",
  finalizing: "Finalizando",
  completed: "Concluído",
  partial: "Parcial",
  failed: "Falhou",
  cancelled: "Cancelado",
};

export function jobStateLabel(s: string | null | undefined): string {
  if (!s) return "—";
  return JOB[s] ?? s;
}

const INTEGRITY: Record<string, string> = {
  intact: "Íntegro",
  compromised: "Comprometido",
  incomplete: "Incompleto",
};

export function integrityLabel(s: string | null | undefined): string {
  if (!s) return "Não verificado";
  return INTEGRITY[s] ?? s;
}

export type Tone = "ok" | "warn" | "bad" | "neutral" | "info";

export function outcomeTone(o: string | null | undefined): Tone {
  switch (o) {
    case "complete":
      return "ok";
    case "partial":
      return "warn";
    case "failed":
    case "cancelled":
      return "bad";
    default:
      return "info";
  }
}

export function integrityTone(s: string | null | undefined): Tone {
  if (s === "intact") return "ok";
  if (s === "compromised" || s === "incomplete") return "bad";
  return "neutral";
}

const AUTH: Record<AuthorizationKind, string> = {
  "judicial-warrant": "Decisão/mandado judicial",
  "owner-consent": "Consentimento do titular",
  other: "Outra base legal",
};

export function authKindLabel(k: AuthorizationKind): string {
  return AUTH[k];
}

export function platformLabel(p: Platform): string {
  return p === "android" ? "Android" : p === "ios" ? "iOS" : "Simulado";
}

export function riskLabel(r: ModificationRisk): string {
  return r === "none" ? "Nenhum conhecido" : r === "low" ? "Baixo" : "Alto";
}

export function adbStateLabel(s: AdbState | null | undefined): string {
  if (s === null || s === undefined) return "Não se aplica (sem conexão ADB)";
  if (typeof s === "object") return `Outro: ${s.other}`;
  return s === "device" ? "Depuração autorizada no aparelho" : s === "unauthorized" ? "Depuração não autorizada" : "Offline";
}

export function availabilityLabel(a: Availability): string {
  switch (a.status) {
    case "available":
      return "Disponível";
    case "unavailable":
      return `Indisponível: ${a.reason}`;
    case "not-implemented":
      return "Não implementado neste build";
  }
}

const FINDING: Record<string, string> = {
  "manifest-missing": "Manifesto ausente",
  "seal-missing": "Selo do manifesto ausente",
  "seal-malformed": "Selo do manifesto inválido",
  "seal-mismatch": "Manifesto não corresponde ao selo",
  "registered-hash-mismatch": "Manifesto difere do registrado na aquisição",
  "manifest-invalid": "Manifesto inválido",
  "manifest-inconsistent": "Manifesto incoerente",
  "sums-mismatch": "SHA256SUMS divergente",
  "artifact-missing": "Artefato ausente",
  "not-regular-file": "Não é arquivo regular",
  "size-mismatch": "Tamanho divergente",
  "hash-mismatch": "SHA-256 divergente",
  "failed-artifact-present": "Arquivo presente para artefato falho",
  "unexpected-entry": "Arquivo não consta do manifesto",
  "staging-leftover": "Área temporária remanescente",
  "read-error": "Erro de leitura",
};

export function findingLabel(kind: string): string {
  return FINDING[kind] ?? kind;
}

/** Filtro simples, sem distinção de maiúsculas, sobre vários campos. */
export function matches(query: string, ...fields: (string | null | undefined)[]): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return fields.some((f) => (f ?? "").toLowerCase().includes(q));
}
