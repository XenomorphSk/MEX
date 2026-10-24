import { describe, expect, it } from "vitest";
import {
  adbStateLabel,
  availabilityLabel,
  findingLabel,
  formatBytes,
  formatUtc,
  integrityTone,
  matches,
  outcomeLabel,
  outcomeTone,
  shortHash,
} from "./format";

describe("formatBytes", () => {
  it("usa unidades binárias e vírgula decimal", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1,00 KiB");
    expect(formatBytes(1572869)).toBe("1,50 MiB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5,00 GiB");
  });
  it("rejeita valores inválidos", () => {
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
  });
});

describe("formatUtc", () => {
  it("mantém UTC e remove microssegundos", () => {
    expect(formatUtc("2025-03-01T13:00:00.123456Z")).toBe("2025-03-01 13:00:00 UTC");
  });
  it("não reinterpreta formatos inesperados", () => {
    expect(formatUtc("2025-03-01T13:00:00Z")).toBe("2025-03-01T13:00:00Z");
    expect(formatUtc(null)).toBe("—");
  });
});

describe("rótulos", () => {
  it("resultado ausente nunca aparece como sucesso", () => {
    expect(outcomeLabel(null)).toBe("Em curso / sem resultado");
    expect(outcomeTone(null)).toBe("info");
    expect(outcomeTone("partial")).toBe("warn");
    expect(outcomeTone("cancelled")).toBe("bad");
  });
  it("integridade não verificada é neutra, não ok", () => {
    expect(integrityTone(null)).toBe("neutral");
    expect(integrityTone("incomplete")).toBe("bad");
  });
  it("estado ADB preserva rótulo desconhecido", () => {
    expect(adbStateLabel({ other: "recovery" })).toBe("Outro: recovery");
    expect(adbStateLabel(null)).toContain("Não se aplica");
  });
  it("disponibilidade inclui o motivo", () => {
    expect(availabilityLabel({ status: "unavailable", reason: "origem inacessível" })).toBe(
      "Indisponível: origem inacessível",
    );
  });
  it("divergência desconhecida mostra o código original", () => {
    expect(findingLabel("hash-mismatch")).toBe("SHA-256 divergente");
    expect(findingLabel("novo-tipo")).toBe("novo-tipo");
  });
});

describe("utilitários", () => {
  it("abrevia hashes", () => {
    expect(shortHash("abcdef0123456789", 6)).toBe("abcdef…");
    expect(shortHash(null)).toBe("—");
  });
  it("filtra sem distinção de maiúsculas", () => {
    expect(matches("dcim", "files/sdcard/DCIM/a.bin")).toBe(true);
    expect(matches("xyz", "abc", null)).toBe(false);
    expect(matches("  ", "abc")).toBe(true);
  });
});
