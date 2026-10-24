-- BlackBit MEX — Migration 0003 (Reporting & Export)
--
-- * Relatórios gerados são registros imutáveis (hash do arquivo emitido).
-- * Exportações de pacotes de evidência: registro append-only, com o
--   resultado da verificação da cópia no destino.

CREATE UNIQUE INDEX idx_reports_stored_path ON reports(stored_path);

CREATE TRIGGER reports_no_update
BEFORE UPDATE ON reports
BEGIN
    SELECT RAISE(ABORT, 'reports: registro imutável');
END;

CREATE TRIGGER reports_no_delete
BEFORE DELETE ON reports
BEGIN
    SELECT RAISE(ABORT, 'reports: exclusão proibida');
END;

CREATE TABLE evidence_exports (
    id                TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    acquisition_id    TEXT NOT NULL REFERENCES acquisitions(id),
    destination       TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 4096),
    manifest_sha256   TEXT NOT NULL CHECK (length(manifest_sha256) = 64
                                           AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    -- Resultado da verificação da CÓPIA, feita no destino após a cópia.
    status            TEXT NOT NULL CHECK (status IN ('intact', 'compromised', 'incomplete')),
    files_copied      INTEGER NOT NULL CHECK (files_copied >= 0),
    bytes_copied      INTEGER NOT NULL CHECK (bytes_copied >= 0),
    exported_by       TEXT NOT NULL REFERENCES operators(id),
    exported_at       TEXT NOT NULL CHECK (length(exported_at) = 27)
) STRICT;

CREATE INDEX idx_exports_acquisition ON evidence_exports(acquisition_id);

CREATE TRIGGER evidence_exports_no_update
BEFORE UPDATE ON evidence_exports
BEGIN
    SELECT RAISE(ABORT, 'evidence_exports: append-only');
END;

CREATE TRIGGER evidence_exports_no_delete
BEFORE DELETE ON evidence_exports
BEGIN
    SELECT RAISE(ABORT, 'evidence_exports: append-only');
END;
