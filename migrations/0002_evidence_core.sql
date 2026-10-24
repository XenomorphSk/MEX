-- BlackBit MEX — Migration 0002 (Evidence Core)
--
-- * Vincula a aquisição ao pacote selado (caminho + SHA-256 do manifesto).
-- * Proveniência de data de modificação na origem.
-- * Registro append-only de verificações de integridade.
-- * Aquisição finalizada torna-se imutável.

ALTER TABLE acquisitions ADD COLUMN package_path TEXT
    CHECK (package_path IS NULL OR length(package_path) > 0);
ALTER TABLE acquisitions ADD COLUMN manifest_sha256 TEXT
    CHECK (manifest_sha256 IS NULL
           OR (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'));

ALTER TABLE artifacts ADD COLUMN source_modified TEXT
    CHECK (source_modified IS NULL OR length(source_modified) = 27);

-- Uma aquisição finalizada (outcome definido) não muda mais: o hash do
-- manifesto registrado aqui é a referência para verificações futuras.
CREATE TRIGGER acquisitions_finished_is_immutable
BEFORE UPDATE ON acquisitions
WHEN OLD.outcome IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'acquisitions: aquisição finalizada é imutável');
END;

CREATE TRIGGER acquisitions_no_delete
BEFORE DELETE ON acquisitions
BEGIN
    SELECT RAISE(ABORT, 'acquisitions: exclusão proibida');
END;

-- Pacote e manifesto só são registrados junto com a finalização.
CREATE TRIGGER acquisitions_manifest_only_on_finish
BEFORE UPDATE OF manifest_sha256, package_path ON acquisitions
WHEN NEW.outcome IS NULL
     AND (NEW.manifest_sha256 IS NOT NULL OR NEW.package_path IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'acquisitions: manifesto só pode ser registrado na finalização');
END;

CREATE TABLE integrity_verifications (
    id                  TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    acquisition_id      TEXT NOT NULL REFERENCES acquisitions(id),
    status              TEXT NOT NULL CHECK (status IN ('intact', 'compromised', 'incomplete')),
    manifest_sha256     TEXT CHECK (manifest_sha256 IS NULL
                                    OR (length(manifest_sha256) = 64
                                        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*')),
    artifacts_checked   INTEGER NOT NULL CHECK (artifacts_checked >= 0),
    bytes_verified      INTEGER NOT NULL CHECK (bytes_verified >= 0),
    findings_count      INTEGER NOT NULL CHECK (findings_count >= 0),
    findings_json       TEXT NOT NULL CHECK (json_valid(findings_json)
                                             AND json_type(findings_json) = 'array'
                                             AND json_array_length(findings_json) = findings_count),
    verified_by         TEXT NOT NULL REFERENCES operators(id),
    verified_at         TEXT NOT NULL CHECK (length(verified_at) = 27),
    CHECK ((status = 'intact') = (findings_count = 0))
) STRICT;

CREATE INDEX idx_verifications_acquisition ON integrity_verifications(acquisition_id);

CREATE TRIGGER integrity_verifications_no_update
BEFORE UPDATE ON integrity_verifications
BEGIN
    SELECT RAISE(ABORT, 'integrity_verifications: append-only');
END;

CREATE TRIGGER integrity_verifications_no_delete
BEFORE DELETE ON integrity_verifications
BEGIN
    SELECT RAISE(ABORT, 'integrity_verifications: append-only');
END;
