-- BlackBit MEX — Migration 0001 (schema inicial)
--
-- Convenções:
--   * Tabelas STRICT (tipagem rígida do SQLite >= 3.37).
--   * IDs: UUID em texto hifenizado minúsculo (36 caracteres).
--   * Timestamps: UTC canônico 'YYYY-MM-DDTHH:MM:SS.ffffffZ' (27 caracteres),
--     ver mex_core::timestamp. Largura fixa => ordenação textual = temporal.
--   * Hashes: SHA-256 em hex minúsculo (64 caracteres).
--   * Enums: os valores aceitos nos CHECK espelham os `as_str()` do Rust;
--     testes em mex-storage verificam a correspondência variante a variante.
--   * Conteúdo de evidência NUNCA é armazenado no banco; apenas metadados.
--   * `PRAGMA foreign_keys` é ativado na conexão (mex-storage), não aqui:
--     dentro da transação da migration o PRAGMA não tem efeito.

-- ------------------------------------------------------------------ pessoas

CREATE TABLE operators (
    id            TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    full_name     TEXT NOT NULL CHECK (length(trim(full_name)) > 0),
    badge         TEXT NOT NULL CHECK (length(trim(badge)) > 0),
    organization  TEXT NOT NULL CHECK (length(trim(organization)) > 0),
    active        INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at    TEXT NOT NULL CHECK (length(created_at) = 27),
    UNIQUE (organization, badge)
) STRICT;

-- -------------------------------------------------------------------- casos

CREATE TABLE cases (
    id          TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    number      TEXT NOT NULL UNIQUE CHECK (length(trim(number)) > 0),
    title       TEXT NOT NULL CHECK (length(trim(title)) > 0),
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_by  TEXT NOT NULL REFERENCES operators(id),
    created_at  TEXT NOT NULL CHECK (length(created_at) = 27)
) STRICT;

CREATE TABLE authorizations (
    id               TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    case_id          TEXT NOT NULL REFERENCES cases(id),
    kind             TEXT NOT NULL CHECK (kind IN ('judicial-warrant', 'owner-consent', 'other')),
    kind_detail      TEXT,
    reference        TEXT NOT NULL CHECK (length(trim(reference)) > 0),
    issuer           TEXT NOT NULL CHECK (length(trim(issuer)) > 0),
    scope_notes      TEXT,
    document_sha256  TEXT CHECK (document_sha256 IS NULL
                                 OR (length(document_sha256) = 64
                                     AND document_sha256 NOT GLOB '*[^0-9a-f]*')),
    recorded_by      TEXT NOT NULL REFERENCES operators(id),
    recorded_at      TEXT NOT NULL CHECK (length(recorded_at) = 27),
    -- "other" exige descrição da base legal.
    CHECK (kind <> 'other' OR length(trim(coalesce(kind_detail, ''))) > 0),
    -- Alvo da FK composta em acquisitions (autorização do mesmo caso).
    UNIQUE (id, case_id)
) STRICT;

-- -------------------------------------------------------------- dispositivos

-- O serial NÃO é único: aparelhos distintos podem reportar o mesmo valor.
CREATE TABLE devices (
    id               TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    platform         TEXT NOT NULL CHECK (platform IN ('android', 'ios', 'simulated')),
    serial           TEXT NOT NULL,
    manufacturer     TEXT,
    model            TEXT,
    os_version       TEXT,
    security_patch   TEXT,
    adb_state        TEXT,   -- rótulo original (device|unauthorized|offline|...)
    first_seen       TEXT NOT NULL CHECK (length(first_seen) = 27),
    last_seen        TEXT NOT NULL CHECK (length(last_seen) = 27),
    CHECK (last_seen >= first_seen)
) STRICT;

-- ---------------------------------------------------------------- aquisições

CREATE TABLE acquisitions (
    id                TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    case_id           TEXT NOT NULL REFERENCES cases(id),
    device_id         TEXT NOT NULL REFERENCES devices(id),
    authorization_id  TEXT NOT NULL,
    operator_id       TEXT NOT NULL REFERENCES operators(id),
    capability_kind   TEXT NOT NULL CHECK (capability_kind IN (
                          'device-info', 'android-logical', 'local-import', 'file-system',
                          'privileged', 'advanced-research', 'ios-backup')),
    adapter_id        TEXT NOT NULL CHECK (length(adapter_id) > 0),
    adapter_version   TEXT NOT NULL CHECK (length(adapter_version) > 0),
    software_version  TEXT NOT NULL CHECK (length(software_version) > 0),
    outcome           TEXT CHECK (outcome IN ('complete', 'partial', 'failed', 'cancelled')),
    limitations_json  TEXT NOT NULL DEFAULT '[]'
                      CHECK (json_valid(limitations_json) AND json_type(limitations_json) = 'array'),
    started_at        TEXT NOT NULL CHECK (length(started_at) = 27),
    finished_at       TEXT CHECK (finished_at IS NULL OR length(finished_at) = 27),
    -- A autorização invocada precisa pertencer ao mesmo caso.
    FOREIGN KEY (authorization_id, case_id) REFERENCES authorizations(id, case_id),
    -- Resultado e fim são preenchidos juntos.
    CHECK ((outcome IS NULL) = (finished_at IS NULL)),
    CHECK (finished_at IS NULL OR finished_at >= started_at)
) STRICT;

CREATE TABLE acquisition_jobs (
    id                   TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    acquisition_id       TEXT NOT NULL REFERENCES acquisitions(id),
    state                TEXT NOT NULL CHECK (state IN (
                             'created', 'validating', 'ready', 'running', 'finalizing',
                             'completed', 'partial', 'failed', 'cancelled')),
    bytes_acquired       INTEGER NOT NULL DEFAULT 0 CHECK (bytes_acquired >= 0),
    bytes_total          INTEGER CHECK (bytes_total IS NULL OR bytes_total >= 0),
    artifacts_completed  INTEGER NOT NULL DEFAULT 0 CHECK (artifacts_completed >= 0),
    artifacts_failed     INTEGER NOT NULL DEFAULT 0 CHECK (artifacts_failed >= 0),
    created_at           TEXT NOT NULL CHECK (length(created_at) = 27),
    updated_at           TEXT NOT NULL CHECK (length(updated_at) = 27)
) STRICT;

-- ---------------------------------------------------------------- artefatos

CREATE TABLE artifacts (
    id              TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    acquisition_id  TEXT NOT NULL REFERENCES acquisitions(id),
    stored_path     TEXT NOT NULL CHECK (length(stored_path) BETWEEN 1 AND 1024
                                         AND substr(stored_path, 1, 1) <> '/'),
    source_path     TEXT,    -- como reportado pela origem; não confiável
    size_bytes      INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    status          TEXT NOT NULL CHECK (status IN ('pending', 'complete', 'failed')),
    failure_reason  TEXT,
    created_at      TEXT NOT NULL CHECK (length(created_at) = 27),
    completed_at    TEXT CHECK (completed_at IS NULL OR length(completed_at) = 27),
    UNIQUE (acquisition_id, stored_path),
    CHECK ((status = 'complete') = (completed_at IS NOT NULL)),
    CHECK ((status = 'failed') = (failure_reason IS NOT NULL))
) STRICT;

CREATE TABLE artifact_hashes (
    artifact_id  TEXT NOT NULL REFERENCES artifacts(id),
    alg          TEXT NOT NULL CHECK (alg IN ('sha-256')),
    hex          TEXT NOT NULL CHECK (length(hex) = 64 AND hex NOT GLOB '*[^0-9a-f]*'),
    computed_at  TEXT NOT NULL CHECK (length(computed_at) = 27),
    PRIMARY KEY (artifact_id, alg)
) STRICT;

-- Um artefato só pode nascer 'pending' ou 'failed'; 'complete' exige que o
-- hash SHA-256 já esteja registrado. Garante no banco a regra "nenhuma
-- evidência completa sem hash".
CREATE TRIGGER artifacts_insert_not_complete
BEFORE INSERT ON artifacts
WHEN NEW.status = 'complete'
BEGIN
    SELECT RAISE(ABORT, 'artifacts: inserir como complete é proibido; use pending + hash + update');
END;

CREATE TRIGGER artifacts_complete_requires_hash
BEFORE UPDATE OF status ON artifacts
WHEN NEW.status = 'complete'
     AND NOT EXISTS (SELECT 1 FROM artifact_hashes
                     WHERE artifact_id = NEW.id AND alg = 'sha-256')
BEGIN
    SELECT RAISE(ABORT, 'artifacts: complete exige hash sha-256 registrado');
END;

-- Estados finais de artefato são imutáveis.
CREATE TRIGGER artifacts_final_is_immutable
BEFORE UPDATE ON artifacts
WHEN OLD.status IN ('complete', 'failed')
BEGIN
    SELECT RAISE(ABORT, 'artifacts: registro finalizado é imutável');
END;

CREATE TRIGGER artifacts_no_delete
BEFORE DELETE ON artifacts
BEGIN
    SELECT RAISE(ABORT, 'artifacts: exclusão proibida');
END;

CREATE TRIGGER artifact_hashes_no_update
BEFORE UPDATE ON artifact_hashes
BEGIN
    SELECT RAISE(ABORT, 'artifact_hashes: registro imutável');
END;

CREATE TRIGGER artifact_hashes_no_delete
BEFORE DELETE ON artifact_hashes
BEGIN
    SELECT RAISE(ABORT, 'artifact_hashes: exclusão proibida');
END;

-- ------------------------------------------------------- cadeia de custódia

CREATE TABLE audit_events (
    seq          INTEGER PRIMARY KEY NOT NULL CHECK (seq >= 0),
    id           TEXT NOT NULL UNIQUE CHECK (length(id) = 36),
    case_id      TEXT REFERENCES cases(id),
    operator_id  TEXT REFERENCES operators(id),
    kind         TEXT NOT NULL CHECK (kind IN (
                     'operator-registered', 'case-created', 'authorization-recorded',
                     'device-registered', 'acquisition-started', 'operation-executed',
                     'job-state-changed', 'acquisition-finished', 'error', 'interrupted',
                     'integrity-verified', 'exported', 'transferred')),
    detail       TEXT NOT NULL CHECK (length(detail) BETWEEN 1 AND 4096),
    at           TEXT NOT NULL CHECK (length(at) = 27),
    prev_hash    TEXT CHECK (prev_hash IS NULL
                             OR (length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*')),
    entry_hash   TEXT NOT NULL UNIQUE
                 CHECK (length(entry_hash) = 64 AND entry_hash NOT GLOB '*[^0-9a-f]*'),
    -- Somente o primeiro evento não tem antecessor.
    CHECK ((seq = 0) = (prev_hash IS NULL))
) STRICT;

-- Append-only no nível do banco. Não protege contra quem tem acesso direto
-- ao arquivo e remove os triggers (ver docs/threat-model.md); a detecção
-- nesse caso depende da verificação da cadeia e de âncoras externas.
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events: append-only, atualização proibida');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events: append-only, exclusão proibida');
END;

-- O novo evento precisa ser exatamente o sucessor do último.
CREATE TRIGGER audit_events_sequential
BEFORE INSERT ON audit_events
WHEN NEW.seq <> coalesce((SELECT max(seq) FROM audit_events) + 1, 0)
  OR coalesce(NEW.prev_hash, '') <>
     coalesce((SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1), '')
BEGIN
    SELECT RAISE(ABORT, 'audit_events: evento fora de sequência ou prev_hash divergente');
END;

-- ---------------------------------------------------------------- relatórios

CREATE TABLE reports (
    id              TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    case_id         TEXT NOT NULL REFERENCES cases(id),
    acquisition_id  TEXT REFERENCES acquisitions(id),
    format          TEXT NOT NULL CHECK (format IN ('json', 'html')),
    stored_path     TEXT NOT NULL CHECK (length(stored_path) BETWEEN 1 AND 1024),
    sha256          TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    generated_by    TEXT NOT NULL REFERENCES operators(id),
    generated_at    TEXT NOT NULL CHECK (length(generated_at) = 27)
) STRICT;

-- ------------------------------------------- pesquisa (isolada da evidência)
-- Nenhuma tabela de evidência referencia estas tabelas.

CREATE TABLE research_devices (
    id                 TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    label              TEXT NOT NULL UNIQUE CHECK (length(trim(label)) > 0),
    manufacturer       TEXT,
    model              TEXT,
    hardware_revision  TEXT,
    firmware           TEXT,
    os_version         TEXT,
    security_patch     TEXT,
    notes              TEXT,
    created_at         TEXT NOT NULL CHECK (length(created_at) = 27)
) STRICT;

CREATE TABLE research_methods (
    id                        TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    name                      TEXT NOT NULL CHECK (length(trim(name)) > 0),
    version                   TEXT NOT NULL CHECK (length(trim(version)) > 0),
    capability_kind           TEXT NOT NULL CHECK (capability_kind IN (
                                  'device-info', 'android-logical', 'local-import', 'file-system',
                                  'privileged', 'advanced-research', 'ios-backup')),
    hypothesis                TEXT NOT NULL CHECK (length(trim(hypothesis)) > 0),
    preconditions_json        TEXT NOT NULL DEFAULT '[]'
                              CHECK (json_valid(preconditions_json) AND json_type(preconditions_json) = 'array'),
    known_modifications_json  TEXT NOT NULL DEFAULT '[]'
                              CHECK (json_valid(known_modifications_json) AND json_type(known_modifications_json) = 'array'),
    status                    TEXT NOT NULL DEFAULT 'EXPERIMENTAL' CHECK (status IN (
                                  'EXPERIMENTAL', 'UNDER_VALIDATION', 'VALIDATED',
                                  'DEPRECATED', 'UNSUPPORTED')),
    created_at                TEXT NOT NULL CHECK (length(created_at) = 27),
    updated_at                TEXT NOT NULL CHECK (length(updated_at) = 27),
    UNIQUE (name, version)
) STRICT;

-- Todo método nasce EXPERIMENTAL.
CREATE TRIGGER research_methods_insert_experimental
BEFORE INSERT ON research_methods
WHEN NEW.status <> 'EXPERIMENTAL'
BEGIN
    SELECT RAISE(ABORT, 'research_methods: método deve ser cadastrado como EXPERIMENTAL');
END;

CREATE TABLE research_method_status_history (
    id                    INTEGER PRIMARY KEY,
    research_method_id    TEXT NOT NULL REFERENCES research_methods(id),
    from_status           TEXT NOT NULL,
    to_status             TEXT NOT NULL,
    changed_by            TEXT NOT NULL REFERENCES operators(id),
    justification         TEXT NOT NULL CHECK (length(trim(justification)) > 0),
    validation_reference  TEXT,
    changed_at            TEXT NOT NULL CHECK (length(changed_at) = 27),
    CHECK (to_status <> 'VALIDATED' OR length(trim(coalesce(validation_reference, ''))) > 0)
) STRICT;

CREATE TABLE compatibility_results (
    id                           TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    research_device_id           TEXT NOT NULL REFERENCES research_devices(id),
    research_method_id           TEXT NOT NULL REFERENCES research_methods(id),
    method_version               TEXT NOT NULL CHECK (length(trim(method_version)) > 0),
    firmware_tested              TEXT,
    os_version_tested            TEXT,
    outcome                      TEXT NOT NULL CHECK (outcome IN ('success', 'partial', 'failure', 'inconclusive')),
    observed_modifications_json  TEXT NOT NULL DEFAULT '[]'
                                 CHECK (json_valid(observed_modifications_json)
                                        AND json_type(observed_modifications_json) = 'array'),
    notes                        TEXT,
    tested_by                    TEXT NOT NULL REFERENCES operators(id),
    tested_at                    TEXT NOT NULL CHECK (length(tested_at) = 27)
) STRICT;

-- ------------------------------------------------------------------- índices

CREATE INDEX idx_authorizations_case   ON authorizations(case_id);
CREATE INDEX idx_devices_serial        ON devices(serial);
CREATE INDEX idx_acquisitions_case     ON acquisitions(case_id);
CREATE INDEX idx_acquisitions_device   ON acquisitions(device_id);
CREATE INDEX idx_jobs_acquisition      ON acquisition_jobs(acquisition_id);
CREATE INDEX idx_artifacts_acquisition ON artifacts(acquisition_id);
CREATE INDEX idx_audit_case            ON audit_events(case_id);
CREATE INDEX idx_reports_case          ON reports(case_id);
CREATE INDEX idx_method_history        ON research_method_status_history(research_method_id);
CREATE INDEX idx_compat_device         ON compatibility_results(research_device_id);
CREATE INDEX idx_compat_method         ON compatibility_results(research_method_id);
