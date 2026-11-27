-- MPG 스키마 (테이블 10개: 기획서 8개 + path_thresholds + path_rule_overrides). 멱등: 여러 번 실행해도 안전.
-- 역할: mpg_admin(admin-api, 소유자 아님), mpg_gateway(읽기 전용, policy_versions만).

CREATE TABLE IF NOT EXISTS admin_users (
    id             SERIAL PRIMARY KEY,
    login_id       TEXT NOT NULL UNIQUE CHECK (login_id ~ '^[a-zA-Z0-9_.-]{3,32}$'),
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('VIEWER', 'OPERATOR', 'ADMIN')),
    failed_count   INT NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    disabled       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ
);

-- 작업본(draft). 발행하면 policy_versions.snapshot 으로 굳는다.
CREATE TABLE IF NOT EXISTS rules (
    id           TEXT PRIMARY KEY CHECK (id ~ '^[A-Z]{2,5}-[0-9]{3}$'),
    category     TEXT NOT NULL CHECK (category IN ('SQLI', 'XSS', 'SCR', 'CMD', 'PATH', 'FILE', 'RESP', 'ENC')),
    kind         TEXT NOT NULL DEFAULT 'regex' CHECK (kind IN ('regex', 'signal', 'analyzer')),
    pattern      TEXT,
    keywords     TEXT[] NOT NULL DEFAULT '{}',
    signal       TEXT,
    analyzer     TEXT,
    weight       INT NOT NULL CHECK (weight BETWEEN 1 AND 10),
    mode         TEXT NOT NULL CHECK (mode IN ('BLOCK', 'DETECT')),
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   TEXT
);

-- 기존 배포 업그레이드: 분류 CMD·PATH·FILE·RESP 추가
ALTER TABLE rules DROP CONSTRAINT IF EXISTS rules_category_check;
ALTER TABLE rules ADD CONSTRAINT rules_category_check
    CHECK (category IN ('SQLI', 'XSS', 'SCR', 'CMD', 'PATH', 'FILE', 'RESP', 'ENC'));

CREATE TABLE IF NOT EXISTS rule_exceptions (
    id                 SERIAL PRIMARY KEY,
    rule_id            TEXT NOT NULL REFERENCES rules(id),
    path               TEXT NOT NULL CHECK (path LIKE '/%' AND path !~ '[*?]'),
    param              TEXT NOT NULL CHECK (param <> '' AND param !~ '[*?]'),
    expires_at         TIMESTAMPTZ NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    source_request_id  UUID,
    active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_by         TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rule_exceptions_active ON rule_exceptions(active, expires_at);

-- 경로(·파라미터)별 차단 임계값. 탐지 임계값은 전역값을 유지한다.
CREATE TABLE IF NOT EXISTS path_thresholds (
    id          SERIAL PRIMARY KEY,
    path        TEXT NOT NULL CHECK (path LIKE '/%' AND path !~ '[*?]'),
    param       TEXT CHECK (param IS NULL OR (param <> '' AND param !~ '[*?]')),
    prefix      BOOLEAN NOT NULL DEFAULT FALSE,
    threshold   INT NOT NULL CHECK (threshold BETWEEN 3 AND 20),
    reason      TEXT NOT NULL DEFAULT '',
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS path_thresholds_unique_active
    ON path_thresholds(path, coalesce(param, ''), prefix) WHERE active;

CREATE TABLE IF NOT EXISTS path_rule_overrides (
    id          SERIAL PRIMARY KEY,
    path        TEXT NOT NULL CHECK (path LIKE '/%' AND path !~ '[*?]'),
    param       TEXT CHECK (param IS NULL OR (param <> '' AND param !~ '[*?]')),
    prefix      BOOLEAN NOT NULL DEFAULT FALSE,
    rule_id     TEXT NOT NULL REFERENCES rules(id),
    mode        TEXT NOT NULL CHECK (mode IN ('BLOCK', 'DETECT')),
    reason      TEXT NOT NULL DEFAULT '',
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS path_rule_overrides_unique_active
    ON path_rule_overrides(path, coalesce(param, ''), prefix, rule_id) WHERE active;

CREATE TABLE IF NOT EXISTS policy_versions (
    version       INT PRIMARY KEY,
    snapshot      JSONB NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT FALSE,
    published_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by  TEXT NOT NULL,
    comment       TEXT NOT NULL DEFAULT '',
    rolled_back_from INT
);
CREATE UNIQUE INDEX IF NOT EXISTS policy_versions_one_active ON policy_versions(active) WHERE active;

CREATE TABLE IF NOT EXISTS regression_runs (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    run_by          TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('test', 'publish', 'rejected', 'cli')),
    policy_version  INT,
    detection_rate  REAL NOT NULL,
    fp_rate         REAL NOT NULL,
    attack_total    INT NOT NULL,
    normal_total    INT NOT NULL,
    report          JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    request_id      UUID PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL,
    client_ip       INET,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    risk_score      INT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('DETECT_ONLY', 'BLOCK')),
    policy_version  INT NOT NULL,
    field_ref       TEXT NOT NULL DEFAULT '',
    masked_sample   TEXT NOT NULL DEFAULT '',
    inspect_ms      REAL,
    false_positive  BOOLEAN NOT NULL DEFAULT FALSE,
    fp_marked_by    TEXT,
    fp_marked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS security_events_ts ON security_events(ts DESC, request_id DESC);
CREATE INDEX IF NOT EXISTS security_events_action_ts ON security_events(action, ts DESC);

CREATE TABLE IF NOT EXISTS event_matches (
    id          BIGSERIAL PRIMARY KEY,
    request_id  UUID NOT NULL REFERENCES security_events(request_id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL,
    field_ref   TEXT NOT NULL,
    score       INT NOT NULL,
    mode        TEXT NOT NULL,
    excepted    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS event_matches_req ON event_matches(request_id);
CREATE INDEX IF NOT EXISTS event_matches_rule ON event_matches(rule_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    before     JSONB,
    after      JSONB,
    reason     TEXT NOT NULL DEFAULT '',
    client_ip  INET
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_ts ON audit_log(action, ts DESC);

-- 감사 기록은 추가만 가능. 권한(REVOKE)과 트리거 두 겹으로 막는다.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mpg_admin') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON admin_users, rules, rule_exceptions, policy_versions,
            regression_runs, security_events, event_matches, path_thresholds, path_rule_overrides TO mpg_admin;
        GRANT SELECT, INSERT ON audit_log TO mpg_admin;
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM mpg_admin;
        GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO mpg_admin;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mpg_gateway') THEN
        REVOKE ALL ON admin_users, rules, rule_exceptions, regression_runs, security_events,
            event_matches, audit_log, path_thresholds, path_rule_overrides FROM mpg_gateway;
        GRANT SELECT ON policy_versions TO mpg_gateway;
    END IF;
END $$;
