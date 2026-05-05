-- ASM Engine schema — executed automatically by Postgres on first container start.
-- This DDL is kept in sync with the `schema` constant in internal/storage/postgres_store.go.
-- All statements use IF NOT EXISTS so re-running is safe.

CREATE TABLE IF NOT EXISTS assets (
    domain     TEXT        PRIMARY KEY,
    ips        TEXT[]      NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    asset_domain TEXT        NOT NULL REFERENCES assets(domain) ON DELETE CASCADE,
    ip           TEXT        NOT NULL,
    number       INTEGER     NOT NULL,
    proto        TEXT        NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (asset_domain, ip, number, proto)
);

CREATE TABLE IF NOT EXISTS services (
    asset_domain TEXT        NOT NULL,
    ip           TEXT        NOT NULL,
    port_number  INTEGER     NOT NULL,
    proto        TEXT        NOT NULL,
    name         TEXT        NOT NULL DEFAULT '',
    version      TEXT        NOT NULL DEFAULT '',
    banner       TEXT        NOT NULL DEFAULT '',
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (asset_domain, ip, port_number, proto),
    FOREIGN KEY (asset_domain, ip, port_number, proto)
        REFERENCES ports(asset_domain, ip, number, proto) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bucket_results (
    url        TEXT        PRIMARY KEY,
    domain     TEXT        NOT NULL,
    provider   TEXT        NOT NULL,
    status     INTEGER     NOT NULL,
    accessible BOOLEAN     NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ports_asset_domain    ON ports(asset_domain);
CREATE INDEX IF NOT EXISTS idx_services_asset_domain ON services(asset_domain);
CREATE INDEX IF NOT EXISTS idx_buckets_domain        ON bucket_results(domain);
