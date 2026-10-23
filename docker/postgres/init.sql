-- DarkIntel — inicializacion de PostgreSQL con pgvector.
--
-- PENDIENTE (trabajo futuro): el pipeline guarda hoy sus resultados en JSON
-- (data/output). Este esquema prepara la migración del almacenamiento y de
-- los embeddings a PostgreSQL + pgvector; ningún servicio lo usa todavía.

CREATE EXTENSION IF NOT EXISTS vector;

-- Posts crudos recolectados por el scraper.
CREATE TABLE IF NOT EXISTS posts (
    id          BIGSERIAL PRIMARY KEY,
    post_id     TEXT UNIQUE NOT NULL,
    source      TEXT,
    url         TEXT,
    lang        TEXT,
    texto       TEXT NOT NULL,
    recolectado TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- IoCs extraidos por el modulo NER.
CREATE TABLE IF NOT EXISTS iocs (
    id       BIGSERIAL PRIMARY KEY,
    post_id  TEXT REFERENCES posts(post_id) ON DELETE CASCADE,
    tipo     TEXT NOT NULL,   -- ip | ipv6 | sha256 | sha1 | md5 | cve | dominio
    valor    TEXT NOT NULL,
    UNIQUE (post_id, tipo, valor)
);

-- Embeddings para clustering. 384 dimensiones = all-MiniLM-L6-v2.
-- Cambiar la dimension si se migra a SecureBERT/DarkBERT (768).
CREATE TABLE IF NOT EXISTS embeddings (
    post_id   TEXT PRIMARY KEY REFERENCES posts(post_id) ON DELETE CASCADE,
    modelo    TEXT NOT NULL DEFAULT 'all-MiniLM-L6-v2',
    vector    vector(384),
    cluster_id INTEGER
);

-- Bundles STIX 2.1 generados por campana/cluster.
CREATE TABLE IF NOT EXISTS stix_bundles (
    id         BIGSERIAL PRIMARY KEY,
    cluster_id INTEGER NOT NULL,
    bundle     JSONB NOT NULL,
    generado   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_iocs_valor ON iocs (valor);
CREATE INDEX IF NOT EXISTS idx_iocs_tipo  ON iocs (tipo);
