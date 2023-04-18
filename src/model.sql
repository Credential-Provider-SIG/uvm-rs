CREATE TABLE IF NOT EXISTS passkeys (
    "id"        TEXT PRIMARY KEY NOT NULL,
    "rp_id"     TEXT NOT NULL,
    "rp_name"   TEXT NOT NULL,
    "user_id"   TEXT NOT NULL,
    "username"  TEXT NOT NULL,
    "counter"   INTEGER DEFAULT 0 NOT NULL,
    "key"       TEXT NOT NULL
);