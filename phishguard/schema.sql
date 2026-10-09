CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender      TEXT    NOT NULL,
    channel     TEXT    NOT NULL,          -- SMS, Email, Shared, Manual ...
    body        TEXT    NOT NULL,
    received_at TEXT    NOT NULL,          -- UTC ISO-8601
    score       INTEGER NOT NULL,          -- 0-100
    level       TEXT    NOT NULL CHECK (level IN ('low', 'medium', 'high')),
    threat_type TEXT    NOT NULL,
    status      TEXT    NOT NULL,          -- Allowed / Flagged / Blocked
    signals     TEXT    NOT NULL,          -- JSON list of {label, why}
    archived    INTEGER NOT NULL DEFAULT 0 -- 1 = cleared from the inbox view
);

CREATE INDEX IF NOT EXISTS idx_messages_received ON messages (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_level ON messages (level);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('access', '0');
