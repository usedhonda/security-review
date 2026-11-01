CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS deliveries_created ON deliveries(created_at);
