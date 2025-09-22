CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT,
    username TEXT,
    event_id INTEGER,
    risk_level TEXT,
    score REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
