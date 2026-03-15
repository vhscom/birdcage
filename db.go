package main

import (
	"database/sql"
	"log/slog"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE")
}

var store *sql.DB

func initDB(path string) {
	var err error
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if path == ":memory:" {
		dsn = ":memory:?_pragma=foreign_keys(1)"
	}
	store, err = sql.Open("sqlite", dsn)
	if err != nil {
		slog.Error("database open failed", "error", err)
		os.Exit(1)
	}
	store.SetMaxOpenConns(1)
	migrate()
}

func migrate() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS account (
			id INTEGER PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_data TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS session (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES account(id),
			user_agent TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			refresh_gen INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_session_expiry ON session(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_session_user_expiry ON session(user_id, expires_at)`,
		`CREATE TABLE IF NOT EXISTS security_event (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			user_id INTEGER,
			user_agent TEXT,
			status INTEGER,
			detail TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			actor_id TEXT NOT NULL DEFAULT 'app:birdcage'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_event_type ON security_event(type)`,
		`CREATE INDEX IF NOT EXISTS idx_event_created ON security_event(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_event_user ON security_event(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_event_ip ON security_event(ip_address)`,
		`CREATE TABLE IF NOT EXISTS agent_credential (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			key_hash TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now')),
			revoked_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_active ON agent_credential(name) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS node (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			label TEXT UNIQUE NOT NULL,
			wg_pubkey TEXT NOT NULL,
			wg_endpoint TEXT,
			wg_endpoint_source TEXT NOT NULL DEFAULT 'manual',
			wg_listen_port INTEGER NOT NULL DEFAULT 51820,
			allowed_ips TEXT NOT NULL DEFAULT '10.0.0.0/32',
			persistent_keepalive INTEGER NOT NULL DEFAULT 25,
			interface_name TEXT NOT NULL DEFAULT 'wg0',
			agent_credential_id INTEGER REFERENCES agent_credential(id),
			last_seen_at TEXT,
			last_status TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_node_agent ON node(agent_credential_id)`,
	}
	for _, s := range stmts {
		if _, err := store.Exec(s); err != nil {
			slog.Error("migrate failed", "error", err, "statement", s)
			os.Exit(1)
		}
	}
}
