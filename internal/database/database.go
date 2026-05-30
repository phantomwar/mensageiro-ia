package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool.Pool to interact with PostgreSQL.
type DB struct {
	Pool *pgxpool.Pool
}

// NewDB connects to PostgreSQL using the provided connection string.
func NewDB(connStr string) (*DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database url: %w", err)
	}

	// Adjust pool configurations
	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	// Ping database to verify connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close closes the underlying connection pool.
func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// InitSchema applies the initial database schema if tables don't exist.
// This matches Section 16 of PROJETO.md and the extended ACL/bootstrap specifications.
func (db *DB) InitSchema(ctx context.Context) error {
	schemaQuery := `
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

	CREATE TABLE IF NOT EXISTS agents (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		agent_id VARCHAR(128) UNIQUE NOT NULL,
		api_key_hash VARCHAR(255) NOT NULL,
		public_key TEXT NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'active',
		metadata JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS capabilities (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		capability VARCHAR(100) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(agent_id, capability)
	);

	CREATE TABLE IF NOT EXISTS agent_acls (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		action_type VARCHAR(10) NOT NULL CHECK (action_type IN ('publish', 'subscribe')),
		subject VARCHAR(255) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(agent_id, action_type, subject)
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		event_type VARCHAR(50) NOT NULL,
		actor_id VARCHAR(100) NOT NULL,
		metadata JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
	CREATE INDEX IF NOT EXISTS idx_capabilities_capability ON capabilities(capability);
	CREATE INDEX IF NOT EXISTS idx_agent_acls_agent_id ON agent_acls(agent_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	`
	_, err := db.Pool.Exec(ctx, schemaQuery)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	return nil
}
