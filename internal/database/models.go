package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrAgentNotFound = errors.New("agent not found")
)

type Agent struct {
	ID         uuid.UUID       `json:"id"`
	AgentID    string          `json:"agent_id"`
	APIKeyHash string          `json:"-"`
	PublicKey  string          `json:"public_key"`
	Status     string          `json:"status"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type ACLRule struct {
	ActionType string `json:"action_type"` // 'publish' or 'subscribe'
	Subject    string `json:"subject"`
}

// CreateAgent registers a new agent in the system, hashing the bootstrap api_key using bcrypt.
func (db *DB) CreateAgent(ctx context.Context, agentID, apiKey, publicKey, status string, metadata []byte) (*Agent, error) {
	// Hash API key
	apiKeyHashBytes, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash api key: %w", err)
	}
	apiKeyHash := string(apiKeyHashBytes)

	if metadata == nil {
		metadata = []byte("{}")
	}

	query := `
	INSERT INTO agents (agent_id, api_key_hash, public_key, status, metadata)
	VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT (agent_id) DO UPDATE 
	SET api_key_hash = EXCLUDED.api_key_hash, 
	    public_key = EXCLUDED.public_key, 
	    status = EXCLUDED.status, 
	    metadata = EXCLUDED.metadata, 
	    updated_at = CURRENT_TIMESTAMP
	RETURNING id, agent_id, public_key, status, metadata, created_at, updated_at
	`

	var agent Agent
	err = db.Pool.QueryRow(ctx, query, agentID, apiKeyHash, publicKey, status, metadata).Scan(
		&agent.ID,
		&agent.AgentID,
		&agent.PublicKey,
		&agent.Status,
		&agent.Metadata,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert agent: %w", err)
	}

	return &agent, nil
}

// GetAgent retrieves an agent from the database.
func (db *DB) GetAgent(ctx context.Context, agentID string) (*Agent, error) {
	query := `
	SELECT id, agent_id, api_key_hash, public_key, status, metadata, created_at, updated_at
	FROM agents
	WHERE agent_id = $1
	`
	var agent Agent
	err := db.Pool.QueryRow(ctx, query, agentID).Scan(
		&agent.ID,
		&agent.AgentID,
		&agent.APIKeyHash,
		&agent.PublicKey,
		&agent.Status,
		&agent.Metadata,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || err.Error() == "no rows in result set" {
			return nil, ErrAgentNotFound
		}
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}
	return &agent, nil
}

// ValidateAgentAPIKey compares a plaintext API key against the stored hash.
func (a *Agent) ValidateAgentAPIKey(apiKey string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(a.APIKeyHash), []byte(apiKey))
	return err == nil
}

// AddCapability registers a capability for an agent.
func (db *DB) AddCapability(ctx context.Context, agentUUID uuid.UUID, capability string) error {
	query := `
	INSERT INTO capabilities (agent_id, capability)
	VALUES ($1, $2)
	ON CONFLICT (agent_id, capability) DO NOTHING
	`
	_, err := db.Pool.Exec(ctx, query, agentUUID, capability)
	if err != nil {
		return fmt.Errorf("failed to add capability: %w", err)
	}
	return nil
}

// ClearCapabilities deletes all capabilities registered for an agent.
func (db *DB) ClearCapabilities(ctx context.Context, agentUUID uuid.UUID) error {
	query := `DELETE FROM capabilities WHERE agent_id = $1`
	_, err := db.Pool.Exec(ctx, query, agentUUID)
	if err != nil {
		return fmt.Errorf("failed to clear capabilities: %w", err)
	}
	return nil
}

// GetCapabilities retrieves all capabilities registered for an agent.
func (db *DB) GetCapabilities(ctx context.Context, agentUUID uuid.UUID) ([]string, error) {
	query := `SELECT capability FROM capabilities WHERE agent_id = $1`
	rows, err := db.Pool.Query(ctx, query, agentUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []string
	for rows.Next() {
		var cap string
		if err := rows.Scan(&cap); err != nil {
			return nil, err
		}
		capabilities = append(capabilities, cap)
	}
	return capabilities, nil
}

// GetAgentsByCapability finds agent IDs that support a given capability.
func (db *DB) GetAgentsByCapability(ctx context.Context, capability string) ([]string, error) {
	query := `
	SELECT a.agent_id
	FROM agents a
	JOIN capabilities c ON a.id = c.agent_id
	WHERE c.capability = $1 AND a.status = 'active'
	`
	rows, err := db.Pool.Query(ctx, query, capability)
	if err != nil {
		return nil, fmt.Errorf("failed to find agents by capability: %w", err)
	}
	defer rows.Close()

	var agents []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		agents = append(agents, id)
	}
	return agents, nil
}

// AddACLRule grants a publish/subscribe permission on a subject to an agent.
func (db *DB) AddACLRule(ctx context.Context, agentUUID uuid.UUID, actionType, subject string) error {
	query := `
	INSERT INTO agent_acls (agent_id, action_type, subject)
	VALUES ($1, $2, $3)
	ON CONFLICT (agent_id, action_type, subject) DO NOTHING
	`
	_, err := db.Pool.Exec(ctx, query, agentUUID, actionType, subject)
	if err != nil {
		return fmt.Errorf("failed to add ACL rule: %w", err)
	}
	return nil
}

// ClearACLRules clears all ACL rules for an agent.
func (db *DB) ClearACLRules(ctx context.Context, agentUUID uuid.UUID) error {
	query := `DELETE FROM agent_acls WHERE agent_id = $1`
	_, err := db.Pool.Exec(ctx, query, agentUUID)
	if err != nil {
		return fmt.Errorf("failed to clear ACL rules: %w", err)
	}
	return nil
}

// GetACLRules retrieves all ACL rules for an agent.
func (db *DB) GetACLRules(ctx context.Context, agentUUID uuid.UUID) ([]ACLRule, error) {
	query := `SELECT action_type, subject FROM agent_acls WHERE agent_id = $1`
	rows, err := db.Pool.Query(ctx, query, agentUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query ACL rules: %w", err)
	}
	defer rows.Close()

	var rules []ACLRule
	for rows.Next() {
		var rule ACLRule
		if err := rows.Scan(&rule.ActionType, &rule.Subject); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// CreateAuditLog saves an audit log entry in the database.
func (db *DB) CreateAuditLog(ctx context.Context, eventType, actorID string, metadata []byte) error {
	if metadata == nil {
		metadata = []byte("{}")
	}
	query := `
	INSERT INTO audit_logs (event_type, actor_id, metadata)
	VALUES ($1, $2, $3)
	`
	_, err := db.Pool.Exec(ctx, query, eventType, actorID, metadata)
	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}
	return nil
}
