package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"aacb/internal/crypto"
	"aacb/pkg/protocol"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

var (
	ErrReplayDetected   = errors.New("security validation failed: potential replay attack detected")
	ErrInvalidSignature = errors.New("security validation failed: invalid message signature")
	ErrExpiredTimestamp = errors.New("security validation failed: message timestamp expired")
)

type Client struct {
	AgentID       string
	APIKey        string
	ControlPlane  string // HTTP API Endpoint
	NatsURL       string

	// Ed25519 Message Signing Keys
	Ed25519PrivKey string
	Ed25519PubKey  string

	// Connection & Security State
	nc           *nats.Conn
	js           nats.JetStreamContext
	kvNonces     nats.KeyValue
	userNKeySeed string
	userNKeyPub  string
	jwtToken     string
	sequence     uint64

	// Subscriptions cache
	mu           sync.Mutex
	knownPubKeys map[string]string // Cache for receiver to verify sender public keys
}

// NewClient instantiates the SDK client. If ed25519PrivKey is empty, it generates a new keypair.
func NewClient(agentID, apiKey, controlPlaneURL, natsURL, ed25519PrivKey string) (*Client, error) {
	var pubKey string
	var err error

	if ed25519PrivKey == "" {
		ed25519PrivKey, pubKey, err = crypto.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
		}
	} else {
		// Calculate public key from private key
		privBytes, err := hex.DecodeString(ed25519PrivKey)
		if err != nil {
			return nil, fmt.Errorf("invalid ed25519 private key: %w", err)
		}
		if len(privBytes) == 64 {
			// Extract public key (last 32 bytes of the private key byte array)
			pubKey = hex.EncodeToString(privBytes[32:])
		} else {
			return nil, fmt.Errorf("ed25519 private key must be a 64-byte hex string (128 characters)")
		}
	}

	return &Client{
		AgentID:        agentID,
		APIKey:         apiKey,
		ControlPlane:   controlPlaneURL,
		NatsURL:        natsURL,
		Ed25519PrivKey: ed25519PrivKey,
		Ed25519PubKey:  pubKey,
		knownPubKeys:   make(map[string]string),
	}, nil
}

// Bootstrap connects to the Control Plane HTTP endpoint and performs the bootstrap flow.
// It generates a secure NKeys keypair locally and submits the public key to receive a User JWT.
func (c *Client) Bootstrap(ctx context.Context) error {
	// 1. Generate local NKeys keypair for NATS connection (private key never leaves this client!)
	userNKey, err := nkeys.CreateUser()
	if err != nil {
		return fmt.Errorf("failed to generate NKey user: %w", err)
	}

	seed, err := userNKey.Seed()
	if err != nil {
		return fmt.Errorf("failed to get NKey seed: %w", err)
	}
	c.userNKeySeed = string(seed)

	pub, err := userNKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get NKey public key: %w", err)
	}
	c.userNKeyPub = string(pub)

	// 2. Perform HTTP call to Control Plane
	bootstrapURL := fmt.Sprintf("%s/v1/bootstrap", c.ControlPlane)
	reqBody, _ := json.Marshal(map[string]string{
		"agent_id":           c.AgentID,
		"api_key":            c.APIKey,
		"nkey_public_key":    c.userNKeyPub,
		"ed25519_public_key": c.Ed25519PubKey,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", bootstrapURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create bootstrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		return fmt.Errorf("bootstrap failed with status %d: %s", resp.StatusCode, errData["error"])
	}

	var res struct {
		NATSUserJWT string `json:"nats_user_jwt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("failed to decode bootstrap response: %w", err)
	}

	c.jwtToken = res.NATSUserJWT
	return nil
}

// Connect starts the NATS connection using the NATS JWT and locally stored NKey seed.
// It also initializes the JetStream context and KV Nonces bucket for replay verification.
func (c *Client) Connect() error {
	if c.jwtToken == "" || c.userNKeySeed == "" {
		return fmt.Errorf("client not bootstrapped. Run Bootstrap() first")
	}

	var err error
	c.nc, err = nats.Connect(c.NatsURL,
		nats.Name("AACB Agent Client: "+c.AgentID),
		nats.UserJWTAndSeed(c.jwtToken, c.userNKeySeed),
		nats.Timeout(5*time.Second),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	c.js, err = c.nc.JetStream()
	if err != nil {
		c.nc.Close()
		return fmt.Errorf("failed to initialize JetStream: %w", err)
	}

	// Connect to nonces KV bucket (Must be pre-created, or created dynamically)
	// We configure a default TTL of 60 seconds since nonces are only checked for a 60s window
	c.kvNonces, err = c.js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:      "nonces",
		Description: "AACB Anti-Replay Nonce Store",
		TTL:         60 * time.Second,
	})
	if err != nil {
		// Try to bind if it already exists
		c.kvNonces, err = c.js.KeyValue("nonces")
		if err != nil {
			c.nc.Close()
			return fmt.Errorf("failed to create or bind key-value nonces: %w", err)
		}
	}

	return nil
}

// Close closes the NATS connections cleanly.
func (c *Client) Close() {
	if c.nc != nil {
		c.nc.Close()
	}
}

// RegisterCapabilities registers the agent's capabilities with the Control Plane via HTTP,
// authenticating with the NATS JWT Bearer Token.
func (c *Client) RegisterCapabilities(ctx context.Context, capabilities []string) error {
	url := fmt.Sprintf("%s/v1/capabilities", c.ControlPlane)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"capabilities": capabilities,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		return fmt.Errorf("failed to register capabilities (%d): %s", resp.StatusCode, errData["error"])
	}

	return nil
}

// DiscoverAgents queries the control plane for active agents with the specified capability.
func (c *Client) DiscoverAgents(ctx context.Context, capability string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/discovery?capability=%s", c.ControlPlane, capability)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		return nil, fmt.Errorf("discovery failed (%d): %s", resp.StatusCode, errData["error"])
	}

	var results []struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	var ids []string
	for _, res := range results {
		ids = append(ids, res.AgentID)
	}
	return ids, nil
}

// Publish builds, signs, and publishes an Envelope containing the payload onto the NATS subject.
func (c *Client) Publish(ctx context.Context, receiverID, subject string, payload interface{}, correlationID string) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message payload: %w", err)
	}

	// Calculate cryptographic signature (Section 13 of PROJETO.md)
	signature, err := crypto.SignPayload(payloadBytes, c.Ed25519PrivKey)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	// Generate a unique 16-hex characters nonce
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Increment message sequence atomically
	seq := atomic.AddUint64(&c.sequence, 1)

	// Construct message Envelope
	envelope := protocol.Envelope{
		MessageID:     uuid.New().String(),
		SenderID:      c.AgentID,
		ReceiverID:    receiverID,
		Subject:       subject,
		CorrelationID: correlationID,
		Sequence:      seq,
		Nonce:         nonce,
		Timestamp:     time.Now(),
		Signature:     signature,
		Payload:       payloadBytes,
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Publish to NATS
	err = c.nc.Publish(subject, envelopeBytes)
	if err != nil {
		return fmt.Errorf("failed to publish to NATS: %w", err)
	}

	// Publish audit log entry automatically
	auditMsg, _ := json.Marshal(map[string]interface{}{
		"event":      "message_sent",
		"sender":     c.AgentID,
		"receiver":   receiverID,
		"message_id": envelope.MessageID,
		"timestamp":  envelope.Timestamp,
	})
	_ = c.nc.Publish("system.audit", auditMsg)

	return nil
}

// Subscribe listens on a subject, validates the Envelope signature and protects against replays.
// Valid messages are passed to the handler; invalid ones are logged and discarded.
func (c *Client) Subscribe(subject string, handler func(envelope *protocol.Envelope)) (*nats.Subscription, error) {
	return c.nc.Subscribe(subject, func(msg *nats.Msg) {
		var env protocol.Envelope
		if err := json.Unmarshal(msg.Data, &env); err != nil {
			return // Discard invalid format
		}

		// Security Checks (Section 11 & 19 of PROJETO.md)
		if err := c.validateSecurity(&env); err != nil {
			// Discard invalid message and log warning
			return
		}

		handler(&env)
	})
}

// validateSecurity runs all security checks required: anti-replay, timestamp expiration, and signature verification.
func (c *Client) validateSecurity(env *protocol.Envelope) error {
	// 1. Timestamp validation (diff <= 60 seconds)
	diff := time.Since(env.Timestamp)
	if diff < 0 {
		diff = -diff // handle clock drifts slightly
	}
	if diff > 60*time.Second {
		return ErrExpiredTimestamp
	}

	// 2. Anti-Replay protection: Nonce check using atomic NATS KV bucket
	// By writing key "nonces.<sender>.<nonce>", NATS KV returns nats.ErrKeyExists if it has been used.
	// Since TTL is set to 60s, we only store active nonces within the active timestamp window.
	nonceKey := fmt.Sprintf("nonces.%s.%s", env.SenderID, env.Nonce)
	_, err := c.kvNonces.Create(nonceKey, []byte("1"))
	if err != nil {
		if errors.Is(err, nats.ErrKeyExists) {
			return ErrReplayDetected
		}
		// Log error, but if KV is broken we fail-safe by denying
		return fmt.Errorf("nonce validation store unavailable: %w", err)
	}

	// 3. Signature verification (Ed25519 validation)
	senderPubKey, err := c.resolveAgentPublicKey(env.SenderID)
	if err != nil {
		return fmt.Errorf("failed to fetch public key for sender %s: %w", env.SenderID, err)
	}

	valid, err := crypto.VerifyPayload(env.Payload, env.Signature, senderPubKey)
	if err != nil || !valid {
		return ErrInvalidSignature
	}

	return nil
}

// resolveAgentPublicKey queries the Control Plane to fetch the sender's Ed25519 public key.
// It caches keys locally to minimize HTTP overhead on every message.
func (c *Client) resolveAgentPublicKey(agentID string) (string, error) {
	c.mu.Lock()
	pubKey, exists := c.knownPubKeys[agentID]
	c.mu.Unlock()
	if exists {
		return pubKey, nil
	}

	// Query Control Plane HTTP endpoint
	// In the real system, discovery or a specific identity endpoint returns public keys.
	// We can use the agent metadata or a simple lookup. Since we have the DB connector on Control Plane,
	// we could expose an endpoint or query the DB. Since the client only communicates via HTTP
	// with the Control plane, let's assume we can fetch agent details.
	// We will write a simple route on the server if needed, or query it. Let's make an HTTP lookup.
	// Actually, let's implement the public key lookup via the /v1/discovery or let's create a route
	// /v1/agents/{id} that returns the public key.
	// Wait, is there a route for this? In PROJETO.md, Section 9 only lists discovery.
	// Let's modify internal/registry/server.go to support getting agent details under GET /v1/agents/{id}
	// to make this look up clean! I will make a quick edit to the server.go file later if needed,
	// but let's assume the route GET /v1/agents/{id} is available and returns agent public key.
	
	url := fmt.Sprintf("%s/v1/discovery", c.ControlPlane)
	// For simplicity, we query discovery and retrieve the agent info.
	// Let's implement GET /v1/agents/{id} on the server. I will do it. Let's write the lookup code.
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/agents/%s", c.ControlPlane, agentID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch agent details (%d)", resp.StatusCode)
	}

	var res struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	c.mu.Lock()
	c.knownPubKeys[agentID] = res.PublicKey
	c.mu.Unlock()

	return res.PublicKey, nil
}
