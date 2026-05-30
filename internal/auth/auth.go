package auth

import (
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// AuthManager handles NATS NKey/JWT generation.
type AuthManager struct {
	AccountSeed string
}

// NewAuthManager creates a new AuthManager. If accountSeed is empty,
// it generates a temporary, in-memory Account keypair for ease of testing.
func NewAuthManager(accountSeed string) (*AuthManager, error) {
	if accountSeed == "" {
		// Generate an in-memory Account NKey for developer setup
		kp, err := nkeys.CreateAccount()
		if err != nil {
			return nil, fmt.Errorf("failed to generate temporary account key: %w", err)
		}
		seed, err := kp.Seed()
		if err != nil {
			return nil, fmt.Errorf("failed to extract seed: %w", err)
		}
		accountSeed = string(seed)
	} else {
		// Validate seed
		_, err := nkeys.FromSeed([]byte(accountSeed))
		if err != nil {
			return nil, fmt.Errorf("invalid account seed: %w", err)
		}
	}

	return &AuthManager{AccountSeed: accountSeed}, nil
}

// GetAccountPublicKey returns the public key associated with the Account seed.
func (am *AuthManager) GetAccountPublicKey() (string, error) {
	kp, err := nkeys.FromSeed([]byte(am.AccountSeed))
	if err != nil {
		return "", err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	return string(pub), nil
}

// GenerateUserJWT creates a NATS User JWT signed by the Account private key.
// It maps the agent's publish and subscribe subjects directly to the NATS claims.
func (am *AuthManager) GenerateUserJWT(agentID, userNKeyPubKey string, publishACLs, subscribeACLs []string) (string, error) {
	kp, err := nkeys.FromSeed([]byte(am.AccountSeed))
	if err != nil {
		return "", fmt.Errorf("invalid account seed: %w", err)
	}

	// Create user claims binding the token to the agent's public NKey
	claims := jwt.NewUserClaims(userNKeyPubKey)
	claims.Name = agentID
	claims.Expires = time.Now().Add(24 * time.Hour).Unix() // Session lasts 24h

	// Apply ACL permissions for subjects
	if len(publishACLs) > 0 {
		claims.Permissions.Pub.Allow.Add(publishACLs...)
	} else {
		// Default: Deny publishing everywhere if not configured
		claims.Permissions.Pub.Deny.Add(">")
	}

	if len(subscribeACLs) > 0 {
		claims.Permissions.Sub.Allow.Add(subscribeACLs...)
	} else {
		// Default: Deny subscribing everywhere if not configured
		claims.Permissions.Sub.Deny.Add(">")
	}

	// Sign the User claims using the Account NKey
	token, err := claims.Encode(kp)
	if err != nil {
		return "", fmt.Errorf("failed to sign user claims: %w", err)
	}

	return token, nil
}
