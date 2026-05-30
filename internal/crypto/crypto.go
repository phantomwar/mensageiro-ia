package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateKeyPair generates a new Ed25519 private and public key pair,
// returning them as hex-encoded strings.
func GenerateKeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 keys: %w", err)
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// SignPayload hashes the payload with SHA-256 and signs the resulting hash
// with the hex-encoded Ed25519 private key.
func SignPayload(payload []byte, privateKeyHex string) (string, error) {
	privBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key length: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	priv := ed25519.PrivateKey(privBytes)

	// Hash payload with SHA-256 (Section 13 of PROJETO.md)
	hash := sha256.Sum256(payload)

	// Sign the hash using Ed25519
	sig := ed25519.Sign(priv, hash[:])

	return hex.EncodeToString(sig), nil
}

// VerifyPayload hashes the payload with SHA-256 and verifies the signature
// against the hash using the hex-encoded Ed25519 public key.
func VerifyPayload(payload []byte, signatureHex string, publicKeyHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(pubBytes))
	}

	pub := ed25519.PublicKey(pubBytes)

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	// Hash payload with SHA-256
	hash := sha256.Sum256(payload)

	// Verify signature of the hash
	isValid := ed25519.Verify(pub, hash[:], sigBytes)
	return isValid, nil
}
