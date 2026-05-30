package crypto

import (
	"testing"
)

func TestKeyPairGenerationAndSigning(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	if len(priv) != 128 || len(pub) != 64 {
		t.Errorf("invalid key lengths: priv=%d, pub=%d", len(priv), len(pub))
	}

	payload := []byte(`{"event":"test","message":"hello world"}`)
	sig, err := SignPayload(payload, priv)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	valid, err := VerifyPayload(payload, sig, pub)
	if err != nil {
		t.Fatalf("failed to verify payload: %v", err)
	}

	if !valid {
		t.Error("signature verification failed for valid payload")
	}

	// Test invalid payload (corrupted message)
	invalidPayload := []byte(`{"event":"test","message":"hello world corrupted"}`)
	valid, err = VerifyPayload(invalidPayload, sig, pub)
	if err != nil {
		t.Fatalf("error during verification: %v", err)
	}
	if valid {
		t.Error("signature verified for modified payload (should fail)")
	}
}
