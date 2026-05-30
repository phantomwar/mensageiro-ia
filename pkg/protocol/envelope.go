package protocol

import (
	"encoding/json"
	"time"
)

// Envelope represents the core communication message container on the AACB.
// It matches the specification defined in Section 10 of PROJETO.md.
type Envelope struct {
	MessageID     string          `json:"message_id"`
	SenderID      string          `json:"sender_id"`
	ReceiverID    string          `json:"receiver_id"`
	Subject       string          `json:"subject"`
	CorrelationID string          `json:"correlation_id"`
	Sequence      uint64          `json:"sequence"`
	Nonce         string          `json:"nonce"`
	Timestamp     time.Time       `json:"timestamp"`
	Signature     string          `json:"signature"`
	Payload       json.RawMessage `json:"payload"`
}
