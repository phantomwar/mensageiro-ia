package audit

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"aacb/internal/database"

	"github.com/nats-io/nats.go"
)

type AuditLogMessage struct {
	Event     string          `json:"event"`
	Sender    string          `json:"sender"`
	Receiver  string          `json:"receiver"`
	MessageID string          `json:"message_id"`
	Timestamp time.Time       `json:"timestamp"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type Listener struct {
	DB      *database.DB
	NatsURL string
	nc      *nats.Conn
	sub     *nats.Subscription
	stop    chan struct{}
}

func NewListener(db *database.DB, natsURL string) *Listener {
	return &Listener{
		DB:      db,
		NatsURL: natsURL,
		stop:    make(chan struct{}),
	}
}

// Start connects to NATS and subscribes to system.audit.
func (l *Listener) Start() error {
	var err error
	// Use standard NATS options. Retry on failure.
	l.nc, err = nats.Connect(l.NatsURL,
		nats.Name("AACB Control Plane Audit Listener"),
		nats.Timeout(5*time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			log.Printf("[AUDIT-NATS] Disconnected from NATS: %v", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Printf("[AUDIT-NATS] Reconnected to NATS at %s", nc.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	// Subscribe to system.audit subject (Section 12 of PROJETO.md)
	l.sub, err = l.nc.Subscribe("system.audit", func(msg *nats.Msg) {
		l.processMessage(msg)
	})
	if err != nil {
		l.nc.Close()
		return err
	}

	log.Printf("[AUDIT] Subscribed to NATS subject: system.audit")
	return nil
}

func (l *Listener) Stop() {
	close(l.stop)
	if l.sub != nil {
		l.sub.Unsubscribe()
	}
	if l.nc != nil {
		l.nc.Close()
	}
}

func (l *Listener) processMessage(msg *nats.Msg) {
	var auditMsg AuditLogMessage
	if err := json.Unmarshal(msg.Data, &auditMsg); err != nil {
		log.Printf("[AUDIT-ERROR] Failed to parse audit payload: %v (raw: %s)", err, string(msg.Data))
		return
	}

	// Format metadata to save in Postgres
	metaBytes, err := json.Marshal(map[string]interface{}{
		"sender":     auditMsg.Sender,
		"receiver":   auditMsg.Receiver,
		"message_id": auditMsg.MessageID,
		"timestamp":  auditMsg.Timestamp,
		"custom":     auditMsg.Metadata,
	})
	if err != nil {
		metaBytes = []byte("{}")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = l.DB.CreateAuditLog(ctx, auditMsg.Event, auditMsg.Sender, metaBytes)
	if err != nil {
		log.Printf("[AUDIT-ERROR] Failed to write audit event to DB: %v", err)
		return
	}

	// Acknowledge the message if it's a JetStream message (JetStream messages can be acked)
	// For core pub/sub, Msg.Ack() is a no-op or returns an error.
	_ = msg.Ack()
}
