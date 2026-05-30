# AI Agent Communication Bus (AACB)

## Version

1.0

## Status

Approved for Implementation

---

# 1. Executive Summary

AACB (AI Agent Communication Bus) é uma plataforma de comunicação segura para agentes de IA distribuídos.

Objetivo:

Permitir que agentes se descubram, autentiquem, comuniquem e cooperem através de uma infraestrutura privada baseada em Tailscale.

O sistema não deve ser tratado como um chat.

O sistema deve ser tratado como um barramento de comunicação para agentes autônomos.

---

# 2. Core Principles

## Zero Trust

Nenhum agente é confiável por padrão.

Toda operação deve ser autenticada.

---

## Identity First

Todo agente possui identidade própria.

---

## Audit Everything

Toda ação é registrada.

---

## Event Driven

Toda comunicação é baseada em eventos.

---

## Secure by Default

Toda comunicação é criptografada.

---

# 3. Technology Stack

Language:

Go 1.24+

Network:

Tailscale

Messaging:

NATS JetStream

Database:

PostgreSQL

Observability:

OpenTelemetry

Logs:

Loki

Metrics:

Prometheus

Dashboard:

Grafana

Containers:

Docker

Future:

Kubernetes

---

# 4. High Level Architecture

```text
                   +----------------+
                   | Admin Console  |
                   +--------+-------+
                            |
                            |
                            v

+------------------------------------------------------+
|                  CONTROL PLANE                       |
|------------------------------------------------------|
| Agent Registry                                       |
| Authentication                                       |
| Authorization                                        |
| Capability Registry                                  |
| Audit Service                                        |
+----------------------+-------------------------------+
                       |
                       |
                       v

+------------------------------------------------------+
|                  MESSAGE PLANE                       |
|------------------------------------------------------|
| NATS JetStream                                       |
| Subjects                                             |
| Queues                                               |
| Persistence                                          |
+----------------------+-------------------------------+

             /             |             \
            /              |              \

     +----------+   +----------+   +----------+
     | Agent A  |   | Agent B  |   | Agent C  |
     +----------+   +----------+   +----------+

                Tailnet (Tailscale)
```

---

# 5. Agent Identity Model

Cada agente recebe:

```json
{
  "agent_id":"planner-001",
  "api_key":"bootstrap_only",
  "public_key":"ed25519_public_key",
  "status":"active",
  "capabilities":[
    "plan",
    "analyze"
  ]
}
```

---

# 6. Authentication Flow

## Bootstrap

Agent -> Control Plane

```json
{
  "agent_id":"planner-001",
  "api_key":"secret"
}
```

Servidor valida.

---

## Session Creation

Servidor gera:

```json
{
  "nats_user_jwt":"...",
  "nats_nkey":"..."
}
```

---

## Runtime

Toda comunicação utiliza:

NATS JWT

NATS NKEY

Não utilizar API Key durante operação normal.

---

# 7. Authorization

ACL baseada em Subjects.

Exemplo:

```yaml
planner-001:

 publish:
   - groups.research
   - agent.executor

 subscribe:
   - agent.planner
```

---

# 8. Capability Registry

Todo agente deve registrar capacidades.

Exemplo:

```json
{
  "agent_id":"coder-001",
  "capabilities":[
    "write_code",
    "review_code",
    "generate_tests"
  ]
}
```

---

# 9. Discovery API

Buscar agentes por capacidade.

Exemplo:

```http
GET /v1/discovery?capability=review_code
```

Resposta:

```json
[
  {
    "agent_id":"reviewer-001"
  }
]
```

---

# 10. Message Envelope

```go
type Envelope struct {

    MessageID string

    SenderID string

    ReceiverID string

    Subject string

    CorrelationID string

    Sequence uint64

    Nonce string

    Timestamp time.Time

    Signature string

    Payload json.RawMessage
}
```

---

# 11. Anti Replay Protection

Toda mensagem deve conter:

Sequence

Nonce

Timestamp

Validação:

Timestamp <= 60 segundos

Nonce único

Sequence crescente

Mensagens inválidas são descartadas.

---

# 12. Message Subjects

## Direct

```text
agents.planner
agents.coder
agents.reviewer
```

---

## Groups

```text
groups.research
groups.coding
groups.operations
```

---

## System

```text
system.audit
system.events
system.alerts
```

---

## RPC

```text
rpc.agent.planner
rpc.agent.coder
```

---

# 13. Message Signing

Toda mensagem assinada usando:

Ed25519

Processo:

Payload

↓

Hash SHA256

↓

Assinatura Ed25519

↓

Transmitir

Validação obrigatória.

---

# 14. Persistence Strategy

## JetStream

Armazena mensagens operacionais.

Retenção:

7 dias

---

## PostgreSQL

Armazena:

Agentes

ACLs

Capabilities

Auditoria

Metadados

---

Não armazenar payloads gigantes no PostgreSQL.

---

# 15. Audit System

Toda operação gera evento.

Exemplo:

```json
{
  "event":"message_sent",
  "sender":"planner",
  "receiver":"coder",
  "message_id":"abc123",
  "timestamp":"2026-05-30T18:00:00Z"
}
```

---

# 16. Database Schema

## agents

```sql
CREATE TABLE agents (
 id UUID PRIMARY KEY,
 agent_id VARCHAR(128) UNIQUE NOT NULL,
 public_key TEXT NOT NULL,
 status VARCHAR(20) NOT NULL,
 metadata JSONB,
 created_at TIMESTAMP NOT NULL
);
```

---

## capabilities

```sql
CREATE TABLE capabilities (
 id UUID PRIMARY KEY,
 agent_id UUID NOT NULL,
 capability VARCHAR(100) NOT NULL
);
```

---

## audit_logs

```sql
CREATE TABLE audit_logs (
 id UUID PRIMARY KEY,
 event_type VARCHAR(50),
 actor_id VARCHAR(100),
 metadata JSONB,
 created_at TIMESTAMP NOT NULL
);
```

---

# 17. Repository Structure

```text
aacb/

cmd/
├── control-plane
├── agent
└── admin

internal/

├── auth
├── registry
├── discovery
├── capabilities
├── messaging
├── audit
├── crypto
├── acl
├── telemetry
└── database

pkg/

├── sdk
└── protocol

deployments/

├── docker
├── compose
└── kubernetes

configs/

tests/

scripts/
```

---

# 18. Docker Compose

Services:

postgres

nats

control-plane

agent-sample

tailscale-sidecar

grafana

prometheus

loki

---

# 19. Security Requirements

Mandatory:

* Tailnet Only
* Ed25519
* NATS JWT
* NKeys
* TLS
* Replay Protection
* ACL Validation
* Rate Limiting

Forbidden:

* Anonymous Agents
* Shared Credentials
* Plaintext Secrets
* Public Network Access

---

# 20. Future Roadmap

V1

* Registry
* Authentication
* Discovery
* Messaging
* Audit

V2

* OpenTelemetry
* Metrics
* Tracing

V3

* End-to-End Encryption

V4

* MCP Integration

V5

* LangGraph Integration

V6

* Multi Tailnet Federation

V7

* Autonomous Agent Marketplace

---

# Final Implementation Objective

Construir uma plataforma de comunicação para agentes de IA baseada em:

Tailscale

NATS JetStream

Go

PostgreSQL

com autenticação forte, autorização granular, descoberta dinâmica de capacidades, auditoria completa e suporte a milhares de agentes simultâneos.
