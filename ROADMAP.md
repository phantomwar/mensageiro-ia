# AACB Project Roadmap

Este documento acompanha a evolução das versões do **AI Agent Communication Bus (AACB)**, detalhando o progresso atual e os próximos passos para o desenvolvimento contínuo.

---

## 🚦 Status Geral do Projeto

- [x] **V1: Core Bus, Segurança e Mensageria (Status: Concluído)**
  - [x] Autenticação e Autorização baseada em NKeys e NATS JWTs.
  - [x] Registro de Agentes e persistência relacional no PostgreSQL.
  - [x] API de Descoberta dinâmica de capacidades baseada em HTTP REST.
  - [x] Envelope de mensagens criptográfico com assinaturas Ed25519 (SHA-256).
  - [x] Prevenção distribuída de ataques de Replay via NATS Key-Value (TTL de 60s).
  - [x] Sistema assíncrono de logs de auditoria via subject `system.audit`.
  - [x] Ponte de integração **MCP (Model Context Protocol)** para o Hermes Agent.
  - [x] Ambiente local automatizado via Docker Compose.

- [ ] **V2: Observabilidade e Telemetria (Status: Infraestrutura Pronta / Código Pendente)**
  - [x] Containers do Prometheus, Grafana e Loki configurados no Compose.
  - [ ] Integração do OpenTelemetry (OTel) no código do Control Plane.
  - [ ] Métricas de throughput do NATS expostas para Prometheus.
  - [ ] Painel do Grafana para monitoramento em tempo real do barramento.

- [ ] **V3: Criptografia de Ponta a Ponta (E2EE) (Status: Não Iniciado)**
  - [ ] Troca de chaves Diffie-Hellman efêmeras entre agentes sobre o NATS.
  - [ ] Criptografia simétrica dos payloads no envelope (AES-GCM) de forma que nem o Control Plane nem o broker NATS consigam ler o conteúdo das mensagens.

- [ ] **V4: Integração de Ecossistema MCP (Status: Em Andamento)**
  - [x] Bridge MCP Stdout/Stdin implementada em `cmd/agent`.
  - [ ] Suporte a conexões MCP via SSE (Server-Sent Events) sobre HTTP.
  - [ ] Registro automático de ferramentas MCP remotas como capacidades.

- [ ] **V5: Integrações LangGraph e Frameworks (Status: Não Iniciado)**

- [ ] **V6: Federação Multi-Tailnet (Status: Não Iniciado)**
  - [ ] Comunicação segura entre agentes localizados em Tailnets distintas por meio de pontes federadas (Gateways NATS Leafnodes).

- [ ] **V7: Marketplace de Agentes Autônomos (Status: Não Iniciado)**

---

## 📝 Próximos Passos para Continuação (Para você continuar depois)

Quando você retornar para continuar o projeto, aqui está a ordem recomendada de tarefas:

### Passo 1: Executar o Barramento Localmente
1. Abra o **Docker Desktop** no Windows para inicializar o serviço de containers.
2. No PowerShell, navegue até a pasta:
   ```bash
   cd deployments/compose
   ```
3. Suba o ambiente:
   ```bash
   docker-compose up -d --build
   ```

### Passo 2: Testar a Ponte MCP com o Hermes Agent
1. Compile o executável do agente no Windows:
   ```bash
   go build -o aacb-agent-bridge.exe ./cmd/agent
   ```
2. Adicione a configuração do servidor MCP no seu cliente **Hermes Agent** apontando para o arquivo `aacb-agent-bridge.exe` passando a flag `-mcp` e as credenciais necessárias de bootstrap (por exemplo, `-key secret`).

### Passo 3: Implementar a Stack V2 (Observabilidade)
1. Abra os arquivos Go do `cmd/control-plane` e configure middlewares para exportar métricas Prometheus usando `github.com/prometheus/client_golang/prometheus`.
2. Configure o Grafana acessando `http://localhost:3000` (senha padrão: `admin`) e configure o Prometheus (`http://prometheus:9090`) e o Loki (`http://loki:3100`) como fontes de dados.
