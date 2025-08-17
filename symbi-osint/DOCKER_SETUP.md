# Docker Setup for Symbi-OSINT

This document provides instructions for running the complete Symbi-OSINT agent stack using Docker Compose.

## Architecture Overview

The Docker setup includes the following services:

- **symbiont-runtime**: Main agent execution environment
- **symbiont-repl**: Interactive REPL server for testing and debugging
- **postgres**: PostgreSQL database with pgvector extension
- **redis**: Caching and session management
- **qdrant**: Vector database for RAG and intelligence correlation
- **prometheus**: Metrics collection
- **grafana**: Monitoring dashboard

## Prerequisites

- Docker Engine 20.10+ 
- Docker Compose 2.0+
- At least 4GB available RAM
- 10GB available disk space

## Quick Start

1. **Clone and navigate to the directory:**
   ```bash
   cd symbi-osint
   ```

2. **Copy environment configuration:**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configurations
   ```

3. **Start the full stack:**
   ```bash
   docker-compose up -d
   ```

4. **Verify services are running:**
   ```bash
   docker-compose ps
   ```

## Service Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| Symbiont API | http://localhost:8080 | REST API for investigations |
| Symbiont MCP | http://localhost:3000 | MCP server |
| REPL Server | http://localhost:9257 | JSON-RPC interface |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Cache |
| Qdrant | http://localhost:6333 | Vector database |
| Prometheus | http://localhost:9090 | Metrics |
| Grafana | http://localhost:3001 | Dashboards |

## Usage Examples

### Starting an Investigation

```bash
# Start a comprehensive investigation
curl -X POST http://localhost:8080/api/v1/investigations/start \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Investigate the domain example.com for potential threats",
    "requester": "analyst@company.com"
  }'
```

### Using the REPL

```bash
# Connect to REPL via JSON-RPC
curl -X POST http://localhost:9257 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "evaluate",
    "params": {"input": "let investigation = start_investigation(\"example.com\")"},
    "id": 1
  }'
```

### Accessing Monitoring

- **Grafana**: Navigate to http://localhost:3001 (admin/admin)
- **Prometheus**: Navigate to http://localhost:9090

## Configuration

### Environment Variables

Key environment variables in [`.env`](.env.example):

```env
# Database
POSTGRES_PASSWORD=your_secure_password

# API Keys
OPENAI_API_KEY=your_openai_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

### Agent Configuration

Agent definitions are mounted from [`./agents/`](./agents/) directory.

### Service Configuration

- **Symbiont**: [`config/symbiont.toml`](config/symbiont.toml)
- **Redis**: [`redis.conf`](redis.conf)
- **Qdrant**: [`qdrant-config.yaml`](qdrant-config.yaml)
- **Prometheus**: [`monitoring/prometheus.yml`](monitoring/prometheus.yml)

## Development Workflow

### Testing Individual Agents

```bash
# Execute specific agent via REPL
curl -X POST http://localhost:9257 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "execute_agent_behavior",
    "params": {
      "agent_id": "ip_intelligence",
      "behavior_name": "analyze_ip",
      "arguments": "8.8.8.8"
    },
    "id": 1
  }'
```

### Viewing Logs

```bash
# View all service logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f symbiont-runtime
docker-compose logs -f symbiont-repl
```

### Debugging

```bash
# Enter container for debugging
docker-compose exec symbiont-runtime /bin/bash

# Check agent status
docker-compose exec symbiont-runtime symbi --version
```

## REPL Integration

The REPL server provides both interactive and programmatic access to the agent system:

### Interactive Mode

Connect via WebSocket or stdio for real-time interaction:

```bash
# Connect via stdio (requires symbi CLI)
docker-compose exec symbiont-repl symbi repl --json-rpc
```

### JSON-RPC Commands

| Method | Description |
|--------|-------------|
| `evaluate` | Execute DSL code |
| `list_agents` | List available agents |
| `execute_agent_behavior` | Run specific agent behavior |
| `get_investigation_status` | Check investigation progress |

### Session Management

```bash
# Create session snapshot
curl -X POST http://localhost:9257 \
  -d '{"jsonrpc": "2.0", "method": "snapshot", "params": {"name": "test1"}, "id": 1}'

# Restore session
curl -X POST http://localhost:9257 \
  -d '{"jsonrpc": "2.0", "method": "restore", "params": {"name": "test1"}, "id": 2}'
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 8080, 3000, 9257, 5432, 6379, 6333, 9090, 3001 are available
2. **Memory issues**: Increase Docker memory limit to at least 4GB
3. **Permission errors**: Ensure Docker has proper file system permissions

### Health Checks

```bash
# Check service health
docker-compose ps

# Test API connectivity
curl http://localhost:8080/health
curl http://localhost:9257 -d '{"jsonrpc": "2.0", "method": "ping", "id": 1}'
```

### Reset Environment

```bash
# Stop and remove all containers
docker-compose down

# Remove volumes (WARNING: destroys data)
docker-compose down -v

# Rebuild and restart
docker-compose up --build -d
```

## Security Considerations

- Change default passwords in production
- Configure proper network isolation
- Enable authentication for exposed services
- Regular security updates of base images
- API key rotation

## Performance Tuning

- Adjust PostgreSQL `shared_buffers` and `work_mem`
- Configure Redis memory limits
- Tune Qdrant vector index parameters
- Scale agent concurrency based on available resources

## Production Deployment

For production deployment:

1. Use external managed databases
2. Configure proper secrets management
3. Set up SSL/TLS termination
4. Implement proper backup strategies
5. Configure log aggregation
6. Set up health monitoring and alerting