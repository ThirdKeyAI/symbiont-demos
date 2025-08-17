# Makefile for Symbi-OSINT Docker Environment
.PHONY: help build up down logs test test-repl test-api clean reset

# Default target
help:
	@echo "Symbi-OSINT Docker Management"
	@echo "=============================="
	@echo ""
	@echo "Commands:"
	@echo "  build      - Build all services"
	@echo "  up         - Start all services"
	@echo "  down       - Stop all services"
	@echo "  logs       - View logs from all services"
	@echo "  test       - Run all tests"
	@echo "  test-repl  - Test REPL functionality"
	@echo "  test-api   - Test REST API"
	@echo "  clean      - Clean containers and images"
	@echo "  reset      - Reset everything (destroys data)"
	@echo "  status     - Show service status"
	@echo ""

# Environment setup
.env:
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.example..."; \
		cp .env.example .env; \
		echo "Please edit .env with your API keys and configuration"; \
	fi

# Build services
build: .env
	docker-compose build --parallel

# Start services
up: .env
	docker-compose up -d
	@echo "Services starting... waiting 30 seconds for initialization"
	@sleep 30
	@echo "Services should be ready. Run 'make status' to check."

# Stop services
down:
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# View logs for specific service
logs-%:
	docker-compose logs -f $*

# Check service status
status:
	@echo "Service Status:"
	@echo "==============="
	docker-compose ps
	@echo ""
	@echo "Testing connectivity..."
	@curl -s http://localhost:8080/health > /dev/null && echo "✓ Runtime API responding" || echo "✗ Runtime API not responding"
	@curl -s http://localhost:9257 -d '{"jsonrpc":"2.0","method":"ping","id":1}' > /dev/null && echo "✓ REPL server responding" || echo "✗ REPL server not responding"
	@curl -s http://localhost:6333/health > /dev/null && echo "✓ Qdrant responding" || echo "✗ Qdrant not responding"
	@curl -s http://localhost:9090/-/healthy > /dev/null && echo "✓ Prometheus responding" || echo "✗ Prometheus not responding"

# Test REPL functionality
test-repl: .env
	@echo "Testing REPL functionality..."
	python3 test-repl.py --wait 5

# Test REST API
test-api: .env
	@echo "Testing REST API..."
	@curl -X POST http://localhost:8080/api/v1/investigations/start \
		-H "Content-Type: application/json" \
		-d '{"query": "Test investigation", "requester": "test"}' \
		&& echo "✓ API test passed" || echo "✗ API test failed"

# Run all tests
test: test-repl test-api

# Clean containers and images
clean:
	docker-compose down --rmi all --volumes --remove-orphans
	docker system prune -f

# Reset everything (WARNING: destroys all data)
reset:
	@echo "WARNING: This will destroy all data. Press Ctrl+C to cancel."
	@sleep 5
	docker-compose down -v
	docker system prune -af
	@echo "Reset complete. Run 'make up' to start fresh."

# Development helpers
dev-shell:
	docker-compose exec symbiont-runtime /bin/bash

repl-shell:
	docker-compose exec symbiont-repl /bin/bash

db-shell:
	docker-compose exec postgres psql -U symbi -d symbi_osint

redis-shell:
	docker-compose exec redis redis-cli

# Monitor services
monitor:
	@echo "Opening monitoring interfaces..."
	@echo "Grafana: http://localhost:3001 (admin/admin)"
	@echo "Prometheus: http://localhost:9090"
	@echo "Press Ctrl+C to stop monitoring logs"
	docker-compose logs -f symbiont-runtime symbiont-repl

# Quick investigation test
quick-test:
	@echo "Running quick investigation test..."
	@curl -X POST http://localhost:8080/api/v1/investigations/start \
		-H "Content-Type: application/json" \
		-d '{"query": "Investigate IP 8.8.8.8", "requester": "test@example.com"}' \
		| python3 -m json.tool

# Update containers
update:
	docker-compose pull
	docker-compose up -d

# Backup data
backup:
	@echo "Creating backup..."
	docker-compose exec postgres pg_dump -U symbi symbi_osint > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup created: backup_$(shell date +%Y%m%d_%H%M%S).sql"