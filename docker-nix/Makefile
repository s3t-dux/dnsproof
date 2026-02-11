# Makefile for DNSProof Docker Setup

# Default target
.PHONY: default
default: docker-run

# Build and run containers
.PHONY: docker-run
docker-run:
	docker-compose up --build

# Stop all containers
.PHONY: docker-stop
docker-stop:
	docker-compose down

# Start without rebuilding
.PHONY: docker-start
docker-start:
	docker-compose up

# Clean up containers + volumes
.PHONY: docker-clean
docker-clean:
	docker-compose down -v

# Show logs
.PHONY: docker-logs
docker-logs:
	docker-compose logs -f

# Open a shell inside the app container
.PHONY: shell
shell:
	docker exec -it dnsproof-app bash
