default:
    @just --list

# Install dependencies using pdm
install:
    pdm install

# Install dependencies including test dependencies
install-dev:
    pdm install -G test

# Run tests
test:
    pdm run pytest

dev:
    pdm run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Build Docker image
build:
    docker compose build

# Start services using docker compose
up:
    docker compose up

# Start services in detached mode
up-detached:
    docker compose up -d

# Stop services
down:
    docker compose down

# View logs
logs:
    docker compose logs -f

# Rebuild and restart services
restart:
    docker compose down
    docker compose up --build

# Run tests in Docker
test-docker:
    docker compose run --rm epa-service pdm run pytest

# Clean up Docker resources
clean-docker:
    docker compose down -v
    docker system prune -f
