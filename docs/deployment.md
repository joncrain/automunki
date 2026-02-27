# AutoMunki Deployment Guide

## Prerequisites

- Docker and Docker Compose
- PostgreSQL 16 (or use the included Docker container)
- Node.js 20+ / Bun 1.0+ (for frontend development)
- Python 3.12+ (for backend development)

## Quick Start with Docker Compose

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/automunki.git
   cd automunki
   ```

2. Create a `.env` file:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Start the services:
   ```bash
   docker compose up -d
   ```

4. Run database migrations:
   ```bash
   docker compose exec backend alembic upgrade head
   ```

5. Import your existing Munki repo:
   ```bash
   docker compose exec backend python -m automunki.cli.main import-repo /path/to/repo
   ```

6. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/api/docs
   - Metrics: http://localhost:8000/metrics

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `SECRET_KEY` | JWT signing secret (generate with `openssl rand -hex 32`) |

### GitHub Integration

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub token for API access |
| `GITHUB_REPO` | Repository in `owner/repo` format |

### AWS / S3

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | AWS region (default: us-east-1) |
| `AWS_S3_BUCKET` | S3 bucket for Munki repo |
| `CLOUDFRONT_DISTRIBUTION_ID` | CloudFront distribution ID |

### Optional

| Variable | Description |
|----------|-------------|
| `DEBUG` | Enable debug mode (default: false) |
| `CORS_ORIGINS` | JSON array of allowed origins |
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications |

## Local Development

### Backend

```bash
cd backend
uv venv
uv pip install -e ".[dev]"

# Start PostgreSQL
docker compose up db -d

# Run migrations
uv run alembic upgrade head

# Start the server
uv run uvicorn automunki.main:app --reload
```

### Frontend

```bash
cd frontend
bun install
bun dev
```

## Database Migrations

```bash
# Create a new migration
cd backend
uv run alembic revision --autogenerate -m "description"

# Apply migrations
uv run alembic upgrade head

# Rollback one migration
uv run alembic downgrade -1
```

## Client Agent Installation

1. Copy `agent/automunki_agent.py` to `/usr/local/munki/` on managed Macs
2. Create config at `/etc/automunki/agent.conf`:
   ```json
   {"api_url": "https://your-automunki-server.com"}
   ```
3. Install the launchd plist:
   ```bash
   sudo cp agent/com.automunki.agent.plist /Library/LaunchDaemons/
   sudo launchctl load /Library/LaunchDaemons/com.automunki.agent.plist
   ```

## Production Considerations

- Use a strong `SECRET_KEY` (generate with `openssl rand -hex 32`)
- Put the frontend behind a reverse proxy (nginx/Caddy) with TLS
- Use managed PostgreSQL (RDS, Cloud SQL) for production
- Set up database backups
- Configure log aggregation (the backend outputs structured JSON logs)
- Monitor the `/health` and `/ready` endpoints
- Set up Prometheus scraping from `/metrics`
