# AutoMunki Deployment Guide

## Architecture

AutoMunki uses a **single-origin proxy** architecture. The Next.js frontend proxies all `/api/*` requests to the FastAPI backend via [rewrites](https://nextjs.org/docs/app/api-reference/config/next-config-js/rewrites). Only **port 3000** needs to be exposed — the backend runs internally and is never accessed directly.

```
Browser / Munki Agent / GitHub Actions
        │
        ▼
   Port 3000 (Next.js)
        │
        ├── /           → React UI
        ├── /api/docs   → FastAPI Swagger docs (proxied)
        └── /api/v1/*   → FastAPI backend (proxied to port 8000)
```

This means:
- One URL for everything (UI, API, docs)
- One ngrok tunnel for external access: `ngrok http 3000`
- No CORS configuration needed
- GitHub Actions uses the same URL as the browser

## Prerequisites

- Docker and Docker Compose (recommended), **or**:
  - PostgreSQL 16
  - Python 3.12+ and [uv](https://docs.astral.sh/uv/)
  - Node.js 20+ / [Bun](https://bun.sh) 1.0+

## Quick Start with Docker Compose

```bash
git clone https://github.com/joncrain/automunki.git
cd automunki
cp .env.example .env
# Edit .env with your configuration (at minimum: SECRET_KEY, GITHUB_TOKEN, GITHUB_REPO)

docker compose up -d
docker compose exec backend alembic upgrade head
```

Access the application at **http://localhost:3000**:
- UI: http://localhost:3000
- API Docs: http://localhost:3000/api/docs
- Health Check: http://localhost:3000/api/health

### Exposing to the Internet (ngrok)

```bash
ngrok http 3000
```

Set `API_PUBLIC_URL` in your `.env` to the ngrok URL so GitHub Actions can call back:

```bash
API_PUBLIC_URL=https://xxxx.ngrok-free.app
```

Restart the backend to pick up the change, or pass it as an environment variable.

## Local Development (without Docker)

### Backend

```bash
cd backend
uv venv
uv pip install -e ".[dev]"

# Start PostgreSQL (or use Docker for just the DB)
docker compose up db -d

# Run migrations
uv run alembic upgrade head

# Start the server on port 8000
uv run uvicorn automunki.main:app --reload
```

### Frontend

```bash
cd frontend
bun install
bun dev
```

The frontend dev server starts on port 3000 and automatically proxies `/api/*` to `http://localhost:8000`. Open http://localhost:3000 — that's the only URL you need.

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

### Proxy / Networking

| Variable | Description |
|----------|-------------|
| `API_PUBLIC_URL` | Public URL for GitHub Actions callbacks (e.g., your ngrok URL). Defaults to the first CORS origin. |
| `BACKEND_URL` | Where Next.js proxies API requests (default: `http://localhost:8000`). Only change if the backend runs on a different host. In Docker Compose this is set to `http://backend:8000` automatically. |

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
| `CORS_ORIGINS` | JSON array of allowed origins. Not needed when using the proxy. |
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications |

## Database Migrations

```bash
cd backend

# Create a new migration
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

The `api_url` is the same single URL (port 3000) — the agent's `/api/v1/reports/checkin` calls are proxied to the backend automatically.

## Cloud Deployment

For production, AutoMunki can use [Neon](https://neon.tech) for managed Postgres:

- **[Neon Database Setup](./neon-database-setup.md)** — Create a Neon project, configure the connection string, run migrations, and use branching for preview environments.

### Hosting Options

Since the Next.js proxy means only one port needs to be exposed, any platform that can run Docker works:

| Platform | Notes |
|----------|-------|
| **Railway** | `docker compose up` equivalent, free tier available, auto-deploy from GitHub |
| **Render** | Docker support, free tier for web services |
| **Fly.io** | Edge deployment, good for low-latency |
| **AWS Lightsail** | Cheapest AWS option, $3.50/mo for a container |
| **Any VPS** | DigitalOcean, Linode, Hetzner — just `docker compose up -d` |

Set `DATABASE_URL` to your Neon connection string and `API_PUBLIC_URL` to the public URL of the deployment.

## Production Considerations

- Use a strong `SECRET_KEY` (generate with `openssl rand -hex 32`)
- Use [Neon](https://neon.tech) for managed Postgres with autoscaling and branching
- Only expose port 3000 — the backend should not be directly accessible
- Set `API_PUBLIC_URL` to your production URL so GitHub Actions callbacks work
- Configure log aggregation (the backend outputs structured JSON logs)
- Monitor the `/health` and `/ready` endpoints (accessible at port 3000 via the proxy)
- Set up Prometheus scraping from `/metrics`
