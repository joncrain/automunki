# Neon Database Setup

AutoMunki uses [Neon](https://neon.tech) as its serverless Postgres database in production. Neon provides autoscaling, branching, and scale-to-zero capabilities on top of standard Postgres.

## Prerequisites

- A [Neon account](https://console.neon.tech/signup)
- The [Neon CLI](https://neon.com/docs/reference/neon-cli) (optional, for automation)

## Create a Neon Project

### Via the Neon Console

1. Go to [console.neon.tech](https://console.neon.tech) and sign in.
2. Click **New Project**.
3. Set the project name to `automunki` (or your preference).
4. Select a region close to your Vercel deployment (e.g., `us-east-2` for US East).
5. Leave the default database name as `neondb` or change it to `automunki`.
6. Click **Create Project**.
7. Copy the connection string from the dashboard — you'll need it for configuration.

### Via the Neon CLI

```bash
# Install the CLI
brew install neonctl
# or: npm install -g neonctl

# Authenticate
neonctl auth

# Create a project
neonctl projects create --name automunki --region-id aws-us-east-2

# Get the connection string
neonctl connection-string --project-id <project-id>
```

## Connection String Format

Neon provides a standard Postgres connection string. AutoMunki uses the `asyncpg` driver, so the URL must use the `postgresql+asyncpg://` scheme:

```
postgresql+asyncpg://<user>:<password>@<endpoint>.neon.tech/<database>?sslmode=require
```

Example:

```
postgresql+asyncpg://automunki_owner:AbC123dEf@ep-cool-darkness-123456.us-east-2.aws.neon.tech/automunki?sslmode=require
```

### Converting from the Neon Dashboard URL

The Neon dashboard shows a `postgresql://` URL. Replace the scheme prefix:

| Neon Dashboard | AutoMunki `.env` |
|---|---|
| `postgresql://user:pass@host/db` | `postgresql+asyncpg://user:pass@host/db?sslmode=require` |

## Configuration

Set the `DATABASE_URL` environment variable:

```bash
# In .env (local development pointing to Neon)
DATABASE_URL=postgresql+asyncpg://user:pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/automunki?sslmode=require

# In GitHub Actions secrets (for CI/CD migrations)
# Settings → Secrets → Actions → DATABASE_URL
```

### Connection Pooling

AutoMunki automatically detects Neon connections (via the `neon.tech` hostname) and adjusts pool settings:

- **Pool size**: 5 connections (vs. 20 for local)
- **Max overflow**: 5 (vs. 10 for local)
- **`pool_pre_ping`**: Enabled — checks connection liveness before each query to handle Neon's scale-to-zero gracefully
- **`pool_recycle`**: 300 seconds — prevents stale connections after Neon compute suspension
- **SSL**: Required automatically for Neon connections

These settings are configured in `backend/automunki/core/db.py`.

### Using Neon's Connection Pooler

For higher concurrency, use Neon's built-in PgBouncer pooler by adding `-pooler` to the endpoint hostname:

```
postgresql+asyncpg://user:pass@ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech/automunki?sslmode=require
```

This is recommended if you expect many concurrent connections (e.g., multiple backend replicas).

## Running Migrations

Alembic migrations work against Neon the same way as local Postgres:

```bash
cd backend

# Set the DATABASE_URL to your Neon connection string
export DATABASE_URL="postgresql+asyncpg://user:pass@ep-xxx.neon.tech/automunki?sslmode=require"

# Run migrations
uv run alembic upgrade head

# Check current migration state
uv run alembic current

# Create a new migration
uv run alembic revision --autogenerate -m "description of change"
```

Migrations also run automatically in CI via the [deploy workflow](../.github/workflows/deploy.yml) on every push to `main`.

## Branching

Neon branches are instant, copy-on-write clones of your database. Use them for:

- **Preview environments**: Create a branch per pull request for isolated testing.
- **Migration testing**: Test schema changes on a branch before applying to production.
- **Development**: Each developer can have their own branch.

### Create a Branch

```bash
# Via CLI
neonctl branches create --name feature-xyz --project-id <project-id>

# Get the branch connection string
neonctl connection-string --branch feature-xyz --project-id <project-id>
```

### Branch Lifecycle

Branches are cheap and ephemeral. Delete them when no longer needed:

```bash
neonctl branches delete feature-xyz --project-id <project-id>
```

## Scale to Zero

Neon computes automatically suspend after 5 minutes of inactivity (configurable). The first query after suspension has a cold-start penalty of a few hundred milliseconds. AutoMunki's `pool_pre_ping=True` setting handles reconnection transparently.

## Monitoring

- **Neon Console**: View query performance, storage usage, and compute activity at [console.neon.tech](https://console.neon.tech).
- **AutoMunki Health Check**: The `/ready` endpoint verifies database connectivity with a `SELECT 1` query.

## Troubleshooting

### `SSL SYSCALL error: EOF detected`

This occurs when the application tries to reuse a connection after Neon compute suspension. The `pool_pre_ping=True` and `pool_recycle=300` settings in `db.py` should prevent this. If it persists, reduce `pool_recycle` to match your Neon scale-to-zero timeout.

### `SSL connection has been closed unexpectedly`

Ensure you're running SQLAlchemy 2.0.33 or later. Earlier versions may reuse idle connections that Neon has closed.

### Connection Timeout on First Request

The first request after compute suspension may take 200-500ms longer due to cold start. This is expected behavior with Neon's scale-to-zero. If this is unacceptable for your use case, you can disable scale-to-zero in the Neon console (requires Launch or Scale plan).
