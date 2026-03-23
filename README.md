# AutoMunki

AutoMunki is a **database-backed web application** for managing **Munki** catalogs, manifests, and pkginfo, together with **AutoPkg** recipe overrides, runs, and approvals. Munki clients continue to use standard HTTP repo URLs; the server compiles catalogs and manifests from PostgreSQL on demand.

This branch (`db-mode`) is the **full-stack product**: Next.js UI, FastAPI API, RBAC, and Postgres—not a Git-only repo wrapper.

## Stack

| Layer | Technology |
|--------|------------|
| UI | Next.js (App Router), React, TanStack Query |
| API | FastAPI, SQLAlchemy 2 (async), Alembic migrations |
| Data | PostgreSQL 16+ |
| Auth | JWT (built-in) or OIDC; optional open registration; **page-level** read/write permissions for signed-in users |

## Features (high level)

- **Munki**: Software (pkginfo), catalogs, manifests (including conditional items and included manifests), on-demand plist compilation for clients
- **AutoPkg**: Recipe overrides, trust status, discover/import, run history, GitHub or local runner flows, approval queue
- **Reporting & audit**: Fleet check-ins, install history, audit log (where enabled)
- **Access control**: UI and API enforce **page keys** (e.g. software, manifests, catalogs, AutoPkg areas, admin). Users can have **read-only** access; mutating actions are hidden when they lack write permission

## Quick start

```bash
cp .env.example .env
# Set at least DATABASE_URL, SECRET_KEY, and (for AutoPkg/GitHub) GITHUB_TOKEN + GITHUB_REPO

docker compose up -d
docker compose exec backend alembic upgrade head
```

Open **http://localhost:3000** (Next.js proxies `/api/*` to the API).

For detailed setup (local dev without Docker, ngrok, production, env vars), see **[docs/deployment.md](docs/deployment.md)**.

Other docs:

- **[docs/architecture.md](docs/architecture.md)** — system design and data flow
- **[docs/contributing.md](docs/contributing.md)** — repo layout and dev workflow

## Repository layout

```
automunki/
├── backend/          # FastAPI app, models, migrations, tests
├── frontend/         # Next.js app
├── agent/            # Optional client reporting agent for managed Macs
├── docs/             # Deployment, architecture, contributing, local runner
└── docker-compose.yml
```

## GitHub Actions

Workflows under `.github/workflows/` support **AutoPkg** (e.g. cloud runner dispatch) and deployment. They assume a running AutoMunki API with `API_PUBLIC_URL` and tokens configured as in the deployment guide—not the legacy “only manual dispatch” workflow described in older READMEs.

## License

Copyright © Jon Crain. AutoMunki is licensed under the **GNU Affero General Public License v3.0 only** — see [LICENSE](LICENSE). If you run a modified version as a network service, AGPL requires you to offer corresponding source to users (see [section 13](https://www.gnu.org/licenses/agpl-3.0.html#section13) of the license).
