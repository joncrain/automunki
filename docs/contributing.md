# Contributing to AutoMunki

## Project Structure

```
automunki/
├── autopkg_src/          # Existing AutoPkg automation (runs on macOS)
│   ├── overrides/        # Recipe override plists
│   ├── autopkg_tools.py  # Main runner (modified to report to API)
│   ├── git_utils.py      # Git/PR helpers
│   ├── slack_utils.py    # Slack notifications
│   └── recipe_list.json  # Active recipe list
├── backend/              # FastAPI Python backend
│   ├── alembic/          # Database migrations
│   ├── automunki/
│   │   ├── api/routes/   # API endpoint handlers
│   │   ├── models/       # SQLAlchemy ORM models
│   │   ├── schemas/      # Pydantic request/response schemas
│   │   ├── services/     # Business logic
│   │   ├── core/         # Config, DB, auth, middleware
│   │   └── cli/          # Management commands
│   └── tests/
├── frontend/             # Next.js React frontend
│   └── src/
│       ├── app/          # Pages (App Router)
│       ├── components/   # Reusable components
│       └── lib/          # API client, utilities
├── agent/                # Client reporting agent for managed Macs
├── docs/                 # Documentation
├── .github/workflows/    # CI/CD workflows
└── docker-compose.yml    # Local development setup
```

## Development Setup

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start just the database
docker compose up db -d

# Run migrations
alembic upgrade head

# Import existing data
python -m automunki.cli.main import-repo /path/to/automunki

# Start dev server
uvicorn automunki.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
bun install
bun dev
```

## Code Style

### Backend (Python)
- Use type hints everywhere
- Prefer `async def` for I/O operations
- Use Pydantic models for all API input/output
- Follow the FastAPI dependency injection pattern
- Keep business logic in `services/`, not in route handlers

### Frontend (TypeScript)
- Use TypeScript strict mode
- Use TanStack Query for all API calls
- Use shadcn/ui components as the base
- Keep pages thin, extract logic into hooks

## Adding a New API Endpoint

1. Add the SQLAlchemy model in `backend/automunki/models/`
2. Create Pydantic schemas in `backend/automunki/schemas/`
3. Add business logic in `backend/automunki/services/`
4. Create the route handler in `backend/automunki/api/routes/`
5. Register the router in `backend/automunki/main.py`
6. Create an Alembic migration: `alembic revision --autogenerate -m "description"`
7. Add the TypeScript types to `frontend/src/lib/api.ts`
8. Build the frontend page/component

## Database Migrations

Always use Alembic for schema changes:

```bash
cd backend
alembic revision --autogenerate -m "add new_field to pkg_info"
alembic upgrade head
```

Review auto-generated migrations before applying - they may need manual adjustment for complex changes.

## Testing

```bash
cd backend
pytest
```
