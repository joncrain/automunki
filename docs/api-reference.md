# AutoMunki API Reference

Base URL: `/api/v1`

Full interactive documentation is available at `/api/docs` (Swagger UI) when the server is running.

## Authentication

All endpoints except `/health`, `/ready`, and `/api/v1/auth/*` require a Bearer token.

```
Authorization: Bearer <jwt_token>
```

### Auth Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Login with email/password, returns JWT |
| POST | `/auth/register` | Register a new user |
| POST | `/auth/logout` | Logout (invalidate token) |
| GET | `/users/me` | Get current user profile |
| PATCH | `/users/me` | Update current user profile |

## PkgInfo (Software)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pkginfo` | List/search software (paginated) |
| GET | `/pkginfo/{id}` | Get software detail |
| GET | `/pkginfo/{id}/plist` | Get compiled plist XML |
| PUT | `/pkginfo/{id}` | Update software metadata |
| DELETE | `/pkginfo/{id}` | Soft-delete software |
| POST | `/pkginfo/{id}/promote` | Promote to a catalog |

### Query Parameters for GET /pkginfo

| Param | Type | Description |
|-------|------|-------------|
| page | int | Page number (default: 1) |
| page_size | int | Items per page (default: 50, max: 200) |
| search | string | Search name/display_name |
| catalog | string | Filter by catalog name |
| category | string | Filter by category |
| name | string | Filter by exact name |
| sort_by | string | Sort field (default: name) |
| sort_order | string | asc or desc |

## Catalogs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/catalogs` | List all catalogs with item counts |
| POST | `/catalogs` | Create a new catalog |
| PUT | `/catalogs/{id}` | Update catalog |
| GET | `/catalogs/{id}/items` | List items in a catalog |
| POST | `/catalogs/{id}/compile` | Generate catalog plist XML |

## Manifests

| Method | Path | Description |
|--------|------|-------------|
| GET | `/manifests` | List all manifests |
| GET | `/manifests/{id}` | Get manifest detail |
| GET | `/manifests/{id}/compile` | Generate manifest plist XML |
| POST | `/manifests` | Create a new manifest |
| PUT | `/manifests/{id}` | Update manifest |
| DELETE | `/manifests/{id}` | Delete manifest |

## AutoPkg

| Method | Path | Description |
|--------|------|-------------|
| POST | `/autopkg/runs` | Trigger a new AutoPkg run |
| GET | `/autopkg/runs` | List run history (paginated) |
| GET | `/autopkg/runs/{id}` | Get run detail with results |
| POST | `/autopkg/runs/{id}/results` | Post per-recipe result (webhook) |
| POST | `/autopkg/runs/{id}/complete` | Mark run as complete (webhook) |
| GET | `/autopkg/recipes` | List managed recipes |
| POST | `/autopkg/recipes` | Create/add a recipe |
| PUT | `/autopkg/recipes/{id}` | Update recipe config |
| GET | `/autopkg/recipes/discover` | Discover recipes from autopkg org |
| GET | `/autopkg/approvals` | List pending approvals |
| POST | `/autopkg/results/{id}/approve` | Approve or reject a result |

## Repo Sync

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sync/compile` | Trigger repo compilation + S3 sync |
| GET | `/sync/status` | Get current sync status |
| GET | `/sync/history` | Get sync history (paginated) |

## Client Reporting

| Method | Path | Description |
|--------|------|-------------|
| POST | `/reports/checkin` | Client agent check-in |
| GET | `/reports/machines` | List fleet machines (paginated) |
| GET | `/reports/machines/{id}` | Get machine detail |
| GET | `/reports/compliance` | Fleet compliance overview |

## Audit Log

| Method | Path | Description |
|--------|------|-------------|
| GET | `/audit` | List audit entries (paginated, filterable) |
| GET | `/audit/{entity_type}/{entity_id}` | Get audit trail for an entity |

### Query Parameters for GET /audit

| Param | Type | Description |
|-------|------|-------------|
| entity_type | string | Filter by entity type |
| action | string | Filter by action |
| user_email | string | Filter by user |

## Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Basic health check |
| GET | `/ready` | Readiness check (includes DB) |
| GET | `/metrics` | Prometheus metrics |
