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

## Settings (UI)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/settings/ui` | Read-only UI config (`github_repo`, default `autopkg_runner_mode`) |

## PkgInfo (Software)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pkginfo` | List/search software (paginated) |
| GET | `/pkginfo/{id}` | Get software detail |
| GET | `/pkginfo/{id}/plist` | Get compiled plist XML |
| GET | `/pkginfo/{id}/install-reports/summary` | Install-report stats + 90-day timeline for this item name |
| PUT | `/pkginfo/{id}` | Update software metadata |
| DELETE | `/pkginfo/{id}` | Soft-delete software |
| POST | `/pkginfo/{id}/promote` | Promote to a catalog |

## UI icons (PNG)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/icons/upload` | Multipart: `file` (PNG), optional form `icon_name` (stem without `.png`) |
| GET | `/icons/{basename}` | Serve `{basename}.png` from the configured UI icons directory |

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
| POST | `/catalogs/makecatalogs` | Verify all catalogs (compile each, return sizes + warnings) |

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
| POST | `/autopkg/runs` | Trigger a new AutoPkg run (body: `recipe_names`, optional `runner`: `github` \| `local`; default from `AUTOPKG_RUNNER_MODE`) |
| GET | `/autopkg/runs` | List run history (paginated) |
| GET | `/autopkg/runs/{id}` | Get run detail with results |
| POST | `/autopkg/runs/{id}/results` | Post per-recipe result (webhook) |
| POST | `/autopkg/runs/{id}/complete` | Mark run as complete (webhook) |
| GET | `/autopkg/metadata-cache` | cloud-autopkg-runner cache blob (per-recipe keys → entries) |
| PUT | `/autopkg/metadata-cache` | Replace entire cache from runner (`cache_data` JSON) |
| DELETE | `/autopkg/metadata-cache` | Clear cache; optional query `recipe_key` (e.g. `AdobeReader.munki.recipe`) deletes one entry |
| GET | `/autopkg/recipes` | List managed recipes |
| POST | `/autopkg/recipes` | Create/add a recipe |
| POST | `/autopkg/recipes/import-override` | Import an existing AutoPkg override plist (XML, base64 binary plist, YAML, or JSON) into `autopkg_recipe` |
| PUT | `/autopkg/recipes/{id}` | Update recipe config |
| GET | `/autopkg/recipes/discover` | List cached GitHub recipe repos (Discover UI) |
| POST | `/autopkg/cache/sync-repos` | Refresh repo list from the autopkg GitHub org |
| POST | `/autopkg/cache/sync-recipes` | Index `.munki.recipe` files for all cached repos |
| POST | `/autopkg/cache/sync-repo/{owner}/{name}` | Index recipes for one cached repo |
| POST | `/autopkg/cache/repos` | Add any public GitHub `owner/repo` to the cache (`is_custom`) |
| DELETE | `/autopkg/cache/repos/{owner}/{name}` | Remove a repo from the cache (org repos return on sync) |
| GET | `/autopkg/approvals` | List pending approvals |
| POST | `/autopkg/results/{id}/approve` | Approve or reject a result |
| POST | `/autopkg/trust/resolve-commit` | Map trust SHA-256 file hashes to a GitHub commit URL (history walk) |

## Client Reporting

| Method | Path | Description |
|--------|------|-------------|
| POST | `/reports/checkin` | Client agent check-in |
| GET | `/reports/machines` | List fleet machines (paginated) |
| GET | `/reports/machines/{id}` | Get machine detail (`product_name`, `device_image_url`, `platform_uuid`, CPU fields, …) |
| GET | `/reports/compliance` | Fleet compliance overview |
| GET | `/reports/installs` | Paginated `client_install_report` rows with hostname/serial |

### POST /reports/checkin

JSON body. **`serial_number`** (string) is required.

Common top-level fields: `hostname`, `os_version`, `os_build`, `machine_model`, `cpu_type`, `cpu_arch`, `physical_cpus`, `logical_cpus`, `ram_mb`, `disk_size_gb`, `disk_free_gb`, `munki_version`, `manifest_name`, `client_identifier`, `installed_software` (array), `install_results` (array), `hardware_info` (object).

`hardware_info` may include `product_name`, `apple_image_family` (for Apple FMIP thumbnail URLs, same idea as [MunkiReport’s `get_model_icon`](https://github.com/munkireport/machine/blob/master/machine_controller.php)), `platform_uuid`, and other agent-specific keys. Unknown keys are stored as sent.

Each successful check-in appends a row to **`client_machine_checkin`** (timestamp) for per-device history and charts.

### GET /reports/machines/{id} response

Includes **`device_image_url`**: a PNG URL from Apple’s public `statici.icloud.com` / `km.support.apple.com` endpoints when the server can derive one from serial + model + `hardware_info` (mirrors MunkiReport behavior). Also **`platform_uuid`** when the agent reported `IOPlatformUUID`, and **`cpu_arch`**, **`physical_cpus`**, **`logical_cpus`** when stored on the machine row.

**`checkin_total`**: all-time count of check-ins for this machine. **`checkin_history`**: array of `{ "date": "YYYY-MM-DD", "count": number }` for the last 90 calendar days (UTC day buckets, including days with zero check-ins).

### Query parameters for GET /reports/installs

| Param | Type | Description |
|-------|------|-------------|
| page | int | Page number (default: 1) |
| page_size | int | Items per page (default: 50, max: 200) |
| search | string | Match item name, hostname, or serial |
| item_name | string | Exact Munki item name (pkginfo `name`); combined with `search` as AND |
| status | string | Exact status (e.g. `installed`, `failed`, `removed`) |

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
