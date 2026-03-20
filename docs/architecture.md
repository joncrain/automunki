# AutoMunki Architecture

## Overview

AutoMunki is a web-based management platform for Munki and AutoPkg. It replaces the traditional Git-based workflow with a database-backed web application while maintaining compatibility with existing Munki clients through **HTTP endpoints** that compile catalogs and manifests from the database on demand.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Mac Fleet                                │
│  ┌──────────────┐  ┌──────────────────┐                        │
│  │ Munki Client │  │ AutoMunki Agent  │                        │
│  └──────┬───────┘  └────────┬─────────┘                        │
└─────────┼──────────────────┼──────────────────────────────────┘
          │                    │
          ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Compose / Host                        │
│  ┌──────────────┐  ┌──────────────────────────────────────────┐  │
│  │ Next.js UI   │  │ FastAPI (:8000)                          │  │
│  │ :3000        │──│ REST API, plist compilation, `/repo/*`   │  │
│  └──────────────┘  └──────────────────┬───────────────────────┘  │
│                                       │                           │
│                            ┌──────────▼─────────────┐             │
│                            │ PostgreSQL 16        │             │
│                            │  - Munki data model  │             │
│                            │  - AutoPkg tracking  │             │
│                            │  - Fleet inventory   │             │
│                            │  - Audit trail       │             │
│                            └──────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
          ▲
          │ workflow_dispatch
┌─────────┴──────────────────┐
│ GitHub Actions             │
│  - AutoPkg macOS Runner    │
└────────────────────────────┘
```

## Data Flow

### AutoPkg Run Flow

1. User triggers run from UI or schedule fires
2. Backend creates `autopkg_run` record, dispatches GitHub Actions workflow
3. macOS runner installs Munki + AutoPkg, runs recipes
4. For each recipe result, runner POSTs to `/api/v1/autopkg/runs/{id}/results`
5. Backend stores results; items needing approval are queued
6. Runner calls `/api/v1/autopkg/runs/{id}/complete` when done
7. Git PRs are still created for the repo (backward compatibility)

### Catalog delivery

Munki catalog and manifest plists are compiled **on demand** when clients request them via the repo HTTP routes (backed by the database). Optional: `POST /api/v1/catalogs/makecatalogs` audits all catalogs and returns warnings (empty catalogs, missing installer paths, plist sizes).

### Client Reporting Flow

1. AutoMunki agent runs on managed Macs (triggered by Munki postflight)
2. Agent collects hardware info, installed software, Munki install results
3. Agent POSTs to `/api/v1/reports/checkin`
4. Backend upserts machine record and stores install reports
5. Fleet dashboard shows compliance and inventory data

## Database Schema

### Core Munki Entities

- **munki_pkginfo** - Software package metadata (name, version, installer details, scripts)
- **munki_catalog** - Named catalogs (test, production, etc.)
- **munki_pkginfo_catalog** - Many-to-many: which packages are in which catalogs
- **munki_manifest** - Munki manifests defining what machines get
- **munki_manifest_item** - Items within manifests (managed_installs, optional_installs, etc.)
- **munki_manifest_catalog** - Which catalogs a manifest searches
- **munki_manifest_inclusion** - Manifest hierarchy (included_manifests)
- **munki_promotion_rule** - Per-title promotion configuration

### AutoPkg Entities

- **autopkg_recipe** - Recipe overrides and configuration (optional `source_repo_full_name` = GitHub `owner/repo`)
- **autopkg_run** - Run history with status tracking
- **autopkg_run_result** - Per-recipe results with approval workflow
- **autopkg_trust_change_request** - Pending trust updates for recipes
- **github_recipe_repo** - Cached GitHub repos for Discover (autopkg org + optional `is_custom` repos)
- **github_recipe** - Cached `.munki.recipe` paths per repo

### Supporting Entities

- **user** - Auth via FastAPI-Users with role field
- **audit_log** - Full compliance audit trail with before/after snapshots
- **client_machine** - Fleet inventory from agent check-ins
- **client_install_report** - Per-machine install status

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI + Python 3.12 |
| ORM | SQLAlchemy 2.0 (async) |
| Migrations | Alembic |
| Database | PostgreSQL 16 |
| Auth | FastAPI-Users (JWT) |
| Frontend | Next.js 15 + Bun |
| UI Components | shadcn/ui + Tailwind CSS |
| Data Tables | TanStack Table |
| Data Fetching | TanStack Query |
| Containers | Docker Compose |
| CI/CD | GitHub Actions |
| CDN | CloudFront + S3 |
| Observability | structlog + Prometheus |
