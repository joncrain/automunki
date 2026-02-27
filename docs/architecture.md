# AutoMunki Architecture

## Overview

AutoMunki is a web-based management platform for Munki and AutoPkg. It replaces the traditional Git-based workflow with a database-backed web application while maintaining compatibility with existing Munki clients through a compilation and sync pipeline.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Mac Fleet                                │
│  ┌──────────────┐  ┌──────────────────┐                        │
│  │ Munki Client │  │ AutoMunki Agent  │                        │
│  └──────┬───────┘  └────────┬─────────┘                        │
└─────────┼──────────────────┼────────────────────────────────────┘
          │                  │
          ▼                  │
┌──────────────────┐         │
│ CloudFront + S3  │         │
│ (Static Repo)    │         │
└──────────────────┘         │
          ▲                  │
          │                  ▼
┌─────────┼──────────────────────────────────────────────────────┐
│         │           Docker Compose                             │
│  ┌──────┴───────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Repo Sync    │  │ Next.js      │  │ FastAPI Backend       │ │
│  │ (GH Action)  │  │ Frontend     │──│  - REST API           │ │
│  │              │  │ :3000        │  │  - Auth (JWT)         │ │
│  └──────────────┘  └──────────────┘  │  - Audit Logging      │ │
│                                      │  - Plist Compilation   │ │
│                                      │  :8000                 │ │
│                                      └──────────┬─────────────┘ │
│                                                 │               │
│                                      ┌──────────▼─────────────┐ │
│                                      │ PostgreSQL 16          │ │
│                                      │  - Munki data model    │ │
│                                      │  - AutoPkg tracking    │ │
│                                      │  - Fleet inventory     │ │
│                                      │  - Audit trail         │ │
│                                      └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
          ▲
          │ workflow_dispatch
┌─────────┴──────────────────┐
│ GitHub Actions             │
│  - AutoPkg macOS Runner    │
│  - Repo Sync Runner        │
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

### Repo Compilation Flow

1. Admin triggers sync from UI or schedule fires
2. Backend dispatches `repo-sync.yml` GitHub Action
3. Action calls API to compile catalogs, manifests, and pkgsinfo as plists
4. Compiled files are synced to S3 via `aws s3 sync`
5. CloudFront cache is invalidated
6. Munki clients download from CloudFront on next check-in

### Client Reporting Flow

1. AutoMunki agent runs on managed Macs (triggered by Munki postflight)
2. Agent collects hardware info, installed software, Munki install results
3. Agent POSTs to `/api/v1/reports/checkin`
4. Backend upserts machine record and stores install reports
5. Fleet dashboard shows compliance and inventory data

## Database Schema

### Core Munki Entities

- **pkg_info** - Software package metadata (name, version, installer details, scripts)
- **catalog** - Named catalogs (test, production, etc.)
- **pkg_info_catalog** - Many-to-many: which packages are in which catalogs
- **manifest** - Munki manifests defining what machines get
- **manifest_item** - Items within manifests (managed_installs, optional_installs, etc.)
- **manifest_catalog** - Which catalogs a manifest searches
- **manifest_inclusion** - Manifest hierarchy (included_manifests)
- **promotion_rule** - Per-title promotion configuration

### AutoPkg Entities

- **autopkg_repo** - Tracked recipe repositories
- **autopkg_recipe** - Recipe overrides and configuration
- **autopkg_run** - Run history with status tracking
- **autopkg_run_result** - Per-recipe results with approval workflow

### Supporting Entities

- **user** - Auth via FastAPI-Users with role field
- **audit_log** - Full compliance audit trail with before/after snapshots
- **client_machine** - Fleet inventory from agent check-ins
- **client_install_report** - Per-machine install status
- **sync_job** - Repo compilation and S3 sync tracking
- **icon** - Icon metadata and S3 references

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
