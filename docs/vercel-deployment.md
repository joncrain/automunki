# Vercel Deployment

The AutoMunki frontend (Next.js) is deployed to [Vercel](https://vercel.com). The backend (FastAPI) runs separately — see [Backend Hosting](#backend-hosting) for options.

## Prerequisites

- A [Vercel account](https://vercel.com/signup)
- The [Vercel CLI](https://vercel.com/docs/cli) installed: `npm install -g vercel`
- The repository pushed to GitHub

## Initial Setup

### 1. Link the Project

```bash
# Authenticate
vercel login

# Link from the repo root (uses git remote to match)
vercel link --repo
```

This creates `.vercel/repo.json` which maps the `frontend/` directory to a Vercel project. Vercel will auto-detect Next.js and configure the build.

### 2. Configure the Project in Vercel Dashboard

In the Vercel project settings:

1. **Root Directory**: Set to `frontend`
2. **Framework Preset**: Next.js (auto-detected)
3. **Build Command**: `bun run build` (auto-detected from `vercel.json`)
4. **Install Command**: `bun install` (auto-detected from `vercel.json`)

### 3. Set Environment Variables

In the Vercel dashboard under **Settings → Environment Variables**, add:

| Variable | Value | Environment |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `https://your-backend-url.com` | Production, Preview |

The frontend uses `NEXT_PUBLIC_API_URL` to connect to the FastAPI backend. If not set, it defaults to `http://localhost:8000`.

## Deployment Methods

### Git Push (Recommended)

Once linked, every push to `main` triggers a production deployment. Pushes to other branches create preview deployments automatically.

```bash
git add .
git commit -m "deploy: update frontend"
git push
```

### CLI Deploy

For manual deployments without pushing to git:

```bash
# Preview deployment
vercel deploy frontend

# Production deployment
vercel deploy frontend --prod
```

### GitHub Actions

The repository includes a [deploy workflow](../.github/workflows/deploy.yml) that:

1. Runs Alembic migrations against Neon
2. Deploys the frontend to Vercel

This runs automatically on push to `main` and can be triggered manually.

#### Required GitHub Secrets

| Secret | Description | How to Get |
|---|---|---|
| `VERCEL_TOKEN` | Vercel API token | [vercel.com/account/tokens](https://vercel.com/account/tokens) |
| `VERCEL_ORG_ID` | Your Vercel team/org ID | `cat .vercel/project.json` after linking, or Vercel dashboard → Settings → General |
| `VERCEL_PROJECT_ID` | The Vercel project ID | `cat .vercel/project.json` after linking, or Vercel dashboard → Settings → General |
| `DATABASE_URL` | Neon connection string | See [Neon Database Setup](./neon-database-setup.md) |

## Frontend Configuration

### `vercel.json`

Located at `frontend/vercel.json`:

```json
{
  "framework": "nextjs",
  "installCommand": "bun install",
  "buildCommand": "bun run build"
}
```

### `next.config.ts`

The Next.js config uses `output: "standalone"` for optimized production builds:

```typescript
const nextConfig: NextConfig = {
  output: "standalone",
};
```

## Backend Hosting

The FastAPI backend is **not** deployed to Vercel — it requires a long-running Python server. Recommended hosting options:

| Platform | Notes |
|---|---|
| **Railway** | One-click deploy from Dockerfile, managed Postgres available |
| **Render** | Free tier available, auto-deploy from GitHub |
| **Fly.io** | Edge deployment, good for low-latency API |
| **Docker on VPS** | Full control, use the existing `backend/Dockerfile` |
| **Cloud Run (GCP)** | Serverless containers, scales to zero |

Whichever platform you choose, set the `DATABASE_URL` environment variable to your Neon connection string and ensure the backend URL is configured as `NEXT_PUBLIC_API_URL` in Vercel.

### CORS Configuration

Update the `CORS_ORIGINS` environment variable to include your Vercel deployment URL:

```bash
CORS_ORIGINS=["https://your-app.vercel.app","http://localhost:3000"]
```

## Custom Domain

1. In the Vercel dashboard, go to **Settings → Domains**.
2. Add your custom domain.
3. Configure DNS as instructed (CNAME or A record).
4. Vercel automatically provisions an SSL certificate.

Update `CORS_ORIGINS` on the backend to include the custom domain.

## Preview Deployments

Every pull request gets an automatic preview deployment with a unique URL. This is useful for:

- Reviewing UI changes before merging
- Testing against a Neon branch database (set `NEXT_PUBLIC_API_URL` per preview environment)
- Sharing work-in-progress with teammates

## Troubleshooting

### Build Fails with Missing Dependencies

Ensure `bun.lock` is committed to the repository. Vercel uses `bun install --frozen-lockfile` which requires the lockfile.

### API Requests Fail in Production

1. Verify `NEXT_PUBLIC_API_URL` is set in Vercel environment variables.
2. Check that the backend's `CORS_ORIGINS` includes the Vercel deployment URL.
3. Ensure the backend is running and accessible from the internet.

### `output: "standalone"` Issues

The `standalone` output mode creates a self-contained build. If you see missing files in production, ensure all necessary files are included in the Next.js build output. Check the [Next.js standalone docs](https://nextjs.org/docs/app/api-reference/config/next-config-js/output#automatically-copying-traced-files) for details.
