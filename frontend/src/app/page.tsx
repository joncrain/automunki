'use client'

import { useQuery } from '@tanstack/react-query'
import { CheckCircle, FolderOpen, Package, Play } from 'lucide-react'
import Link from 'next/link'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  type AutoPkgRunRead,
  api,
  type CatalogRead,
  type PaginatedResponse,
} from '@/lib/api'
import { formatDate } from '@/lib/format'

export default function DashboardPage() {
  const { data: catalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
  })

  const { data: runs } = useQuery({
    queryKey: ['autopkg-runs-dash'],
    queryFn: () =>
      api.get<PaginatedResponse<AutoPkgRunRead>>('/autopkg/runs?page_size=5'),
  })

  const { data: software } = useQuery({
    queryKey: ['software-count'],
    queryFn: () => api.get<PaginatedResponse<unknown>>('/pkginfo?page_size=1'),
  })

  const { data: approvals } = useQuery({
    queryKey: ['pending-approvals'],
    queryFn: () => api.get<unknown[]>('/autopkg/approvals'),
  })

  const totalTitles = software?.total ?? 0
  const totalCatalogs = catalogs?.length ?? 0
  const lastRun = runs?.items?.[0]
  const pendingApprovals = Array.isArray(approvals) ? approvals.length : 0

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Dashboard</h1>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-l-4 border-l-gruvbox-blue/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Software Titles
            </CardTitle>
            <Package className="h-4 w-4 text-gruvbox-blue" aria-hidden="true" />
          </CardHeader>
          <CardContent>
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {totalTitles}
            </div>
            <p className="text-xs text-muted-foreground">
              Packages in the repository
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-gruvbox-green/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Catalogs</CardTitle>
            <FolderOpen
              className="h-4 w-4 text-gruvbox-green"
              aria-hidden="true"
            />
          </CardHeader>
          <CardContent>
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {totalCatalogs}
            </div>
            <p className="text-xs text-muted-foreground">
              {catalogs?.map((c) => `${c.name} (${c.item_count})`).join(', ') ??
                'Loading...'}
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-gruvbox-purple/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Last Run</CardTitle>
            <Play className="h-4 w-4 text-gruvbox-purple" aria-hidden="true" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {lastRun ? (
                <Badge
                  variant={
                    lastRun.status === 'completed'
                      ? 'default'
                      : lastRun.status === 'failed'
                        ? 'destructive'
                        : 'secondary'
                  }
                >
                  {lastRun.status}
                </Badge>
              ) : (
                'No runs'
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {lastRun
                ? `${lastRun.recipes_imported ?? 0} imported, ${lastRun.recipes_failed ?? 0} failed`
                : 'No AutoPkg runs recorded'}
            </p>
          </CardContent>
        </Card>

        <Card className="border-l-4 border-l-gruvbox-yellow/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Pending Approvals
            </CardTitle>
            <CheckCircle
              className="h-4 w-4 text-gruvbox-yellow"
              aria-hidden="true"
            />
          </CardHeader>
          <CardContent>
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {pendingApprovals}
            </div>
            <p className="text-xs text-muted-foreground">
              Items awaiting review
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent AutoPkg Runs</CardTitle>
          </CardHeader>
          <CardContent>
            {runs?.items?.length ? (
              <div className="space-y-3">
                {runs.items.map((run) => (
                  <Link
                    key={run.id}
                    href="/autopkg/runs"
                    className="flex items-center justify-between rounded-md border p-3 transition-colors hover:bg-accent"
                  >
                    <div>
                      <Badge
                        variant={
                          run.status === 'completed'
                            ? 'default'
                            : run.status === 'failed'
                              ? 'destructive'
                              : 'secondary'
                        }
                      >
                        {run.status}
                      </Badge>
                      <span className="ml-2 text-sm text-muted-foreground">
                        {run.trigger_type}
                      </span>
                    </div>
                    <span
                      suppressHydrationWarning
                      className="text-sm text-muted-foreground"
                    >
                      {formatDate(run.created_at)}
                    </span>
                  </Link>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No runs yet</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Catalogs Overview</CardTitle>
          </CardHeader>
          <CardContent>
            {catalogs?.length ? (
              <div className="space-y-3">
                {catalogs.map((cat) => (
                  <Link
                    key={cat.id}
                    href="/catalogs"
                    className="flex items-center justify-between rounded-md border p-3 transition-colors hover:bg-accent"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{cat.name}</span>
                      {cat.is_production && (
                        <Badge variant="default">Production</Badge>
                      )}
                    </div>
                    <span
                      className="text-sm text-muted-foreground"
                      style={{ fontVariantNumeric: 'tabular-nums' }}
                    >
                      {cat.item_count} items
                    </span>
                  </Link>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No catalogs yet</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
