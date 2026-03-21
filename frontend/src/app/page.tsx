'use client'

import { useQuery } from '@tanstack/react-query'
import {
  BookMarked,
  CheckCircle,
  FolderOpen,
  Package,
  Play,
  ScrollText,
} from 'lucide-react'
import Link from 'next/link'
import type { ComponentType, ReactNode } from 'react'
import { AutoPkgRunsChart } from '@/components/dashboard/autopkg-runs-chart'
import {
  SoftwareAvatarCircles,
  useSoftwarePreviewPackages,
} from '@/components/software-avatar-circles'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  type AutoPkgRecipeRead,
  type AutoPkgRunRead,
  api,
  type CatalogRead,
  type ManifestRead,
  type PaginatedResponse,
} from '@/lib/api'
import { formatDate } from '@/lib/format'
import {
  type MunkiAccentKey,
  munkiAccents,
  munkiSectionHeadingClass,
  munkiSectionMarkerClass,
} from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

type StatLinkCardProps = {
  href: string
  title: string
  icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean }>
  children: ReactNode
  footer: ReactNode
} & (
  | { accent: MunkiAccentKey; borderClass?: never; iconClass?: never }
  | { accent?: never; borderClass: string; iconClass: string }
)

function StatLinkCard({
  href,
  title,
  icon: Icon,
  children,
  footer,
  accent,
  borderClass,
  iconClass,
}: StatLinkCardProps) {
  const cardClass =
    accent !== undefined
      ? munkiAccents[accent].statCard
      : cn('border-l-4', borderClass, 'bg-muted/40')
  const iconCls = accent !== undefined ? munkiAccents[accent].icon : iconClass
  return (
    <Link
      href={href}
      className="block rounded-xl outline-none ring-offset-background transition-opacity hover:opacity-95 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
    >
      <Card className={cn('h-full', cardClass)}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
          <Icon className={cn('h-4 w-4', iconCls)} aria-hidden />
        </CardHeader>
        <CardContent className="space-y-1">
          {children}
          <p className="text-xs text-muted-foreground">{footer}</p>
        </CardContent>
      </Card>
    </Link>
  )
}

export default function DashboardPage() {
  const { data: catalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
  })

  const { data: runsPage } = useQuery({
    queryKey: ['autopkg-runs-dash'],
    queryFn: () =>
      api.get<PaginatedResponse<AutoPkgRunRead>>('/autopkg/runs?page_size=100'),
  })

  const { data: softwarePreviewPage } = useSoftwarePreviewPackages({
    pageSize: 6,
  })

  const { data: manifests } = useQuery({
    queryKey: ['manifests'],
    queryFn: () => api.get<ManifestRead[]>('/manifests'),
  })

  const { data: recipes } = useQuery({
    queryKey: ['autopkg-recipes-dash'],
    queryFn: () => api.get<AutoPkgRecipeRead[]>('/autopkg/recipes'),
  })

  const { data: approvals } = useQuery({
    queryKey: ['pending-approvals'],
    queryFn: () => api.get<unknown[]>('/autopkg/approvals'),
  })

  const runs = runsPage?.items ?? []
  const totalTitles = softwarePreviewPage?.total ?? 0
  const softwarePreviewItems = softwarePreviewPage?.items ?? []
  const totalCatalogs = catalogs?.length ?? 0
  const totalManifests = manifests?.length ?? 0
  const totalRecipes = recipes?.length ?? 0
  const totalRuns = runsPage?.total ?? 0
  const lastRun = runs[0]
  const pendingApprovals = Array.isArray(approvals) ? approvals.length : 0
  const recentRuns = runs.slice(0, 5)

  return (
    <div className="space-y-10">
      <h1
        className={cn(
          'text-3xl font-bold text-pretty',
          munkiAccents.dashboard.pageTitle,
        )}
      >
        Dashboard
      </h1>

      <section className="space-y-4">
        <h2 className={munkiSectionHeadingClass()}>
          <span className={munkiSectionMarkerClass()} aria-hidden />
          Munki
        </h2>
        <div className="grid gap-4 md:grid-cols-3">
          <StatLinkCard
            href="/software"
            accent="software"
            title="Software"
            icon={Package}
            footer="Packages in the repository"
          >
            <div className="flex min-h-10 items-center justify-between gap-3">
              <div
                className="text-2xl font-bold"
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {totalTitles}
              </div>
              <SoftwareAvatarCircles
                packages={softwarePreviewItems}
                total={totalTitles}
                interactive={false}
              />
            </div>
          </StatLinkCard>

          <StatLinkCard
            href="/catalogs"
            accent="catalogs"
            title="Catalogs"
            icon={FolderOpen}
            footer={
              catalogs?.length
                ? catalogs.map((c) => `${c.name} (${c.item_count})`).join(', ')
                : 'Loading...'
            }
          >
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {totalCatalogs}
            </div>
          </StatLinkCard>

          <StatLinkCard
            href="/manifests"
            accent="manifests"
            title="Manifests"
            icon={ScrollText}
            footer="Computer manifests in the repo"
          >
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {totalManifests}
            </div>
          </StatLinkCard>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Card
            className={cn('flex flex-col', munkiAccents.catalogs.overviewCard)}
          >
            <CardHeader>
              <CardTitle>Catalogs overview</CardTitle>
              <CardDescription>
                Production and staging catalogs with item counts
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1">
              {catalogs?.length ? (
                <div className="space-y-3">
                  {catalogs.map((cat) => (
                    <Link
                      key={cat.id}
                      href="/catalogs"
                      className={cn(
                        'flex items-center justify-between rounded-md border p-3 transition-colors',
                        munkiAccents.catalogs.overviewRow,
                      )}
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <span className="truncate font-medium">{cat.name}</span>
                        {cat.is_production && (
                          <Badge variant="default">Production</Badge>
                        )}
                      </div>
                      <span
                        className="shrink-0 text-sm text-muted-foreground"
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

          <Card
            className={cn('flex flex-col', munkiAccents.manifests.overviewCard)}
          >
            <CardHeader>
              <CardTitle>Manifests overview</CardTitle>
              <CardDescription>
                Computer manifests and install rules
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1">
              {manifests?.length ? (
                <div className="space-y-3">
                  {[...manifests]
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((m) => {
                      const installCount =
                        m.managed_installs.length +
                        m.managed_uninstalls.length +
                        m.optional_installs.length
                      return (
                        <Link
                          key={m.id}
                          href={`/manifests/${m.id}`}
                          className={cn(
                            'flex items-center justify-between gap-2 rounded-md border p-3 transition-colors',
                            munkiAccents.manifests.overviewRow,
                          )}
                        >
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-medium">
                              {m.display_name ?? m.name}
                            </div>
                            {m.display_name ? (
                              <div className="truncate text-xs text-muted-foreground">
                                {m.name}
                              </div>
                            ) : null}
                          </div>
                          <span
                            className="shrink-0 text-sm text-muted-foreground"
                            style={{ fontVariantNumeric: 'tabular-nums' }}
                          >
                            {installCount} installs
                          </span>
                        </Link>
                      )
                    })}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No manifests yet
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold tracking-tight">AutoPkg</h2>
        <div className="grid gap-4 md:grid-cols-3">
          <StatLinkCard
            href="/approvals"
            borderClass="border-l-gruvbox-yellow/50"
            title="Pending approvals"
            icon={CheckCircle}
            iconClass="text-gruvbox-yellow"
            footer="Items awaiting review"
          >
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {pendingApprovals}
            </div>
          </StatLinkCard>

          <StatLinkCard
            href="/autopkg/runs"
            borderClass="border-l-gruvbox-red/50"
            title="Runs"
            icon={Play}
            iconClass="text-gruvbox-red"
            footer="Total runs recorded in the system"
          >
            <div className="space-y-1">
              <div
                className="text-2xl font-bold"
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {totalRuns}
              </div>
              {lastRun ? (
                <div className="flex flex-wrap items-center gap-2">
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
                  <span className="text-xs text-muted-foreground">
                    {lastRun.recipes_imported ?? 0} imported,{' '}
                    {lastRun.recipes_failed ?? 0} failed
                  </span>
                </div>
              ) : null}
            </div>
          </StatLinkCard>

          <StatLinkCard
            href="/autopkg/recipes"
            borderClass="border-l-gruvbox-orange/50"
            title="Recipes"
            icon={BookMarked}
            iconClass="text-gruvbox-orange"
            footer="Configured AutoPkg recipes"
          >
            <div
              className="text-2xl font-bold"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              {totalRecipes}
            </div>
          </StatLinkCard>
        </div>

        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
            <div>
              <CardTitle>Run activity</CardTitle>
              <CardDescription>
                Runs per day over the last 30 days (from your 100 most recent
                runs)
              </CardDescription>
            </div>
            <Link
              href="/autopkg/runs"
              className="text-sm font-medium text-primary underline-offset-4 hover:underline"
            >
              View all
            </Link>
          </CardHeader>
          <CardContent>
            <AutoPkgRunsChart runs={runs} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle>Recent AutoPkg runs</CardTitle>
            <Link
              href="/autopkg/runs"
              className="text-sm font-medium text-primary underline-offset-4 hover:underline"
            >
              All runs
            </Link>
          </CardHeader>
          <CardContent>
            {recentRuns.length ? (
              <div className="space-y-3">
                {recentRuns.map((run) => (
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
      </section>
    </div>
  )
}
