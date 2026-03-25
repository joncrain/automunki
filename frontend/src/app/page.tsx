'use client'

import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  BookMarked,
  CheckCircle,
  FolderOpen,
  MonitorSmartphone,
  MoonStar,
  Package,
  Percent,
  Play,
  ScrollText,
} from 'lucide-react'
import Link from 'next/link'
import type { ComponentType, ReactNode } from 'react'
import { AutoPkgRunsChart } from '@/components/dashboard/autopkg-runs-chart'
import { FleetTimeseriesChart } from '@/components/dashboard/fleet-timeseries-chart'
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
  type FleetActivityTimeseries,
  type FleetComplianceOverview,
  type ManifestRead,
  type PaginatedResponse,
} from '@/lib/api'
import { manifestTitle } from '@/lib/manifest-title'
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

  const { data: compliance, isLoading: complianceLoading } = useQuery({
    queryKey: ['reports-compliance'],
    queryFn: () => api.get<FleetComplianceOverview>('/reports/compliance'),
  })

  const { data: fleetActivity, isLoading: fleetActivityLoading } = useQuery({
    queryKey: ['reports-fleet-activity', 30],
    queryFn: () =>
      api.get<FleetActivityTimeseries>('/reports/fleet-activity?days=30'),
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
                              {manifestTitle(m)}
                            </div>
                            {manifestTitle(m) !== m.name ? (
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
        <h2 className={munkiSectionHeadingClass()}>
          <span className={munkiSectionMarkerClass()} aria-hidden />
          Device reporting
        </h2>
        <p className="max-w-2xl text-sm text-muted-foreground">
          Macs checking in via the AutoMunki agent or Munki postflight. Open{' '}
          <Link
            href="/reporting"
            className="font-medium text-primary underline-offset-4 hover:underline"
          >
            Devices
          </Link>{' '}
          or{' '}
          <Link
            href="/reporting/installs"
            className="font-medium text-primary underline-offset-4 hover:underline"
          >
            Installs
          </Link>{' '}
          for full lists.
        </p>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card
            className={cn(
              'border-l-4 border-l-gruvbox-blue/50 bg-gruvbox-blue/[0.06]',
            )}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Fleet size</CardTitle>
              <MonitorSmartphone
                className="size-4 text-gruvbox-blue"
                aria-hidden
              />
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-semibold">
                {complianceLoading ? '—' : (compliance?.total_machines ?? 0)}
              </p>
              <CardDescription>machines in database</CardDescription>
            </CardContent>
          </Card>
          <Card
            className={cn(
              'border-l-4 border-l-gruvbox-green/50 bg-gruvbox-green/[0.06]',
            )}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active (7d)</CardTitle>
              <Activity className="size-4 text-gruvbox-green" aria-hidden />
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-semibold">
                {complianceLoading
                  ? '—'
                  : (compliance?.checked_in_last_7_days ?? 0)}
              </p>
              <CardDescription>checked in recently</CardDescription>
            </CardContent>
          </Card>
          <Card
            className={cn(
              'border-l-4 border-l-gruvbox-orange/50 bg-gruvbox-orange/[0.07]',
            )}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Stale (30d+)
              </CardTitle>
              <MoonStar className="size-4 text-gruvbox-orange" aria-hidden />
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-semibold">
                {complianceLoading
                  ? '—'
                  : (compliance?.stale_over_30_days ?? 0)}
              </p>
              <CardDescription>no check-in in 30 days</CardDescription>
            </CardContent>
          </Card>
          <Card
            className={cn(
              'border-l-4 border-l-gruvbox-purple/50 bg-gruvbox-purple/[0.06]',
            )}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">7-day reach</CardTitle>
              <Percent className="size-4 text-gruvbox-purple" aria-hidden />
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-semibold">
                {complianceLoading
                  ? '—'
                  : `${compliance?.compliance_percentage ?? 0}%`}
              </p>
              <CardDescription>of fleet reporting weekly</CardDescription>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card
            className={cn('flex flex-col', munkiAccents.reporting.statCard)}
          >
            <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
              <div>
                <CardTitle>Check-ins over time</CardTitle>
                <CardDescription>
                  Check-in events per day (last 30 days)
                </CardDescription>
              </div>
              <Link
                href="/reporting"
                className="shrink-0 text-sm font-medium text-primary underline-offset-4 hover:underline"
              >
                Devices
              </Link>
            </CardHeader>
            <CardContent className="flex-1">
              {fleetActivityLoading ? (
                <p className="text-sm text-muted-foreground">Loading…</p>
              ) : (
                <FleetTimeseriesChart
                  points={fleetActivity?.checkins_by_day ?? []}
                  seriesLabel="Check-ins"
                  gradientId="fillFleetCheckins"
                  strokeVar="var(--chart-1)"
                  emptyMessage="No check-ins yet — data appears after Macs report in."
                />
              )}
            </CardContent>
          </Card>

          <Card
            className={cn('flex flex-col', munkiAccents.reporting.statCard)}
          >
            <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
              <div>
                <CardTitle>Install rows over time</CardTitle>
                <CardDescription>
                  Managed install report rows recorded per day (last 30 days)
                </CardDescription>
              </div>
              <Link
                href="/reporting/installs"
                className="shrink-0 text-sm font-medium text-primary underline-offset-4 hover:underline"
              >
                Installs
              </Link>
            </CardHeader>
            <CardContent className="flex-1">
              {fleetActivityLoading ? (
                <p className="text-sm text-muted-foreground">Loading…</p>
              ) : (
                <FleetTimeseriesChart
                  points={fleetActivity?.install_rows_by_day ?? []}
                  seriesLabel="Rows"
                  gradientId="fillFleetInstalls"
                  strokeVar="var(--chart-3)"
                  emptyMessage="No install report rows yet — they appear when clients send ManagedInstallReport data."
                />
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
      </section>
    </div>
  )
}
