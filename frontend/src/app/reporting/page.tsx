'use client'

import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Activity, MonitorSmartphone, MoonStar, Percent } from 'lucide-react'
import Link from 'next/link'
import { parseAsInteger, parseAsString, useQueryState } from 'nuqs'
import { DataTable } from '@/components/data-table'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  api,
  type ClientMachineSummary,
  type FleetComplianceOverview,
  type PaginatedResponse,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

const columns: ColumnDef<ClientMachineSummary>[] = [
  {
    accessorKey: 'hostname',
    header: 'Hostname',
    cell: ({ row }) => (
      <Link
        href={`/reporting/devices/${row.original.id}`}
        className="font-medium text-primary underline-offset-4 hover:underline"
      >
        {row.original.hostname || '—'}
      </Link>
    ),
  },
  {
    accessorKey: 'serial_number',
    header: 'Serial',
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.serial_number}</span>
    ),
  },
  {
    accessorKey: 'manifest_name',
    header: 'Manifest',
    cell: ({ row }) => row.original.manifest_name || '—',
  },
  {
    accessorKey: 'munki_version',
    header: 'Munki',
    cell: ({ row }) => row.original.munki_version || '—',
  },
  {
    accessorKey: 'last_checkin_at',
    header: 'Last check-in',
    cell: ({ row }) =>
      row.original.last_checkin_at ? (
        <span suppressHydrationWarning className="text-sm">
          {formatDateTime(row.original.last_checkin_at)}
        </span>
      ) : (
        <span className="text-muted-foreground">Never</span>
      ),
  },
  {
    accessorKey: 'install_report_count',
    header: 'Install rows',
    cell: ({ row }) => (
      <Badge variant="outline">{row.original.install_report_count}</Badge>
    ),
  },
]

export default function ReportingPage() {
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
  const [pageSize, setPageSize] = useQueryState(
    'pageSize',
    parseAsInteger.withDefault(50),
  )
  const [search, setSearch] = useQueryState('q', parseAsString.withDefault(''))

  const { data: compliance, isLoading: complianceLoading } = useQuery({
    queryKey: ['reports-compliance'],
    queryFn: () => api.get<FleetComplianceOverview>('/reports/compliance'),
  })

  const { data, isLoading } = useQuery({
    queryKey: ['reports-machines', page, pageSize, search],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('page_size', String(pageSize))
      if (search.trim()) params.set('search', search.trim())
      return api.get<PaginatedResponse<ClientMachineSummary>>(
        `/reports/machines?${params.toString()}`,
      )
    },
  })

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-6">
      <div>
        <h1
          className={cn(
            'text-3xl font-bold text-pretty',
            munkiAccents.reporting.pageTitle,
          )}
        >
          Devices
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
          Reporting: Macs that have checked in via the AutoMunki agent or Munki
          postflight client. Install rows reflect the latest payload from each
          check-in (
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            ManagedInstallReport
          </code>
          ).
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="border-l-4 border-l-gruvbox-blue/50 bg-gruvbox-blue/[0.06]">
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
        <Card className="border-l-4 border-l-gruvbox-green/50 bg-gruvbox-green/[0.06]">
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
        <Card className="border-l-4 border-l-gruvbox-orange/50 bg-gruvbox-orange/[0.07]">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Stale (30d+)</CardTitle>
            <MoonStar className="size-4 text-gruvbox-orange" aria-hidden />
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-semibold">
              {complianceLoading ? '—' : (compliance?.stale_over_30_days ?? 0)}
            </p>
            <CardDescription>no check-in in 30 days</CardDescription>
          </CardContent>
        </Card>
        <Card className="border-l-4 border-l-gruvbox-purple/50 bg-gruvbox-purple/[0.06]">
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

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search hostname or serial…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value || null)
            setPage(1)
          }}
          className="max-w-sm"
          aria-label="Search devices"
        />
      </div>

      <div className="min-h-0 flex-1">
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          pageCount={data?.total_pages ?? 1}
          page={page}
          pageSize={pageSize}
          total={data?.total}
          onPageChange={setPage}
          onPageSizeChange={(size) => {
            setPageSize(size)
            setPage(1)
          }}
          isLoading={isLoading}
        />
      </div>
    </div>
  )
}
