'use client'

import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { X } from 'lucide-react'
import Link from 'next/link'
import { parseAsInteger, parseAsString, useQueryState } from 'nuqs'
import { DataTable } from '@/components/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  api,
  type ClientInstallReportListItem,
  type PaginatedResponse,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

const STATUS_OPTIONS = [
  'installed',
  'failed',
  'removed',
  'removal_failed',
  'unknown',
]

function statusVariant(status: string) {
  switch (status) {
    case 'installed':
      return 'default' as const
    case 'failed':
    case 'removal_failed':
      return 'destructive' as const
    case 'removed':
      return 'secondary' as const
    default:
      return 'outline' as const
  }
}

const columns: ColumnDef<ClientInstallReportListItem>[] = [
  {
    accessorKey: 'created_at',
    header: 'Reported',
    cell: ({ row }) => (
      <span suppressHydrationWarning className="text-sm">
        {formatDateTime(row.original.created_at)}
      </span>
    ),
  },
  {
    accessorKey: 'item_name',
    header: 'Item',
    cell: ({ row }) => (
      <span className="font-medium">{row.original.item_name || '—'}</span>
    ),
  },
  {
    accessorKey: 'item_version',
    header: 'Version',
    cell: ({ row }) => row.original.item_version || '—',
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => (
      <Badge variant={statusVariant(row.original.status)}>
        {row.original.status}
      </Badge>
    ),
  },
  {
    accessorKey: 'hostname',
    header: 'Device',
    cell: ({ row }) => (
      <Link
        href={`/reporting/devices/${row.original.machine_id}`}
        className="text-primary underline-offset-4 hover:underline"
      >
        {row.original.hostname || row.original.serial_number || '—'}
      </Link>
    ),
  },
  {
    accessorKey: 'serial_number',
    header: 'Serial',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-muted-foreground">
        {row.original.serial_number || '—'}
      </span>
    ),
  },
  {
    accessorKey: 'install_date',
    header: 'Install time',
    cell: ({ row }) =>
      row.original.install_date ? (
        <span suppressHydrationWarning className="text-sm">
          {formatDateTime(row.original.install_date)}
        </span>
      ) : (
        '—'
      ),
  },
  {
    accessorKey: 'error_message',
    header: 'Note',
    cell: ({ row }) => (
      <span className="line-clamp-2 max-w-[240px] text-sm text-muted-foreground">
        {row.original.error_message || '—'}
      </span>
    ),
  },
]

export default function ReportingInstallsPage() {
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
  const [pageSize, setPageSize] = useQueryState(
    'pageSize',
    parseAsInteger.withDefault(50),
  )
  const [search, setSearch] = useQueryState('q', parseAsString.withDefault(''))
  const [status, setStatus] = useQueryState(
    'status',
    parseAsString.withDefault(''),
  )
  const [itemName, setItemName] = useQueryState(
    'item_name',
    parseAsString.withDefault(''),
  )

  const { data, isLoading } = useQuery({
    queryKey: ['reports-installs', page, pageSize, search, status, itemName],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('page_size', String(pageSize))
      if (search.trim()) params.set('search', search.trim())
      if (status.trim()) params.set('status', status.trim())
      if (itemName.trim()) params.set('item_name', itemName.trim())
      return api.get<PaginatedResponse<ClientInstallReportListItem>>(
        `/reports/installs?${params.toString()}`,
      )
    },
  })

  const hasFilters = Boolean(search.trim() || status.trim() || itemName.trim())

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <div>
        <h1
          className={cn(
            'text-3xl font-bold text-pretty',
            munkiAccents.reporting.pageTitle,
          )}
        >
          Installs
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
          Latest install-result rows from client check-ins (
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            client_install_report
          </code>
          ). One row set per device per check-in.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Exact Munki item name (optional)"
          value={itemName}
          onChange={(e) => {
            setItemName(e.target.value || null)
            setPage(1)
          }}
          className="max-w-[220px]"
          aria-label="Filter by exact item name"
        />
        <Input
          placeholder="Search item, hostname, or serial…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value || null)
            setPage(1)
          }}
          className="max-w-sm"
          aria-label="Search installs"
        />
        <Select
          value={status || '_all'}
          onValueChange={(v) => {
            setStatus(v === '_all' ? null : v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All statuses</SelectItem>
            {STATUS_OPTIONS.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {hasFilters && (
          <Button
            variant="ghost"
            size="sm"
            aria-label="Clear filters"
            onClick={() => {
              setSearch(null)
              setStatus(null)
              setItemName(null)
              setPage(1)
            }}
          >
            <X className="mr-1 h-4 w-4" />
            Clear
          </Button>
        )}
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
