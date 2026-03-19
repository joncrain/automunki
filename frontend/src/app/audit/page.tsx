'use client'

import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { X } from 'lucide-react'
import { parseAsInteger, parseAsString, useQueryState } from 'nuqs'
import { DataTable } from '@/components/data-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { type AuditLogRead, api, type PaginatedResponse } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

const ACTION_OPTIONS = [
  'create',
  'update',
  'delete',
  'promote',
  'approve',
  'reject',
  'import',
]

const ENTITY_OPTIONS = [
  'pkg_info',
  'manifest',
  'catalog',
  'autopkg_run',
  'repository',
]

const actionVariant = (action: string) => {
  switch (action) {
    case 'create':
      return 'default' as const
    case 'update':
      return 'secondary' as const
    case 'delete':
      return 'destructive' as const
    case 'promote':
    case 'approve':
      return 'default' as const
    case 'reject':
      return 'destructive' as const
    default:
      return 'outline' as const
  }
}

const columns: ColumnDef<AuditLogRead>[] = [
  {
    accessorKey: 'created_at',
    header: 'Time',
    cell: ({ row }) => (
      <span suppressHydrationWarning className="text-sm">
        {formatDateTime(row.original.created_at)}
      </span>
    ),
  },
  {
    accessorKey: 'action',
    header: 'Action',
    cell: ({ row }) => (
      <Badge variant={actionVariant(row.original.action)}>
        {row.original.action}
      </Badge>
    ),
  },
  {
    accessorKey: 'entity_type',
    header: 'Entity Type',
    cell: ({ row }) => (
      <Badge variant="outline">{row.original.entity_type}</Badge>
    ),
  },
  {
    accessorKey: 'entity_name',
    header: 'Entity',
    cell: ({ row }) => (
      <span className="truncate">
        {row.original.entity_name || row.original.entity_id}
      </span>
    ),
  },
  {
    accessorKey: 'user_email',
    header: 'User',
    cell: ({ row }) => row.original.user_email || 'system',
  },
  {
    accessorKey: 'notes',
    header: 'Notes',
    cell: ({ row }) => (
      <span className="line-clamp-1 text-sm text-muted-foreground">
        {row.original.notes || '—'}
      </span>
    ),
  },
]

export default function AuditPage() {
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
  const [pageSize, setPageSize] = useQueryState(
    'pageSize',
    parseAsInteger.withDefault(50),
  )
  const [action, setAction] = useQueryState(
    'action',
    parseAsString.withDefault(''),
  )
  const [entityType, setEntityType] = useQueryState(
    'entityType',
    parseAsString.withDefault(''),
  )

  const { data, isLoading } = useQuery({
    queryKey: ['audit', page, pageSize, action, entityType],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('page_size', String(pageSize))
      if (action) params.set('action', action)
      if (entityType) params.set('entity_type', entityType)
      return api.get<PaginatedResponse<AuditLogRead>>(
        `/audit?${params.toString()}`,
      )
    },
  })

  const hasFilters = action || entityType

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <h1 className="text-3xl font-bold">Audit Log</h1>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={action || '_all'}
          onValueChange={(v) => {
            setAction(v === '_all' ? null : v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Action" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All Actions</SelectItem>
            {ACTION_OPTIONS.map((a) => (
              <SelectItem key={a} value={a}>
                {a}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={entityType || '_all'}
          onValueChange={(v) => {
            setEntityType(v === '_all' ? null : v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Entity Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All Entities</SelectItem>
            {ENTITY_OPTIONS.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
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
              setAction(null)
              setEntityType(null)
              setPage(1)
            }}
          >
            <X className="mr-1 h-4 w-4" />
            Clear
          </Button>
        )}
      </div>

      <div className="flex-1 min-h-0">
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
