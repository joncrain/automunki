'use client'

import { useQuery } from '@tanstack/react-query'
import type {
  ColumnDef,
  SortingState,
  VisibilityState,
} from '@tanstack/react-table'
import { Package, Search, X } from 'lucide-react'
import Link from 'next/link'
import { parseAsInteger, parseAsString, useQueryState } from 'nuqs'
import { useState } from 'react'
import { ColumnVisibilityMenu, DataTable } from '@/components/data-table'
import { SoftwareIcon } from '@/components/software-icon'
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
  type CatalogRead,
  type PaginatedResponse,
  type PkgInfoSummary,
} from '@/lib/api'
import { formatDate } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

const columns: ColumnDef<PkgInfoSummary>[] = [
  {
    accessorKey: 'display_name',
    header: 'Name',
    cell: ({ row }) => (
      <Link
        href={`/software/${row.original.id}`}
        className="flex items-center gap-3 font-medium hover:underline"
      >
        <SoftwareIcon
          name={row.original.name}
          displayName={row.original.display_name}
          size="sm"
        />
        <span className="truncate">
          {row.original.display_name || row.original.name}
        </span>
      </Link>
    ),
    enableHiding: false,
  },
  {
    accessorKey: 'version',
    header: 'Version',
    cell: ({ row }) => (
      <span className="font-mono text-sm">{row.original.version}</span>
    ),
  },
  {
    accessorKey: 'category',
    header: 'Category',
    cell: ({ row }) =>
      row.original.category ? (
        <Badge variant="outline">{row.original.category}</Badge>
      ) : null,
  },
  {
    accessorKey: 'developer',
    header: 'Developer',
    cell: ({ row }) => (
      <span className="truncate text-sm">{row.original.developer}</span>
    ),
  },
  {
    accessorKey: 'catalog_names',
    header: 'Catalogs',
    enableSorting: false,
    cell: ({ row }) => (
      <div className="flex gap-1">
        {row.original.catalog_names.map((c) => (
          <Badge key={c} variant="secondary">
            {c}
          </Badge>
        ))}
      </div>
    ),
  },
  {
    accessorKey: 'minimum_os_version',
    header: 'Min OS',
    cell: ({ row }) => (
      <span className="font-mono text-sm text-muted-foreground">
        {row.original.minimum_os_version ?? '—'}
      </span>
    ),
  },
  {
    accessorKey: 'installer_type',
    header: 'Installer Type',
    cell: ({ row }) =>
      row.original.installer_type ? (
        <Badge variant="outline">{row.original.installer_type}</Badge>
      ) : (
        <span className="text-sm text-muted-foreground">—</span>
      ),
  },
  {
    accessorKey: 'unattended_install',
    header: 'Unattended',
    cell: ({ row }) => (
      <Badge variant={row.original.unattended_install ? 'default' : 'outline'}>
        {row.original.unattended_install ? 'Yes' : 'No'}
      </Badge>
    ),
  },
  {
    accessorKey: 'unattended_uninstall',
    header: 'Unattended Uninstall',
    cell: ({ row }) => (
      <Badge
        variant={row.original.unattended_uninstall ? 'default' : 'outline'}
      >
        {row.original.unattended_uninstall ? 'Yes' : 'No'}
      </Badge>
    ),
  },
  {
    accessorKey: 'restart_action',
    header: 'Restart Action',
    cell: ({ row }) =>
      row.original.restart_action ? (
        <Badge variant="secondary">{row.original.restart_action}</Badge>
      ) : (
        <span className="text-sm text-muted-foreground">—</span>
      ),
  },
  {
    accessorKey: 'updated_at',
    header: 'Updated',
    cell: ({ row }) => (
      <span suppressHydrationWarning className="text-sm text-muted-foreground">
        {formatDate(row.original.updated_at)}
      </span>
    ),
  },
]

const DEFAULT_COLUMN_VISIBILITY: VisibilityState = {
  display_name: true,
  version: true,
  category: true,
  developer: true,
  catalog_names: true,
  minimum_os_version: false,
  installer_type: false,
  unattended_install: true,
  unattended_uninstall: false,
  restart_action: false,
  updated_at: true,
}

export default function SoftwarePage() {
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
  const [pageSize, setPageSize] = useQueryState(
    'pageSize',
    parseAsInteger.withDefault(50),
  )
  const [search, setSearch] = useQueryState(
    'search',
    parseAsString.withDefault(''),
  )
  const [category, setCategory] = useQueryState(
    'category',
    parseAsString.withDefault(''),
  )
  const [catalog, setCatalog] = useQueryState(
    'catalog',
    parseAsString.withDefault(''),
  )
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'display_name', desc: false },
  ])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(
    DEFAULT_COLUMN_VISIBILITY,
  )

  const sortBy =
    sorting[0]?.id === 'display_name' ? 'name' : (sorting[0]?.id ?? 'name')
  const sortOrder = sorting[0]?.desc ? 'desc' : 'asc'

  const { data, isLoading } = useQuery({
    queryKey: [
      'pkginfo',
      page,
      pageSize,
      search,
      category,
      catalog,
      sortBy,
      sortOrder,
    ],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('page_size', String(pageSize))
      params.set('sort_by', sortBy)
      params.set('sort_order', sortOrder)
      if (search) params.set('search', search)
      if (category) params.set('category', category)
      if (catalog) params.set('catalog', catalog)
      return api.get<PaginatedResponse<PkgInfoSummary>>(
        `/pkginfo?${params.toString()}`,
      )
    },
  })

  const { data: catalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
  })

  const { data: categories } = useQuery({
    queryKey: ['pkginfo-categories'],
    queryFn: () => api.get<string[]>('/pkginfo/categories'),
  })

  const hasFilters = search || category || catalog

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <div className="flex items-center justify-between">
        <div
          className={cn(
            'flex items-center gap-3',
            munkiAccents.software.pageTitle,
          )}
        >
          <Package
            className={cn('h-8 w-8 shrink-0', munkiAccents.software.icon)}
            aria-hidden
          />
          <h1 className="text-3xl font-bold text-pretty">Software Catalog</h1>
        </div>
      </div>

      <div className="flex w-full flex-wrap items-center gap-2">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search software..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value || null)
                setPage(1)
              }}
              className="pl-9"
            />
          </div>

          <Select
            value={category || '_all'}
            onValueChange={(v) => {
              setCategory(v === '_all' ? null : v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All Categories</SelectItem>
              {(categories ?? []).map((c) => (
                <SelectItem key={c} value={c}>
                  {c}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={catalog || '_all'}
            onValueChange={(v) => {
              setCatalog(v === '_all' ? null : v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Catalog" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All Catalogs</SelectItem>
              {catalogs?.map((c) => (
                <SelectItem key={c.id} value={c.name}>
                  {c.name}
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
                setCategory(null)
                setCatalog(null)
                setPage(1)
              }}
            >
              <X className="mr-1 h-4 w-4" />
              Clear
            </Button>
          )}
        </div>

        <div className="ml-auto shrink-0">
          <ColumnVisibilityMenu
            columns={columns}
            columnVisibility={columnVisibility}
            onColumnVisibilityChange={setColumnVisibility}
          />
        </div>
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
          sorting={sorting}
          onSortingChange={(next) => {
            setSorting(next)
            setPage(1)
          }}
          defaultColumnVisibility={DEFAULT_COLUMN_VISIBILITY}
          columnVisibility={columnVisibility}
          onColumnVisibilityChange={setColumnVisibility}
          hideColumnPicker
        />
      </div>
    </div>
  )
}
