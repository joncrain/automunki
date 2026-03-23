'use client'

import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type OnChangeFn,
  type RowSelectionState,
  type SortingState,
  useReactTable,
  type VisibilityState,
} from '@tanstack/react-table'
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Settings2,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  pageCount?: number
  page?: number
  pageSize?: number
  total?: number
  onPageChange?: (page: number) => void
  onPageSizeChange?: (size: number) => void
  isLoading?: boolean
  sorting?: SortingState
  onSortingChange?: (sorting: SortingState) => void
  defaultColumnVisibility?: VisibilityState
  columnVisibility?: VisibilityState
  onColumnVisibilityChange?: OnChangeFn<VisibilityState>
  hideColumnPicker?: boolean
  enableRowSelection?: boolean
  rowSelection?: RowSelectionState
  onRowSelectionChange?: OnChangeFn<RowSelectionState>
  getRowId?: (row: TData) => string
}

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100]

function columnDefId<TData, TValue>(col: ColumnDef<TData, TValue>): string {
  if (col.id) return col.id
  if ('accessorKey' in col && col.accessorKey != null) {
    return String(col.accessorKey)
  }
  return ''
}

function selectColumnDef<TData>(): ColumnDef<TData, unknown> {
  return {
    id: 'select',
    header: ({ table }) => (
      <Checkbox
        checked={
          table.getIsAllPageRowsSelected()
            ? true
            : table.getIsSomePageRowsSelected()
              ? 'indeterminate'
              : false
        }
        onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
        aria-label="Select all rows on this page"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(v) => row.toggleSelected(!!v)}
        aria-label="Select row"
        onClick={(e) => e.stopPropagation()}
      />
    ),
    enableSorting: false,
    enableHiding: false,
  }
}

export function ColumnVisibilityMenu<TData, TValue>({
  columns: columnDefs,
  columnVisibility,
  onColumnVisibilityChange,
}: {
  columns: ColumnDef<TData, TValue>[]
  columnVisibility: VisibilityState
  onColumnVisibilityChange: OnChangeFn<VisibilityState>
}) {
  const toggleable = columnDefs.filter((c) => c.enableHiding !== false)

  if (toggleable.length === 0) return null

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <Settings2 className="mr-2 size-4" aria-hidden="true" />
          Columns
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {toggleable.map((col) => {
          const id = columnDefId(col)
          if (!id) return null
          const label = typeof col.header === 'string' ? col.header : id
          return (
            <DropdownMenuCheckboxItem
              key={id}
              checked={columnVisibility[id] !== false}
              onCheckedChange={(v) => {
                onColumnVisibilityChange((prev) => ({
                  ...prev,
                  [id]: !!v,
                }))
              }}
            >
              {label}
            </DropdownMenuCheckboxItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function DataTable<TData, TValue>({
  columns,
  data,
  pageCount = 1,
  page = 1,
  pageSize = 50,
  total,
  onPageChange,
  onPageSizeChange,
  isLoading,
  sorting: externalSorting,
  onSortingChange: externalOnSortingChange,
  defaultColumnVisibility,
  columnVisibility: columnVisibilityProp,
  onColumnVisibilityChange: onColumnVisibilityChangeProp,
  hideColumnPicker = false,
  enableRowSelection = false,
  rowSelection: rowSelectionProp,
  onRowSelectionChange: onRowSelectionChangeProp,
  getRowId: getRowIdProp,
}: DataTableProps<TData, TValue>) {
  const [internalSorting, setInternalSorting] = useState<SortingState>([])
  const [internalColumnVisibility, setInternalColumnVisibility] =
    useState<VisibilityState>(() => defaultColumnVisibility ?? {})
  const [internalRowSelection, setInternalRowSelection] =
    useState<RowSelectionState>({})

  const columnVisibility =
    columnVisibilityProp !== undefined
      ? columnVisibilityProp
      : internalColumnVisibility

  const rowSelection = rowSelectionProp ?? internalRowSelection
  const handleRowSelectionChange =
    onRowSelectionChangeProp ?? setInternalRowSelection

  const tableColumns = useMemo(
    () =>
      enableRowSelection ? [selectColumnDef<TData>(), ...columns] : columns,
    [enableRowSelection, columns],
  )

  const colSpan = tableColumns.length

  const isManualSort = !!externalOnSortingChange
  const sorting = externalSorting ?? internalSorting

  const table = useReactTable({
    data,
    columns: tableColumns,
    getCoreRowModel: getCoreRowModel(),
    ...(isManualSort
      ? { manualSorting: true }
      : { getSortedRowModel: getSortedRowModel() }),
    manualPagination: true,
    pageCount,
    enableRowSelection,
    onRowSelectionChange: enableRowSelection
      ? handleRowSelectionChange
      : undefined,
    getRowId: getRowIdProp
      ? (row) => getRowIdProp(row)
      : (row, index) => {
          const r = row as { id?: string }
          return r.id ?? String(index)
        },
    state: {
      sorting,
      columnVisibility,
      ...(enableRowSelection ? { rowSelection } : {}),
    },
    onSortingChange: (updater) => {
      const next = typeof updater === 'function' ? updater(sorting) : updater
      if (externalOnSortingChange) {
        externalOnSortingChange(next)
      } else {
        setInternalSorting(next)
      }
    },
    onColumnVisibilityChange: (updater) => {
      if (onColumnVisibilityChangeProp) {
        onColumnVisibilityChangeProp(updater)
      } else {
        setInternalColumnVisibility(updater)
      }
    },
  })

  const showFooter = onPageChange || total != null

  const toggleableColumns = table
    .getAllColumns()
    .filter((col) => col.getCanHide())

  return (
    <div className="flex h-full min-w-0 flex-col">
      {toggleableColumns.length > 0 &&
        defaultColumnVisibility &&
        !hideColumnPicker && (
          <div className="flex justify-end pb-2">
            <ColumnVisibilityMenu
              columns={columns}
              columnVisibility={columnVisibility}
              onColumnVisibilityChange={(updater) => {
                if (onColumnVisibilityChangeProp) {
                  onColumnVisibilityChangeProp(updater)
                } else {
                  setInternalColumnVisibility(updater)
                }
              }}
            />
          </div>
        )}

      <div className="min-h-0 min-w-0 flex-1 overflow-x-auto overflow-y-auto rounded-md border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder ? null : header.column.getCanSort() ? (
                      <button
                        type="button"
                        className="flex items-center gap-1 hover:text-foreground"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                        {header.column.getIsSorted() === 'asc' ? (
                          <ArrowUp className="size-3.5" />
                        ) : header.column.getIsSorted() === 'desc' ? (
                          <ArrowDown className="size-3.5" />
                        ) : (
                          <ArrowUpDown className="size-3.5 opacity-40" />
                        )}
                      </button>
                    ) : (
                      flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={colSpan} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() ? 'selected' : undefined}
                  className={
                    row.getIsSelected() ? 'bg-muted/40 hover:bg-muted/50' : ''
                  }
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={colSpan} className="h-24 text-center">
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {showFooter && (
        <div className="flex items-center justify-between px-2 py-3">
          <div
            className="text-sm text-muted-foreground"
            style={{ fontVariantNumeric: 'tabular-nums' }}
          >
            {total != null
              ? `Showing ${data.length} of ${total}`
              : `${data.length} rows`}
          </div>

          <div className="flex items-center gap-4">
            {onPageSizeChange && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Rows</span>
                <Select
                  value={String(pageSize)}
                  onValueChange={(v) => onPageSizeChange(Number(v))}
                >
                  <SelectTrigger className="h-8 w-[70px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAGE_SIZE_OPTIONS.map((size) => (
                      <SelectItem key={size} value={String(size)}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {onPageChange && pageCount > 1 && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  aria-label="Previous page"
                  onClick={() => onPageChange(page - 1)}
                  disabled={page <= 1}
                >
                  <ChevronLeft className="h-4 w-4" />
                  Previous
                </Button>
                <span
                  className="text-sm text-muted-foreground"
                  style={{ fontVariantNumeric: 'tabular-nums' }}
                >
                  {page} / {pageCount}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  aria-label="Next page"
                  onClick={() => onPageChange(page + 1)}
                  disabled={page >= pageCount}
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
