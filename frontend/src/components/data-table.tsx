'use client'

import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
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
}

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100]

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
}: DataTableProps<TData, TValue>) {
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    pageCount,
  })

  const showFooter = onPageChange || total != null

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 overflow-auto rounded-md border">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-background">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center"
                >
                  Loading...
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
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
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center"
                >
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {showFooter && (
        <div className="flex items-center justify-between border-t px-2 py-3">
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
