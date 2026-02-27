"use client";

import { useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import Link from "next/link";
import { parseAsInteger, parseAsString, useQueryState } from "nuqs";
import {
  api,
  type CatalogRead,
  type PaginatedResponse,
  type PkgInfoSummary,
} from "@/lib/api";
import { formatDate, initials, avatarColor } from "@/lib/format";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Search, X } from "lucide-react";

const columns: ColumnDef<PkgInfoSummary>[] = [
  {
    accessorKey: "display_name",
    header: "Name",
    cell: ({ row }) => (
      <Link
        href={`/software/${row.original.id}`}
        className="flex items-center gap-3 font-medium hover:underline"
      >
        <div
          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-xs font-bold ${avatarColor(row.original.name)}`}
        >
          {initials(row.original.display_name || row.original.name)}
        </div>
        <span className="truncate">
          {row.original.display_name || row.original.name}
        </span>
      </Link>
    ),
  },
  {
    accessorKey: "version",
    header: "Version",
    cell: ({ row }) => (
      <span className="font-mono text-sm">{row.original.version}</span>
    ),
  },
  {
    accessorKey: "category",
    header: "Category",
    cell: ({ row }) =>
      row.original.category ? (
        <Badge variant="outline">{row.original.category}</Badge>
      ) : null,
  },
  {
    accessorKey: "developer",
    header: "Developer",
    cell: ({ row }) => (
      <span className="truncate text-sm">{row.original.developer}</span>
    ),
  },
  {
    accessorKey: "catalog_names",
    header: "Catalogs",
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
    accessorKey: "unattended_install",
    header: "Unattended",
    cell: ({ row }) => (
      <Badge variant={row.original.unattended_install ? "default" : "outline"}>
        {row.original.unattended_install ? "Yes" : "No"}
      </Badge>
    ),
  },
  {
    accessorKey: "updated_at",
    header: "Updated",
    cell: ({ row }) => (
      <span suppressHydrationWarning className="text-sm text-muted-foreground">
        {formatDate(row.original.updated_at)}
      </span>
    ),
  },
];

export default function SoftwarePage() {
  const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
  const [pageSize, setPageSize] = useQueryState(
    "pageSize",
    parseAsInteger.withDefault(50)
  );
  const [search, setSearch] = useQueryState(
    "search",
    parseAsString.withDefault("")
  );
  const [category, setCategory] = useQueryState(
    "category",
    parseAsString.withDefault("")
  );
  const [catalog, setCatalog] = useQueryState(
    "catalog",
    parseAsString.withDefault("")
  );

  const { data, isLoading } = useQuery({
    queryKey: ["pkginfo", page, pageSize, search, category, catalog],
    queryFn: () => {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("page_size", String(pageSize));
      if (search) params.set("search", search);
      if (category) params.set("category", category);
      if (catalog) params.set("catalog", catalog);
      return api.get<PaginatedResponse<PkgInfoSummary>>(
        `/pkginfo?${params.toString()}`
      );
    },
  });

  const { data: catalogs } = useQuery({
    queryKey: ["catalogs"],
    queryFn: () => api.get<CatalogRead[]>("/catalogs"),
  });

  const categories = Array.from(
    new Set((data?.items ?? []).map((i) => i.category).filter(Boolean))
  ).sort() as string[];

  const hasFilters = search || category || catalog;

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Software Catalog</h1>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search software..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value || null);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>

        <Select
          value={category || "_all"}
          onValueChange={(v) => {
            setCategory(v === "_all" ? null : v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All Categories</SelectItem>
            {categories.map((c) => (
              <SelectItem key={c} value={c}>
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={catalog || "_all"}
          onValueChange={(v) => {
            setCatalog(v === "_all" ? null : v);
            setPage(1);
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
              setSearch(null);
              setCategory(null);
              setCatalog(null);
              setPage(1);
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
            setPageSize(size);
            setPage(1);
          }}
          isLoading={isLoading}
        />
      </div>
    </div>
  );
}
