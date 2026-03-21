'use client'

import { useQuery } from '@tanstack/react-query'
import {
  type AvatarCircleItem,
  AvatarCircles,
} from '@/components/ui/avatar-circles'
import { api, type PaginatedResponse, type PkgInfoSummary } from '@/lib/api'
import { cn } from '@/lib/utils'

export function pkgInfoSummaryToAvatarItem(
  pkg: PkgInfoSummary,
): AvatarCircleItem {
  return {
    imageUrl: `/icons/${encodeURIComponent(pkg.name)}.png`,
    name: pkg.name,
    alt: pkg.display_name ?? pkg.name,
  }
}

export type SoftwareAvatarCirclesProps = {
  packages: PkgInfoSummary[]
  total: number
  className?: string
  circleClassName?: string
  interactive?: boolean
  /** When true, render nothing if `packages` is empty */
  hideWhenEmpty?: boolean
}

export function SoftwareAvatarCircles({
  packages,
  total,
  className,
  circleClassName,
  interactive = false,
  hideWhenEmpty = true,
}: SoftwareAvatarCirclesProps) {
  const avatarUrls = packages.map(pkgInfoSummaryToAvatarItem)
  const overflow = Math.max(0, total - avatarUrls.length)

  if (hideWhenEmpty && avatarUrls.length === 0) {
    return null
  }

  return (
    <AvatarCircles
      interactive={interactive}
      className={cn('-space-x-2', className)}
      circleClassName={circleClassName ?? 'h-8 w-8'}
      avatarUrls={avatarUrls}
      numPeople={overflow > 0 ? overflow : undefined}
    />
  )
}

export type SoftwareNameAvatarCirclesProps = {
  /** Munki pkginfo names (e.g. `managed_installs` entries) */
  names: string[]
  maxVisible?: number
  className?: string
  circleClassName?: string
  interactive?: boolean
  hideWhenEmpty?: boolean
}

/** Overlapping icons from package names only (no API fetch). */
export function SoftwareNameAvatarCircles({
  names,
  maxVisible = 6,
  className,
  circleClassName,
  interactive = false,
  hideWhenEmpty = true,
}: SoftwareNameAvatarCirclesProps) {
  const total = names.length
  const visible = names.slice(0, maxVisible)
  const avatarUrls: AvatarCircleItem[] = visible.map((name) => ({
    imageUrl: `/icons/${encodeURIComponent(name)}.png`,
    name,
    alt: name,
  }))
  const overflow = Math.max(0, total - avatarUrls.length)

  if (hideWhenEmpty && total === 0) {
    return null
  }

  return (
    <AvatarCircles
      interactive={interactive}
      className={cn('-space-x-2', className)}
      circleClassName={circleClassName ?? 'h-7 w-7'}
      avatarUrls={avatarUrls}
      numPeople={overflow > 0 ? overflow : undefined}
    />
  )
}

export type UseSoftwarePreviewPackagesOptions = {
  pageSize?: number
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

/**
 * Shared pkginfo preview for dashboard-style UI. Uses a stable query key so
 * multiple `SoftwareAvatarCircles` (or manual consumers) dedupe in React Query.
 */
export function useSoftwarePreviewPackages(
  options: UseSoftwarePreviewPackagesOptions = {},
) {
  const { pageSize = 6, sortBy = 'updated_at', sortOrder = 'desc' } = options

  return useQuery({
    queryKey: ['software-preview', pageSize, sortBy, sortOrder],
    queryFn: () =>
      api.get<PaginatedResponse<PkgInfoSummary>>(
        `/pkginfo?page_size=${pageSize}&page=1&sort_by=${sortBy}&sort_order=${sortOrder}`,
      ),
  })
}

export type UseCatalogSoftwarePreviewOptions =
  UseSoftwarePreviewPackagesOptions & {
    catalogName: string
    /** Skip fetch when zero (e.g. empty catalog) */
    itemCount: number
  }

/**
 * Recent pkginfo rows for a single catalog (by name). One query per catalog;
 * keys dedupe if the same catalog is mounted twice.
 */
export function useCatalogSoftwarePreview({
  catalogName,
  itemCount,
  pageSize = 6,
  sortBy = 'updated_at',
  sortOrder = 'desc',
}: UseCatalogSoftwarePreviewOptions) {
  const params = new URLSearchParams({
    page_size: String(pageSize),
    page: '1',
    sort_by: sortBy,
    sort_order: sortOrder,
    catalog: catalogName,
  })

  return useQuery({
    queryKey: [
      'catalog-software-preview',
      catalogName,
      pageSize,
      sortBy,
      sortOrder,
    ],
    queryFn: () =>
      api.get<PaginatedResponse<PkgInfoSummary>>(
        `/pkginfo?${params.toString()}`,
      ),
    enabled: itemCount > 0,
  })
}

export type CatalogSoftwareAvatarCirclesProps = Omit<
  SoftwareAvatarCirclesProps,
  'packages' | 'total'
> & {
  catalogName: string
  itemCount: number
  pageSize?: number
}

/** Fetches a pkginfo slice for the catalog and renders overlapping software icons */
export function CatalogSoftwareAvatarCircles({
  catalogName,
  itemCount,
  pageSize = 6,
  className,
  circleClassName,
  interactive = false,
}: CatalogSoftwareAvatarCirclesProps) {
  const { data, isLoading, isError } = useCatalogSoftwarePreview({
    catalogName,
    itemCount,
    pageSize,
  })

  if (itemCount === 0 || isLoading || isError || !data) {
    return null
  }

  return (
    <SoftwareAvatarCircles
      packages={data.items}
      total={data.total}
      className={className}
      circleClassName={circleClassName}
      interactive={interactive}
    />
  )
}
