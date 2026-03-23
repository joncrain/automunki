'use client'

import { useQuery } from '@tanstack/react-query'
import { api, type PaginatedResponse, type PkgInfoSummary } from '@/lib/api'

/** All pkginfo rows for a Munki item name (each version is a row), newest first. */
export function usePkginfoVersionsForName(baseName: string, enabled: boolean) {
  return useQuery({
    queryKey: ['pkginfo-versions', baseName],
    queryFn: () =>
      api.get<PaginatedResponse<PkgInfoSummary>>(
        `/pkginfo?name=${encodeURIComponent(baseName)}&page_size=200&sort_by=version&sort_order=desc`,
      ),
    enabled: enabled && baseName.length > 0,
    staleTime: 60_000,
  })
}
