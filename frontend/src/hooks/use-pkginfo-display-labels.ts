'use client'

import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import { api, type PaginatedResponse, type PkgInfoSummary } from '@/lib/api'
import { parseManifestItemRef } from '@/lib/manifest-item-ref'

/** Resolve manifest item refs (incl. pinned `name-version`) to pkginfo display_name. */
export function usePkginfoDisplayLabels(names: string[]) {
  const uniqueRaw = useMemo(
    () => [...new Set(names)].sort(),
    [names.join('\0')],
  )

  const uniqueBases = useMemo(() => {
    const s = new Set<string>()
    for (const raw of uniqueRaw) {
      s.add(parseManifestItemRef(raw).baseName)
    }
    return [...s].sort()
  }, [uniqueRaw.join('\0')])

  return useQuery({
    queryKey: ['pkginfo-display-labels', uniqueRaw.join('\0')],
    queryFn: async () => {
      const byBase: Record<string, string> = {}
      await Promise.all(
        uniqueBases.map(async (base) => {
          try {
            const res = await api.get<PaginatedResponse<PkgInfoSummary>>(
              `/pkginfo?name=${encodeURIComponent(base)}&page_size=1`,
            )
            const pkg = res.items[0]
            const d = pkg?.display_name?.trim()
            byBase[base] = d || base
          } catch {
            byBase[base] = base
          }
        }),
      )
      const out: Record<string, string> = {}
      for (const raw of uniqueRaw) {
        const { baseName } = parseManifestItemRef(raw)
        out[raw] = byBase[baseName] ?? raw
      }
      return out
    },
    enabled: uniqueRaw.length > 0,
    staleTime: 5 * 60 * 1000,
  })
}

export interface PkginfoItemMeta {
  displayName: string
  iconName: string | null
}

/** Resolve item keys to pkginfo ``display_name`` and ``icon_name`` (detail fetch per base). */
export function usePkginfoItemMeta(names: string[]) {
  const uniqueRaw = useMemo(
    () => [...new Set(names)].sort(),
    [names.join('\0')],
  )

  const uniqueBases = useMemo(() => {
    const s = new Set<string>()
    for (const raw of uniqueRaw) {
      s.add(parseManifestItemRef(raw).baseName)
    }
    return [...s].sort()
  }, [uniqueRaw.join('\0')])

  return useQuery({
    queryKey: ['pkginfo-item-meta', uniqueRaw.join('\0')],
    queryFn: async () => {
      const byBase: Record<string, PkginfoItemMeta> = {}
      await Promise.all(
        uniqueBases.map(async (base) => {
          try {
            const res = await api.get<PaginatedResponse<PkgInfoSummary>>(
              `/pkginfo?name=${encodeURIComponent(base)}&page_size=1`,
            )
            const pkg = res.items[0]
            if (!pkg) {
              byBase[base] = { displayName: base, iconName: null }
              return
            }
            const d = pkg.display_name?.trim()
            byBase[base] = {
              displayName: d || base,
              iconName: pkg.icon_name?.trim() || null,
            }
          } catch {
            byBase[base] = { displayName: base, iconName: null }
          }
        }),
      )
      const out: Record<string, PkginfoItemMeta> = {}
      for (const raw of uniqueRaw) {
        const { baseName } = parseManifestItemRef(raw)
        out[raw] = byBase[baseName] ?? { displayName: raw, iconName: null }
      }
      return out
    },
    enabled: uniqueRaw.length > 0,
    staleTime: 5 * 60 * 1000,
  })
}
