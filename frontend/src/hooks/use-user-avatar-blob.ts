'use client'

import { useEffect, useState } from 'react'

const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''

/**
 * Fetches ``GET /users/me/avatar`` with the JWT (``<img src>`` cannot) and
 * exposes a blob URL for ``AvatarImage``.
 */
export function useUserAvatarBlobUrl(
  hasAvatar: boolean | undefined,
  updatedAt: string | undefined | null,
): string | null {
  const [url, setUrl] = useState<string | null>(null)

  useEffect(() => {
    if (!hasAvatar) {
      setUrl(null)
      return
    }

    let cancelled = false
    let created: string | null = null

    const token =
      typeof window !== 'undefined' ? localStorage.getItem('token') : null
    const qs =
      updatedAt != null && updatedAt !== ''
        ? `?t=${encodeURIComponent(updatedAt)}`
        : ''
    const u = `${API_BASE}/api/v1/users/me/avatar${qs}`

    void fetch(u, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => (r.ok ? r.blob() : null))
      .then((blob) => {
        if (!blob || cancelled) return
        const next = URL.createObjectURL(blob)
        if (cancelled) {
          URL.revokeObjectURL(next)
          return
        }
        created = next
        setUrl(next)
      })
      .catch(() => {
        if (!cancelled) setUrl(null)
      })

    return () => {
      cancelled = true
      if (created) URL.revokeObjectURL(created)
      setUrl(null)
    }
  }, [hasAvatar, updatedAt])

  return url
}
