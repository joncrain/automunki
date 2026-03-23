'use client'

import { useRouter } from 'next/navigation'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'

import { PAGE_KEYS } from '@/lib/page-keys'

const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''

export type AuthUser = {
  id: string
  email: string
  is_active: boolean
  is_superuser: boolean
  is_verified: boolean
  display_name?: string | null
  role?: string
  updated_at?: string | null
  has_avatar?: boolean
}

export type MePayload = {
  user: AuthUser
  permissions: Record<string, string>
  auth_mode: string
}

const AuthContext = createContext<{
  me: MePayload | null
  /** ``me.auth_mode`` if logged in, else ``GET /auth/config`` (no separate env). */
  authMode: string | null
  /** From ``GET /auth/config`` — ``POST /auth/register`` allowed when true. */
  registrationOpen: boolean
  loading: boolean
  refresh: () => Promise<void>
  logout: () => void
  canRead: (pageKey: string) => boolean
  canWrite: (pageKey: string) => boolean
} | null>(null)

function authHeaders(): HeadersInit {
  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null
  const h: Record<string, string> = {}
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<MePayload | null>(null)
  const [serverAuthMode, setServerAuthMode] = useState<string | null>(null)
  const [registrationOpen, setRegistrationOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  const authMode = useMemo(
    () => me?.auth_mode ?? serverAuthMode ?? null,
    [me, serverAuthMode],
  )

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      let modeFromConfig: string | null = null
      try {
        const cfgRes = await fetch(`${API_BASE}/api/v1/auth/config`)
        if (cfgRes.ok) {
          const cfg = (await cfgRes.json()) as {
            auth_mode: string
            registration_open?: boolean
          }
          modeFromConfig = cfg.auth_mode
          setServerAuthMode(cfg.auth_mode)
          setRegistrationOpen(Boolean(cfg.registration_open))
        } else {
          setServerAuthMode(null)
          setRegistrationOpen(false)
        }
      } catch {
        setServerAuthMode(null)
        setRegistrationOpen(false)
      }

      const res = await fetch(`${API_BASE}/api/v1/auth/me`, {
        headers: { ...authHeaders() },
      })
      if (res.status === 401) {
        setMe(null)
        if (modeFromConfig !== 'disabled' && typeof window !== 'undefined') {
          const path = window.location.pathname
          if (
            path !== '/login' &&
            path !== '/register' &&
            path !== '/auth/callback'
          ) {
            router.push(`/login?next=${encodeURIComponent(path || '/')}`)
          }
        }
        return
      }
      if (!res.ok) {
        setMe(null)
        return
      }
      const data = (await res.json()) as MePayload
      setMe(data)
    } finally {
      setLoading(false)
    }
  }, [router])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const logout = useCallback(() => {
    localStorage.removeItem('token')
    setMe(null)
    router.push('/login')
  }, [router])

  const resolvedModeForRbac = useMemo(() => {
    if (authMode != null) return authMode
    if (loading) return null
    return 'jwt'
  }, [authMode, loading])

  const canRead = useCallback(
    (pageKey: string) => {
      if (resolvedModeForRbac === null || resolvedModeForRbac === 'disabled') {
        return true
      }
      if (me?.user.is_superuser) {
        return true
      }
      const p = me?.permissions[pageKey]
      if (p === 'read' || p === 'write') {
        return true
      }
      if (
        me &&
        Object.keys(me.permissions).length === 0 &&
        pageKey !== PAGE_KEYS.adminAccess
      ) {
        return true
      }
      return false
    },
    [me, resolvedModeForRbac],
  )

  const canWrite = useCallback(
    (pageKey: string) => {
      if (resolvedModeForRbac === null || resolvedModeForRbac === 'disabled') {
        return true
      }
      if (me?.user.is_superuser) {
        return true
      }
      return me?.permissions[pageKey] === 'write'
    },
    [me, resolvedModeForRbac],
  )

  const value = useMemo(
    () => ({
      me,
      authMode,
      registrationOpen,
      loading,
      refresh,
      logout,
      canRead,
      canWrite,
    }),
    [
      me,
      authMode,
      registrationOpen,
      loading,
      refresh,
      logout,
      canRead,
      canWrite,
    ],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return ctx
}
