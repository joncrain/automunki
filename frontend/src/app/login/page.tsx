'use client'

import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { useEffect, useState } from 'react'
import { AuthBrandHeader } from '@/components/auth-brand-header'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''
const apiRoot = API_BASE ? `${API_BASE}/api/v1` : '/api/v1'

export default function LoginPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const next = searchParams.get('next') || '/'
  const registered = searchParams.get('registered') === '1'
  const [authMode, setAuthMode] = useState<string | null>(null)
  const [registrationOpen, setRegistrationOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const res = await fetch(`${apiRoot}/auth/config`)
        if (!res.ok) throw new Error('config')
        const data = (await res.json()) as {
          auth_mode: string
          registration_open?: boolean
        }
        if (!cancelled) {
          setAuthMode(data.auth_mode)
          setRegistrationOpen(Boolean(data.registration_open))
        }
      } catch {
        if (!cancelled) {
          setAuthMode('jwt')
          setRegistrationOpen(false)
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  if (authMode === null) {
    return (
      <div className="mx-auto max-w-sm space-y-6 p-6">
        <AuthBrandHeader />
        <p className="text-center text-sm text-muted-foreground">Loading…</p>
      </div>
    )
  }

  if (authMode === 'disabled') {
    return (
      <div className="mx-auto max-w-sm space-y-4 p-6">
        <AuthBrandHeader />
        <h1 className="text-xl font-semibold">Authentication disabled</h1>
        <p className="text-sm text-muted-foreground">
          The API is running with{' '}
          <code className="rounded bg-muted px-1">AUTH_MODE=disabled</code>. No
          login is required. Set{' '}
          <code className="rounded bg-muted px-1">AUTH_MODE=jwt</code> or{' '}
          <code className="rounded bg-muted px-1">oidc</code> on the server to
          require sign-in.
        </p>
        <Button type="button" onClick={() => router.push('/')}>
          Continue to app
        </Button>
      </div>
    )
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setPending(true)
    try {
      const body = new URLSearchParams()
      body.set('username', email)
      body.set('password', password)
      const res = await fetch(`${apiRoot}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setError(
          typeof err.detail === 'string'
            ? err.detail
            : 'Login failed. Check your email and password.',
        )
        return
      }
      const data = (await res.json()) as { access_token: string }
      localStorage.setItem('token', data.access_token)
      router.push(next)
      router.refresh()
    } finally {
      setPending(false)
    }
  }

  const showRegisterLink =
    registrationOpen && authMode !== 'disabled' && authMode !== null

  return (
    <div className="mx-auto max-w-sm space-y-6 p-6">
      <AuthBrandHeader />
      <h1 className="text-center text-xl font-semibold sm:text-left">
        Sign in
      </h1>
      {registered ? (
        <p className="text-sm text-muted-foreground">
          Account created. Sign in with your new password.
        </p>
      ) : null}
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <Button type="submit" className="w-full" disabled={pending}>
          {pending ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
      {showRegisterLink ? (
        <p className="text-center text-sm text-muted-foreground">
          No account?{' '}
          <Link
            href={`/register${next !== '/' ? `?next=${encodeURIComponent(next)}` : ''}`}
            className="underline"
          >
            Create one
          </Link>
        </p>
      ) : null}
      {authMode === 'oidc' ? (
        <div className="border-t pt-4">
          <a href={`${apiRoot}/auth/oidc/authorize`}>
            <Button type="button" variant="outline" className="w-full">
              Continue with SSO
            </Button>
          </a>
        </div>
      ) : null}
    </div>
  )
}
