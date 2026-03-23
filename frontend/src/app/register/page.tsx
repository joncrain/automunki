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

type AuthConfig = {
  auth_mode: string
  registration_open: boolean
}

export default function RegisterPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const next = searchParams.get('next') || '/'
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const res = await fetch(`${apiRoot}/auth/config`)
        if (!res.ok) throw new Error('config')
        const data = (await res.json()) as AuthConfig
        if (!cancelled) setConfig(data)
      } catch {
        if (!cancelled)
          setConfig({
            auth_mode: 'jwt',
            registration_open: false,
          })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  if (config === null) {
    return (
      <div className="mx-auto max-w-sm space-y-6 p-6">
        <AuthBrandHeader />
        <p className="text-center text-sm text-muted-foreground">Loading…</p>
      </div>
    )
  }

  if (config.auth_mode === 'disabled') {
    return (
      <div className="mx-auto max-w-sm space-y-4 p-6">
        <AuthBrandHeader />
        <h1 className="text-xl font-semibold">Registration unavailable</h1>
        <p className="text-sm text-muted-foreground">
          Authentication is disabled on the server. Use the app without signing
          in.
        </p>
        <Button type="button" onClick={() => router.push('/')}>
          Continue to app
        </Button>
      </div>
    )
  }

  if (!config.registration_open) {
    return (
      <div className="mx-auto max-w-sm space-y-4 p-6">
        <AuthBrandHeader />
        <h1 className="text-xl font-semibold">Registration closed</h1>
        <p className="text-sm text-muted-foreground">
          New account sign-up is disabled (
          <code className="rounded bg-muted px-1">
            AUTH_REGISTRATION_OPEN=false
          </code>
          ). Ask an administrator for access.
        </p>
        <Button type="button" variant="outline" asChild>
          <Link href="/login">Back to sign in</Link>
        </Button>
      </div>
    )
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    setPending(true)
    try {
      const res = await fetch(`${apiRoot}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          display_name: displayName.trim() || null,
        }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        const d = err.detail
        const msg =
          typeof d === 'string'
            ? d
            : Array.isArray(d)
              ? d
                  .map((x: { msg?: string }) => x?.msg)
                  .filter(Boolean)
                  .join('; ')
              : 'Registration failed.'
        setError(msg || `Error ${res.status}`)
        return
      }
      const body = new URLSearchParams()
      body.set('username', email)
      body.set('password', password)
      const loginRes = await fetch(`${apiRoot}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      })
      if (!loginRes.ok) {
        router.push('/login?registered=1')
        return
      }
      const tokenData = (await loginRes.json()) as { access_token: string }
      localStorage.setItem('token', tokenData.access_token)
      router.push(next)
      router.refresh()
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="mx-auto max-w-sm space-y-6 p-6">
      <AuthBrandHeader />
      <div>
        <h1 className="text-center text-xl font-semibold sm:text-left">
          Create account
        </h1>
        {config.auth_mode === 'oidc' ? (
          <p className="mt-1 text-sm text-muted-foreground">
            Create a password-based account, or{' '}
            <Link href="/login" className="underline">
              sign in with SSO
            </Link>
            .
          </p>
        ) : null}
      </div>
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="reg-email">Email</Label>
          <Input
            id="reg-email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="reg-display">Display name (optional)</Label>
          <Input
            id="reg-display"
            type="text"
            autoComplete="name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="reg-password">Password</Label>
          <Input
            id="reg-password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="reg-confirm">Confirm password</Label>
          <Input
            id="reg-confirm"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            minLength={8}
          />
        </div>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <Button type="submit" className="w-full" disabled={pending}>
          {pending ? 'Creating account…' : 'Create account'}
        </Button>
      </form>
      <p className="text-center text-sm text-muted-foreground">
        Already have an account?{' '}
        <Link href="/login" className="underline">
          Sign in
        </Link>
      </p>
    </div>
  )
}
