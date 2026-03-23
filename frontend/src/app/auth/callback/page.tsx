'use client'

import { useRouter, useSearchParams } from 'next/navigation'
import { Suspense, useEffect, useState } from 'react'
import { AuthBrandHeader } from '@/components/auth-brand-header'

function AuthCallbackInner() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    const token = searchParams.get('token')
    if (!token) {
      setErr('Missing token')
      return
    }
    localStorage.setItem('token', token)
    router.replace('/')
    router.refresh()
  }, [router, searchParams])

  if (err) {
    return (
      <div className="mx-auto max-w-sm space-y-6 p-6">
        <AuthBrandHeader />
        <p className="text-destructive">{err}</p>
      </div>
    )
  }
  return (
    <div className="mx-auto max-w-sm space-y-6 p-6">
      <AuthBrandHeader />
      <p className="text-center text-muted-foreground">Signing you in…</p>
    </div>
  )
}

export default function AuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-sm space-y-6 p-6">
          <AuthBrandHeader />
          <p className="text-center text-muted-foreground">Loading…</p>
        </div>
      }
    >
      <AuthCallbackInner />
    </Suspense>
  )
}
