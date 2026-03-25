'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  api,
  type MunkiRepoBasicAuthPatchBody,
  type MunkiRepoBasicAuthPatchResponse,
  type MunkiRepoBasicAuthRead,
  type UiSettingsRead,
} from '@/lib/api'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

const MUNKI_BASIC_AUTH_WIKI =
  'https://github.com/munki/munki/wiki/Using-Basic-Authentication'

function MunkiRepoBasicAuthCard() {
  const queryClient = useQueryClient()
  const { data, isPending, isError, error } = useQuery({
    queryKey: ['settings', 'munki-repo-basic-auth'],
    queryFn: () =>
      api.get<MunkiRepoBasicAuthRead>('/settings/munki-repo-basic-auth'),
  })

  const [enabled, setEnabled] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [oneTimeHeader, setOneTimeHeader] = useState<string | null>(null)

  useEffect(() => {
    if (data) {
      setEnabled(data.enabled)
      setUsername(data.username)
      setPassword('')
    }
  }, [data])

  const mutation = useMutation({
    mutationFn: (body: MunkiRepoBasicAuthPatchBody) =>
      api.patch<MunkiRepoBasicAuthPatchResponse>(
        '/settings/munki-repo-basic-auth',
        body,
      ),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({
        queryKey: ['settings', 'munki-repo-basic-auth'],
      })
      setPassword('')
      setOneTimeHeader(res.client_authorization_header ?? null)
    },
  })

  const envLocked = data?.env_override_active === true
  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const body: MunkiRepoBasicAuthPatchBody = {
      enabled,
      username,
    }
    if (password.length > 0) {
      body.password = password
    }
    mutation.mutate(body)
  }

  return (
    <Card className="sm:col-span-2">
      <CardHeader>
        <CardTitle>Munki repository (clients)</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Require HTTP Basic authentication for{' '}
          <code className="text-xs">/repo</code> (catalogs, manifests,
          redirects). Munki clients use{' '}
          <a
            className="text-primary underline underline-offset-2"
            href={MUNKI_BASIC_AUTH_WIKI}
            rel="noopener noreferrer"
            target="_blank"
          >
            AdditionalHttpHeaders
          </a>
          , not the web UI JWT.
        </p>

        {isPending ? (
          <Skeleton className="h-40 w-full" />
        ) : isError ? (
          <p className="text-sm text-destructive">
            {error instanceof Error ? error.message : 'Failed to load'}
          </p>
        ) : envLocked ? (
          <div className="space-y-2 rounded-md border border-border bg-muted/40 p-4 text-sm">
            <p>
              Basic auth is active via{' '}
              <code className="text-xs">MUNKI_REPO_BASIC_AUTH_USER</code> and{' '}
              <code className="text-xs">MUNKI_REPO_BASIC_AUTH_PASSWORD</code> on
              the API server (overrides the database).
            </p>
            <p className="text-muted-foreground">
              Username in use:{' '}
              <span className="font-medium text-foreground">
                {data?.username ?? ''}
              </span>
            </p>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="flex flex-row items-center justify-between gap-4 rounded-lg border border-border p-4">
              <div className="space-y-0.5">
                <Label htmlFor="repo-basic-enabled">Require Basic auth</Label>
                <p className="text-sm text-muted-foreground">
                  When on, clients must send a valid username and password for{' '}
                  <code className="text-xs">/repo</code>.
                </p>
              </div>
              <Switch
                checked={enabled}
                id="repo-basic-enabled"
                onCheckedChange={setEnabled}
              />
            </div>
            <div className="grid gap-2 sm:max-w-md">
              <Label htmlFor="repo-basic-user">Username</Label>
              <Input
                autoComplete="off"
                id="repo-basic-user"
                onChange={(e) => setUsername(e.target.value)}
                value={username}
              />
            </div>
            <div className="grid gap-2 sm:max-w-md">
              <Label htmlFor="repo-basic-pass">New password</Label>
              <Input
                autoComplete="new-password"
                id="repo-basic-pass"
                onChange={(e) => setPassword(e.target.value)}
                placeholder={
                  enabled
                    ? 'Required when first enabling'
                    : 'Leave blank to keep stored password'
                }
                type="password"
                value={password}
              />
              <p className="text-xs text-muted-foreground">
                Omit to keep the current password. Set when enabling for the
                first time or to rotate.
              </p>
            </div>
            {mutation.isError && (
              <p className="text-sm text-destructive">
                {mutation.error instanceof Error
                  ? mutation.error.message
                  : 'Save failed'}
              </p>
            )}
            {oneTimeHeader && (
              <div className="space-y-2 rounded-md border border-border bg-muted/30 p-3 text-sm">
                <p className="font-medium">
                  Copy for ManagedInstalls (one-time)
                </p>
                <code className="block break-all rounded bg-muted px-2 py-1.5 text-xs">
                  {oneTimeHeader}
                </code>
                <Button
                  className="mt-1"
                  onClick={() => {
                    void navigator.clipboard.writeText(oneTimeHeader)
                  }}
                  size="sm"
                  type="button"
                  variant="secondary"
                >
                  Copy header line
                </Button>
              </div>
            )}
            <Button disabled={mutation.isPending} type="submit">
              {mutation.isPending ? 'Saving…' : 'Save'}
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  )
}

export default function SettingsPage() {
  const { data, isPending, isError, error } = useQuery({
    queryKey: ['settings', 'ui'],
    queryFn: () => api.get<UiSettingsRead>('/settings/ui'),
  })

  return (
    <div className="space-y-6">
      <h1
        className={cn(
          'text-3xl font-bold text-pretty',
          munkiAccents.settings.pageTitle,
        )}
      >
        Settings
      </h1>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>GitHub Integration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="github-repo">Repository</Label>
              {isPending ? (
                <Skeleton className="h-10 w-full" />
              ) : (
                <Input
                  id="github-repo"
                  readOnly
                  value={isError ? '' : (data?.github_repo ?? '')}
                  placeholder={
                    isError
                      ? 'Could not load'
                      : data?.github_repo
                        ? undefined
                        : 'Not configured'
                  }
                />
              )}
              {isError && (
                <p className="text-sm text-destructive">
                  {error instanceof Error ? error.message : 'Failed to load'}
                </p>
              )}
              <p className="text-sm text-muted-foreground">
                Configured via GITHUB_REPO on the API server
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>AutoPkg runner</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid gap-2">
              <Label>Default runner</Label>
              {isPending ? (
                <Skeleton className="h-10 w-full" />
              ) : (
                <Input
                  readOnly
                  value={
                    isError
                      ? ''
                      : data?.autopkg_runner_mode === 'local'
                        ? 'Local Mac (script)'
                        : 'GitHub Actions'
                  }
                  placeholder={isError ? 'Could not load' : undefined}
                />
              )}
              <p className="text-sm text-muted-foreground">
                Set <code className="text-xs">AUTOPKG_RUNNER_MODE=github</code>{' '}
                or <code className="text-xs">local</code> on the API server. You
                can override this each time you trigger a run on the Runs page.
              </p>
              <p className="text-sm text-muted-foreground">
                Local runs only register in AutoMunki — run AutoPkg on a Mac
                using{' '}
                <code className="text-xs">docs/local-autopkg-runner.md</code> in
                the repo.
              </p>
            </div>
          </CardContent>
        </Card>

        <MunkiRepoBasicAuthCard />

        <Card>
          <CardHeader>
            <CardTitle>About</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Version</span>
                <span>0.1.0</span>
              </div>
              <Separator />
              <div className="flex justify-between">
                <span className="text-muted-foreground">Backend</span>
                <span>FastAPI + Python 3.12</span>
              </div>
              <Separator />
              <div className="flex justify-between">
                <span className="text-muted-foreground">Frontend</span>
                <span>Next.js + React</span>
              </div>
              <Separator />
              <div className="flex justify-between">
                <span className="text-muted-foreground">Database</span>
                <span>PostgreSQL 16</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
