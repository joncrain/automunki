'use client'

import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { api, type UiSettingsRead } from '@/lib/api'

export default function SettingsPage() {
  const { data, isPending, isError, error } = useQuery({
    queryKey: ['settings', 'ui'],
    queryFn: () => api.get<UiSettingsRead>('/settings/ui'),
  })

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Settings</h1>

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
