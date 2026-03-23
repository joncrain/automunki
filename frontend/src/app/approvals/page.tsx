'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CheckCircle,
  ExternalLink,
  Loader2,
  ShieldAlert,
  XCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { useAuth } from '@/components/auth-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  type AutoPkgRecipeRead,
  api,
  type RunResultRead,
  type TrustChangeRequestRead,
  type TrustCommitResolveResponse,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { PAGE_KEYS } from '@/lib/page-keys'
import {
  githubBlobUrlForTrustEntry,
  trustRepoPathForTrustEntry,
} from '@/lib/trust-github'
import { cn } from '@/lib/utils'

function TrustCommitLink({
  repo,
  path,
  change,
  oldSha256,
  newSha256,
}: {
  repo: string
  path: string
  change: string
  oldSha256?: string
  newSha256?: string
}) {
  const canResolve =
    (change === 'modified' && Boolean(oldSha256) && Boolean(newSha256)) ||
    (change === 'added' && Boolean(newSha256))

  const { data, isPending, isError } = useQuery({
    queryKey: [
      'trust-resolve-commit',
      repo,
      path,
      change,
      oldSha256,
      newSha256,
    ],
    queryFn: () =>
      api.post<TrustCommitResolveResponse>('/autopkg/trust/resolve-commit', {
        github_repo: repo,
        github_path: path,
        old_sha256: change === 'modified' ? oldSha256 : null,
        new_sha256: newSha256,
      }),
    enabled: canResolve,
    staleTime: 86_400_000,
  })

  if (!canResolve) return null
  if (isPending) {
    return (
      <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 shrink-0 animate-spin" aria-hidden />
        Looking up commit…
      </p>
    )
  }
  if (isError || !data?.commit_url) return null
  return (
    <p className="mt-1">
      <a
        href={data.commit_url}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
      >
        <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
        View introducing commit
      </a>
    </p>
  )
}

function DiffEntry({
  name,
  info,
  fileUrl,
  trustLocation,
}: {
  name: string
  info: Record<string, string>
  fileUrl: string | null
  trustLocation: { github_repo: string; github_path: string } | null
}) {
  return (
    <div className="rounded-md border bg-muted/30 px-3 py-2 mb-1">
      <p className="font-mono text-sm font-medium">{name}</p>
      {fileUrl && (
        <p className="mt-1">
          <a
            href={fileUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
          >
            <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
            View file on GitHub
          </a>
        </p>
      )}
      {trustLocation && (
        <TrustCommitLink
          repo={trustLocation.github_repo}
          path={trustLocation.github_path}
          change={info.change}
          oldSha256={info.old_sha256}
          newSha256={info.new_sha256}
        />
      )}
      <p className="text-xs text-muted-foreground mt-1">
        Change:{' '}
        <Badge
          variant={info.change === 'not_found' ? 'destructive' : 'outline'}
        >
          {info.change}
        </Badge>
      </p>
      {info.change === 'modified' && (
        <div className="mt-1 grid gap-1 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-destructive line-through truncate">
              {info.old_sha256?.slice(0, 16)}...
            </span>
            <span className="text-gruvbox-green truncate">
              {info.new_sha256?.slice(0, 16)}...
            </span>
          </div>
        </div>
      )}
      {info.change === 'not_found' && (
        <p className="mt-1 text-xs text-destructive">
          Could not fetch this file from GitHub to verify.
        </p>
      )}
    </div>
  )
}

function TrustDiffViewer({
  diff,
  oldTrustInfo,
  newTrustInfo,
}: {
  diff: Record<string, unknown> | null
  oldTrustInfo?: unknown
  newTrustInfo?: unknown
}) {
  if (!diff) return null

  const parentDiff = (diff.parent_recipes ?? {}) as Record<
    string,
    Record<string, string>
  >
  const procDiff = (diff.non_core_processors ?? {}) as Record<
    string,
    Record<string, string>
  >

  const hasDiffs =
    Object.keys(parentDiff).length > 0 || Object.keys(procDiff).length > 0

  if (!hasDiffs) {
    return (
      <p className="text-sm text-muted-foreground">No differences found.</p>
    )
  }

  return (
    <div className="space-y-3">
      {Object.keys(parentDiff).length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-1">
            Parent Recipes
          </h5>
          {Object.entries(parentDiff).map(([key, info]) => (
            <DiffEntry
              key={key}
              name={key}
              info={info}
              fileUrl={githubBlobUrlForTrustEntry(
                oldTrustInfo,
                newTrustInfo,
                'parent_recipes',
                key,
              )}
              trustLocation={trustRepoPathForTrustEntry(
                oldTrustInfo,
                newTrustInfo,
                'parent_recipes',
                key,
              )}
            />
          ))}
        </div>
      )}
      {Object.keys(procDiff).length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-1">
            Non-Core Processors
          </h5>
          {Object.entries(procDiff).map(([key, info]) => (
            <DiffEntry
              key={key}
              name={key}
              info={info}
              fileUrl={githubBlobUrlForTrustEntry(
                oldTrustInfo,
                newTrustInfo,
                'non_core_processors',
                key,
              )}
              trustLocation={trustRepoPathForTrustEntry(
                oldTrustInfo,
                newTrustInfo,
                'non_core_processors',
                key,
              )}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export default function ApprovalsPage() {
  const queryClient = useQueryClient()

  const { data: approvals, isLoading: approvalsLoading } = useQuery({
    queryKey: ['pending-approvals'],
    queryFn: () => api.get<RunResultRead[]>('/autopkg/approvals'),
  })

  const { data: trustChanges, isLoading: trustLoading } = useQuery({
    queryKey: ['pending-trust-changes'],
    queryFn: () =>
      api.get<TrustChangeRequestRead[]>(
        '/autopkg/trust-changes?status=pending',
      ),
  })

  const { data: allRecipes } = useQuery({
    queryKey: ['autopkg-recipes'],
    queryFn: () => api.get<AutoPkgRecipeRead[]>('/autopkg/recipes'),
  })

  const recipesById = new Map((allRecipes ?? []).map((r) => [r.id, r]))

  const approveMutation = useMutation({
    mutationFn: ({ id, approved }: { id: string; approved: boolean }) =>
      api.post(`/autopkg/results/${id}/approve`, { approved }),
    onSuccess: (_, variables) => {
      toast.success(variables.approved ? 'Item approved' : 'Item rejected')
      queryClient.invalidateQueries({ queryKey: ['pending-approvals'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const trustApproveMutation = useMutation({
    mutationFn: ({
      recipeId,
      approved,
    }: {
      recipeId: string
      approved: boolean
    }) =>
      api.post(`/autopkg/recipes/${recipeId}/approve-trust`, {
        approved,
      }),
    onSuccess: (_, variables) => {
      toast.success(
        variables.approved ? 'Trust change approved' : 'Trust change rejected',
      )
      queryClient.invalidateQueries({
        queryKey: ['pending-trust-changes'],
      })
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const pendingApprovals = approvals?.length ?? 0
  const pendingTrust = trustChanges?.length ?? 0
  const isLoading = approvalsLoading || trustLoading

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Loading...
      </div>
    )
  }

  const hasNothing = pendingApprovals === 0 && pendingTrust === 0

  return (
    <div className="space-y-6">
      <h1
        className={cn(
          'text-3xl font-bold text-pretty',
          munkiAccents.approvals.pageTitle,
        )}
      >
        Approval Queue
      </h1>

      {hasNothing ? (
        <Card>
          <CardContent className="flex items-center justify-center p-12">
            <div className="text-center">
              <CheckCircle
                className="mx-auto h-12 w-12 text-gruvbox-green/50"
                aria-hidden="true"
              />
              <h3 className="mt-4 text-lg font-medium">All caught up!</h3>
              <p className="text-sm text-muted-foreground">
                No items pending approval
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Tabs defaultValue={pendingTrust > 0 ? 'trust' : 'imports'}>
          <TabsList>
            <TabsTrigger value="imports">
              Import Approvals
              {pendingApprovals > 0 && (
                <Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
                  {pendingApprovals}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="trust">
              Trust Changes
              {pendingTrust > 0 && (
                <Badge
                  variant="default"
                  className="ml-1.5 text-xs px-1.5 bg-gruvbox-yellow text-primary-foreground"
                >
                  {pendingTrust}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="imports" className="space-y-4 mt-4">
            {pendingApprovals === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">
                No import approvals pending.
              </p>
            ) : (
              approvals?.map((item) => {
                const title =
                  item.imported_display_name?.trim() || item.recipe_name
                return (
                  <Card
                    key={item.id}
                    className="border-l-4 border-l-gruvbox-yellow/40"
                  >
                    <CardHeader>
                      <CardTitle className="flex flex-col gap-3 text-left sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0 space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="truncate">{title}</span>
                            <Badge
                              variant={
                                item.status === 'imported'
                                  ? 'default'
                                  : item.status === 'trust_failed'
                                    ? 'destructive'
                                    : 'secondary'
                              }
                            >
                              {item.status}
                            </Badge>
                          </div>
                          {item.imported_display_name &&
                            item.recipe_name !== item.imported_display_name && (
                              <p className="text-xs font-normal text-muted-foreground font-mono">
                                Report: {item.recipe_name}
                              </p>
                            )}
                        </div>
                        {canMutateApprovals ? (
                          <div className="flex shrink-0 gap-2">
                            <Button
                              size="sm"
                              variant="default"
                              aria-label={`Approve ${title}`}
                              onClick={() =>
                                approveMutation.mutate({
                                  id: item.id,
                                  approved: true,
                                })
                              }
                              disabled={approveMutation.isPending}
                            >
                              <CheckCircle className="mr-1 h-4 w-4" />
                              Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              aria-label={`Reject ${title}`}
                              onClick={() =>
                                approveMutation.mutate({
                                  id: item.id,
                                  approved: false,
                                })
                              }
                              disabled={approveMutation.isPending}
                            >
                              <XCircle className="mr-1 h-4 w-4" />
                              Reject
                            </Button>
                          </div>
                        ) : null}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="grid gap-2 md:grid-cols-3">
                      {item.imported_version && (
                        <div>
                          <span className="text-sm text-muted-foreground">
                            Version
                          </span>
                          <p className="font-mono">{item.imported_version}</p>
                        </div>
                      )}
                      {item.imported_catalogs && (
                        <div>
                          <span className="text-sm text-muted-foreground">
                            Catalogs
                          </span>
                          <div className="mt-1 flex gap-1">
                            {item.imported_catalogs.map((c) => (
                              <Badge key={c} variant="secondary">
                                {c}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      <div>
                        <span className="text-sm text-muted-foreground">
                          Date
                        </span>
                        <p suppressHydrationWarning>
                          {formatDateTime(item.created_at)}
                        </p>
                      </div>
                      {item.error_message && (
                        <div className="col-span-full">
                          <span className="text-sm text-muted-foreground">
                            Error
                          </span>
                          <pre className="mt-1 overflow-auto rounded-md bg-muted p-2 text-sm">
                            {item.error_message}
                          </pre>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )
              })
            )}
          </TabsContent>

          <TabsContent value="trust" className="space-y-4 mt-4">
            {pendingTrust === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">
                No trust changes pending approval.
              </p>
            ) : (
              trustChanges?.map((change) => {
                const recipe = recipesById.get(change.recipe_id)
                return (
                  <Card
                    key={change.id}
                    className="border-l-4 border-l-gruvbox-yellow/40"
                  >
                    <CardHeader>
                      <CardTitle className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <ShieldAlert className="h-5 w-5 text-gruvbox-yellow" />
                          <span>{recipe?.name ?? 'Unknown Recipe'}</span>
                          <Badge
                            variant="default"
                            className="bg-gruvbox-yellow text-primary-foreground"
                          >
                            Trust Changed
                          </Badge>
                        </div>
                        {canMutateApprovals ? (
                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              variant="default"
                              aria-label={`Approve trust for ${recipe?.name ?? 'recipe'}`}
                              onClick={() =>
                                trustApproveMutation.mutate({
                                  recipeId: change.recipe_id,
                                  approved: true,
                                })
                              }
                              disabled={trustApproveMutation.isPending}
                            >
                              <CheckCircle className="mr-1 h-4 w-4" />
                              Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              aria-label={`Reject trust for ${recipe?.name ?? 'recipe'}`}
                              onClick={() =>
                                trustApproveMutation.mutate({
                                  recipeId: change.recipe_id,
                                  approved: false,
                                })
                              }
                              disabled={trustApproveMutation.isPending}
                            >
                              <XCircle className="mr-1 h-4 w-4" />
                              Reject
                            </Button>
                          </div>
                        ) : null}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid gap-2 md:grid-cols-2 mb-3">
                        <div>
                          <span className="text-sm text-muted-foreground">
                            Recipe
                          </span>
                          <p className="font-mono text-sm">
                            {recipe?.identifier ?? change.recipe_id}
                          </p>
                        </div>
                        <div>
                          <span className="text-sm text-muted-foreground">
                            Requested
                          </span>
                          <p suppressHydrationWarning>
                            {formatDateTime(change.requested_at)}
                          </p>
                        </div>
                      </div>
                      <div>
                        <span className="text-sm font-medium">
                          Changes Detected
                        </span>
                        <div className="mt-2">
                          <TrustDiffViewer
                            diff={change.diff as Record<string, unknown> | null}
                            oldTrustInfo={
                              change.old_trust_info ?? recipe?.trust_info
                            }
                            newTrustInfo={change.new_trust_info}
                          />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
