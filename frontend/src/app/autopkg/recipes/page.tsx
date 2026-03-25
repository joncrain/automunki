'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type {
  ColumnDef,
  RowSelectionState,
  VisibilityState,
} from '@tanstack/react-table'
import {
  Compass,
  FileUp,
  Loader2,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
  X,
} from 'lucide-react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { parseAsString, useQueryState } from 'nuqs'
import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { useAuth } from '@/components/auth-provider'
import { ColumnVisibilityMenu, DataTable } from '@/components/data-table'
import { SoftwareIcon } from '@/components/software-icon'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { type PkginfoItemMeta } from '@/hooks/use-pkginfo-display-labels'
import {
  type AutoPkgRecipeRead,
  type AutoPkgRunRead,
  api,
  type CatalogRead,
} from '@/lib/api'
import {
  pkginfoCatalogsFromRecipe,
  recipeInputName,
  recipeListIconName,
  recipePkginfoKey,
} from '@/lib/autopkg-recipe'
import {
  canTriggerRunRecipe,
  QuickRunDialog,
  type RecipeQuickRunTarget,
  toastLocalRunRegistered,
} from '@/lib/autopkg-run'
import { formatDateTime } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { PAGE_KEYS } from '@/lib/page-keys'
import { cn } from '@/lib/utils'

/** XML/YAML text, or binary plist as base64 (matches backend ``import-override``). */
async function fileToImportOverrideContent(file: File): Promise<string> {
  const buf = await file.arrayBuffer()
  const u8 = new Uint8Array(buf)
  const head = new TextDecoder('latin1').decode(u8.subarray(0, 8))
  if (head === 'bplist00') {
    let binary = ''
    const chunk = 8192
    for (let i = 0; i < u8.length; i += chunk) {
      binary += String.fromCharCode(
        ...u8.subarray(i, Math.min(i + chunk, u8.length)),
      )
    }
    return btoa(binary)
  }
  return new TextDecoder('utf-8').decode(u8)
}

function trustStatusBadge(status: string) {
  switch (status) {
    case 'verified':
      return (
        <Badge
          variant="default"
          className="bg-gruvbox-green text-primary-foreground hover:bg-gruvbox-green/90"
        >
          <ShieldCheck className="mr-1 h-3 w-3" />
          Verified
        </Badge>
      )
    case 'failed':
      return (
        <Badge variant="destructive">
          <ShieldAlert className="mr-1 h-3 w-3" />
          Failed
        </Badge>
      )
    case 'pending_approval':
      return (
        <Badge
          variant="default"
          className="bg-gruvbox-yellow text-primary-foreground hover:bg-gruvbox-yellow/90"
        >
          <ShieldAlert className="mr-1 h-3 w-3" />
          Pending
        </Badge>
      )
    default:
      return (
        <Badge variant="secondary">
          <ShieldQuestion className="mr-1 h-3 w-3" />
          Unknown
        </Badge>
      )
  }
}

function makeColumns(
  pkgMeta: Record<string, PkginfoItemMeta> | undefined,
  onToggleEnabled: (id: string, enabled: boolean) => void,
  onToggleAutoPromote: (id: string, auto: boolean) => void,
  onEdit: (recipe: AutoPkgRecipeRead) => void,
  onRunRecipe: (recipe: AutoPkgRecipeRead) => void,
  onVerifyTrust: (id: string) => void,
  onDelete: (recipe: AutoPkgRecipeRead) => void,
  verifyingTrustId: string | null,
  pendingRunRecipeName: string | null,
  isRunPending: boolean,
  opts: {
    canEditRecipes: boolean
    canRun: boolean
    canVerifyTrust: boolean
  },
): ColumnDef<AutoPkgRecipeRead>[] {
  return [
    {
      id: 'item_icon',
      header: '',
      size: 44,
      cell: ({ row }) => {
        const key = recipePkginfoKey(row.original)
        const meta = pkgMeta?.[key]
        return (
          <div className="flex justify-center">
            <SoftwareIcon
              name={key}
              iconName={recipeListIconName(meta?.iconName, row.original)}
              displayName={meta?.displayName ?? key}
              size="sm"
            />
          </div>
        )
      },
    },
    {
      id: 'pkg_display_name',
      header: 'Display Name',
      accessorFn: (row) => pkgMeta?.[recipePkginfoKey(row)]?.displayName ?? '',
      cell: ({ row }) => {
        const key = recipePkginfoKey(row.original)
        const label = pkgMeta?.[key]?.displayName
        return (
          <button
            type="button"
            className="max-w-[min(280px,28vw)] truncate text-left text-sm font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-sm"
            onClick={() => onEdit(row.original)}
            title={label ?? undefined}
          >
            {label ?? '—'}
          </button>
        )
      },
    },
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <button
          type="button"
          className="flex items-center gap-2 text-left hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-sm"
          onClick={() => onEdit(row.original)}
        >
          <span className="font-medium">{row.original.name}</span>
          {row.original.is_override && (
            <Badge variant="outline" className="text-xs">
              Override
            </Badge>
          )}
        </button>
      ),
    },
    {
      accessorKey: 'identifier',
      header: 'Identifier',
      cell: ({ row }) => (
        <span className="truncate font-mono text-sm text-muted-foreground">
          {row.original.identifier}
        </span>
      ),
    },
    {
      id: 'input_name',
      accessorFn: (row) => recipeInputName(row),
      header: 'Input NAME',
      cell: ({ row }) => {
        const n = recipeInputName(row.original)
        return n ? (
          <span className="truncate text-sm" title={n}>
            {n}
          </span>
        ) : (
          '—'
        )
      },
    },
    {
      accessorKey: 'parent_recipe',
      header: 'Parent recipe',
      cell: ({ row }) => {
        const p = row.original.parent_recipe
        if (!p) return '—'
        return (
          <span
            className="max-w-[200px] truncate font-mono text-xs text-muted-foreground"
            title={p}
          >
            {p}
          </span>
        )
      },
    },
    {
      accessorKey: 'source_repo_full_name',
      header: 'Repo',
      cell: ({ row }) => {
        const repo = row.original.source_repo_full_name
        if (!repo) return '—'
        return (
          <a
            href={`https://github.com/${repo}`}
            target="_blank"
            rel="noopener noreferrer"
            className="block max-w-[160px] truncate font-mono text-xs text-primary underline-offset-4 hover:underline"
            title={repo}
          >
            {repo}
          </a>
        )
      },
    },
    {
      accessorKey: 'trust_status',
      header: 'Trust',
      cell: ({ row }) => {
        const isVerifying = verifyingTrustId === row.original.id
        return (
          <div className="flex items-center gap-1">
            {trustStatusBadge(row.original.trust_status)}
            {opts.canVerifyTrust && row.original.is_override && (
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0"
                aria-label={`Verify trust for ${row.original.name}`}
                disabled={isVerifying}
                onClick={() => onVerifyTrust(row.original.id)}
              >
                <RefreshCw
                  className={`h-3 w-3 ${isVerifying ? 'animate-spin' : ''}`}
                />
              </Button>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: 'is_enabled',
      header: 'Enabled',
      cell: ({ row }) =>
        opts.canEditRecipes ? (
          <Switch
            checked={row.original.is_enabled}
            onCheckedChange={(checked) =>
              onToggleEnabled(row.original.id, checked)
            }
            aria-label={`Toggle ${row.original.name} enabled`}
          />
        ) : (
          <span className="text-sm text-muted-foreground">
            {row.original.is_enabled ? 'Yes' : 'No'}
          </span>
        ),
    },
    {
      accessorKey: 'auto_promote',
      header: 'Auto Promote',
      cell: ({ row }) =>
        opts.canEditRecipes ? (
          <Switch
            checked={row.original.auto_promote}
            onCheckedChange={(checked) =>
              onToggleAutoPromote(row.original.id, checked)
            }
            aria-label={`Toggle ${row.original.name} auto-promote`}
          />
        ) : (
          <span className="text-sm text-muted-foreground">
            {row.original.auto_promote ? 'Yes' : 'No'}
          </span>
        ),
    },
    {
      id: 'pkginfo_catalogs',
      header: 'Catalogs',
      cell: ({ row }) => {
        const cats = pkginfoCatalogsFromRecipe(row.original)
        if (cats.length === 0) return '—'
        return (
          <div className="flex flex-wrap gap-1">
            {cats.map((c) => (
              <Badge key={c} variant="secondary">
                {c}
              </Badge>
            ))}
          </div>
        )
      },
    },
    {
      accessorKey: 'last_run_status',
      header: 'Run status',
      cell: ({ row }) => {
        const st = row.original.last_run_status
        if (!st) return '—'
        const ok = ['success', 'imported', 'no_change'].includes(st)
        return <Badge variant={ok ? 'default' : 'destructive'}>{st}</Badge>
      },
    },
    {
      accessorKey: 'last_run_at',
      header: 'Last run at',
      cell: ({ row }) => {
        const at = row.original.last_run_at
        if (!at) return '—'
        return (
          <span
            suppressHydrationWarning
            className="whitespace-nowrap text-sm text-muted-foreground"
          >
            {formatDateTime(at)}
          </span>
        )
      },
    },
    {
      accessorKey: 'updated_at',
      header: 'Updated',
      cell: ({ row }) => (
        <span
          suppressHydrationWarning
          className="whitespace-nowrap text-sm text-muted-foreground"
        >
          {formatDateTime(row.original.updated_at)}
        </span>
      ),
    },
    {
      id: 'run',
      header: '',
      enableHiding: false,
      size: 48,
      cell: ({ row }) => {
        if (!opts.canRun) return null
        const r = row.original
        const runnable = canTriggerRunRecipe(r)
        const isThisPending =
          pendingRunRecipeName !== null && pendingRunRecipeName === r.name
        return (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0"
            aria-label={`Run recipe ${r.name}`}
            title={
              runnable
                ? 'Run this recipe'
                : 'Trust failed or pending — cannot run until resolved'
            }
            disabled={!runnable || isRunPending}
            onClick={(e) => {
              e.stopPropagation()
              onRunRecipe(r)
            }}
          >
            {isThisPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
          </Button>
        )
      },
    },
    {
      id: 'actions',
      header: '',
      enableHiding: false,
      cell: ({ row }) =>
        opts.canEditRecipes && row.original.is_override ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
            aria-label={`Delete override ${row.original.name}`}
            onClick={(e) => {
              e.stopPropagation()
              onDelete(row.original)
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        ) : null,
    },
  ]
}

const DEFAULT_COLUMN_VISIBILITY: VisibilityState = {
  select: true,
  item_icon: true,
  pkg_display_name: true,
  name: false,
  identifier: false,
  input_name: false,
  parent_recipe: false,
  source_repo_full_name: false,
  trust_status: true,
  is_enabled: true,
  auto_promote: false,
  pkginfo_catalogs: true,
  last_run_status: true,
  last_run_at: true,
  updated_at: false,
}

export default function RecipesPage() {
  const { canWrite } = useAuth()
  const canEditRecipes = canWrite(PAGE_KEYS.autopkgRecipes)
  const canRun = canWrite(PAGE_KEYS.autopkgRuns)
  const canVerifyTrustBtn = canWrite(PAGE_KEYS.autopkgApprovals)
  const canVerifyAllRepos = canWrite(PAGE_KEYS.autopkgDiscover)

  const queryClient = useQueryClient()
  const router = useRouter()
  const [search, setSearch] = useQueryState(
    'search',
    parseAsString.withDefault(''),
  )
  const [enabled, setEnabled] = useQueryState(
    'enabled',
    parseAsString.withDefault(''),
  )
  const [quickRun, setQuickRun] = useState<RecipeQuickRunTarget | null>(null)
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({})
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(
    DEFAULT_COLUMN_VISIBILITY,
  )

  useEffect(() => {
    if (!canRun) setRowSelection({})
  }, [canRun])

  const [importOpen, setImportOpen] = useState(false)
  const [importContent, setImportContent] = useState('')
  const [importBatchItems, setImportBatchItems] = useState<
    { fileName: string; content: string }[] | null
  >(null)
  const [importName, setImportName] = useState('')
  const [importSourceRepo, setImportSourceRepo] = useState('')
  const [importRefreshTrust, setImportRefreshTrust] = useState(true)

  const { data: recipes, isLoading } = useQuery({
    queryKey: ['autopkg-recipes'],
    queryFn: () => api.get<AutoPkgRecipeRead[]>('/autopkg/recipes'),
  })

  const pkgMeta = useMemo(() => {
    if (!recipes?.length) return undefined
    const m: Record<string, PkginfoItemMeta> = {}
    for (const r of recipes) {
      const key = recipePkginfoKey(r)
      m[key] = {
        displayName: r.pkginfo_display_name?.trim() || key,
        iconName: r.pkginfo_icon_name?.trim() ?? null,
      }
    }
    return m
  }, [recipes])

  const updateMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      api.put(`/autopkg/recipes/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const [verifyingTrustId, setVerifyingTrustId] = useState<string | null>(null)

  const verifyTrustMutation = useMutation({
    mutationFn: (id: string) => {
      setVerifyingTrustId(id)
      return api.post<{ name: string; trust_status: string; error?: string }>(
        `/autopkg/recipes/${id}/verify-trust`,
      )
    },
    onSuccess: (data) => {
      setVerifyingTrustId(null)
      if (data.trust_status === 'verified') {
        toast.success(`${data.name}: Trust verified`)
      } else if (data.trust_status === 'pending_approval') {
        toast.warning(`${data.name}: Trust changed — approval required`)
      } else {
        toast.info(`${data.name}: ${data.error || 'Could not verify trust'}`)
      }
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => {
      setVerifyingTrustId(null)
      toast.error(err.message)
    },
  })

  const verifyAllMutation = useMutation({
    mutationFn: () =>
      api.post<{
        total: number
        verified: number
        failed: number
        errors: number
      }>('/autopkg/repos/update'),
    onSuccess: (data) => {
      toast.success(
        `Verified ${data.total} recipes: ${data.verified} OK, ${data.failed} changed, ${data.errors} errors`,
      )
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const [deletingRecipe, setDeletingRecipe] =
    useState<AutoPkgRecipeRead | null>(null)

  const importOverrideMutation = useMutation({
    mutationFn: (body: {
      content: string
      name?: string | null
      source_repo_full_name?: string | null
      refresh_trust: boolean
    }) =>
      api.post<AutoPkgRecipeRead>('/autopkg/recipes/import-override', {
        content: body.content,
        name: body.name?.trim() || null,
        source_repo_full_name: body.source_repo_full_name?.trim() || null,
        is_enabled: true,
        auto_promote: false,
        refresh_trust: body.refresh_trust,
      }),
    onSuccess: (recipe) => {
      toast.success(`Imported override ${recipe.name}`)
      setImportOpen(false)
      setImportContent('')
      setImportBatchItems(null)
      setImportName('')
      setImportSourceRepo('')
      setImportRefreshTrust(true)
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const importBatchMutation = useMutation({
    mutationFn: async (args: {
      items: { fileName: string; content: string }[]
      refresh_trust: boolean
    }) => {
      const imported: string[] = []
      const failed: { file: string; error: string }[] = []
      for (const item of args.items) {
        try {
          const recipe = await api.post<AutoPkgRecipeRead>(
            '/autopkg/recipes/import-override',
            {
              content: item.content,
              name: null,
              source_repo_full_name: null,
              is_enabled: true,
              auto_promote: false,
              refresh_trust: args.refresh_trust,
            },
          )
          imported.push(recipe.name)
        } catch (e) {
          failed.push({
            file: item.fileName,
            error: e instanceof Error ? e.message : String(e),
          })
        }
      }
      return { imported, failed }
    },
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
      if (data.failed.length === 0) {
        toast.success(
          `Imported ${data.imported.length} override${data.imported.length === 1 ? '' : 's'}`,
        )
        setImportOpen(false)
        setImportContent('')
        setImportBatchItems(null)
        setImportName('')
        setImportSourceRepo('')
        setImportRefreshTrust(true)
      } else if (data.imported.length === 0) {
        toast.error(
          `Failed to import ${data.failed.length} file${data.failed.length === 1 ? '' : 's'}`,
          {
            description: data.failed
              .map((f) => `${f.file}: ${f.error}`)
              .join('\n'),
          },
        )
      } else {
        toast.warning(
          `Imported ${data.imported.length}, ${data.failed.length} failed`,
          {
            description: data.failed
              .map((f) => `${f.file}: ${f.error}`)
              .join('\n'),
          },
        )
        const failedNames = new Set(data.failed.map((f) => f.file))
        setImportBatchItems(
          variables.items.filter((i) => failedNames.has(i.fileName)),
        )
      }
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const inlineDeleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/autopkg/recipes/${id}`),
    onSuccess: () => {
      toast.success(`Deleted override ${deletingRecipe?.name ?? 'recipe'}`)
      setDeletingRecipe(null)
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const triggerRunMutation = useMutation({
    mutationFn: (args: {
      recipeNames: string[] | null
      runner: 'github' | 'local'
    }) =>
      api.post<AutoPkgRunRead>('/autopkg/runs', {
        recipe_names: args.recipeNames,
        runner: args.runner,
      }),
    onSuccess: (run) => {
      setRowSelection({})
      if (run.runner_type === 'local') {
        toastLocalRunRegistered(run)
      } else {
        toast.success('AutoPkg run triggered on GitHub Actions', {
          description: `Run ID: ${run.id}`,
          duration: 15_000,
        })
      }
      queryClient.invalidateQueries({ queryKey: ['autopkg-runs'] })
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes-enabled'] })
    },
    onError: (err: Error) =>
      toast.error(`Failed to trigger run: ${err.message}`),
  })

  const pendingRunRecipeName =
    triggerRunMutation.isPending &&
    triggerRunMutation.variables?.recipeNames?.length === 1
      ? triggerRunMutation.variables.recipeNames[0]
      : null

  const pendingRunAll =
    triggerRunMutation.isPending &&
    (triggerRunMutation.variables?.recipeNames === null ||
      triggerRunMutation.variables?.recipeNames === undefined)

  const recipeById = useMemo(
    () => new Map((recipes ?? []).map((r) => [r.id, r])),
    [recipes],
  )

  const selectedRecipes = useMemo(() => {
    return Object.keys(rowSelection)
      .filter((id) => rowSelection[id])
      .map((id) => recipeById.get(id))
      .filter((r): r is AutoPkgRecipeRead => r != null)
  }, [rowSelection, recipeById])

  /** Header "Run selected" is loading (explicit list while selection is non-empty). */
  const pendingRunSelectedList =
    triggerRunMutation.isPending &&
    selectedRecipes.length > 0 &&
    triggerRunMutation.variables?.recipeNames != null &&
    triggerRunMutation.variables.recipeNames.length >= 1

  const onToggleEnabled = (id: string, val: boolean) =>
    updateMutation.mutate({ id, is_enabled: val })

  const onToggleAutoPromote = (id: string, val: boolean) =>
    updateMutation.mutate({ id, auto_promote: val })

  const columns = useMemo(
    () =>
      makeColumns(
        pkgMeta,
        onToggleEnabled,
        onToggleAutoPromote,
        (recipe) => router.push(`/autopkg/recipes/${recipe.id}`),
        (recipe) => setQuickRun({ mode: 'single', recipe }),
        (id) => verifyTrustMutation.mutate(id),
        setDeletingRecipe,
        verifyingTrustId,
        pendingRunRecipeName,
        triggerRunMutation.isPending,
        {
          canEditRecipes,
          canRun,
          canVerifyTrust: canVerifyTrustBtn,
        },
      ),
    [
      pkgMeta,
      router,
      verifyingTrustId,
      pendingRunRecipeName,
      triggerRunMutation.isPending,
      verifyTrustMutation,
      canEditRecipes,
      canRun,
      canVerifyTrustBtn,
    ],
  )

  const filtered = (recipes ?? []).filter((r) => {
    if (search) {
      const q = search.toLowerCase()
      const inputName = recipeInputName(r).toLowerCase()
      const display = (
        pkgMeta?.[recipePkginfoKey(r)]?.displayName ?? ''
      ).toLowerCase()
      const parent = (r.parent_recipe ?? '').toLowerCase()
      const repo = (r.source_repo_full_name ?? '').toLowerCase()
      if (
        !r.name.toLowerCase().includes(q) &&
        !r.identifier.toLowerCase().includes(q) &&
        !inputName.includes(q) &&
        !display.includes(q) &&
        !parent.includes(q) &&
        !repo.includes(q)
      )
        return false
    }
    if (enabled === 'true' && !r.is_enabled) return false
    if (enabled === 'false' && r.is_enabled) return false
    return true
  })

  const hasFilters = search || enabled

  return (
    <div className="flex h-[calc(100vh-3rem)] min-w-0 w-full max-w-full flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1
          className={cn(
            'text-3xl font-bold text-pretty',
            munkiAccents.autopkg.pageTitle,
          )}
        >
          Recipe Management
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          {canRun && selectedRecipes.length > 0 ? (
            <>
              <Button
                size="sm"
                disabled={triggerRunMutation.isPending}
                onClick={() =>
                  setQuickRun({ mode: 'selected', recipes: selectedRecipes })
                }
              >
                {pendingRunSelectedList ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                Run selected ({selectedRecipes.length})
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={triggerRunMutation.isPending}
                onClick={() => setRowSelection({})}
              >
                Clear selection
              </Button>
            </>
          ) : canRun ? (
            <Button
              size="sm"
              disabled={triggerRunMutation.isPending}
              onClick={() => setQuickRun({ mode: 'all' })}
            >
              {pendingRunAll ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Run all
            </Button>
          ) : null}
          {canVerifyAllRepos ? (
            <Button
              variant="outline"
              size="sm"
              disabled={verifyAllMutation.isPending}
              onClick={() => verifyAllMutation.mutate()}
            >
              {verifyAllMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
              Verify All
            </Button>
          ) : null}
          <Button variant="outline" asChild>
            <Link href="/autopkg/discover">
              <Compass className="h-4 w-4" />
              Discover
            </Link>
          </Button>
          {canEditRecipes ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setImportOpen(true)}
            >
              <FileUp className="h-4 w-4" />
              Import
            </Button>
          ) : null}
        </div>
      </div>

      <div className="flex w-full flex-wrap items-center gap-2">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search recipes..."
              value={search}
              onChange={(e) => setSearch(e.target.value || null)}
              className="pl-9"
            />
          </div>

          <Select
            value={enabled || '_all'}
            onValueChange={(v) => setEnabled(v === '_all' ? null : v)}
          >
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_all">All</SelectItem>
              <SelectItem value="true">Enabled</SelectItem>
              <SelectItem value="false">Disabled</SelectItem>
            </SelectContent>
          </Select>

          {hasFilters && (
            <Button
              variant="ghost"
              size="sm"
              aria-label="Clear filters"
              onClick={() => {
                setSearch(null)
                setEnabled(null)
              }}
            >
              <X className="mr-1 h-4 w-4" />
              Clear
            </Button>
          )}
        </div>

        <div className="ml-auto shrink-0">
          <ColumnVisibilityMenu
            columns={columns}
            columnVisibility={columnVisibility}
            onColumnVisibilityChange={setColumnVisibility}
          />
        </div>
      </div>

      <div className="min-h-0 min-w-0 flex-1">
        <DataTable
          columns={columns}
          data={filtered}
          total={filtered.length}
          isLoading={isLoading}
          defaultColumnVisibility={DEFAULT_COLUMN_VISIBILITY}
          columnVisibility={columnVisibility}
          onColumnVisibilityChange={setColumnVisibility}
          hideColumnPicker
          enableRowSelection={canRun}
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
          getRowId={(row) => row.id}
        />
      </div>

      <QuickRunDialog
        open={quickRun !== null}
        onOpenChange={(open) => {
          if (!open) setQuickRun(null)
        }}
        target={quickRun}
        isPending={triggerRunMutation.isPending}
        onConfirm={(runner, recipeNames) => {
          triggerRunMutation.mutate({ recipeNames, runner })
        }}
      />

      <Dialog
        open={importOpen}
        onOpenChange={(open) => {
          setImportOpen(open)
          if (!open) {
            setImportContent('')
            setImportBatchItems(null)
            setImportName('')
            setImportSourceRepo('')
            setImportRefreshTrust(true)
          }
        }}
      >
        <DialogContent className="sm:max-w-[1200px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Import existing override</DialogTitle>
            <DialogDescription>
              Paste XML plist text, YAML, JSON, or base64-encoded binary plist
              from your AutoPkg recipe repo or{' '}
              <span className="font-mono">
                ~/Library/AutoPkg/RecipeOverrides
              </span>
              . Identifier must not already exist in Automunki. Choose multiple
              files to import all at once (optional name/repo and editing are
              skipped for batch imports).
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="import-override-file">File (optional)</Label>
              <Input
                id="import-override-file"
                type="file"
                multiple
                accept=".plist,.recipe,.yaml,.yml,text/plain,application/octet-stream"
                className="cursor-pointer"
                onChange={async (e) => {
                  const input = e.target
                  // Copy before clearing: ``FileList`` is live; resetting value empties it.
                  const files = Array.from(input.files ?? [])
                  input.value = ''
                  if (files.length === 0) return
                  try {
                    if (files.length === 1) {
                      setImportBatchItems(null)
                      const text = await fileToImportOverrideContent(files[0])
                      setImportContent(text)
                      toast.success(`Loaded ${files[0].name}`)
                    } else {
                      setImportContent('')
                      setImportName('')
                      setImportSourceRepo('')
                      const items = await Promise.all(
                        files.map(async (f) => ({
                          fileName: f.name,
                          content: await fileToImportOverrideContent(f),
                        })),
                      )
                      setImportBatchItems(items)
                      toast.success(
                        `Loaded ${items.length} files — review and Import all`,
                      )
                    }
                  } catch {
                    toast.error('Could not read file(s)')
                  }
                }}
              />
            </div>
            {importBatchItems && importBatchItems.length > 0 ? (
              <div className="space-y-2">
                <Label>Files to import ({importBatchItems.length})</Label>
                <ul className="max-h-48 overflow-y-auto rounded-md border px-3 py-2 text-sm font-mono">
                  {importBatchItems.map((item, idx) => (
                    <li
                      key={`${item.fileName}-${idx}`}
                      className="truncate py-0.5"
                    >
                      {item.fileName}
                    </li>
                  ))}
                </ul>
                <p className="text-xs text-muted-foreground">
                  Each file is imported with default name from its identifier.
                  Use a single file if you need optional fields or to edit
                  content before importing.
                </p>
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <Label htmlFor="import-override-content">
                    Override content
                  </Label>
                  <Textarea
                    id="import-override-content"
                    value={importContent}
                    onChange={(e) => {
                      setImportContent(e.target.value)
                      if (e.target.value.trim()) setImportBatchItems(null)
                    }}
                    placeholder="<?xml version=&quot;1.0&quot;… or base64 bplist…"
                    rows={12}
                    className="font-mono text-xs min-h-[200px]"
                  />
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="import-name">Display name (optional)</Label>
                    <Input
                      id="import-name"
                      value={importName}
                      onChange={(e) => setImportName(e.target.value)}
                      placeholder="Defaults to last segment of Identifier"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="import-repo">Source repo (optional)</Label>
                    <Input
                      id="import-repo"
                      value={importSourceRepo}
                      onChange={(e) => setImportSourceRepo(e.target.value)}
                      placeholder="owner/repo"
                      className="font-mono text-sm"
                    />
                  </div>
                </div>
              </>
            )}
            <div className="flex items-center gap-3 rounded-md border px-3 py-2">
              <Switch
                id="import-refresh-trust"
                checked={importRefreshTrust}
                onCheckedChange={setImportRefreshTrust}
              />
              <Label htmlFor="import-refresh-trust" className="cursor-pointer">
                Resolve trust from GitHub
              </Label>
            </div>
            <p className="text-xs text-muted-foreground">
              When enabled, parent recipes are hashed via the GitHub API and
              trust is marked verified. Turn off to import only the plist (trust
              stays unknown; use &quot;Re-fetch Trust&quot; in the recipe editor
              later).
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={
                importBatchItems && importBatchItems.length > 0
                  ? importBatchMutation.isPending
                  : !importContent.trim() || importOverrideMutation.isPending
              }
              onClick={() => {
                if (importBatchItems && importBatchItems.length > 0) {
                  importBatchMutation.mutate({
                    items: importBatchItems,
                    refresh_trust: importRefreshTrust,
                  })
                } else {
                  importOverrideMutation.mutate({
                    content: importContent,
                    name: importName || null,
                    source_repo_full_name: importSourceRepo || null,
                    refresh_trust: importRefreshTrust,
                  })
                }
              }}
            >
              {importBatchMutation.isPending ||
              importOverrideMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <FileUp className="mr-2 h-4 w-4" />
              )}
              {importBatchItems && importBatchItems.length > 0
                ? `Import all (${importBatchItems.length})`
                : 'Import'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!deletingRecipe}
        onOpenChange={(open) => {
          if (!open) setDeletingRecipe(null)
        }}
      >
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete Override</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete the override for{' '}
              <strong>{deletingRecipe?.name}</strong>? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeletingRecipe(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={inlineDeleteMutation.isPending}
              onClick={() => {
                if (deletingRecipe) {
                  inlineDeleteMutation.mutate(deletingRecipe.id)
                }
              }}
            >
              {inlineDeleteMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="mr-2 h-4 w-4" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
