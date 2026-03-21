'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef, VisibilityState } from '@tanstack/react-table'
import {
  Compass,
  FileUp,
  GripVertical,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
  X,
} from 'lucide-react'
import Link from 'next/link'
import { parseAsString, useQueryState } from 'nuqs'
import { Fragment, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ColumnVisibilityMenu, DataTable } from '@/components/data-table'
import { PkginfoIconUpload } from '@/components/pkginfo-icon-upload'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import {
  type AutoPkgRecipeRead,
  type AutoPkgRunRead,
  api,
  type CatalogRead,
} from '@/lib/api'
import {
  buildLocalRunnerShellCommand,
  canTriggerRunRecipe,
  LocalRunnerToastBody,
  QuickRunDialog,
} from '@/lib/autopkg-run'
import { formatDateTime } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
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

function extractPkginfo(
  inputVars: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (!inputVars || typeof inputVars !== 'object') return {}
  const pkginfo = inputVars.pkginfo
  if (!pkginfo || typeof pkginfo !== 'object') return {}
  return pkginfo as Record<string, unknown>
}

/** Split catalog names from the recipe UI (commas, slashes, or pipes). */
function parseCatalogListInput(raw: string): string[] {
  return raw
    .split(/[,/|]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Munki catalog names from ``Input.pkginfo.catalogs`` on the recipe. */
function pkginfoCatalogsFromInput(
  inputVars: Record<string, unknown> | null | undefined,
): string[] {
  const c = extractPkginfo(inputVars).catalogs
  if (Array.isArray(c)) {
    return c.filter((x): x is string => typeof x === 'string')
  }
  return []
}

/** Canonical recipe Input dict: override plist first, then legacy ``input_variables``. */
function recipeInputDict(
  recipe: AutoPkgRecipeRead,
): Record<string, unknown> | null {
  const od = recipe.override_data as Record<string, unknown> | null | undefined
  if (od?.Input && typeof od.Input === 'object') {
    return od.Input as Record<string, unknown>
  }
  return (recipe.input_variables as Record<string, unknown> | null) ?? null
}

function pkginfoCatalogsFromRecipe(recipe: AutoPkgRecipeRead): string[] {
  return pkginfoCatalogsFromInput(recipeInputDict(recipe))
}

function recipeInputName(recipe: AutoPkgRecipeRead): string {
  const inp = recipeInputDict(recipe)
  const n = inp?.NAME
  return typeof n === 'string' && n.trim() ? n : ''
}

function makeColumns(
  onToggleEnabled: (id: string, enabled: boolean) => void,
  onToggleAutoPromote: (id: string, auto: boolean) => void,
  onEdit: (recipe: AutoPkgRecipeRead) => void,
  onRunRecipe: (recipe: AutoPkgRecipeRead) => void,
  onVerifyTrust: (id: string) => void,
  onDelete: (recipe: AutoPkgRecipeRead) => void,
  verifyingTrustId: string | null,
  pendingRunRecipeName: string | null,
  isRunPending: boolean,
): ColumnDef<AutoPkgRecipeRead>[] {
  return [
    {
      accessorKey: 'name',
      header: 'Name',
      enableHiding: false,
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
            {row.original.is_override && (
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
      cell: ({ row }) => (
        <Switch
          checked={row.original.is_enabled}
          onCheckedChange={(checked) =>
            onToggleEnabled(row.original.id, checked)
          }
          aria-label={`Toggle ${row.original.name} enabled`}
        />
      ),
    },
    {
      accessorKey: 'auto_promote',
      header: 'Auto Promote',
      cell: ({ row }) => (
        <Switch
          checked={row.original.auto_promote}
          onCheckedChange={(checked) =>
            onToggleAutoPromote(row.original.id, checked)
          }
          aria-label={`Toggle ${row.original.name} auto-promote`}
        />
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
        row.original.is_override ? (
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
  identifier: true,
  input_name: false,
  parent_recipe: false,
  source_repo_full_name: false,
  trust_status: true,
  is_enabled: true,
  auto_promote: true,
  pkginfo_catalogs: true,
  last_run_status: true,
  last_run_at: true,
  updated_at: false,
}

export default function RecipesPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useQueryState(
    'search',
    parseAsString.withDefault(''),
  )
  const [enabled, setEnabled] = useQueryState(
    'enabled',
    parseAsString.withDefault(''),
  )
  const [editingRecipe, setEditingRecipe] = useState<AutoPkgRecipeRead | null>(
    null,
  )
  const [quickRunTarget, setQuickRunTarget] = useState<
    AutoPkgRecipeRead | 'all' | null
  >(null)
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(
    DEFAULT_COLUMN_VISIBILITY,
  )

  const [importOpen, setImportOpen] = useState(false)
  const [importContent, setImportContent] = useState('')
  const [importName, setImportName] = useState('')
  const [importSourceRepo, setImportSourceRepo] = useState('')
  const [importRefreshTrust, setImportRefreshTrust] = useState(true)

  const { data: recipes, isLoading } = useQuery({
    queryKey: ['autopkg-recipes'],
    queryFn: () => api.get<AutoPkgRecipeRead[]>('/autopkg/recipes'),
  })

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
      setImportName('')
      setImportSourceRepo('')
      setImportRefreshTrust(true)
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
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
      if (run.runner_type === 'local') {
        const cmd = buildLocalRunnerShellCommand(run)
        toast.success('Local run registered — run from your clone', {
          description: <LocalRunnerToastBody cmd={cmd} />,
          duration: Infinity,
          closeButton: true,
        })
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

  const onToggleEnabled = (id: string, val: boolean) =>
    updateMutation.mutate({ id, is_enabled: val })

  const onToggleAutoPromote = (id: string, val: boolean) =>
    updateMutation.mutate({ id, auto_promote: val })

  const columns = useMemo(
    () =>
      makeColumns(
        onToggleEnabled,
        onToggleAutoPromote,
        setEditingRecipe,
        (recipe) => setQuickRunTarget(recipe),
        (id) => verifyTrustMutation.mutate(id),
        setDeletingRecipe,
        verifyingTrustId,
        pendingRunRecipeName,
        triggerRunMutation.isPending,
      ),
    [
      verifyingTrustId,
      pendingRunRecipeName,
      triggerRunMutation.isPending,
      verifyTrustMutation,
    ],
  )

  const filtered = (recipes ?? []).filter((r) => {
    if (search) {
      const q = search.toLowerCase()
      const inputName = recipeInputName(r).toLowerCase()
      const parent = (r.parent_recipe ?? '').toLowerCase()
      const repo = (r.source_repo_full_name ?? '').toLowerCase()
      if (
        !r.name.toLowerCase().includes(q) &&
        !r.identifier.toLowerCase().includes(q) &&
        !inputName.includes(q) &&
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
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            disabled={triggerRunMutation.isPending}
            onClick={() => setQuickRunTarget('all')}
          >
            {pendingRunAll ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            Run all
          </Button>
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
          <Button variant="outline" asChild>
            <Link href="/autopkg/discover">
              <Compass className="h-4 w-4" />
              Discover
            </Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setImportOpen(true)}
          >
            <FileUp className="h-4 w-4" />
            Import
          </Button>
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
        />
      </div>

      {editingRecipe && (
        <RecipeEditDialog
          recipe={editingRecipe}
          onClose={() => setEditingRecipe(null)}
          onSaved={() => {
            queryClient.invalidateQueries({
              queryKey: ['autopkg-recipes'],
            })
            setEditingRecipe(null)
          }}
          onDeleted={() => {
            queryClient.invalidateQueries({
              queryKey: ['autopkg-recipes'],
            })
            setEditingRecipe(null)
          }}
        />
      )}

      <QuickRunDialog
        open={quickRunTarget !== null}
        onOpenChange={(open) => {
          if (!open) setQuickRunTarget(null)
        }}
        recipe={quickRunTarget === 'all' ? null : quickRunTarget}
        isPending={triggerRunMutation.isPending}
        onConfirm={(runner) => {
          const names =
            quickRunTarget === 'all' || quickRunTarget === null
              ? null
              : [quickRunTarget.name]
          triggerRunMutation.mutate({ recipeNames: names, runner })
        }}
      />

      <Dialog
        open={importOpen}
        onOpenChange={(open) => {
          setImportOpen(open)
          if (!open) {
            setImportContent('')
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
              . Identifier must not already exist in Automunki.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="import-override-file">File (optional)</Label>
              <Input
                id="import-override-file"
                type="file"
                accept=".plist,.recipe,.yaml,.yml,text/plain,application/octet-stream"
                className="cursor-pointer"
                onChange={async (e) => {
                  const f = e.target.files?.[0]
                  e.target.value = ''
                  if (!f) return
                  try {
                    const text = await fileToImportOverrideContent(f)
                    setImportContent(text)
                    toast.success(`Loaded ${f.name}`)
                  } catch {
                    toast.error('Could not read file')
                  }
                }}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="import-override-content">Override content</Label>
              <Textarea
                id="import-override-content"
                value={importContent}
                onChange={(e) => setImportContent(e.target.value)}
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
                !importContent.trim() || importOverrideMutation.isPending
              }
              onClick={() =>
                importOverrideMutation.mutate({
                  content: importContent,
                  name: importName || null,
                  source_repo_full_name: importSourceRepo || null,
                  refresh_trust: importRefreshTrust,
                })
              }
            >
              {importOverrideMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <FileUp className="mr-2 h-4 w-4" />
              )}
              Import
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

// ── Structured key/value editor ──────────────────────────────────────────

type KVEntry = { id: string; key: string; value: string }

let _kvId = 0
function nextKvId() {
  return `kv-${++_kvId}`
}

function kvFromDict(
  dict: Record<string, unknown> | null | undefined,
): KVEntry[] {
  if (!dict || typeof dict !== 'object') return []
  return Object.entries(dict).map(([key, value]) => ({
    id: nextKvId(),
    key,
    value: typeof value === 'string' ? value : JSON.stringify(value),
  }))
}

function kvToDict(entries: KVEntry[]): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const { key, value } of entries) {
    if (!key.trim()) continue
    try {
      result[key.trim()] = JSON.parse(value)
    } catch {
      result[key.trim()] = value
    }
  }
  return result
}

function KeyValueEditor({
  entries,
  onChange,
  keyPlaceholder = 'KEY',
  valuePlaceholder = 'Value',
  readOnly = false,
}: {
  entries: KVEntry[]
  onChange: (entries: KVEntry[]) => void
  keyPlaceholder?: string
  valuePlaceholder?: string
  readOnly?: boolean
}) {
  const update = (index: number, field: 'key' | 'value', val: string) => {
    const next = [...entries]
    next[index] = { ...next[index], [field]: val }
    onChange(next)
  }

  const remove = (index: number) => {
    onChange(entries.filter((_, i) => i !== index))
  }

  const add = () => {
    onChange([...entries, { id: nextKvId(), key: '', value: '' }])
  }

  return (
    <div className="space-y-2">
      {entries.length === 0 && !readOnly && (
        <p className="text-xs text-muted-foreground py-1">
          No entries. Click + to add one.
        </p>
      )}
      {entries.length === 0 && readOnly && (
        <p className="text-xs text-muted-foreground py-1">No entries.</p>
      )}
      {entries.map((entry, i) => (
        <div key={entry.id} className="flex items-start gap-2">
          {!readOnly && (
            <GripVertical className="mt-2.5 h-4 w-4 shrink-0 text-muted-foreground/50" />
          )}
          <Input
            value={entry.key}
            onChange={(e) => update(i, 'key', e.target.value)}
            placeholder={keyPlaceholder}
            className="font-mono text-sm flex-[2]"
            readOnly={readOnly}
          />
          <Input
            value={entry.value}
            onChange={(e) => update(i, 'value', e.target.value)}
            placeholder={valuePlaceholder}
            className="font-mono text-sm flex-[3]"
            readOnly={readOnly}
          />
          {!readOnly && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="shrink-0 mt-0.5"
              aria-label={`Remove ${entry.key}`}
              onClick={() => remove(i)}
            >
              <Trash2 className="h-4 w-4 text-destructive" />
            </Button>
          )}
        </div>
      ))}
      {!readOnly && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={add}
          className="w-full"
        >
          <Plus className="mr-1 h-4 w-4" />
          Add Entry
        </Button>
      )}
    </div>
  )
}

// ── Trust info viewer ────────────────────────────────────────────────────

function TrustInfoViewer({
  trustInfo,
}: {
  trustInfo: Record<string, unknown> | null | undefined
}) {
  if (!trustInfo) {
    return (
      <p className="text-sm text-muted-foreground py-2">
        No trust info recorded. Create or update the override to generate trust
        info.
      </p>
    )
  }

  const parentRecipes =
    (trustInfo.parent_recipes as Record<string, Record<string, string>>) ?? {}
  const processors =
    (trustInfo.non_core_processors as Record<string, Record<string, string>>) ??
    {}

  return (
    <div className="space-y-4">
      <div>
        <h4 className="text-sm font-medium mb-2">Parent Recipes</h4>
        {Object.keys(parentRecipes).length === 0 ? (
          <p className="text-xs text-muted-foreground">None</p>
        ) : (
          <div className="space-y-2">
            {Object.entries(parentRecipes).map(([identifier, info]) => (
              <div
                key={identifier}
                className="rounded-md border bg-muted/30 px-3 py-2"
              >
                <p className="font-mono text-sm font-medium">{identifier}</p>
                {info.github_repo && (
                  <p className="mt-0.5 truncate text-xs text-muted-foreground">
                    <span className="text-muted-foreground/70">Repo:</span>{' '}
                    <a
                      href={`https://github.com/${info.github_repo}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:underline"
                    >
                      {info.github_repo}
                    </a>
                    {info.github_path && (
                      <>
                        {' / '}
                        <span className="font-mono">{info.github_path}</span>
                      </>
                    )}
                  </p>
                )}
                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                  <span className="text-muted-foreground/70">SHA256:</span>{' '}
                  <code className="bg-muted px-1 rounded">
                    {info.sha256_hash}
                  </code>
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <h4 className="text-sm font-medium mb-2">Non-Core Processors</h4>
        {Object.keys(processors).length === 0 ? (
          <p className="text-xs text-muted-foreground">None</p>
        ) : (
          <div className="space-y-2">
            {Object.entries(processors).map(([name, info]) => (
              <div
                key={name}
                className="rounded-md border bg-muted/30 px-3 py-2"
              >
                <p className="font-mono text-sm font-medium">{name}</p>
                {info.github_repo && (
                  <p className="mt-0.5 truncate text-xs text-muted-foreground">
                    <span className="text-muted-foreground/70">Repo:</span>{' '}
                    {info.github_repo}
                    {info.github_path && (
                      <>
                        {' / '}
                        <span className="font-mono">{info.github_path}</span>
                      </>
                    )}
                  </p>
                )}
                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                  <span className="text-muted-foreground/70">SHA256:</span>{' '}
                  <code className="bg-muted px-1 rounded">
                    {info.sha256_hash}
                  </code>
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── pkginfo field helpers ─────────────────────────────────────────────────

const PKGINFO_TEXT_FIELDS = [
  { key: 'description', label: 'Description', multiline: true },
  { key: 'display_name', label: 'Display Name', multiline: false },
  { key: 'developer', label: 'Developer', multiline: false },
  { key: 'name', label: 'Package Name', multiline: false },
  { key: 'category', label: 'Category', multiline: false },
  { key: 'minimum_os_version', label: 'Minimum OS Version', multiline: false },
  { key: 'maximum_os_version', label: 'Maximum OS Version', multiline: false },
  { key: 'uninstall_method', label: 'Uninstall Method', multiline: false },
] as const

const PKGINFO_BOOL_FIELDS = [
  { key: 'unattended_install', label: 'Unattended Install' },
  { key: 'unattended_uninstall', label: 'Unattended Uninstall' },
  { key: 'autoremove', label: 'Auto Remove' },
  { key: 'uninstallable', label: 'Uninstallable' },
] as const

const PKGINFO_LIST_FIELDS = [
  { key: 'catalogs', label: 'Catalogs' },
  { key: 'blocking_applications', label: 'Blocking Applications' },
  { key: 'requires', label: 'Requires' },
  { key: 'update_for', label: 'Update For' },
] as const

function extractNonPkginfoInput(
  inputVars: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (!inputVars || typeof inputVars !== 'object') return {}
  const result: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(inputVars)) {
    if (k !== 'pkginfo') result[k] = v
  }
  return result
}

// ── Recipe edit dialog ───────────────────────────────────────────────────

function RecipeEditDialog({
  recipe,
  onClose,
  onSaved,
  onDeleted,
}: {
  recipe: AutoPkgRecipeRead
  onClose: () => void
  onSaved: () => void
  onDeleted: () => void
}) {
  const inputVarsRaw = recipe.input_variables as Record<string, unknown> | null
  const canonicalInput = recipeInputDict(recipe) ?? inputVarsRaw ?? {}
  const hasStoredOverridePlist = Boolean(recipe.override_data)

  const [identifier, setIdentifier] = useState(recipe.identifier)
  const [name, setName] = useState(recipe.name)
  const [parentRecipe, setParentRecipe] = useState(recipe.parent_recipe ?? '')
  const [sourceRepoFullName, setSourceRepoFullName] = useState(
    recipe.source_repo_full_name ?? '',
  )
  const [isEnabled, setIsEnabled] = useState(recipe.is_enabled)
  const [isOverride, setIsOverride] = useState(recipe.is_override)
  const [autoPromote, setAutoPromote] = useState(recipe.auto_promote)

  const [nonPkginfoEntries, setNonPkginfoEntries] = useState<KVEntry[]>(
    kvFromDict(extractNonPkginfoInput(canonicalInput)),
  )

  const initialPkginfo = extractPkginfo(canonicalInput)
  const [pkginfo, setPkginfo] =
    useState<Record<string, unknown>>(initialPkginfo)
  const [iconRevision, setIconRevision] = useState(0)

  const updatePkgField = (key: string, value: unknown) => {
    setPkginfo((prev) => ({ ...prev, [key]: value }))
  }

  const { data: catalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
  })

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.put(`/autopkg/recipes/${recipe.id}`, payload),
    onSuccess: () => {
      toast.success(`Recipe ${name} updated`)
      onSaved()
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/autopkg/recipes/${recipe.id}`),
    onSuccess: () => {
      toast.success(`Recipe ${recipe.name} deleted`)
      onDeleted()
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const updateTrustMutation = useMutation({
    mutationFn: () =>
      api.post<{ name: string; trust_status: string }>(
        `/autopkg/recipes/${recipe.id}/update-trust`,
      ),
    onSuccess: (data) => {
      toast.success(`Trust info updated for ${data.name}`)
      onSaved()
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const handleSave = () => {
    const nonPkgDict = kvToDict(nonPkginfoEntries)
    const hasPkginfo = Object.keys(pkginfo).length > 0
    const fullInput: Record<string, unknown> = {
      ...nonPkgDict,
      ...(hasPkginfo ? { pkginfo } : {}),
    }

    const payload: Record<string, unknown> = {
      identifier,
      name,
      parent_recipe: parentRecipe || null,
      source_repo_full_name: sourceRepoFullName.trim() || null,
      is_enabled: isEnabled,
      is_override: isOverride,
      auto_promote: autoPromote,
    }

    if (hasStoredOverridePlist) {
      const prev =
        (recipe.override_data as Record<string, unknown> | null) ?? {}
      payload.override_data = {
        ...prev,
        Identifier: identifier,
        ParentRecipe: parentRecipe || '',
        Input: fullInput,
      }
      payload.input_variables =
        Object.keys(nonPkgDict).length > 0 ? nonPkgDict : null
    } else {
      payload.input_variables =
        Object.keys(fullInput).length > 0 ? fullInput : null
    }

    saveMutation.mutate(payload)
  }

  const catalogNames = (catalogs ?? []).map((c) => c.name)
  const nonPkginfoCount = nonPkginfoEntries.length
  const pkginfoCount = Object.keys(pkginfo).length

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Edit Recipe: {recipe.name}</DialogTitle>
          <DialogDescription>
            Modify the recipe override settings. Changes are saved to the
            database.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="general" className="w-full">
          <TabsList className="w-full grid grid-cols-4">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="input">
              Input
              {nonPkginfoCount > 0 && (
                <Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
                  {nonPkginfoCount}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="pkginfo">
              pkginfo
              {pkginfoCount > 0 && (
                <Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
                  {pkginfoCount}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="trust">Trust Info</TabsTrigger>
          </TabsList>

          <TabsContent value="general" className="space-y-4 mt-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="recipe-name">Name</Label>
                <Input
                  id="recipe-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="recipe-identifier">Identifier</Label>
                <Input
                  id="recipe-identifier"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  className="font-mono text-sm"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="recipe-parent">Parent Recipe</Label>
              <Input
                id="recipe-parent"
                value={parentRecipe}
                onChange={(e) => setParentRecipe(e.target.value)}
                placeholder="com.github.autopkg.munki.Firefox"
                className="font-mono text-sm"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="recipe-source-repo">Source repo (GitHub)</Label>
              <Input
                id="recipe-source-repo"
                value={sourceRepoFullName}
                onChange={(e) => setSourceRepoFullName(e.target.value)}
                placeholder="autopkg/recipes"
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                Used for runner repo-add hints and inferred repo lists
                (owner/repo, no URL).
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="flex items-center gap-3 rounded-md border px-3 py-2">
                <Switch
                  id="recipe-enabled"
                  checked={isEnabled}
                  onCheckedChange={setIsEnabled}
                />
                <Label htmlFor="recipe-enabled" className="cursor-pointer">
                  Enabled
                </Label>
              </div>
              <div className="flex items-center gap-3 rounded-md border px-3 py-2">
                <Switch
                  id="recipe-override"
                  checked={isOverride}
                  onCheckedChange={setIsOverride}
                />
                <Label htmlFor="recipe-override" className="cursor-pointer">
                  Override
                </Label>
              </div>
              <div className="flex items-center gap-3 rounded-md border px-3 py-2">
                <Switch
                  id="recipe-auto-promote"
                  checked={autoPromote}
                  onCheckedChange={setAutoPromote}
                />
                <Label htmlFor="recipe-auto-promote" className="cursor-pointer">
                  Auto Promote
                </Label>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="recipe-catalogs">Catalogs</Label>
              <p className="text-xs text-muted-foreground">
                Stored as{' '}
                <span className="font-mono">Input.pkginfo.catalogs</span> (what
                AutoPkg writes into pkginfo).
              </p>
              <div className="flex flex-wrap gap-1 mb-2">
                {catalogNames.map((cat) => {
                  const values = Array.isArray(pkginfo.catalogs)
                    ? (pkginfo.catalogs as string[]).filter(
                        (x): x is string => typeof x === 'string',
                      )
                    : []
                  const selected = values.includes(cat)
                  return (
                    <Badge
                      key={cat}
                      variant={selected ? 'default' : 'outline'}
                      className="cursor-pointer"
                      onClick={() => {
                        const next = selected
                          ? values.filter((c) => c !== cat)
                          : [...values, cat]
                        updatePkgField(
                          'catalogs',
                          next.length > 0 ? next : undefined,
                        )
                      }}
                    >
                      {cat}
                    </Badge>
                  )
                })}
              </div>
              <Input
                id="recipe-catalogs"
                value={
                  Array.isArray(pkginfo.catalogs)
                    ? (pkginfo.catalogs as string[]).join(', ')
                    : ''
                }
                onChange={(e) => {
                  const next = parseCatalogListInput(e.target.value)
                  updatePkgField('catalogs', next.length > 0 ? next : undefined)
                }}
                placeholder="testing, dev, staging or testing/dev/staging"
              />
            </div>

            <div className="space-y-2 rounded-md border p-4">
              <Label>Software icon</Label>
              <p className="text-xs text-muted-foreground">
                PNG for the web UI (same folder as static{' '}
                <span className="font-mono">/icons/*.png</span>). Uses Icon Name
                from pkginfo if set, otherwise Package Name.
              </p>
              <div className="flex flex-wrap items-center gap-4">
                <SoftwareIcon
                  name={
                    typeof pkginfo.name === 'string' && pkginfo.name
                      ? pkginfo.name
                      : 'package'
                  }
                  displayName={
                    typeof pkginfo.display_name === 'string'
                      ? pkginfo.display_name
                      : null
                  }
                  iconName={
                    typeof pkginfo.icon_name === 'string'
                      ? pkginfo.icon_name
                      : null
                  }
                  size="md"
                  cacheRevision={iconRevision}
                />
                <PkginfoIconUpload
                  suggestedBasename={
                    typeof pkginfo.name === 'string' ? pkginfo.name : ''
                  }
                  currentIconName={
                    typeof pkginfo.icon_name === 'string'
                      ? pkginfo.icon_name
                      : ''
                  }
                  onIconNameApplied={(v) => {
                    updatePkgField('icon_name', v)
                    setIconRevision((r) => r + 1)
                  }}
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="input" className="mt-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Input Variables</Label>
                <span className="text-xs text-muted-foreground">
                  Non-pkginfo keys (e.g. NAME, MUNKI_REPO_SUBDIR)
                </span>
              </div>
              <KeyValueEditor
                entries={nonPkginfoEntries}
                onChange={setNonPkginfoEntries}
                keyPlaceholder="VARIABLE_NAME"
                valuePlaceholder="value"
              />
            </div>
          </TabsContent>

          <TabsContent value="pkginfo" className="mt-4">
            <PkginfoEditor
              pkginfo={pkginfo}
              onUpdate={updatePkgField}
              catalogNames={catalogNames}
              onIconFileUploaded={() => setIconRevision((r) => r + 1)}
            />
          </TabsContent>

          <TabsContent value="trust" className="mt-4">
            <TrustInfoViewer
              trustInfo={recipe.trust_info as Record<string, unknown> | null}
            />
            {recipe.is_override && recipe.parent_recipe && (
              <div className="mt-4 pt-4 border-t">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={updateTrustMutation.isPending}
                  onClick={() => updateTrustMutation.mutate()}
                >
                  {updateTrustMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="mr-2 h-4 w-4" />
                  )}
                  Re-fetch Trust Info from GitHub
                </Button>
                <p className="mt-1 text-xs text-muted-foreground">
                  Re-resolves all parent recipes and updates stored hashes and
                  locations.
                </p>
              </div>
            )}
          </TabsContent>
        </Tabs>

        <DialogFooter className="flex-row items-center justify-between sm:justify-between">
          <Button
            variant="destructive"
            size="sm"
            disabled={deleteMutation.isPending}
            onClick={() => {
              if (
                window.confirm(
                  `Delete override "${recipe.name}"? This cannot be undone.`,
                )
              ) {
                deleteMutation.mutate()
              }
            }}
          >
            <Trash2 className="mr-1 h-4 w-4" />
            {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={saveMutation.isPending || !name || !identifier}
            >
              {saveMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── pkginfo editor (mirrors software detail page style) ──────────────────

function PkginfoEditor({
  pkginfo,
  onUpdate,
  catalogNames,
  onIconFileUploaded,
}: {
  pkginfo: Record<string, unknown>
  onUpdate: (key: string, value: unknown) => void
  catalogNames: string[]
  onIconFileUploaded?: () => void
}) {
  const getString = (key: string) => (pkginfo[key] as string) ?? ''
  const getBool = (key: string) => (pkginfo[key] as boolean) ?? false
  const getList = (key: string) => (pkginfo[key] as string[]) ?? []

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        {PKGINFO_TEXT_FIELDS.map((field) => (
          <Fragment key={field.key}>
            <div className="space-y-2">
              <Label htmlFor={`pkg-${field.key}`}>{field.label}</Label>
              {field.multiline ? (
                <Textarea
                  id={`pkg-${field.key}`}
                  value={getString(field.key)}
                  onChange={(e) =>
                    onUpdate(field.key, e.target.value || undefined)
                  }
                  rows={3}
                  className="text-sm"
                />
              ) : (
                <Input
                  id={`pkg-${field.key}`}
                  value={getString(field.key)}
                  onChange={(e) =>
                    onUpdate(field.key, e.target.value || undefined)
                  }
                  className="text-sm"
                />
              )}
            </div>
            {field.key === 'name' && (
              <div className="space-y-2">
                <Label htmlFor="pkg-icon_name">Icon Name</Label>
                <p className="text-xs text-muted-foreground">
                  Filename stem without .png (Munki pkginfo).
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <Input
                    id="pkg-icon_name"
                    value={getString('icon_name')}
                    onChange={(e) =>
                      onUpdate('icon_name', e.target.value || undefined)
                    }
                    className="max-w-md text-sm"
                    placeholder={
                      getString('name') || 'defaults to package name for upload'
                    }
                  />
                  <PkginfoIconUpload
                    suggestedBasename={getString('name')}
                    currentIconName={getString('icon_name')}
                    onIconNameApplied={(v) => {
                      onUpdate('icon_name', v)
                      onIconFileUploaded?.()
                    }}
                  />
                </div>
              </div>
            )}
          </Fragment>
        ))}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {PKGINFO_BOOL_FIELDS.map((field) => (
          <div
            key={field.key}
            className="flex items-center gap-3 rounded-md border px-3 py-2"
          >
            <Switch
              id={`pkg-${field.key}`}
              checked={getBool(field.key)}
              onCheckedChange={(checked) => onUpdate(field.key, checked)}
            />
            <Label htmlFor={`pkg-${field.key}`} className="cursor-pointer">
              {field.label}
            </Label>
          </div>
        ))}
      </div>

      {PKGINFO_LIST_FIELDS.map((field) => {
        const values = getList(field.key)
        const isThisCatalogs = field.key === 'catalogs'
        return (
          <div key={field.key} className="space-y-2">
            <Label>{field.label}</Label>
            {isThisCatalogs && catalogNames.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1">
                {catalogNames.map((cat) => {
                  const selected = values.includes(cat)
                  return (
                    <Badge
                      key={cat}
                      variant={selected ? 'default' : 'outline'}
                      className="cursor-pointer"
                      onClick={() => {
                        const next = selected
                          ? values.filter((v) => v !== cat)
                          : [...values, cat]
                        onUpdate(field.key, next.length > 0 ? next : undefined)
                      }}
                    >
                      {cat}
                    </Badge>
                  )
                })}
              </div>
            )}
            <Input
              value={values.join(', ')}
              onChange={(e) => {
                const next = parseCatalogListInput(e.target.value)
                onUpdate(field.key, next.length > 0 ? next : undefined)
              }}
              placeholder={
                isThisCatalogs
                  ? 'Comma, slash, or pipe — e.g. testing, dev, staging'
                  : `Comma-separated ${field.label.toLowerCase()}`
              }
              className="text-sm"
            />
          </div>
        )
      })}
    </div>
  )
}
