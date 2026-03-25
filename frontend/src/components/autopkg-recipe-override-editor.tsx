'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Braces,
  FileText,
  GripVertical,
  Loader2,
  Package,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { Fragment, useCallback, useEffect, useState } from 'react'
import { toast } from 'sonner'
import { PkginfoIconUpload } from '@/components/pkginfo-icon-upload'
import { SoftwareIcon } from '@/components/software-icon'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { type AutoPkgRecipeRead, api, type CatalogRead } from '@/lib/api'
import {
  extractNonPkginfoInput,
  extractPkginfo,
  parseCatalogListInput,
  recipeIconUploadBasename,
  recipeInputDict,
} from '@/lib/autopkg-recipe'
import { cn } from '@/lib/utils'

const recipeDetailTabContentClass = cn(
  'space-y-4',
  'animate-in fade-in-0 slide-in-from-bottom-1 duration-300',
)

function recipeDetailTabTrigger(activeRing: string) {
  return cn(
    'group/tab flex-none gap-2 px-4 py-2.5 min-h-11 rounded-lg border border-transparent',
    'text-muted-foreground transition-[transform,box-shadow,background-color,border-color,color] duration-200 ease-out will-change-transform',
    'hover:bg-background/80 hover:text-foreground',
    'data-[state=inactive]:hover:scale-[1.03] data-[state=inactive]:hover:-translate-y-0.5',
    'data-[state=inactive]:hover:border-border/35 data-[state=inactive]:hover:shadow-sm',
    'data-[state=active]:scale-[1.02] data-[state=active]:bg-background data-[state=active]:shadow-md',
    'data-[state=active]:border-border/60 data-[state=active]:hover:scale-[1.03]',
    'motion-reduce:data-[state=inactive]:hover:scale-100 motion-reduce:data-[state=inactive]:hover:translate-y-0',
    'motion-reduce:data-[state=active]:scale-100 motion-reduce:data-[state=active]:hover:scale-100',
    activeRing,
  )
}

const recipeTabIconClass =
  'size-4 shrink-0 opacity-70 transition-[opacity,transform] duration-200 ease-out group-hover/tab:opacity-100 group-data-[state=inactive]/tab:group-hover/tab:scale-105 group-data-[state=active]/tab:opacity-100 group-data-[state=active]/tab:scale-110 group-data-[state=active]/tab:group-hover/tab:scale-[1.18] motion-reduce:group-hover/tab:scale-100 motion-reduce:group-data-[state=active]/tab:scale-100 motion-reduce:group-data-[state=active]/tab:group-hover/tab:scale-100'

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

function PkginfoEditor({
  pkginfo,
  onUpdate,
  catalogNames,
  onIconFileUploaded,
  packageBasenameForIcons,
  readOnly = false,
}: {
  pkginfo: Record<string, unknown>
  onUpdate: (key: string, value: unknown) => void
  catalogNames: string[]
  onIconFileUploaded?: () => void
  /** Resolved product name (``Input.NAME``), never template tokens like ``NAME``. */
  packageBasenameForIcons: string
  readOnly?: boolean
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
                  readOnly={readOnly}
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
                  readOnly={readOnly}
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
                    readOnly={readOnly}
                    onChange={(e) =>
                      onUpdate('icon_name', e.target.value || undefined)
                    }
                    className="max-w-md text-sm"
                    placeholder={
                      packageBasenameForIcons ||
                      'defaults to package name for upload'
                    }
                  />
                  <PkginfoIconUpload
                    suggestedBasename={packageBasenameForIcons}
                    currentIconName={getString('icon_name')}
                    disabled={readOnly}
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
              disabled={readOnly}
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
                      className={readOnly ? undefined : 'cursor-pointer'}
                      onClick={
                        readOnly
                          ? undefined
                          : () => {
                              const next = selected
                                ? values.filter((v) => v !== cat)
                                : [...values, cat]
                              onUpdate(
                                field.key,
                                next.length > 0 ? next : undefined,
                              )
                            }
                      }
                    >
                      {cat}
                    </Badge>
                  )
                })}
              </div>
            )}
            <Input
              value={values.join(', ')}
              readOnly={readOnly}
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

// ── Main editor ──────────────────────────────────────────────────────────

export type RecipeOverrideToolbarApi = {
  save: () => void
  deleteRecipe: () => void
  isSaving: boolean
  isDeleting: boolean
  canSave: boolean
}

export function RecipeOverrideEditor({
  recipe,
  onDeleted,
  readOnly = false,
  onToolbarApiChange,
}: {
  recipe: AutoPkgRecipeRead
  onDeleted?: () => void
  readOnly?: boolean
  /** When not read-only, exposes save/delete for a header toolbar (see recipe detail page). */
  onToolbarApiChange?: (api: RecipeOverrideToolbarApi | null) => void
}) {
  const queryClient = useQueryClient()
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

  useEffect(() => {
    const iv = recipe.input_variables as Record<string, unknown> | null
    const nextCanonical = recipeInputDict(recipe) ?? iv ?? {}
    setIdentifier(recipe.identifier)
    setName(recipe.name)
    setParentRecipe(recipe.parent_recipe ?? '')
    setSourceRepoFullName(recipe.source_repo_full_name ?? '')
    setIsEnabled(recipe.is_enabled)
    setIsOverride(recipe.is_override)
    setAutoPromote(recipe.auto_promote)
    setNonPkginfoEntries(kvFromDict(extractNonPkginfoInput(nextCanonical)))
    setPkginfo(extractPkginfo(nextCanonical))
  }, [recipe.id, recipe.updated_at])

  const updatePkgField = (key: string, value: unknown) => {
    setPkginfo((prev) => ({ ...prev, [key]: value }))
  }

  const { data: catalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
  })

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.put<AutoPkgRecipeRead>(`/autopkg/recipes/${recipe.id}`, payload),
    onSuccess: (updated) => {
      toast.success(`Recipe ${updated.name} updated`)
      queryClient.setQueryData(['autopkg-recipe', recipe.id], updated)
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
      queryClient.invalidateQueries({ queryKey: ['pkginfo-item-meta'] })
      queryClient.invalidateQueries({ queryKey: ['pkginfo-display-labels'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/autopkg/recipes/${recipe.id}`),
    onSuccess: () => {
      toast.success(`Recipe ${recipe.name} deleted`)
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
      queryClient.removeQueries({ queryKey: ['autopkg-recipe', recipe.id] })
      onDeleted?.()
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
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipe', recipe.id] })
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const handleSave = useCallback(() => {
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
  }, [
    nonPkginfoEntries,
    pkginfo,
    identifier,
    name,
    parentRecipe,
    sourceRepoFullName,
    isEnabled,
    isOverride,
    autoPromote,
    hasStoredOverridePlist,
    recipe.override_data,
    saveMutation,
  ])

  const handleDelete = useCallback(() => {
    if (
      window.confirm(`Delete override "${recipe.name}"? This cannot be undone.`)
    ) {
      deleteMutation.mutate()
    }
  }, [deleteMutation, recipe.name])

  useEffect(() => {
    if (readOnly) {
      onToolbarApiChange?.(null)
      return
    }
    onToolbarApiChange?.({
      save: handleSave,
      deleteRecipe: handleDelete,
      isSaving: saveMutation.isPending,
      isDeleting: deleteMutation.isPending,
      canSave:
        Boolean(name.trim() && identifier.trim()) && !saveMutation.isPending,
    })
  }, [
    readOnly,
    onToolbarApiChange,
    handleSave,
    handleDelete,
    saveMutation.isPending,
    deleteMutation.isPending,
    name,
    identifier,
  ])

  const catalogNames = (catalogs ?? []).map((c) => c.name)
  const nonPkginfoCount = nonPkginfoEntries.length
  const pkginfoCount = Object.keys(pkginfo).length
  const iconUploadBasename = recipeIconUploadBasename(pkginfo, recipe)

  return (
    <>
      <Tabs defaultValue="general" className="gap-4">
        <TabsList
          className={cn(
            'h-auto w-full flex-wrap gap-2 rounded-xl p-2 sm:p-2.5',
            'border border-gruvbox-orange/20 bg-gradient-to-br from-muted/90 via-muted/55 to-muted/25',
            'shadow-sm transition-[border-color,box-shadow] duration-300 ease-out',
            'hover:border-gruvbox-orange/40 hover:shadow-md dark:border-gruvbox-orange/30 dark:hover:border-gruvbox-orange/50',
          )}
        >
          <TabsTrigger
            value="general"
            className={recipeDetailTabTrigger(
              'data-[state=active]:text-gruvbox-blue data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-blue/30',
            )}
          >
            <FileText className={recipeTabIconClass} aria-hidden />
            General
          </TabsTrigger>
          <TabsTrigger
            value="input"
            className={recipeDetailTabTrigger(
              'data-[state=active]:text-gruvbox-purple data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-purple/30',
            )}
          >
            <Braces className={recipeTabIconClass} aria-hidden />
            Input
            {nonPkginfoCount > 0 && (
              <Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
                {nonPkginfoCount}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger
            value="pkginfo"
            className={recipeDetailTabTrigger(
              'data-[state=active]:text-gruvbox-green data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-green/30',
            )}
          >
            <Package className={recipeTabIconClass} aria-hidden />
            pkginfo
            {pkginfoCount > 0 && (
              <Badge variant="secondary" className="ml-1.5 text-xs px-1.5">
                {pkginfoCount}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger
            value="trust"
            className={recipeDetailTabTrigger(
              'data-[state=active]:text-gruvbox-yellow data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-yellow/35',
            )}
          >
            <ShieldCheck className={recipeTabIconClass} aria-hidden />
            Trust Info
          </TabsTrigger>
        </TabsList>

        <TabsContent value="general" className={recipeDetailTabContentClass}>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="recipe-name">Name</Label>
              <Input
                id="recipe-name"
                value={name}
                readOnly={readOnly}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="recipe-identifier">Identifier</Label>
              <Input
                id="recipe-identifier"
                value={identifier}
                readOnly={readOnly}
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
              readOnly={readOnly}
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
              readOnly={readOnly}
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
                disabled={readOnly}
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
                disabled={readOnly}
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
                disabled={readOnly}
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
                    className={readOnly ? undefined : 'cursor-pointer'}
                    onClick={
                      readOnly
                        ? undefined
                        : () => {
                            const next = selected
                              ? values.filter((c) => c !== cat)
                              : [...values, cat]
                            updatePkgField(
                              'catalogs',
                              next.length > 0 ? next : undefined,
                            )
                          }
                    }
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
              readOnly={readOnly}
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
                name={iconUploadBasename}
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
                suggestedBasename={iconUploadBasename}
                currentIconName={
                  typeof pkginfo.icon_name === 'string' ? pkginfo.icon_name : ''
                }
                disabled={readOnly}
                onIconNameApplied={(v) => {
                  updatePkgField('icon_name', v)
                  setIconRevision((r) => r + 1)
                }}
              />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="input" className={recipeDetailTabContentClass}>
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
              readOnly={readOnly}
            />
          </div>
        </TabsContent>

        <TabsContent value="pkginfo" className={recipeDetailTabContentClass}>
          <PkginfoEditor
            pkginfo={pkginfo}
            onUpdate={updatePkgField}
            catalogNames={catalogNames}
            packageBasenameForIcons={iconUploadBasename}
            onIconFileUploaded={() => setIconRevision((r) => r + 1)}
            readOnly={readOnly}
          />
        </TabsContent>

        <TabsContent value="trust" className={recipeDetailTabContentClass}>
          <TrustInfoViewer
            trustInfo={recipe.trust_info as Record<string, unknown> | null}
          />
          {recipe.is_override && recipe.parent_recipe && !readOnly && (
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
    </>
  )
}
