'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileText, Pencil, Plus, Save, Trash2, X } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { useAuth } from '@/components/auth-provider'
import { ManifestConditionalBlocksEditor } from '@/components/manifest-conditional-blocks-editor'
import { ManifestItemSectionsTabs } from '@/components/manifest-item-sections-tabs'
import { SoftwareIcon } from '@/components/software-icon'
import { Badge } from '@/components/ui/badge'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Button } from '@/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
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
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { Textarea } from '@/components/ui/textarea'
import { usePkginfoDisplayLabels } from '@/hooks/use-pkginfo-display-labels'
import { api, type CatalogRead, type ManifestRead } from '@/lib/api'
import {
  type ConditionalItemBlock,
  collectManifestItemRefsFromConditional,
  parseConditionalItemsFromApi,
  serializeConditionalItemsForApi,
  validateConditionalBlocks,
} from '@/lib/manifest-conditional-items'
import type { ManifestItemSectionKey } from '@/lib/manifest-item-section-defs'
import { manifestTitle, manifestTitleForName } from '@/lib/manifest-title'
import { munkiAccents } from '@/lib/munki-accents'
import { PAGE_KEYS } from '@/lib/page-keys'
import { cn } from '@/lib/utils'

type SectionsState = Record<ManifestItemSectionKey, string[]>

function manifestToSections(m: ManifestRead): SectionsState {
  return {
    managed_installs: [...m.managed_installs],
    managed_uninstalls: [...m.managed_uninstalls],
    managed_updates: [...m.managed_updates],
    optional_installs: [...m.optional_installs],
    featured_items: [...m.featured_items],
    default_installs: [...m.default_installs],
  }
}

const commandPopoverContentClass =
  'flex max-h-[min(70vh,440px)] w-[min(100vw-2rem,380px)] flex-col overflow-hidden p-0'

const commandRootClass = 'flex min-h-0 flex-1 flex-col overflow-hidden'

export default function ManifestDetailPage() {
  const params = useParams()
  const router = useRouter()
  const queryClient = useQueryClient()
  const id = params.id as string

  const { canWrite } = useAuth()
  const canMutateManifests = canWrite(PAGE_KEYS.munkiManifests)

  const [sections, setSections] = useState<SectionsState | null>(null)
  const [conditionalItems, setConditionalItems] = useState<
    ConditionalItemBlock[]
  >([])
  const [catalogNames, setCatalogNames] = useState<string[]>([])
  const [includedManifestNames, setIncludedManifestNames] = useState<string[]>(
    [],
  )
  const [dirty, setDirty] = useState(false)
  const hydratedManifestId = useRef<string | null>(null)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [metaDialogOpen, setMetaDialogOpen] = useState(false)
  const [editName, setEditName] = useState('')
  const [editDisplayName, setEditDisplayName] = useState('')
  const [editNotes, setEditNotes] = useState('')

  const { data: manifest, isLoading } = useQuery({
    queryKey: ['manifest', id],
    queryFn: () => api.get<ManifestRead>(`/manifests/${id}`),
  })

  useEffect(() => {
    if (!manifest) return
    if (hydratedManifestId.current === manifest.id) return
    hydratedManifestId.current = manifest.id
    setSections(manifestToSections(manifest))
    setCatalogNames([...manifest.catalog_names])
    setIncludedManifestNames([...manifest.included_manifest_names])
    setConditionalItems(
      parseConditionalItemsFromApi(manifest.conditional_items),
    )
  }, [manifest])

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.put(`/manifests/${id}`, payload),
    onSuccess: () => {
      toast.success('Manifest saved')
      queryClient.invalidateQueries({ queryKey: ['manifest', id] })
      queryClient.invalidateQueries({ queryKey: ['manifests'] })
      setDirty(false)
    },
    onError: (err: Error) => toast.error(`Save failed: ${err.message}`),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/manifests/${id}`),
    onSuccess: () => {
      toast.success('Manifest deleted')
      queryClient.invalidateQueries({ queryKey: ['manifests'] })
      queryClient.removeQueries({ queryKey: ['manifest', id] })
      setDeleteOpen(false)
      router.push('/manifests')
    },
    onError: (err: Error) => toast.error(`Delete failed: ${err.message}`),
  })

  const metaMutation = useMutation({
    mutationFn: (payload: {
      name: string
      display_name: string | null
      notes: string | null
    }) => api.put(`/manifests/${id}`, payload),
    onSuccess: () => {
      toast.success('Manifest details updated')
      queryClient.invalidateQueries({ queryKey: ['manifest', id] })
      queryClient.invalidateQueries({ queryKey: ['manifests'] })
      setMetaDialogOpen(false)
    },
    onError: (err: Error) => toast.error(`Update failed: ${err.message}`),
  })

  const openMetaDialog = () => {
    if (!manifest) return
    setEditName(manifest.name)
    setEditDisplayName(manifest.display_name ?? '')
    setEditNotes(manifest.notes ?? '')
    setMetaDialogOpen(true)
  }

  const handleMetaSave = () => {
    const n = editName.trim()
    if (!n) return
    metaMutation.mutate({
      name: n,
      display_name: editDisplayName.trim() || null,
      notes: editNotes.trim() || null,
    })
  }

  const handleBeforeUnload = useCallback(
    (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault()
    },
    [dirty],
  )

  useEffect(() => {
    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => window.removeEventListener('beforeunload', handleBeforeUnload)
  }, [handleBeforeUnload])

  const handleSave = () => {
    if (!sections) return
    const err = validateConditionalBlocks(conditionalItems)
    if (err) {
      toast.error(err)
      return
    }
    saveMutation.mutate({
      ...sections,
      catalog_names: catalogNames,
      included_manifest_names: includedManifestNames,
      conditional_items: serializeConditionalItemsForApi(conditionalItems),
    })
  }

  const addItem = (section: ManifestItemSectionKey, name: string) => {
    setSections((prev) => {
      if (!prev) return prev
      if (prev[section].includes(name)) return prev
      return { ...prev, [section]: [...prev[section], name] }
    })
    setDirty(true)
  }

  const removeItem = (section: ManifestItemSectionKey, name: string) => {
    setSections((prev) => {
      if (!prev) return prev
      return { ...prev, [section]: prev[section].filter((n) => n !== name) }
    })
    setDirty(true)
  }

  const reorderItems = (
    section: ManifestItemSectionKey,
    oldIndex: number,
    newIndex: number,
  ) => {
    setSections((prev) => {
      if (!prev) return prev
      const items = [...prev[section]]
      const [moved] = items.splice(oldIndex, 1)
      items.splice(newIndex, 0, moved)
      return { ...prev, [section]: items }
    })
    setDirty(true)
  }

  const addCatalog = (name: string) => {
    if (catalogNames.includes(name)) return
    setCatalogNames((prev) => [...prev, name])
    setDirty(true)
  }

  const removeCatalog = (name: string) => {
    setCatalogNames((prev) => prev.filter((n) => n !== name))
    setDirty(true)
  }

  const addIncludedManifest = (name: string) => {
    if (includedManifestNames.includes(name)) return
    setIncludedManifestNames((prev) => [...prev, name])
    setDirty(true)
  }

  const removeIncludedManifest = (name: string) => {
    setIncludedManifestNames((prev) => prev.filter((n) => n !== name))
    setDirty(true)
  }

  const replaceSectionItem = (
    section: ManifestItemSectionKey,
    oldRaw: string,
    newRaw: string,
  ) => {
    if (newRaw === oldRaw) return
    setSections((prev) => {
      if (!prev) return prev
      const list = prev[section]
      const idx = list.indexOf(oldRaw)
      if (idx === -1) return prev
      if (list.some((x, i) => x === newRaw && i !== idx)) {
        toast.error('That item is already in this list')
        return prev
      }
      const next = [...list]
      next[idx] = newRaw
      return { ...prev, [section]: next }
    })
    setDirty(true)
  }

  const uniqueInstallNames = useMemo(() => {
    if (!sections) return []
    const fromSections = Object.values(sections).flat()
    const fromConditional =
      collectManifestItemRefsFromConditional(conditionalItems)
    return [...new Set([...fromSections, ...fromConditional])]
  }, [sections, conditionalItems])

  const { data: pkgDisplayLabels } = usePkginfoDisplayLabels(uniqueInstallNames)

  if (isLoading || !manifest) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Loading...
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-8">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/manifests">Manifests</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>{manifestTitle(manifest)}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-col gap-1">
            <h1
              className={cn(
                'inline-flex min-w-0 max-w-full items-center gap-1.5 text-3xl font-bold text-pretty',
                munkiAccents.manifests.pageTitle,
              )}
            >
              <span className="min-w-0 max-w-full flex-1 truncate flex items-center gap-1">
                {manifestTitle(manifest)}
                {canMutateManifests ? (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="size-8 shrink-0 text-muted-foreground/20 hover:bg-muted/50 hover:text-foreground"
                    aria-label="Edit manifest name, display name, and notes"
                    onClick={openMetaDialog}
                    disabled={
                      saveMutation.isPending ||
                      deleteMutation.isPending ||
                      metaMutation.isPending
                    }
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                ) : null}
              </span>
            </h1>
            {manifest.display_name?.trim() ? (
              <p className="font-mono text-sm text-muted-foreground">
                {manifest.name}
              </p>
            ) : null}
          </div>
          {manifest.notes?.trim() ? (
            <p className="mt-2 max-w-3xl whitespace-pre-wrap text-sm text-muted-foreground">
              {manifest.notes}
            </p>
          ) : null}
        </div>
        {canMutateManifests ? (
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <Button
              onClick={handleSave}
              disabled={!dirty || saveMutation.isPending}
            >
              <Save data-icon="inline-start" />
              {saveMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="text-muted-foreground hover:text-destructive"
              aria-label="Delete manifest"
              onClick={() => setDeleteOpen(true)}
              disabled={saveMutation.isPending || deleteMutation.isPending}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ) : null}
      </div>

      <Dialog open={metaDialogOpen} onOpenChange={setMetaDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Manifest details</DialogTitle>
            <DialogDescription>
              Plist name (used by Munki clients), optional display label, and
              internal notes.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-1">
            <div className="grid gap-2">
              <Label htmlFor="manifest-edit-name">Name</Label>
              <Input
                id="manifest-edit-name"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                autoComplete="off"
                placeholder="e.g. site_default"
              />
              <p className="text-xs text-muted-foreground">
                This is the manifest name in the repo and in{' '}
                <code className="rounded bg-muted px-1 py-0.5 text-[0.8rem]">
                  included_manifests
                </code>
                . Renaming updates plist output; ensure your repo sync matches.
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="manifest-edit-display-name">
                Display name (optional)
              </Label>
              <Input
                id="manifest-edit-display-name"
                value={editDisplayName}
                onChange={(e) => setEditDisplayName(e.target.value)}
                autoComplete="off"
                placeholder="Shown in Automunki only"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="manifest-edit-notes">Notes (optional)</Label>
              <Textarea
                id="manifest-edit-notes"
                value={editNotes}
                onChange={(e) => setEditNotes(e.target.value)}
                rows={4}
                placeholder="Internal notes…"
                className="resize-y"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setMetaDialogOpen(false)}
              disabled={metaMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="button"
              onClick={handleMetaSave}
              disabled={metaMutation.isPending || !editName.trim()}
            >
              {metaMutation.isPending ? 'Saving…' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete manifest</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &ldquo;
              {manifestTitle(manifest)}&rdquo;? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteOpen(false)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteMutation.mutate()}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ManifestCatalogRow
        catalogNames={catalogNames}
        onAdd={addCatalog}
        onRemove={removeCatalog}
        disabled={saveMutation.isPending || !canMutateManifests}
      />

      <IncludedManifestsPanel
        currentManifestName={manifest.name}
        currentTitle={manifestTitle(manifest)}
        includedNames={includedManifestNames}
        onAdd={addIncludedManifest}
        onRemove={removeIncludedManifest}
        editDisabled={!canMutateManifests}
      />

      <ManifestItemSectionsTabs
        sections={sections}
        getItemLabel={(name) => pkgDisplayLabels?.[name] ?? name}
        onAdd={addItem}
        onRemove={removeItem}
        onReorder={reorderItems}
        onReplaceItem={replaceSectionItem}
        disabled={saveMutation.isPending || !canMutateManifests}
      />

      <ManifestConditionalBlocksEditor
        blocks={conditionalItems}
        onChange={(next) => {
          setConditionalItems(next)
          setDirty(true)
        }}
        getPkgItemLabel={(name) => pkgDisplayLabels?.[name] ?? name}
        currentManifestName={manifest.name}
        disabled={saveMutation.isPending || !canMutateManifests}
      />
    </div>
  )
}

function ManifestCatalogRow({
  catalogNames,
  onAdd,
  onRemove,
  disabled,
}: {
  catalogNames: string[]
  onAdd: (name: string) => void
  onRemove: (name: string) => void
  disabled?: boolean
}) {
  const [popoverOpen, setPopoverOpen] = useState(false)

  const { data: allCatalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
    enabled: popoverOpen,
  })

  const available = (allCatalogs ?? []).filter(
    (c) => !catalogNames.includes(c.name),
  )

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-dashed border-muted-foreground/25 bg-muted/20 px-3 py-2">
      <span
        className={cn('mr-1 text-sm font-medium', munkiAccents.catalogs.icon)}
      >
        Catalogs
      </span>
      {catalogNames.length === 0 ? (
        <span className="text-sm text-muted-foreground">
          None — add at least one catalog.
        </span>
      ) : (
        catalogNames.map((c) => (
          <Badge
            key={c}
            variant="secondary"
            className="gap-1 border border-gruvbox-green/20 pr-1 text-sm"
          >
            {c}
            <button
              type="button"
              aria-label={`Remove catalog ${c}`}
              className="ml-0.5 rounded-full p-0.5 hover:bg-muted"
              onClick={() => onRemove(c)}
              disabled={disabled}
            >
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))
      )}
      <Popover open={popoverOpen} onOpenChange={setPopoverOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            aria-label="Add catalog"
            disabled={disabled}
          >
            <Plus className="h-3.5 w-3.5" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className={commandPopoverContentClass} align="start">
          <Command className={commandRootClass}>
            <CommandInput placeholder="Search catalogs..." />
            <CommandList className="max-h-[min(50vh,320px)]">
              <CommandEmpty>No catalogs available.</CommandEmpty>
              <CommandGroup>
                {available.map((cat) => (
                  <CommandItem
                    key={cat.id}
                    value={cat.name}
                    onSelect={() => {
                      onAdd(cat.name)
                      setPopoverOpen(false)
                    }}
                  >
                    <div className="flex min-w-0 flex-col">
                      <span className="truncate">{cat.name}</span>
                      {cat.display_name && (
                        <span className="truncate text-xs text-muted-foreground">
                          {cat.display_name}
                        </span>
                      )}
                    </div>
                    <Badge
                      variant="secondary"
                      className="ml-auto shrink-0 text-xs"
                    >
                      {cat.item_count}
                    </Badge>
                  </CommandItem>
                ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  )
}

type InclusionTreeNode = {
  name: string
  id: string | undefined
  /** True when this name already appears on the path (circular include). */
  circular: boolean
  children: InclusionTreeNode[]
}

const MAX_INCLUSION_TREE_DEPTH = 12

function buildInclusionSubtree(
  name: string,
  manifestByName: Map<string, ManifestRead>,
  path: Set<string>,
  depth: number,
): InclusionTreeNode {
  const m = manifestByName.get(name)
  const id = m?.id
  if (path.has(name)) {
    return { name, id, circular: true, children: [] }
  }
  if (depth >= MAX_INCLUSION_TREE_DEPTH || !m) {
    return { name, id, circular: false, children: [] }
  }
  const nextPath = new Set(path)
  nextPath.add(name)
  const children: InclusionTreeNode[] = []
  for (const childName of m.included_manifest_names) {
    children.push(
      buildInclusionSubtree(childName, manifestByName, nextPath, depth + 1),
    )
  }
  return { name, id, circular: false, children }
}

function IncludedManifestsPanel({
  currentManifestName,
  currentTitle,
  includedNames,
  onAdd,
  onRemove,
  editDisabled = false,
}: {
  currentManifestName: string
  currentTitle: string
  includedNames: string[]
  onAdd: (name: string) => void
  onRemove: (name: string) => void
  editDisabled?: boolean
}) {
  const { data: allManifests } = useQuery({
    queryKey: ['manifests'],
    queryFn: () => api.get<ManifestRead[]>('/manifests'),
  })

  const manifestByName = useMemo(() => {
    const m = new Map<string, ManifestRead>()
    for (const man of allManifests ?? []) {
      m.set(man.name, man)
    }
    return m
  }, [allManifests])

  const inclusionRoots = useMemo(() => {
    const basePath = new Set([currentManifestName])
    return includedNames.map((name) =>
      buildInclusionSubtree(name, manifestByName, basePath, 0),
    )
  }, [currentManifestName, includedNames, manifestByName])

  return (
    <div className="rounded-xl border bg-muted/10 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-muted-foreground uppercase">
            Included manifests
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Direct includes are editable. Indented rows show nested includes
            from those manifests (merged by Munki; order still follows your
            list).
          </p>
        </div>
        <AddManifestButton
          onAdd={onAdd}
          existingItems={includedNames}
          currentManifestName={currentManifestName}
          disabled={editDisabled}
        />
      </div>

      <div className="mt-4 flex flex-col gap-3">
        <div
          className={cn(
            'flex items-center gap-3 rounded-lg border bg-card px-4 py-3 shadow-sm',
            'border-l-4 border-l-gruvbox-purple/70',
          )}
        >
          <FileText
            className={cn('size-5 shrink-0', munkiAccents.manifests.icon)}
            aria-hidden
          />
          <div className="min-w-0 flex-1">
            <p className="truncate font-medium">{currentTitle}</p>
            <p className="text-xs text-muted-foreground">
              {currentTitle !== currentManifestName
                ? currentManifestName
                : 'This manifest'}
            </p>
          </div>
          <Badge variant="outline" className="shrink-0 text-xs">
            root
          </Badge>
        </div>

        {includedNames.length > 0 && (
          <div className="ml-2 flex flex-col gap-2 border-l-2 border-muted-foreground/25 pl-4">
            {inclusionRoots.map((root, idx) => (
              <InclusionTreeBranch
                key={`${idx}-${root.name}`}
                node={root}
                depth={0}
                orderLabel={idx + 1}
                manifestByName={manifestByName}
                onRemoveDirect={onRemove}
                editDisabled={editDisabled}
              />
            ))}
          </div>
        )}

        {includedNames.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No included manifests. Use + to nest another manifest under{' '}
            <span className="font-medium text-foreground">{currentTitle}</span>.
          </p>
        )}
      </div>
    </div>
  )
}

function InclusionTreeBranch({
  node,
  depth,
  orderLabel,
  manifestByName,
  onRemoveDirect,
  editDisabled = false,
}: {
  node: InclusionTreeNode
  depth: number
  /** Set for top-level direct includes only (1-based). */
  orderLabel?: number
  manifestByName: Map<string, ManifestRead>
  onRemoveDirect: (name: string) => void
  editDisabled?: boolean
}) {
  const isDirect = depth === 0
  const childId = node.id
  const displayLabel = manifestTitleForName(manifestByName, node.name)

  return (
    <div className="flex flex-col gap-2">
      <div
        className={cn(
          'flex items-center gap-2 rounded-md border px-3 py-2 shadow-sm',
          isDirect
            ? 'bg-card/90'
            : 'border-dashed border-muted-foreground/20 bg-muted/30',
        )}
      >
        <FileText
          className={cn(
            'size-4 shrink-0',
            isDirect
              ? 'text-muted-foreground'
              : 'size-3.5 text-muted-foreground/80',
          )}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0">
            {childId ? (
              <Link
                href={`/manifests/${childId}`}
                className={cn(
                  'text-primary underline-offset-4 hover:underline',
                  isDirect ? 'font-medium' : 'text-sm font-medium',
                )}
              >
                {displayLabel}
              </Link>
            ) : (
              <span className={cn('font-medium', !isDirect && 'text-sm')}>
                {displayLabel}
              </span>
            )}
            {node.circular && (
              <Badge
                variant="outline"
                className="text-[10px] text-amber-700 dark:text-amber-400"
              >
                circular
              </Badge>
            )}
          </div>
          {displayLabel !== node.name && (
            <p className="truncate text-xs text-muted-foreground">
              {node.name}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            {isDirect ? (
              <>Included #{orderLabel}</>
            ) : (
              <>
                Nested include
                {node.children.length > 0 ? ' · also includes below' : ''}
              </>
            )}
          </p>
        </div>
        {isDirect && !editDisabled && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
            aria-label={`Remove included manifest ${displayLabel}`}
            onClick={() => onRemoveDirect(node.name)}
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      {node.children.length > 0 && (
        <div className="flex flex-col gap-2 border-l border-muted-foreground/20 pl-3">
          {node.children.map((child) => (
            <InclusionTreeBranch
              key={`${node.name}>${child.name}`}
              node={child}
              depth={depth + 1}
              manifestByName={manifestByName}
              onRemoveDirect={onRemoveDirect}
              editDisabled={editDisabled}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function AddManifestButton({
  onAdd,
  existingItems,
  currentManifestName,
  disabled = false,
}: {
  onAdd: (name: string) => void
  existingItems: string[]
  currentManifestName: string
  disabled?: boolean
}) {
  const [open, setOpen] = useState(false)

  const { data: manifests } = useQuery({
    queryKey: ['manifests'],
    queryFn: () => api.get<ManifestRead[]>('/manifests'),
    enabled: open,
  })

  const available = (manifests ?? []).filter(
    (m) => m.name !== currentManifestName && !existingItems.includes(m.name),
  )

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          aria-label="Add included manifest"
          disabled={disabled}
        >
          <Plus className="mr-1 h-4 w-4" />
          Include manifest
        </Button>
      </PopoverTrigger>
      <PopoverContent className={commandPopoverContentClass} align="end">
        <Command className={commandRootClass}>
          <CommandInput placeholder="Search manifests..." />
          <CommandList className="max-h-[min(50vh,320px)]">
            <CommandEmpty>No manifests available.</CommandEmpty>
            <CommandGroup>
              {available.map((m) => (
                <CommandItem
                  key={m.id}
                  value={[m.name, m.display_name].filter(Boolean).join(' ')}
                  onSelect={() => {
                    onAdd(m.name)
                    setOpen(false)
                  }}
                >
                  <FileText
                    className={cn(
                      'size-4 shrink-0',
                      munkiAccents.manifests.icon,
                    )}
                    aria-hidden
                  />
                  <div className="flex min-w-0 flex-col">
                    <span className="truncate">{manifestTitle(m)}</span>
                    {manifestTitle(m) !== m.name && (
                      <span className="truncate text-xs text-muted-foreground">
                        {m.name}
                      </span>
                    )}
                  </div>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
