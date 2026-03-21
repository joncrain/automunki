'use client'

import {
  closestCenter,
  DndContext,
  type DragEndEvent,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileText, GripVertical, Plus, Save, X } from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
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
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  api,
  type CatalogRead,
  type ManifestRead,
  type PaginatedResponse,
  type PkgInfoSummary,
} from '@/lib/api'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

const ITEM_SECTIONS = [
  {
    key: 'managed_installs',
    label: 'Managed Installs',
    variant: 'outline' as const,
    accent:
      'border-l-gruvbox-blue/70 bg-gruvbox-blue/[0.07] dark:bg-gruvbox-blue/[0.12]',
    rowAccent:
      'border-gruvbox-blue/30 bg-gruvbox-blue/[0.04] dark:bg-gruvbox-blue/[0.08]',
  },
  {
    key: 'managed_uninstalls',
    label: 'Managed Uninstalls',
    variant: 'destructive' as const,
    accent:
      'border-l-destructive/80 bg-destructive/[0.08] dark:bg-destructive/[0.12]',
    rowAccent:
      'border-destructive/35 bg-destructive/[0.06] dark:bg-destructive/[0.1]',
  },
  {
    key: 'managed_updates',
    label: 'Managed Updates',
    variant: 'secondary' as const,
    accent:
      'border-l-gruvbox-aqua/70 bg-gruvbox-aqua/[0.07] dark:bg-gruvbox-aqua/[0.1]',
    rowAccent:
      'border-gruvbox-aqua/30 bg-gruvbox-aqua/[0.04] dark:bg-gruvbox-aqua/[0.08]',
  },
  {
    key: 'optional_installs',
    label: 'Optional Installs',
    variant: 'outline' as const,
    accent: 'border-l-muted-foreground/50 bg-muted/40 dark:bg-muted/25',
    rowAccent: 'border-muted-foreground/25 bg-muted/30 dark:bg-muted/20',
  },
  {
    key: 'featured_items',
    label: 'Featured Items',
    variant: 'default' as const,
    accent:
      'border-l-gruvbox-yellow/60 bg-gruvbox-yellow/[0.08] dark:bg-gruvbox-yellow/[0.12]',
    rowAccent:
      'border-gruvbox-yellow/30 bg-gruvbox-yellow/[0.05] dark:bg-gruvbox-yellow/[0.08]',
  },
  {
    key: 'default_installs',
    label: 'Default Installs',
    variant: 'secondary' as const,
    accent:
      'border-l-gruvbox-purple/60 bg-gruvbox-purple/[0.07] dark:bg-gruvbox-purple/[0.1]',
    rowAccent:
      'border-gruvbox-purple/30 bg-gruvbox-purple/[0.04] dark:bg-gruvbox-purple/[0.08]',
  },
] as const

type SectionKey = (typeof ITEM_SECTIONS)[number]['key']
type SectionsState = Record<SectionKey, string[]>

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
  const queryClient = useQueryClient()
  const id = params.id as string

  const [sections, setSections] = useState<SectionsState | null>(null)
  const [catalogNames, setCatalogNames] = useState<string[]>([])
  const [includedManifestNames, setIncludedManifestNames] = useState<string[]>(
    [],
  )
  const [dirty, setDirty] = useState(false)

  const { data: manifest, isLoading } = useQuery({
    queryKey: ['manifest', id],
    queryFn: () => api.get<ManifestRead>(`/manifests/${id}`),
  })

  useEffect(() => {
    if (manifest && !sections) {
      setSections(manifestToSections(manifest))
      setCatalogNames([...manifest.catalog_names])
      setIncludedManifestNames([...manifest.included_manifest_names])
    }
  }, [manifest, sections])

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
    saveMutation.mutate({
      ...sections,
      catalog_names: catalogNames,
      included_manifest_names: includedManifestNames,
    })
  }

  const addItem = (section: SectionKey, name: string) => {
    setSections((prev) => {
      if (!prev) return prev
      if (prev[section].includes(name)) return prev
      return { ...prev, [section]: [...prev[section], name] }
    })
    setDirty(true)
  }

  const removeItem = (section: SectionKey, name: string) => {
    setSections((prev) => {
      if (!prev) return prev
      return { ...prev, [section]: prev[section].filter((n) => n !== name) }
    })
    setDirty(true)
  }

  const reorderItems = (
    section: SectionKey,
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
            <BreadcrumbPage>{manifest.name}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <h1
          className={cn(
            'text-3xl font-bold text-pretty',
            munkiAccents.manifests.pageTitle,
          )}
        >
          {manifest.name}
        </h1>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Button
            onClick={handleSave}
            disabled={!dirty || saveMutation.isPending}
          >
            <Save data-icon="inline-start" />
            {saveMutation.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </div>

      <ManifestCatalogRow
        catalogNames={catalogNames}
        onAdd={addCatalog}
        onRemove={removeCatalog}
        disabled={saveMutation.isPending}
      />

      <IncludedManifestsPanel
        currentName={manifest.name}
        includedNames={includedManifestNames}
        onAdd={addIncludedManifest}
        onRemove={removeIncludedManifest}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {ITEM_SECTIONS.map((sec) => (
          <SortableSection
            key={sec.key}
            label={sec.label}
            badgeVariant={sec.variant}
            accent={sec.accent}
            rowAccent={sec.rowAccent}
            items={sections?.[sec.key] ?? []}
            onAdd={(name) => addItem(sec.key, name)}
            onRemove={(name) => removeItem(sec.key, name)}
            onReorder={(oldIdx, newIdx) =>
              reorderItems(sec.key, oldIdx, newIdx)
            }
          />
        ))}
      </div>
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

function IncludedManifestsPanel({
  currentName,
  includedNames,
  onAdd,
  onRemove,
}: {
  currentName: string
  includedNames: string[]
  onAdd: (name: string) => void
  onRemove: (name: string) => void
}) {
  const { data: allManifests } = useQuery({
    queryKey: ['manifests'],
    queryFn: () => api.get<ManifestRead[]>('/manifests'),
  })

  const idByName = useMemo(() => {
    const m = new Map<string, string>()
    for (const man of allManifests ?? []) {
      m.set(man.name, man.id)
    }
    return m
  }, [allManifests])

  return (
    <div className="rounded-xl border bg-muted/10 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-muted-foreground uppercase">
            Included manifests
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Nested manifests are merged into this one (order matters in Munki).
          </p>
        </div>
        <AddManifestButton
          onAdd={onAdd}
          existingItems={includedNames}
          currentManifestName={currentName}
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
            <p className="truncate font-medium">{currentName}</p>
            <p className="text-xs text-muted-foreground">This manifest</p>
          </div>
          <Badge variant="outline" className="shrink-0 text-xs">
            root
          </Badge>
        </div>

        {includedNames.length > 0 && (
          <div className="ml-2 flex flex-col gap-2 border-l-2 border-muted-foreground/25 pl-4">
            {includedNames.map((name, idx) => {
              const childId = idByName.get(name)
              return (
                <div
                  key={name}
                  className="flex items-center gap-2 rounded-md border bg-card/90 px-3 py-2 shadow-sm"
                >
                  <FileText
                    className="size-4 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1">
                    {childId ? (
                      <Link
                        href={`/manifests/${childId}`}
                        className="font-medium text-primary underline-offset-4 hover:underline"
                      >
                        {name}
                      </Link>
                    ) : (
                      <span className="font-medium">{name}</span>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Included #{idx + 1}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                    aria-label={`Remove included manifest ${name}`}
                    onClick={() => onRemove(name)}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              )
            })}
          </div>
        )}

        {includedNames.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No included manifests. Use + to nest another manifest under{' '}
            <span className="font-medium text-foreground">{currentName}</span>.
          </p>
        )}
      </div>
    </div>
  )
}

function SortableSection({
  label,
  badgeVariant,
  accent,
  rowAccent,
  items,
  onAdd,
  onRemove,
  onReorder,
}: {
  label: string
  badgeVariant: 'outline' | 'destructive' | 'secondary' | 'default'
  accent: string
  rowAccent: string
  items: string[]
  onAdd: (name: string) => void
  onRemove: (name: string) => void
  onReorder: (oldIndex: number, newIndex: number) => void
}) {
  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    }),
  )

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event
    if (!over || active.id === over.id) return
    const oldIndex = items.indexOf(active.id as string)
    const newIndex = items.indexOf(over.id as string)
    if (oldIndex !== -1 && newIndex !== -1) {
      onReorder(oldIndex, newIndex)
    }
  }

  return (
    <div
      className={cn(
        'flex flex-col gap-3 rounded-xl border bg-card py-4 shadow-sm',
        'border-l-4',
        accent,
      )}
    >
      <div className="flex items-center justify-between gap-2 px-4">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate font-semibold">{label}</span>
          <Badge variant="secondary" className="shrink-0 text-xs">
            {items.length}
          </Badge>
        </div>
        <AddSoftwareButton onAdd={onAdd} existingItems={items} />
      </div>
      <div className="px-4">
        {items.length === 0 ? (
          <p className="rounded-md border border-dashed py-6 text-center text-sm text-muted-foreground">
            No items. Use + to add software.
          </p>
        ) : (
          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragEnd={handleDragEnd}
          >
            <SortableContext
              items={items}
              strategy={verticalListSortingStrategy}
            >
              <div className="flex flex-col gap-1.5">
                {items.map((item) => (
                  <SortableItem
                    key={item}
                    id={item}
                    badgeVariant={badgeVariant}
                    rowAccent={rowAccent}
                    onRemove={() => onRemove(item)}
                  />
                ))}
              </div>
            </SortableContext>
          </DndContext>
        )}
      </div>
    </div>
  )
}

function SortableItem({
  id,
  badgeVariant,
  rowAccent,
  onRemove,
}: {
  id: string
  badgeVariant: 'outline' | 'destructive' | 'secondary' | 'default'
  rowAccent: string
  onRemove: () => void
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id,
  })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  }

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={cn(
        'flex items-center gap-2 rounded-md border px-2 py-1.5',
        rowAccent,
      )}
    >
      <button
        type="button"
        className="cursor-grab touch-none text-muted-foreground hover:text-foreground"
        aria-label={`Reorder ${id}`}
        {...attributes}
        {...listeners}
      >
        <GripVertical className="h-4 w-4" />
      </button>
      <SoftwareIcon name={id} size="sm" className="shrink-0" />
      <Badge
        variant={badgeVariant}
        className="min-w-0 flex-1 justify-start truncate font-normal"
      >
        {id}
      </Badge>
      <button
        type="button"
        aria-label={`Remove ${id}`}
        className="shrink-0 text-muted-foreground hover:text-destructive"
        onClick={onRemove}
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

function AddSoftwareButton({
  onAdd,
  existingItems,
}: {
  onAdd: (name: string) => void
  existingItems: string[]
}) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')

  const { data } = useQuery({
    queryKey: ['pkginfo-search', search],
    queryFn: () =>
      api.get<PaginatedResponse<PkgInfoSummary>>(
        `/pkginfo?page_size=40${search ? `&search=${encodeURIComponent(search)}` : ''}`,
      ),
    enabled: open,
  })

  const itemsByName = useMemo(() => {
    const m = new Map<string, PkgInfoSummary>()
    for (const item of data?.items ?? []) {
      if (!m.has(item.name)) m.set(item.name, item)
    }
    return m
  }, [data?.items])

  const uniqueNames = [...itemsByName.keys()].filter(
    (n) => !existingItems.includes(n),
  )

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" aria-label="Add software">
          <Plus className="h-4 w-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className={commandPopoverContentClass} align="end">
        <Command shouldFilter={false} className={commandRootClass}>
          <CommandInput
            placeholder="Search software..."
            value={search}
            onValueChange={setSearch}
          />
          <CommandList className="max-h-[min(50vh,320px)]">
            <CommandEmpty>No results.</CommandEmpty>
            <CommandGroup>
              {uniqueNames.map((name) => {
                const pkg = itemsByName.get(name)
                const title = pkg?.display_name?.trim() || name
                const developer = pkg?.developer?.trim()
                return (
                  <CommandItem
                    key={name}
                    value={[name, pkg?.display_name, developer]
                      .filter(Boolean)
                      .join(' ')}
                    onSelect={() => {
                      onAdd(name)
                      setOpen(false)
                      setSearch('')
                    }}
                    className="gap-2"
                  >
                    <SoftwareIcon
                      name={name}
                      displayName={pkg?.display_name}
                      size="sm"
                      className="shrink-0"
                    />
                    <div className="flex min-w-0 flex-col">
                      <span className="truncate font-medium">{title}</span>
                      {developer ? (
                        <span className="truncate text-xs text-muted-foreground">
                          {developer}
                        </span>
                      ) : (
                        title !== name && (
                          <span className="truncate text-xs text-muted-foreground">
                            {name}
                          </span>
                        )
                      )}
                    </div>
                  </CommandItem>
                )
              })}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

function AddManifestButton({
  onAdd,
  existingItems,
  currentManifestName,
}: {
  onAdd: (name: string) => void
  existingItems: string[]
  currentManifestName: string
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
        <Button variant="outline" size="sm" aria-label="Add included manifest">
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
                  value={m.name}
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
                  <span className="truncate">{m.name}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
