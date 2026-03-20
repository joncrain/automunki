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
import { GripVertical, Plus, Save, X } from 'lucide-react'
import { useParams } from 'next/navigation'
import { useCallback, useEffect, useState } from 'react'
import { toast } from 'sonner'
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
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
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

const ITEM_SECTIONS = [
  {
    key: 'managed_installs',
    label: 'Managed Installs',
    variant: 'outline' as const,
  },
  {
    key: 'managed_uninstalls',
    label: 'Managed Uninstalls',
    variant: 'destructive' as const,
  },
  {
    key: 'managed_updates',
    label: 'Managed Updates',
    variant: 'secondary' as const,
  },
  {
    key: 'optional_installs',
    label: 'Optional Installs',
    variant: 'outline' as const,
  },
  {
    key: 'featured_items',
    label: 'Featured Items',
    variant: 'default' as const,
  },
  {
    key: 'default_installs',
    label: 'Default Installs',
    variant: 'secondary' as const,
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
    <div className="space-y-6">
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

      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">{manifest.name}</h1>
        <Button
          onClick={handleSave}
          disabled={!dirty || saveMutation.isPending}
        >
          <Save className="mr-1 h-4 w-4" />
          {saveMutation.isPending ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center justify-between text-base">
              <div className="flex items-center gap-2">
                Catalogs
                <Badge variant="secondary" className="text-xs">
                  {catalogNames.length}
                </Badge>
              </div>
              <AddCatalogButton
                onAdd={addCatalog}
                existingItems={catalogNames}
              />
            </CardTitle>
          </CardHeader>
          <CardContent>
            {catalogNames.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No catalogs assigned. A manifest needs at least one catalog.
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {catalogNames.map((name) => (
                  <Badge
                    key={name}
                    variant="secondary"
                    className="gap-1 pr-1 text-sm"
                  >
                    {name}
                    <button
                      type="button"
                      aria-label={`Remove catalog ${name}`}
                      className="ml-1 rounded-full p-0.5 hover:bg-muted"
                      onClick={() => removeCatalog(name)}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center justify-between text-base">
              <div className="flex items-center gap-2">
                Included Manifests
                <Badge variant="secondary" className="text-xs">
                  {includedManifestNames.length}
                </Badge>
              </div>
              <AddManifestButton
                onAdd={addIncludedManifest}
                existingItems={includedManifestNames}
                currentManifestName={manifest.name}
              />
            </CardTitle>
          </CardHeader>
          <CardContent>
            {includedManifestNames.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No included manifests. Click + to include another manifest.
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {includedManifestNames.map((name) => (
                  <Badge
                    key={name}
                    variant="secondary"
                    className="gap-1 pr-1 text-sm"
                  >
                    {name}
                    <button
                      type="button"
                      aria-label={`Remove included manifest ${name}`}
                      className="ml-1 rounded-full p-0.5 hover:bg-muted"
                      onClick={() => removeIncludedManifest(name)}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        {ITEM_SECTIONS.map((sec) => (
          <SortableSection
            key={sec.key}
            label={sec.label}
            badgeVariant={sec.variant}
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

function SortableSection({
  label,
  badgeVariant,
  items,
  onAdd,
  onRemove,
  onReorder,
}: {
  label: string
  badgeVariant: 'outline' | 'destructive' | 'secondary' | 'default'
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
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center justify-between text-base">
          <div className="flex items-center gap-2">
            {label}
            <Badge variant="secondary" className="text-xs">
              {items.length}
            </Badge>
          </div>
          <AddSoftwareButton onAdd={onAdd} existingItems={items} />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="py-4 text-center text-sm text-muted-foreground">
            No items. Click + to add software.
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
              <div className="space-y-1">
                {items.map((item) => (
                  <SortableItem
                    key={item}
                    id={item}
                    badgeVariant={badgeVariant}
                    onRemove={() => onRemove(item)}
                  />
                ))}
              </div>
            </SortableContext>
          </DndContext>
        )}
      </CardContent>
    </Card>
  )
}

function SortableItem({
  id,
  badgeVariant,
  onRemove,
}: {
  id: string
  badgeVariant: 'outline' | 'destructive' | 'secondary' | 'default'
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
      className="flex items-center gap-2 rounded-md border bg-card px-3 py-2"
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
      <Badge variant={badgeVariant} className="flex-1">
        {id}
      </Badge>
      <button
        type="button"
        aria-label={`Remove ${id}`}
        className="text-muted-foreground hover:text-destructive"
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
        `/pkginfo?page_size=20${search ? `&search=${encodeURIComponent(search)}` : ''}`,
      ),
    enabled: open,
  })

  const uniqueNames = Array.from(
    new Set((data?.items ?? []).map((i) => i.name)),
  ).filter((n) => !existingItems.includes(n))

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" aria-label="Add software">
          <Plus className="h-4 w-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[300px] p-0" align="end">
        <Command shouldFilter={false}>
          <CommandInput
            placeholder="Search software..."
            value={search}
            onValueChange={setSearch}
          />
          <CommandList>
            <CommandEmpty>No results.</CommandEmpty>
            <CommandGroup>
              {uniqueNames.map((name) => (
                <CommandItem
                  key={name}
                  value={name}
                  onSelect={() => {
                    onAdd(name)
                    setOpen(false)
                    setSearch('')
                  }}
                >
                  {name}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

function AddCatalogButton({
  onAdd,
  existingItems,
}: {
  onAdd: (name: string) => void
  existingItems: string[]
}) {
  const [open, setOpen] = useState(false)

  const { data: catalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
    enabled: open,
  })

  const available = (catalogs ?? []).filter(
    (c) => !existingItems.includes(c.name),
  )

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" aria-label="Add catalog">
          <Plus className="h-4 w-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[250px] p-0" align="end">
        <Command>
          <CommandInput placeholder="Search catalogs..." />
          <CommandList>
            <CommandEmpty>No catalogs available.</CommandEmpty>
            <CommandGroup>
              {available.map((cat) => (
                <CommandItem
                  key={cat.id}
                  value={cat.name}
                  onSelect={() => {
                    onAdd(cat.name)
                    setOpen(false)
                  }}
                >
                  <div className="flex flex-col">
                    <span>{cat.name}</span>
                    {cat.display_name && (
                      <span className="text-xs text-muted-foreground">
                        {cat.display_name}
                      </span>
                    )}
                  </div>
                  <Badge variant="secondary" className="ml-auto text-xs">
                    {cat.item_count}
                  </Badge>
                </CommandItem>
              ))}
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
          <Plus className="h-4 w-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[300px] p-0" align="end">
        <Command>
          <CommandInput placeholder="Search manifests..." />
          <CommandList>
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
                  {m.name}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
