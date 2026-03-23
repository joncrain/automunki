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
import { useQuery } from '@tanstack/react-query'
import { GripVertical, Pin, Plus, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { SoftwareIcon } from '@/components/software-icon'
import { Badge } from '@/components/ui/badge'
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
import { usePkginfoVersionsForName } from '@/hooks/use-pkginfo-versions'
import { api, type PaginatedResponse, type PkgInfoSummary } from '@/lib/api'
import {
  formatManifestItemRef,
  manifestItemBaseNamesInUse,
  parseManifestItemRef,
} from '@/lib/manifest-item-ref'
import { cn } from '@/lib/utils'

const commandPopoverContentClass =
  'flex max-h-[min(70vh,440px)] w-[min(100vw-2rem,380px)] flex-col overflow-hidden p-0'

const commandRootClass = 'flex min-h-0 flex-1 flex-col overflow-hidden'

function PinVersionButton({
  rawId,
  onPick,
}: {
  rawId: string
  onPick: (newRaw: string) => void
}) {
  const { baseName, version: pinnedVersion } = parseManifestItemRef(rawId)
  const [open, setOpen] = useState(false)
  const { data, isFetching } = usePkginfoVersionsForName(baseName, open)

  const versions = useMemo(() => {
    const seen = new Set<string>()
    const out: string[] = []
    for (const p of data?.items ?? []) {
      if (p.version && !seen.has(p.version)) {
        seen.add(p.version)
        out.push(p.version)
      }
    }
    return out
  }, [data?.items])

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className={cn(
            'size-7 shrink-0 text-muted-foreground/45 hover:text-foreground',
            pinnedVersion && 'text-amber-800/70 dark:text-amber-400/70',
          )}
          aria-label={
            pinnedVersion
              ? `Pinned to ${pinnedVersion}. Change or clear pin`
              : 'Pin to a specific version'
          }
        >
          <Pin className="h-3.5 w-3.5" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[min(100vw-2rem,20rem)] p-0" align="end">
        <div className="border-b px-3 py-2">
          <p className="text-xs font-medium text-muted-foreground">
            Pin catalog version
          </p>
          <p className="truncate font-mono text-sm">{baseName}</p>
        </div>
        <Command shouldFilter={false}>
          <CommandList className="max-h-[min(50vh,280px)]">
            <CommandGroup>
              <CommandItem
                value="__latest__"
                onSelect={() => {
                  onPick(baseName)
                  setOpen(false)
                }}
              >
                Latest in catalog (clear pin)
              </CommandItem>
              {isFetching && versions.length === 0 ? (
                <div className="px-3 py-2 text-sm text-muted-foreground">
                  Loading versions…
                </div>
              ) : null}
              {!isFetching && versions.length === 0 ? (
                <div className="px-3 py-2 text-sm text-muted-foreground">
                  No pkginfo rows found for this name.
                </div>
              ) : null}
              {versions.map((v) => (
                <CommandItem
                  key={v}
                  value={v}
                  onSelect={() => {
                    onPick(formatManifestItemRef(baseName, v))
                    setOpen(false)
                  }}
                >
                  <span className="font-mono text-sm">{v}</span>
                  {pinnedVersion === v ? (
                    <span className="ml-auto text-xs text-muted-foreground">
                      current
                    </span>
                  ) : null}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
        <p className="border-t px-3 py-2 text-[11px] leading-snug text-muted-foreground">
          Uses Munki&apos;s{' '}
          <a
            href="https://github.com/munki/munki/wiki/Manifests#item-names"
            className="underline underline-offset-2"
            target="_blank"
            rel="noreferrer"
          >
            name–version
          </a>{' '}
          manifest syntax. Avoid pinning managed_updates this way.
        </p>
      </PopoverContent>
    </Popover>
  )
}

function SortableItem({
  id,
  label,
  rowAccent,
  allowVersionPin,
  onReplaceItem,
  onRemove,
}: {
  id: string
  label: string
  rowAccent: string
  allowVersionPin: boolean
  onReplaceItem: (oldRaw: string, newRaw: string) => void
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

  const { baseName, version: pinnedVersion } = parseManifestItemRef(id)
  const showManifestRefLine = pinnedVersion != null || id !== label

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
      <SoftwareIcon
        name={baseName}
        displayName={label}
        size="sm"
        className="shrink-0"
      />
      <div className="min-w-0 flex-1">
        <span className="block truncate text-sm">{label}</span>
        {showManifestRefLine ? (
          <span className="block truncate font-mono text-xs text-muted-foreground">
            {id}
          </span>
        ) : null}
      </div>
      {allowVersionPin ? (
        <PinVersionButton
          rawId={id}
          onPick={(newRaw) => onReplaceItem(id, newRaw)}
        />
      ) : null}
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
  disabled = false,
}: {
  onAdd: (name: string) => void
  existingItems: string[]
  disabled?: boolean
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

  const basesInUse = useMemo(
    () => manifestItemBaseNamesInUse(existingItems),
    [existingItems.join('\0')],
  )

  const uniqueNames = [...itemsByName.keys()].filter((n) => !basesInUse.has(n))

  return (
    <Popover open={disabled ? false : open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          aria-label="Add software"
          disabled={disabled}
        >
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

export function ManifestSortableStringList({
  label,
  accent,
  rowAccent,
  allowVersionPin,
  items,
  getItemLabel,
  onAdd,
  onRemove,
  onReorder,
  onReplaceItem,
  variant = 'default',
  disabled = false,
}: {
  label: string
  accent: string
  rowAccent: string
  allowVersionPin: boolean
  items: string[]
  getItemLabel: (name: string) => string
  onAdd: (name: string) => void
  onRemove: (name: string) => void
  onReorder: (oldIndex: number, newIndex: number) => void
  onReplaceItem: (oldRaw: string, newRaw: string) => void
  variant?: 'default' | 'compact'
  disabled?: boolean
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

  const isCompact = variant === 'compact'
  const accentClass = isCompact
    ? accent.replace(/border-l-4/g, 'border-l-2')
    : accent

  return (
    <div
      className={cn(
        'flex flex-col gap-2 rounded-lg border bg-card/80 shadow-sm',
        isCompact ? 'py-2' : 'py-4',
        accentClass,
      )}
    >
      <div
        className={cn(
          'flex items-center justify-between gap-2',
          isCompact ? 'px-2' : 'px-4',
        )}
      >
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={cn(
              'truncate font-semibold',
              isCompact ? 'text-xs' : 'text-sm',
            )}
          >
            {label}
          </span>
          <Badge variant="secondary" className="shrink-0 text-[10px]">
            {items.length}
          </Badge>
        </div>
        <AddSoftwareButton
          onAdd={onAdd}
          existingItems={items}
          disabled={disabled}
        />
      </div>
      <div className={cn(isCompact ? 'px-2' : 'px-4')}>
        {items.length === 0 ? (
          <p
            className={cn(
              'rounded-md border border-dashed text-center text-muted-foreground',
              isCompact ? 'py-3 text-xs' : 'py-6 text-sm',
            )}
          >
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
                    label={getItemLabel(item)}
                    rowAccent={rowAccent}
                    allowVersionPin={allowVersionPin}
                    onReplaceItem={onReplaceItem}
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
