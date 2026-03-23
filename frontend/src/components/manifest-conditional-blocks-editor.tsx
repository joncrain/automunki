'use client'

import { useQuery } from '@tanstack/react-query'
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileText,
  Plus,
  Trash2,
} from 'lucide-react'
import Link from 'next/link'
import { useMemo, useState } from 'react'
import { ManifestItemSectionsTabs } from '@/components/manifest-item-sections-tabs'
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
import { Textarea } from '@/components/ui/textarea'
import { api, type ManifestRead } from '@/lib/api'
import {
  appendNestedBlockAtPath,
  type ConditionalItemBlock,
  getBlockAtPath,
  newConditionalBlock,
  removeBlockAtPath,
  reorderBlockAmongSiblings,
  setBlockAtPath,
} from '@/lib/manifest-conditional-items'
import type { ManifestItemSectionKey } from '@/lib/manifest-item-section-defs'
import { manifestTitle } from '@/lib/manifest-title'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

const commandPopoverContentClass =
  'flex max-h-[min(70vh,440px)] w-[min(100vw-2rem,380px)] flex-col overflow-hidden p-0'

const commandRootClass = 'flex min-h-0 flex-1 flex-col overflow-hidden'

function siblingListAndIndex(
  blocks: ConditionalItemBlock[],
  path: number[],
): { siblings: ConditionalItemBlock[]; index: number; parentPath: number[] } {
  if (path.length === 0) {
    return { siblings: blocks, index: -1, parentPath: [] }
  }
  const parentPath = path.slice(0, -1)
  const index = path[path.length - 1]
  const siblings =
    parentPath.length === 0
      ? blocks
      : (getBlockAtPath(blocks, parentPath)?.conditional_items ?? [])
  return { siblings, index, parentPath }
}

function conditionalBlockItemSections(
  block: ConditionalItemBlock,
): Record<ManifestItemSectionKey, string[]> {
  return {
    managed_installs: block.managed_installs ?? [],
    managed_uninstalls: block.managed_uninstalls ?? [],
    managed_updates: block.managed_updates ?? [],
    optional_installs: block.optional_installs ?? [],
    featured_items: block.featured_items ?? [],
    default_installs: block.default_installs ?? [],
  }
}

function moveBlockInTree(
  blocks: ConditionalItemBlock[],
  blockPath: number[],
  delta: -1 | 1,
): ConditionalItemBlock[] {
  if (blockPath.length === 0) return blocks
  const { siblings, index, parentPath } = siblingListAndIndex(blocks, blockPath)
  const newIdx = index + delta
  if (newIdx < 0 || newIdx >= siblings.length) return blocks
  return reorderBlockAmongSiblings(blocks, parentPath, index, newIdx)
}

function AddIncludedManifestButton({
  onAdd,
  existingItems,
  currentManifestName,
  disabled,
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

  const available = useMemo(
    () =>
      (manifests ?? []).filter(
        (m) =>
          m.name !== currentManifestName && !existingItems.includes(m.name),
      ),
    [manifests, currentManifestName, existingItems],
  )

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
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

function ConditionalIncludedManifests({
  names,
  onAdd,
  onRemove,
  currentManifestName,
  disabled,
}: {
  names: string[]
  onAdd: (name: string) => void
  onRemove: (name: string) => void
  currentManifestName: string
  disabled?: boolean
}) {
  const { data: allManifests } = useQuery({
    queryKey: ['manifests'],
    queryFn: () => api.get<ManifestRead[]>('/manifests'),
  })

  const byName = useMemo(() => {
    const m = new Map<string, ManifestRead>()
    for (const man of allManifests ?? []) m.set(man.name, man)
    return m
  }, [allManifests])

  return (
    <div
      className={cn(
        'flex flex-col gap-2 rounded-lg border border-l-2 border-muted-foreground/35 bg-muted/20 py-2',
        'border-l-gruvbox-purple/60 bg-gruvbox-purple/[0.06] dark:bg-gruvbox-purple/[0.1]',
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 px-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold">Included manifests</span>
          <Badge variant="secondary" className="text-[10px]">
            {names.length}
          </Badge>
        </div>
        <AddIncludedManifestButton
          onAdd={onAdd}
          existingItems={names}
          currentManifestName={currentManifestName}
          disabled={disabled}
        />
      </div>
      <div className="px-2">
        {names.length === 0 ? (
          <p className="rounded-md border border-dashed py-3 text-center text-xs text-muted-foreground">
            No included manifests in this block.
          </p>
        ) : (
          <div className="flex flex-col gap-1.5">
            {names.map((name) => {
              const m = byName.get(name)
              const title = m ? manifestTitle(m) : name
              return (
                <div
                  key={name}
                  className="flex items-center gap-2 rounded-md border border-gruvbox-purple/25 bg-card/80 px-2 py-1.5"
                >
                  <FileText
                    className="size-4 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1">
                    {m ? (
                      <Link
                        href={`/manifests/${m.id}`}
                        className="truncate text-sm font-medium text-primary underline-offset-4 hover:underline"
                      >
                        {title}
                      </Link>
                    ) : (
                      <span className="truncate text-sm font-medium">
                        {title}
                      </span>
                    )}
                    {title !== name && (
                      <p className="truncate font-mono text-xs text-muted-foreground">
                        {name}
                      </p>
                    )}
                  </div>
                  <button
                    type="button"
                    aria-label={`Remove ${name}`}
                    className="shrink-0 text-muted-foreground hover:text-destructive"
                    disabled={disabled}
                    onClick={() => onRemove(name)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function ConditionalBlockCard({
  blocks,
  path,
  onChange,
  getPkgItemLabel,
  currentManifestName,
  disabled,
}: {
  blocks: ConditionalItemBlock[]
  path: number[]
  onChange: (next: ConditionalItemBlock[]) => void
  getPkgItemLabel: (ref: string) => string
  currentManifestName: string
  disabled?: boolean
}) {
  const block = getBlockAtPath(blocks, path)
  if (!block) return null

  const { siblings, index, parentPath } = siblingListAndIndex(blocks, path)
  const canMoveUp = index > 0
  const canMoveDown = index >= 0 && index < siblings.length - 1

  const patchBlock = (patch: Partial<ConditionalItemBlock>) => {
    onChange(setBlockAtPath(blocks, path, { ...block, ...patch }))
  }

  const setSectionItems = (key: ManifestItemSectionKey, values: string[]) => {
    const next: ConditionalItemBlock = { ...block }
    if (values.length) {
      ;(next as Record<string, unknown>)[key as string] = values
    } else {
      delete (next as Record<string, unknown>)[key as string]
    }
    onChange(setBlockAtPath(blocks, path, next))
  }

  const replaceSectionItem = (
    key: ManifestItemSectionKey,
    oldRaw: string,
    newRaw: string,
  ) => {
    const list = (block[key] as string[] | undefined) ?? []
    const idx = list.indexOf(oldRaw)
    if (idx === -1) return
    if (list.some((x, i) => x === newRaw && i !== idx)) return
    const nextList = [...list]
    nextList[idx] = newRaw
    setSectionItems(key, nextList)
  }

  const depth = path.length

  return (
    <div
      className={cn(
        'rounded-xl border bg-card/90 shadow-sm',
        depth > 0 && 'ml-2 border-dashed border-muted-foreground/30',
      )}
    >
      <div
        className={cn(
          'flex flex-col gap-3 border-b border-muted-foreground/15 p-4',
          'bg-gradient-to-br from-muted/30 to-transparent',
        )}
      >
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              Condition
              {depth > 0 ? ` (nested ${depth})` : ''}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              NSPredicate evaluated on the client. See{' '}
              <a
                href="https://github.com/munki/munki/wiki/Conditional-Items"
                className="text-primary underline-offset-2 hover:underline"
                target="_blank"
                rel="noreferrer"
              >
                Conditional Items
                <ExternalLink className="ml-0.5 inline size-3 align-[-0.125em] opacity-70" />
              </a>
              .
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-1">
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="size-8"
              aria-label="Move block up"
              disabled={disabled || !canMoveUp}
              onClick={() => onChange(moveBlockInTree(blocks, path, -1))}
            >
              <ChevronUp className="h-4 w-4" />
            </Button>
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="size-8"
              aria-label="Move block down"
              disabled={disabled || !canMoveDown}
              onClick={() => onChange(moveBlockInTree(blocks, path, 1))}
            >
              <ChevronDown className="h-4 w-4" />
            </Button>
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="size-8 text-muted-foreground hover:text-destructive"
              aria-label="Remove conditional block"
              disabled={disabled}
              onClick={() => onChange(removeBlockAtPath(blocks, path))}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <Textarea
          value={block.condition}
          onChange={(e) => patchBlock({ condition: e.target.value })}
          disabled={disabled}
          placeholder='e.g. machine_type == "laptop" AND os_vers BEGINSWITH "14."'
          className="min-h-[5rem] font-mono text-sm"
          spellCheck={false}
        />
      </div>

      <div className="flex flex-col gap-3 p-4">
        <ConditionalIncludedManifests
          names={block.included_manifests ?? []}
          onAdd={(name) => {
            const cur = block.included_manifests ?? []
            if (cur.includes(name)) return
            patchBlock({ included_manifests: [...cur, name] })
          }}
          onRemove={(name) => {
            const cur = block.included_manifests ?? []
            const next = cur.filter((n) => n !== name)
            patchBlock({
              included_manifests: next.length ? next : undefined,
            })
          }}
          currentManifestName={currentManifestName}
          disabled={disabled}
        />

        <ManifestItemSectionsTabs
          sections={conditionalBlockItemSections(block)}
          getItemLabel={getPkgItemLabel}
          onAdd={(key, name) => {
            const items = (block[key] as string[] | undefined) ?? []
            if (items.includes(name)) return
            setSectionItems(key, [...items, name])
          }}
          onRemove={(key, name) => {
            const items = (block[key] as string[] | undefined) ?? []
            setSectionItems(
              key,
              items.filter((n) => n !== name),
            )
          }}
          onReorder={(key, from, to) => {
            const items = [...((block[key] as string[] | undefined) ?? [])]
            const [moved] = items.splice(from, 1)
            items.splice(to, 0, moved)
            setSectionItems(key, items)
          }}
          onReplaceItem={(key, oldRaw, newRaw) =>
            replaceSectionItem(key, oldRaw, newRaw)
          }
          listVariant="compact"
          disabled={disabled}
        />

        <div className="rounded-lg border border-dashed border-muted-foreground/25 bg-muted/10 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs font-medium text-muted-foreground">
              Nested conditional items
            </p>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={disabled}
              onClick={() =>
                onChange(
                  appendNestedBlockAtPath(blocks, path, newConditionalBlock()),
                )
              }
            >
              <Plus className="mr-1 h-4 w-4" />
              Add nested block
            </Button>
          </div>
          {(block.conditional_items ?? []).length > 0 ? (
            <div className="mt-3 flex flex-col gap-3">
              {(block.conditional_items ?? []).map((child, childIdx) => (
                <ConditionalBlockCard
                  key={child._uiId ?? `${path.join('-')}-${childIdx}`}
                  blocks={blocks}
                  path={[...path, childIdx]}
                  onChange={onChange}
                  getPkgItemLabel={getPkgItemLabel}
                  currentManifestName={currentManifestName}
                  disabled={disabled}
                />
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs text-muted-foreground">
              Optional. Nest further predicates inside this block (same as
              ANDing conditions in one string).
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

export function ManifestConditionalBlocksEditor({
  blocks,
  onChange,
  getPkgItemLabel,
  currentManifestName,
  disabled,
}: {
  blocks: ConditionalItemBlock[]
  onChange: (next: ConditionalItemBlock[]) => void
  getPkgItemLabel: (ref: string) => string
  currentManifestName: string
  disabled?: boolean
}) {
  return (
    <div
      className={cn(
        'rounded-xl border border-l-4 border-muted-foreground/30 bg-card p-4 shadow-sm',
        'border-l-amber-400/50 bg-amber-500/[0.04] dark:border-l-amber-500/35 dark:bg-amber-500/[0.07]',
      )}
    >
      <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-muted-foreground uppercase">
            Conditional items
          </h2>
          <p className="mt-0.5 max-w-3xl text-xs text-muted-foreground">
            When the predicate is true on a Mac, Munki merges these lists into
            the effective manifest. Predicates use client facts (hostname,
            os_vers, custom condition scripts, etc.).
          </p>
        </div>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="shrink-0"
          disabled={disabled}
          onClick={() => onChange([...blocks, newConditionalBlock()])}
        >
          <Plus className="mr-1 h-4 w-4" />
          Add block
        </Button>
      </div>

      {blocks.length === 0 ? (
        <p className="mt-4 rounded-lg border border-dashed py-8 text-center text-sm text-muted-foreground">
          No conditional blocks. Add one to scope installs, uninstalls, or
          includes to matching machines only.
        </p>
      ) : (
        <div className="mt-4 flex flex-col gap-4">
          {blocks.map((b, i) => (
            <ConditionalBlockCard
              key={b._uiId ?? `root-${i}`}
              blocks={blocks}
              path={[i]}
              onChange={onChange}
              getPkgItemLabel={getPkgItemLabel}
              currentManifestName={currentManifestName}
              disabled={disabled}
            />
          ))}
        </div>
      )}
    </div>
  )
}
