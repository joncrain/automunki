'use client'

import { ManifestSortableStringList } from '@/components/manifest-sortable-string-list'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  MANIFEST_ITEM_SECTION_DEFAULT_TAB,
  MANIFEST_ITEM_SECTION_TAB_DEFS,
  type ManifestItemSectionKey,
} from '@/lib/manifest-item-section-defs'
import { cn } from '@/lib/utils'

const manifestItemsTabContentClass = cn(
  'space-y-4',
  'animate-in fade-in-0 slide-in-from-bottom-1 duration-300',
)

function manifestItemsTabTrigger(activeRing: string) {
  return cn(
    'group/tab flex-none gap-1.5 px-2.5 py-1.5 min-h-9 rounded-lg border border-transparent text-xs',
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

const manifestItemsTabIconClass =
  'size-3.5 shrink-0 opacity-70 transition-[opacity,transform] duration-200 ease-out group-hover/tab:opacity-100 group-data-[state=inactive]/tab:group-hover/tab:scale-105 group-data-[state=active]/tab:opacity-100 group-data-[state=active]/tab:scale-110 group-data-[state=active]/tab:group-hover/tab:scale-[1.18] motion-reduce:group-hover/tab:scale-100 motion-reduce:group-data-[state=active]/tab:scale-100 motion-reduce:group-data-[state=active]/tab:group-hover/tab:scale-100'

export type { ManifestItemSectionKey }

type Props = {
  sections: Record<ManifestItemSectionKey, string[]> | null
  getItemLabel: (itemRef: string) => string
  onAdd: (section: ManifestItemSectionKey, name: string) => void
  onRemove: (section: ManifestItemSectionKey, name: string) => void
  onReorder: (section: ManifestItemSectionKey, from: number, to: number) => void
  onReplaceItem: (
    section: ManifestItemSectionKey,
    oldRaw: string,
    newRaw: string,
  ) => void
  disabled?: boolean
  /** `compact` for nested conditional blocks; `default` for manifest detail. */
  listVariant?: 'default' | 'compact'
  /** Override initial tab (defaults to managed_installs). */
  defaultTab?: ManifestItemSectionKey
  className?: string
}

/**
 * Tab bar + one panel per Munki manifest software list (managed_installs, etc.).
 * Used on the manifest detail page and inside conditional item blocks.
 */
export function ManifestItemSectionsTabs({
  sections,
  getItemLabel,
  onAdd,
  onRemove,
  onReorder,
  onReplaceItem,
  disabled,
  listVariant = 'default',
  defaultTab = MANIFEST_ITEM_SECTION_DEFAULT_TAB,
  className,
}: Props) {
  return (
    <Tabs defaultValue={defaultTab} className={cn('gap-4', className)}>
      <TabsList
        className={cn(
          'h-auto w-full flex-wrap gap-1.5 rounded-xl p-1.5 sm:p-2',
          'border border-gruvbox-blue/20 bg-gradient-to-br from-muted/90 via-muted/55 to-muted/25',
          'shadow-sm transition-[border-color,box-shadow] duration-300 ease-out',
          'hover:border-gruvbox-blue/40 hover:shadow-md dark:border-gruvbox-blue/30 dark:hover:border-gruvbox-blue/50',
        )}
      >
        {MANIFEST_ITEM_SECTION_TAB_DEFS.map((sec) => {
          const Icon = sec.Icon
          const count = sections?.[sec.key]?.length ?? 0
          return (
            <TabsTrigger
              key={sec.key}
              value={sec.key}
              className={manifestItemsTabTrigger(sec.tabActiveClass)}
            >
              <Icon className={manifestItemsTabIconClass} aria-hidden />
              <span className="flex min-w-0 items-center gap-1.5">
                <span className="truncate font-medium leading-tight">
                  {sec.label}
                </span>
                <Badge
                  variant="secondary"
                  className={cn(
                    'h-5 min-w-5 shrink-0 border-border/40 bg-muted/70 px-1.5 font-mono text-[10px] leading-none tabular-nums',
                    'group-data-[state=active]/tab:border-border/60 group-data-[state=active]/tab:bg-background group-data-[state=active]/tab:text-foreground',
                  )}
                >
                  {count}
                </Badge>
              </span>
            </TabsTrigger>
          )
        })}
      </TabsList>
      {MANIFEST_ITEM_SECTION_TAB_DEFS.map((sec) => (
        <TabsContent
          key={sec.key}
          value={sec.key}
          className={manifestItemsTabContentClass}
        >
          <ManifestSortableStringList
            label={sec.label}
            accent={sec.accent}
            rowAccent={sec.rowAccent}
            allowVersionPin={sec.allowVersionPin}
            items={sections?.[sec.key] ?? []}
            getItemLabel={getItemLabel}
            onAdd={(name) => onAdd(sec.key, name)}
            onRemove={(name) => onRemove(sec.key, name)}
            onReorder={(from, to) => onReorder(sec.key, from, to)}
            onReplaceItem={(oldRaw, newRaw) =>
              onReplaceItem(sec.key, oldRaw, newRaw)
            }
            variant={listVariant}
            disabled={disabled}
          />
        </TabsContent>
      ))}
    </Tabs>
  )
}
