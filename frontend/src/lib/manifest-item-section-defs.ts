import type { LucideIcon } from 'lucide-react'
import {
  ListChecks,
  Package,
  RefreshCw,
  SquareStack,
  Star,
  Trash2,
} from 'lucide-react'

/** Munki manifest software list keys (main manifest + conditional blocks). */
export type ManifestItemSectionKey =
  | 'managed_installs'
  | 'managed_uninstalls'
  | 'managed_updates'
  | 'optional_installs'
  | 'featured_items'
  | 'default_installs'

export type ManifestItemSectionTabDef = {
  key: ManifestItemSectionKey
  label: string
  Icon: LucideIcon
  tabActiveClass: string
  accent: string
  rowAccent: string
  allowVersionPin: boolean
}

/** Shared metadata for tab UI + sortable lists (manifest detail + conditional blocks). */
export const MANIFEST_ITEM_SECTION_TAB_DEFS: readonly ManifestItemSectionTabDef[] =
  [
    {
      key: 'managed_installs',
      label: 'Managed Installs',
      Icon: Package,
      tabActiveClass:
        'data-[state=active]:text-gruvbox-blue data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-blue/30',
      accent:
        'border-l-gruvbox-blue/70 bg-gruvbox-blue/[0.07] dark:bg-gruvbox-blue/[0.12]',
      rowAccent:
        'border-gruvbox-blue/30 bg-gruvbox-blue/[0.04] dark:bg-gruvbox-blue/[0.08]',
      allowVersionPin: true,
    },
    {
      key: 'managed_uninstalls',
      label: 'Managed Uninstalls',
      Icon: Trash2,
      tabActiveClass:
        'data-[state=active]:text-destructive data-[state=active]:ring-2 data-[state=active]:ring-destructive/30',
      accent:
        'border-l-destructive/80 bg-destructive/[0.08] dark:bg-destructive/[0.12]',
      rowAccent:
        'border-destructive/35 bg-destructive/[0.06] dark:bg-destructive/[0.1]',
      allowVersionPin: false,
    },
    {
      key: 'managed_updates',
      label: 'Managed Updates',
      Icon: RefreshCw,
      tabActiveClass:
        'data-[state=active]:text-gruvbox-aqua data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-aqua/30',
      accent:
        'border-l-gruvbox-aqua/70 bg-gruvbox-aqua/[0.07] dark:bg-gruvbox-aqua/[0.1]',
      rowAccent:
        'border-gruvbox-aqua/30 bg-gruvbox-aqua/[0.04] dark:bg-gruvbox-aqua/[0.08]',
      allowVersionPin: false,
    },
    {
      key: 'optional_installs',
      label: 'Optional Installs',
      Icon: SquareStack,
      tabActiveClass:
        'data-[state=active]:text-foreground data-[state=active]:ring-2 data-[state=active]:ring-muted-foreground/35',
      accent: 'border-l-muted-foreground/50 bg-muted/40 dark:bg-muted/25',
      rowAccent: 'border-muted-foreground/25 bg-muted/30 dark:bg-muted/20',
      allowVersionPin: true,
    },
    {
      key: 'featured_items',
      label: 'Featured Items',
      Icon: Star,
      tabActiveClass:
        'data-[state=active]:text-gruvbox-yellow data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-yellow/30',
      accent:
        'border-l-gruvbox-yellow/60 bg-gruvbox-yellow/[0.08] dark:bg-gruvbox-yellow/[0.12]',
      rowAccent:
        'border-gruvbox-yellow/30 bg-gruvbox-yellow/[0.05] dark:bg-gruvbox-yellow/[0.08]',
      allowVersionPin: true,
    },
    {
      key: 'default_installs',
      label: 'Default Installs',
      Icon: ListChecks,
      tabActiveClass:
        'data-[state=active]:text-gruvbox-purple data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-purple/30',
      accent:
        'border-l-gruvbox-purple/60 bg-gruvbox-purple/[0.07] dark:bg-gruvbox-purple/[0.1]',
      rowAccent:
        'border-gruvbox-purple/30 bg-gruvbox-purple/[0.04] dark:bg-gruvbox-purple/[0.08]',
      allowVersionPin: true,
    },
  ]

export const MANIFEST_ITEM_SECTION_DEFAULT_TAB: ManifestItemSectionKey =
  MANIFEST_ITEM_SECTION_TAB_DEFS[0].key
