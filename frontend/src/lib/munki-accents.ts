/**
 * Shared Munki UI accents: Software (blue/teal), Catalogs (green), Manifests (purple),
 * plus AutoPkg, dashboard, approvals, audit, settings for page titles.
 * Keep borders and backgrounds low-contrast so they read as wayfinding, not noise.
 */
export const munkiAccents = {
  software: {
    pageTitle: 'border-l-4 border-l-gruvbox-blue/50 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-blue/50 bg-gruvbox-blue/[0.06]',
    icon: 'text-gruvbox-blue',
    overviewCard: 'border-l-4 border-l-gruvbox-blue/40 bg-gruvbox-blue/[0.05]',
    overviewRow: 'hover:bg-gruvbox-blue/[0.06]',
  },
  catalogs: {
    pageTitle: 'border-l-4 border-l-gruvbox-green/50 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-green/50 bg-gruvbox-green/[0.06]',
    icon: 'text-gruvbox-green',
    overviewCard:
      'border-l-4 border-l-gruvbox-green/40 bg-gruvbox-green/[0.05]',
    overviewRow: 'hover:bg-gruvbox-green/[0.06]',
    catalogGridCard:
      'border-l-4 border-l-gruvbox-green/40 cursor-pointer transition-colors hover:bg-gruvbox-green/[0.04]',
  },
  manifests: {
    pageTitle: 'border-l-4 border-l-gruvbox-purple/50 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-purple/50 bg-gruvbox-purple/[0.06]',
    icon: 'text-gruvbox-purple',
    overviewCard:
      'border-l-4 border-l-gruvbox-purple/40 bg-gruvbox-purple/[0.05]',
    overviewRow: 'hover:bg-gruvbox-purple/[0.06]',
    manifestGridCard:
      'border-l-4 border-l-gruvbox-purple/40 transition-colors hover:bg-gruvbox-purple/[0.04]',
  },
  dashboard: {
    pageTitle: 'border-l-4 border-l-gruvbox-aqua/50 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-aqua/50 bg-gruvbox-aqua/[0.06]',
    icon: 'text-gruvbox-aqua',
  },
  autopkg: {
    pageTitle: 'border-l-4 border-l-gruvbox-orange/50 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-orange/50 bg-gruvbox-orange/[0.06]',
    icon: 'text-gruvbox-orange',
  },
  approvals: {
    pageTitle: 'border-l-4 border-l-gruvbox-yellow/50 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-yellow/50 bg-gruvbox-yellow/[0.06]',
    icon: 'text-gruvbox-yellow',
  },
  audit: {
    pageTitle: 'border-l-4 border-l-gruvbox-red/45 pl-4',
    statCard: 'border-l-4 border-l-gruvbox-red/45 bg-gruvbox-red/[0.06]',
    icon: 'text-gruvbox-red',
  },
  reporting: {
    pageTitle: 'border-l-4 border-l-cyan-600/45 pl-4 dark:border-l-cyan-500/50',
    statCard:
      'border-l-4 border-l-cyan-600/40 bg-cyan-600/[0.06] dark:border-l-cyan-500/45 dark:bg-cyan-500/[0.08]',
    icon: 'text-cyan-700 dark:text-cyan-400',
  },
  settings: {
    pageTitle: 'border-l-4 border-l-muted-foreground/40 pl-4',
    statCard: 'border-l-4 border-l-muted-foreground/40 bg-muted/30',
    icon: 'text-muted-foreground',
  },
} as const

export type MunkiAccentKey = keyof typeof munkiAccents

/** Section heading marker (dashboard): ties the three accents together. */
export function munkiSectionHeadingClass() {
  return 'flex items-center gap-3 text-xl font-semibold tracking-tight text-pretty'
}

export function munkiSectionMarkerClass() {
  return 'h-7 w-1 shrink-0 rounded-full bg-gradient-to-b from-gruvbox-blue/90 via-gruvbox-green/90 to-gruvbox-purple/90'
}
