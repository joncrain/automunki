/**
 * Shared Munki UI accents: Software (blue/teal), Catalogs (green), Manifests (purple).
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
} as const

export type MunkiAccentKey = keyof typeof munkiAccents

/** Section heading marker (dashboard): ties the three accents together. */
export function munkiSectionHeadingClass() {
  return 'flex items-center gap-3 text-xl font-semibold tracking-tight text-pretty'
}

export function munkiSectionMarkerClass() {
  return 'h-7 w-1 shrink-0 rounded-full bg-gradient-to-b from-gruvbox-blue/90 via-gruvbox-green/90 to-gruvbox-purple/90'
}
