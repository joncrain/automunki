/**
 * Munki manifest item refs: pkginfo `name`, or `name-version`, or `name--version`
 * when the version contains dashes. See
 * https://github.com/munki/munki/wiki/Manifests (item names).
 */
export function parseManifestItemRef(raw: string): {
  baseName: string
  version: string | null
} {
  const double = raw.indexOf('--')
  if (double !== -1) {
    const baseName = raw.slice(0, double)
    const version = raw.slice(double + 2).trim() || null
    return { baseName, version }
  }
  const dash = raw.indexOf('-')
  if (dash === -1) {
    return { baseName: raw, version: null }
  }
  const version = raw.slice(dash + 1).trim() || null
  return { baseName: raw.slice(0, dash), version }
}

export function formatManifestItemRef(
  baseName: string,
  version: string | null | undefined,
): string {
  const v = version?.trim()
  if (!v) return baseName
  if (v.includes('-')) return `${baseName}--${v}`
  return `${baseName}-${v}`
}

export function manifestItemBaseNamesInUse(items: string[]): Set<string> {
  return new Set(items.map((raw) => parseManifestItemRef(raw).baseName))
}
