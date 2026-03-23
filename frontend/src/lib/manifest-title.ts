import type { ManifestRead } from '@/lib/api'

/** Primary label for a manifest: trimmed display name, or the plist `name`. */
export function manifestTitle(
  m: Pick<ManifestRead, 'name' | 'display_name'>,
): string {
  const d = m.display_name?.trim()
  return d || m.name
}

export function manifestTitleForName(
  manifestByName: Map<string, ManifestRead>,
  name: string,
): string {
  const m = manifestByName.get(name)
  return m ? manifestTitle(m) : name
}
