/**
 * Build a GitHub web URL for a trust entry (recipe or processor file).
 * Uses HEAD so the default branch resolves correctly on GitHub.
 */

function getTrustEntry(
  trustInfo: unknown,
  section: 'parent_recipes' | 'non_core_processors',
  key: string,
): { github_repo: string; github_path: string } | null {
  if (!trustInfo || typeof trustInfo !== 'object') return null
  const sec = (trustInfo as Record<string, unknown>)[section]
  if (!sec || typeof sec !== 'object') return null
  const entry = (sec as Record<string, unknown>)[key]
  if (!entry || typeof entry !== 'object') return null
  const e = entry as Record<string, string>
  const repo = e.github_repo
  const path = e.github_path
  if (repo && path) return { github_repo: repo, github_path: path }
  return null
}

/** Repo + path for a trust diff row (from stored or computed trust info). */
export function trustRepoPathForTrustEntry(
  oldTrustInfo: unknown,
  newTrustInfo: unknown,
  section: 'parent_recipes' | 'non_core_processors',
  key: string,
): { github_repo: string; github_path: string } | null {
  return (
    getTrustEntry(oldTrustInfo, section, key) ??
    getTrustEntry(newTrustInfo, section, key)
  )
}

export function githubBlobUrlForTrustEntry(
  oldTrustInfo: unknown,
  newTrustInfo: unknown,
  section: 'parent_recipes' | 'non_core_processors',
  key: string,
): string | null {
  const loc = trustRepoPathForTrustEntry(
    oldTrustInfo,
    newTrustInfo,
    section,
    key,
  )
  if (!loc) return null
  const enc = loc.github_path.split('/').map(encodeURIComponent).join('/')
  return `https://github.com/${loc.github_repo}/blob/HEAD/${enc}`
}
