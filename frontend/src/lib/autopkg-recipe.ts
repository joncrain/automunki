import type { AutoPkgRecipeRead } from '@/lib/api'

/** Canonical recipe Input dict: override plist first, then legacy ``input_variables``. */
export function recipeInputDict(
  recipe: AutoPkgRecipeRead,
): Record<string, unknown> | null {
  const od = recipe.override_data as Record<string, unknown> | null | undefined
  if (od?.Input && typeof od.Input === 'object') {
    return od.Input as Record<string, unknown>
  }
  return (recipe.input_variables as Record<string, unknown> | null) ?? null
}

export function extractPkginfo(
  inputVars: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (!inputVars || typeof inputVars !== 'object') return {}
  const pkginfo = inputVars.pkginfo
  if (!pkginfo || typeof pkginfo !== 'object') return {}
  return pkginfo as Record<string, unknown>
}

/** Split catalog names from the recipe UI (commas, slashes, or pipes). */
export function parseCatalogListInput(raw: string): string[] {
  return raw
    .split(/[,/|]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Munki catalog names from ``Input.pkginfo.catalogs`` on the recipe. */
export function pkginfoCatalogsFromInput(
  inputVars: Record<string, unknown> | null | undefined,
): string[] {
  const c = extractPkginfo(inputVars).catalogs
  if (Array.isArray(c)) {
    return c.filter((x): x is string => typeof x === 'string')
  }
  return []
}

export function pkginfoCatalogsFromRecipe(recipe: AutoPkgRecipeRead): string[] {
  return pkginfoCatalogsFromInput(recipeInputDict(recipe))
}

export function recipeInputName(recipe: AutoPkgRecipeRead): string {
  const inp = recipeInputDict(recipe)
  const n = inp?.NAME
  return typeof n === 'string' && n.trim() ? n : ''
}

/** Munki pkg name for icon / pkginfo lookup: recipe ``Input.NAME`` or recipe file name. */
export function recipePkginfoKey(recipe: AutoPkgRecipeRead): string {
  return recipeInputName(recipe) || recipe.name
}

/**
 * Template tokens sometimes stored in override pkginfo ``name`` — not valid Munki
 * package ids or icon stems (would save as e.g. ``NAME.png`` and clobber other apps).
 */
export function isPkginfoNamePlaceholder(name: string): boolean {
  const s = name.trim()
  if (!s) return true
  if (/^%NAME%$/i.test(s)) return true
  if (/^NAME$/i.test(s)) return true
  if (/^\$\{NAME\}$/.test(s)) return true
  if (/^%\{NAME\}%$/.test(s)) return true
  if (/^%name%$/i.test(s)) return true
  return false
}

/**
 * Stable basename for icons / UI: ``Input.NAME`` (resolved product name), else literal
 * pkginfo ``name`` when not a template, else recipe file name.
 */
export function recipeIconUploadBasename(
  pkginfo: Record<string, unknown>,
  recipe: AutoPkgRecipeRead,
): string {
  const fromInput = recipeInputName(recipe)
  if (fromInput) return fromInput
  const raw = pkginfo.name
  if (typeof raw === 'string' && raw.trim() && !isPkginfoNamePlaceholder(raw)) {
    return raw.trim()
  }
  return recipe.name
}

/** ``icon_name`` from ``Input.pkginfo`` on the recipe (may differ from DB until pkginfo is imported). */
export function recipePkginfoIconName(
  recipe: AutoPkgRecipeRead,
): string | null {
  const pi = extractPkginfo(recipeInputDict(recipe))
  const v = pi.icon_name
  return typeof v === 'string' && v.trim() ? v.trim() : null
}

/** Prefer catalog/pkginfo DB value; fall back to the recipe override’s pkginfo. */
export function recipeListIconName(
  dbIconName: string | null | undefined,
  recipe: AutoPkgRecipeRead,
): string | undefined {
  const fromDb = dbIconName?.trim()
  if (fromDb) return fromDb
  return recipePkginfoIconName(recipe) ?? undefined
}

export function extractNonPkginfoInput(
  inputVars: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (!inputVars || typeof inputVars !== 'object') return {}
  const result: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(inputVars)) {
    if (k !== 'pkginfo') result[k] = v
  }
  return result
}
