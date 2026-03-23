/**
 * Munki manifest conditional_items (array of blocks with NSPredicate `condition`).
 * @see https://github.com/munki/munki/wiki/Conditional-Items
 */

export type ConditionalItemBlock = {
  /** Client-only; omitted when saving to the API */
  _uiId?: string
  condition: string
  managed_installs?: string[]
  managed_uninstalls?: string[]
  managed_updates?: string[]
  optional_installs?: string[]
  featured_items?: string[]
  default_installs?: string[]
  included_manifests?: string[]
  conditional_items?: ConditionalItemBlock[]
}

const LIST_KEYS = [
  'managed_installs',
  'managed_uninstalls',
  'managed_updates',
  'optional_installs',
  'featured_items',
  'default_installs',
] as const satisfies ReadonlyArray<keyof ConditionalItemBlock>

function normalizeBlock(raw: Record<string, unknown>): ConditionalItemBlock {
  const condition =
    typeof raw.condition === 'string' ? raw.condition.trim() : ''
  const block: ConditionalItemBlock = {
    _uiId: crypto.randomUUID(),
    condition,
  }

  for (const key of LIST_KEYS) {
    const v = raw[key]
    if (Array.isArray(v) && v.every((x) => typeof x === 'string') && v.length) {
      block[key] = [...v]
    }
  }

  const inc = raw.included_manifests
  if (
    Array.isArray(inc) &&
    inc.every((x) => typeof x === 'string') &&
    inc.length
  ) {
    block.included_manifests = [...inc]
  }

  const nested = raw.conditional_items
  if (Array.isArray(nested) && nested.length) {
    block.conditional_items = nested
      .filter((n) => n && typeof n === 'object')
      .map((n) => normalizeBlock(n as Record<string, unknown>))
  }

  return block
}

/** Parse API / plist-backed JSON into editable blocks (skips invalid entries). */
export function parseConditionalItemsFromApi(
  raw: unknown,
): ConditionalItemBlock[] {
  if (raw == null || !Array.isArray(raw)) return []
  const out: ConditionalItemBlock[] = []
  for (const x of raw) {
    if (x && typeof x === 'object' && 'condition' in x) {
      out.push(normalizeBlock(x as Record<string, unknown>))
    }
  }
  return out
}

function serializeOneBlock(
  b: ConditionalItemBlock,
): ConditionalItemBlock | null {
  const { _uiId: _unused, ...rest } = b
  void _unused
  const c = rest.condition.trim()
  if (!c) return null
  const o: ConditionalItemBlock = { condition: c }

  for (const key of LIST_KEYS) {
    const arr = rest[key]
    if (arr?.length) o[key] = [...arr]
  }

  if (rest.included_manifests?.length) {
    o.included_manifests = [...rest.included_manifests]
  }

  if (rest.conditional_items?.length) {
    const nested = rest.conditional_items
      .map(serializeOneBlock)
      .filter(Boolean) as ConditionalItemBlock[]
    if (nested.length) o.conditional_items = nested
  }

  return o
}

/** Shape sent to PUT /manifests (null clears / matches backend empty). */
export function serializeConditionalItemsForApi(
  blocks: ConditionalItemBlock[],
): ConditionalItemBlock[] | null {
  const out: ConditionalItemBlock[] = []
  for (const b of blocks) {
    const s = serializeOneBlock(b)
    if (s) out.push(s)
  }
  return out.length ? out : null
}

function validateBlockRecursive(
  b: ConditionalItemBlock,
  path: string,
): string | null {
  if (!b.condition.trim()) {
    return `Empty condition in ${path}`
  }
  const nested = b.conditional_items
  if (nested) {
    for (let i = 0; i < nested.length; i++) {
      const err = validateBlockRecursive(
        nested[i],
        `${path} → nested #${i + 1}`,
      )
      if (err) return err
    }
  }
  return null
}

export function validateConditionalBlocks(
  blocks: ConditionalItemBlock[],
): string | null {
  for (let i = 0; i < blocks.length; i++) {
    const err = validateBlockRecursive(blocks[i], `block #${i + 1}`)
    if (err) return err
  }
  return null
}

export function collectManifestItemRefsFromConditional(
  blocks: ConditionalItemBlock[],
): string[] {
  const out: string[] = []
  function walk(b: ConditionalItemBlock) {
    for (const key of LIST_KEYS) {
      const arr = b[key]
      if (arr) out.push(...arr)
    }
    for (const c of b.conditional_items ?? []) walk(c)
  }
  for (const b of blocks) walk(b)
  return out
}

export function newConditionalBlock(): ConditionalItemBlock {
  return { _uiId: crypto.randomUUID(), condition: 'arch == "arm64"' }
}

export function getBlockAtPath(
  blocks: ConditionalItemBlock[],
  path: number[],
): ConditionalItemBlock | undefined {
  let list = blocks
  let cur: ConditionalItemBlock | undefined
  for (const i of path) {
    cur = list[i]
    if (!cur) return undefined
    list = cur.conditional_items ?? []
  }
  return cur
}

export function setBlockAtPath(
  blocks: ConditionalItemBlock[],
  path: number[],
  next: ConditionalItemBlock,
): ConditionalItemBlock[] {
  if (path.length === 0) return blocks
  const [head, ...rest] = path
  if (rest.length === 0) {
    return blocks.map((b, i) => (i === head ? next : b))
  }
  return blocks.map((b, i) =>
    i === head
      ? {
          ...b,
          conditional_items: setBlockAtPath(
            b.conditional_items ?? [],
            rest,
            next,
          ),
        }
      : b,
  )
}

export function removeBlockAtPath(
  blocks: ConditionalItemBlock[],
  path: number[],
): ConditionalItemBlock[] {
  if (path.length === 0) return blocks
  const [head, ...rest] = path
  if (rest.length === 0) {
    return blocks.filter((_, i) => i !== head)
  }
  return blocks.map((b, i) =>
    i === head
      ? {
          ...b,
          conditional_items: removeBlockAtPath(b.conditional_items ?? [], rest),
        }
      : b,
  )
}

export function appendNestedBlockAtPath(
  blocks: ConditionalItemBlock[],
  parentPath: number[],
  child: ConditionalItemBlock,
): ConditionalItemBlock[] {
  if (parentPath.length === 0) {
    return [...blocks, child]
  }
  const [head, ...rest] = parentPath
  return blocks.map((b, i) => {
    if (i !== head) return b
    if (rest.length === 0) {
      const kids = [...(b.conditional_items ?? []), child]
      return { ...b, conditional_items: kids }
    }
    return {
      ...b,
      conditional_items: appendNestedBlockAtPath(
        b.conditional_items ?? [],
        rest,
        child,
      ),
    }
  })
}

export function reorderBlockAmongSiblings(
  blocks: ConditionalItemBlock[],
  pathToParent: number[],
  fromIndex: number,
  toIndex: number,
): ConditionalItemBlock[] {
  if (pathToParent.length === 0) {
    const next = [...blocks]
    const [moved] = next.splice(fromIndex, 1)
    next.splice(toIndex, 0, moved)
    return next
  }
  const [head, ...rest] = pathToParent
  return blocks.map((b, i) =>
    i === head
      ? {
          ...b,
          conditional_items: reorderBlockAmongSiblings(
            b.conditional_items ?? [],
            rest,
            fromIndex,
            toIndex,
          ),
        }
      : b,
  )
}
