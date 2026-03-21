const dateFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
})

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
})

export function formatDate(value: string | Date): string {
  const d = typeof value === 'string' ? new Date(value) : value
  return dateFormatter.format(d)
}

export function formatDateTime(value: string | Date): string {
  const d = typeof value === 'string' ? new Date(value) : value
  return dateTimeFormatter.format(d)
}

/** Past-only relative label (e.g. "3 days ago"). */
export function formatRelativeTimeAgo(iso: string | Date): string {
  const then = typeof iso === 'string' ? new Date(iso).getTime() : iso.getTime()
  if (Number.isNaN(then)) return '—'
  const now = Date.now()
  const diffSec = Math.max(0, Math.floor((now - then) / 1000))
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  if (diffSec < 45) return rtf.format(-diffSec, 'second')
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return rtf.format(-diffMin, 'minute')
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 48) return rtf.format(-diffHr, 'hour')
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 60) return rtf.format(-diffDay, 'day')
  const diffMonth = Math.floor(diffDay / 30)
  if (diffMonth < 24) return rtf.format(-diffMonth, 'month')
  const diffYear = Math.floor(diffDay / 365)
  return rtf.format(-diffYear, 'year')
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
  return `${Math.round(bytes / (1024 * 1024))} MB`
}

export function initials(name: string): string {
  return name
    .split(/[\s-_]+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? '')
    .join('')
}

const AVATAR_COLORS = [
  'bg-gruvbox-blue/15 text-gruvbox-blue',
  'bg-gruvbox-green/15 text-gruvbox-green',
  'bg-gruvbox-purple/15 text-gruvbox-purple',
  'bg-gruvbox-yellow/15 text-gruvbox-yellow',
  'bg-gruvbox-red/15 text-gruvbox-red',
  'bg-gruvbox-aqua/15 text-gruvbox-aqua',
  'bg-gruvbox-orange/15 text-gruvbox-orange',
  'bg-primary/15 text-primary',
]

export function avatarColor(name: string): string {
  let hash = 0
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash)
  }
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length]
}
