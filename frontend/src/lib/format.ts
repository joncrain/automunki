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
  'bg-blue-500/15 text-blue-700 dark:text-blue-400',
  'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400',
  'bg-violet-500/15 text-violet-700 dark:text-violet-400',
  'bg-amber-500/15 text-amber-700 dark:text-amber-400',
  'bg-rose-500/15 text-rose-700 dark:text-rose-400',
  'bg-cyan-500/15 text-cyan-700 dark:text-cyan-400',
  'bg-orange-500/15 text-orange-700 dark:text-orange-400',
  'bg-pink-500/15 text-pink-700 dark:text-pink-400',
]

export function avatarColor(name: string): string {
  let hash = 0
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash)
  }
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length]
}
