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
