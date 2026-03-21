'use client'

import { useEffect, useState } from 'react'
import { avatarColor, initials } from '@/lib/format'

interface SoftwareIconProps {
  name: string
  displayName?: string | null
  iconName?: string | null
  size?: 'sm' | 'md' | 'lg'
  className?: string
  /** Bump after uploading a new PNG so the browser reloads ``/icons/….png``. */
  cacheRevision?: number
}

const sizeClasses = {
  sm: 'h-8 w-8 text-xs rounded-md',
  md: 'h-10 w-10 text-sm rounded-lg',
  lg: 'h-12 w-12 text-lg rounded-lg',
}

function iconUrl(name: string, cacheRevision?: number): string {
  const base = `/icons/${encodeURIComponent(name)}.png`
  return cacheRevision !== undefined ? `${base}?v=${cacheRevision}` : base
}

export function SoftwareIcon({
  name,
  displayName,
  iconName,
  size = 'sm',
  className = '',
  cacheRevision,
}: SoftwareIconProps) {
  const [imgFailed, setImgFailed] = useState(false)

  const candidateName = iconName || name

  useEffect(() => {
    setImgFailed(false)
  }, [candidateName, cacheRevision])
  const alt = displayName || name
  const sizeClass = sizeClasses[size]

  if (imgFailed) {
    return (
      <div
        className={`flex shrink-0 items-center justify-center font-bold ${sizeClass} ${avatarColor(name)} ${className}`}
      >
        {initials(alt)}
      </div>
    )
  }

  return (
    <div
      className={`flex shrink-0 items-center justify-center overflow-hidden font-bold ${sizeClass} ${avatarColor(name)} ${className}`}
    >
      <img
        width={48}
        height={48}
        src={iconUrl(candidateName, cacheRevision)}
        alt={alt}
        className="size-full object-cover"
        onError={() => setImgFailed(true)}
      />
    </div>
  )
}
