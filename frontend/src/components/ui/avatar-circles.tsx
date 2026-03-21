'use client'

import { useState } from 'react'
import { avatarColor, initials } from '@/lib/format'
import { cn } from '@/lib/utils'

export interface AvatarCircleItem {
  imageUrl: string
  /** Used when `interactive` is true */
  profileUrl?: string
  alt?: string
  /** Stable key for `avatarColor()` (e.g. pkg name); same idea as `SoftwareIcon`’s `name` */
  name?: string
}

interface AvatarCirclesProps {
  className?: string
  numPeople?: number
  avatarUrls: AvatarCircleItem[]
  /** When false, renders non-link wrappers so the component can live inside a parent link */
  interactive?: boolean
  circleClassName?: string
}

function AvatarCircleCell({
  item,
  index,
  circleCn,
  interactive,
}: {
  item: AvatarCircleItem
  index: number
  circleCn: string
  interactive: boolean
}) {
  const [imgFailed, setImgFailed] = useState(false)
  const alt = item.alt ?? item.name ?? `Avatar ${index + 1}`
  const colorKey = item.name ?? item.alt ?? `idx-${index}`
  const label = item.alt ?? item.name ?? '?'

  const shell = cn(
    'flex shrink-0 items-center justify-center overflow-hidden rounded-full border-2 border-white font-bold text-xs dark:border-gray-800',
    circleCn,
    avatarColor(colorKey),
  )

  const inner = imgFailed ? (
    <span aria-hidden>{initials(label)}</span>
  ) : (
    <img
      className="size-full object-cover"
      src={item.imageUrl}
      alt={alt}
      onError={() => setImgFailed(true)}
    />
  )

  const body = (
    <div className={shell} aria-label={imgFailed ? alt : undefined}>
      {inner}
    </div>
  )

  if (!interactive) {
    return <span className="inline-flex shrink-0">{body}</span>
  }
  return (
    <a
      href={item.profileUrl ?? '#'}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex shrink-0"
    >
      {body}
    </a>
  )
}

export const AvatarCircles = ({
  numPeople,
  className,
  avatarUrls,
  interactive = true,
  circleClassName,
}: AvatarCirclesProps) => {
  const circleCn = circleClassName ?? 'h-10 w-10'
  const overflowInner = (
    <span className="text-center text-xs font-medium text-white dark:text-black">
      +{numPeople}
    </span>
  )
  const overflowShellClass = cn(
    'flex items-center justify-center rounded-full border-2 border-white bg-black hover:bg-gray-600 dark:border-gray-800 dark:bg-white',
    circleCn,
  )

  return (
    <div className={cn('z-10 flex -space-x-4 rtl:space-x-reverse', className)}>
      {avatarUrls.map((item, index) => (
        <AvatarCircleCell
          key={index}
          item={item}
          index={index}
          circleCn={circleCn}
          interactive={interactive}
        />
      ))}
      {(numPeople ?? 0) > 0 &&
        (interactive ? (
          <a
            className={cn(overflowShellClass, 'text-center')}
            href=""
            aria-label={`${numPeople} more`}
          >
            {overflowInner}
          </a>
        ) : (
          <span
            className={cn(overflowShellClass, 'shrink-0')}
            aria-label={`${numPeople} more`}
          >
            {overflowInner}
          </span>
        ))}
    </div>
  )
}
