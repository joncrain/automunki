'use client'

import type { ComponentType } from 'react'
import { useState } from 'react'
import { cn } from '@/lib/utils'

/**
 * Primary artwork: Apple’s public FMIP device thumbnails (same URLs as MunkiReport’s
 * `get_model_icon` in [munkireport/machine](https://github.com/munkireport/machine)).
 * Falls back to SVG silhouettes if the URL fails or is missing.
 */

export type MacFormFactor =
  | 'laptop'
  | 'imac'
  | 'mini'
  | 'tower'
  | 'studio'
  | 'generic'

export function inferMacFormFactor(
  machineModel: string | null | undefined,
  productName: string | null | undefined,
): MacFormFactor {
  const blob = `${machineModel ?? ''} ${productName ?? ''}`.toLowerCase()
  if (blob.includes('book')) return 'laptop'
  if (blob.includes('imac')) return 'imac'
  if (blob.includes('studio')) return 'studio'
  if (blob.includes('mini')) return 'mini'
  if (blob.includes('macpro')) return 'tower'
  if (blob.includes('mac pro')) return 'tower'
  return 'generic'
}

function LaptopSilhouette({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 200 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <rect
        x="28"
        y="18"
        width="144"
        height="82"
        rx="6"
        className="stroke-muted-foreground/50"
        strokeWidth="2"
      />
      <path
        d="M12 102h176l-8 8H20l-8-8z"
        className="fill-muted/50 stroke-muted-foreground/40"
        strokeWidth="1.5"
      />
      <rect
        x="40"
        y="30"
        width="120"
        height="56"
        rx="2"
        className="fill-muted/30"
      />
    </svg>
  )
}

function ImacSilhouette({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 200 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <rect
        x="36"
        y="16"
        width="128"
        height="72"
        rx="4"
        className="stroke-muted-foreground/50"
        strokeWidth="2"
      />
      <rect
        x="44"
        y="24"
        width="112"
        height="56"
        rx="2"
        className="fill-muted/35"
      />
      <path
        d="M88 88h24v6H88zm-12 6h48l-6 14H94l-6-14z"
        className="fill-muted/60 stroke-muted-foreground/35"
        strokeWidth="1"
      />
    </svg>
  )
}

function MiniSilhouette({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 200 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <rect
        x="52"
        y="44"
        width="96"
        height="36"
        rx="4"
        className="stroke-muted-foreground/50 fill-muted/25"
        strokeWidth="2"
      />
      <circle cx="100" cy="62" r="3" className="fill-muted-foreground/35" />
    </svg>
  )
}

function TowerSilhouette({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 200 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <rect
        x="68"
        y="20"
        width="64"
        height="88"
        rx="4"
        className="stroke-muted-foreground/50 fill-muted/20"
        strokeWidth="2"
      />
      <rect
        x="76"
        y="32"
        width="48"
        height="6"
        rx="1"
        className="fill-muted/45"
      />
      <rect
        x="76"
        y="44"
        width="48"
        height="6"
        rx="1"
        className="fill-muted/45"
      />
      <rect
        x="76"
        y="56"
        width="48"
        height="6"
        rx="1"
        className="fill-muted/45"
      />
    </svg>
  )
}

function StudioSilhouette({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 200 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <title>Compact desktop</title>
      <rect
        x="48"
        y="40"
        width="104"
        height="44"
        rx="20"
        className="stroke-muted-foreground/50 fill-muted/25"
        strokeWidth="2"
      />
      <rect
        x="72"
        y="84"
        width="56"
        height="8"
        rx="2"
        className="fill-muted/50"
      />
    </svg>
  )
}

function GenericSilhouette({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 200 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <rect
        x="40"
        y="28"
        width="120"
        height="64"
        rx="8"
        className="stroke-muted-foreground/45 fill-muted/20"
        strokeWidth="2"
      />
      <path
        d="M100 22v8M100 92v8"
        className="stroke-muted-foreground/30"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  )
}

const SILHOUETTES: Record<
  MacFormFactor,
  ComponentType<{ className?: string }>
> = {
  laptop: LaptopSilhouette,
  imac: ImacSilhouette,
  mini: MiniSilhouette,
  tower: TowerSilhouette,
  studio: StudioSilhouette,
  generic: GenericSilhouette,
}

export function MacDeviceHeroVisual({
  machineModel,
  productName,
  imageUrl,
  className,
}: {
  machineModel: string | null | undefined
  productName: string | null | undefined
  /** Apple CDN thumbnail when available. */
  imageUrl?: string | null
  className?: string
}) {
  const factor = inferMacFormFactor(machineModel, productName)
  const Silhouette = SILHOUETTES[factor]
  const [rasterFailed, setRasterFailed] = useState(false)
  const showRaster = Boolean(imageUrl && !rasterFailed)
  const alt =
    [productName, machineModel].filter(Boolean).join(' · ') || 'Mac hardware'

  return (
    <div
      className={cn(
        'relative flex aspect-[5/3] w-full max-w-md items-center justify-center overflow-hidden rounded-2xl border bg-gradient-to-br from-muted/60 via-background to-gruvbox-blue/[0.07] dark:to-gruvbox-aqua/[0.08]',
        className,
      )}
    >
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_30%_20%,var(--tw-gradient-stops))] from-gruvbox-blue/10 via-transparent to-transparent dark:from-gruvbox-aqua/15" />
      {showRaster ? (
        // Apple CDN URLs: plain img avoids next/image remotePatterns / loader edge cases (we do not optimize these).
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={imageUrl as string}
          alt={alt}
          className="absolute inset-0 z-[1] box-border object-contain p-6"
          onError={() => setRasterFailed(true)}
        />
      ) : (
        <Silhouette className="relative z-[1] h-[min(52%,9rem)] w-[85%] text-foreground opacity-90" />
      )}
    </div>
  )
}
