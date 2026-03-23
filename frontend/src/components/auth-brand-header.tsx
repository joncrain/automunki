import { Package } from 'lucide-react'
import Link from 'next/link'

/** Matches the sidebar app identity; use on sign-in and other auth screens. */
export function AuthBrandHeader() {
  return (
    <div className="mb-2 flex justify-center">
      <Link
        href="/"
        className="flex items-center gap-3 rounded-lg outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring"
      >
        <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <Package className="size-5" />
        </div>
        <div className="min-w-0 text-left">
          <div className="text-lg font-semibold tracking-tight">AutoMunki</div>
          <div className="text-sm text-muted-foreground">Munki Management</div>
        </div>
      </Link>
    </div>
  )
}
