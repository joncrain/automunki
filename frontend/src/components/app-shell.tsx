'use client'

import { usePathname } from 'next/navigation'
import { Suspense } from 'react'
import { AppSidebar } from '@/components/app-sidebar'
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'

function pathHidesSidebar(pathname: string | null): boolean {
  if (!pathname) return false
  if (pathname === '/login' || pathname === '/register') return true
  if (pathname.startsWith('/auth/')) return true
  return false
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const authLayout = pathHidesSidebar(pathname)

  if (authLayout) {
    return (
      <main className="min-h-svh min-w-0 flex-1">
        <Suspense>{children}</Suspense>
      </main>
    )
  }

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4 md:hidden">
          <SidebarTrigger />
          <span className="font-semibold">AutoMunki</span>
        </header>
        <main className="min-w-0 flex-1 overflow-auto">
          <Suspense>
            <div className="container mx-auto min-w-0 max-w-full p-6">
              {children}
            </div>
          </Suspense>
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
