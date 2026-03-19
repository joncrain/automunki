import type { Metadata } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import { Suspense } from 'react'
import './globals.css'
import { AppSidebar } from '@/components/app-sidebar'
import { Providers } from '@/components/providers'
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
})

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
})

export const metadata: Metadata = {
  title: 'AutoMunki',
  description: 'Munki and AutoPkg web management platform',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <Providers>
          <SidebarProvider>
            <AppSidebar />
            <SidebarInset>
              <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4 md:hidden">
                <SidebarTrigger />
                <span className="font-semibold">AutoMunki</span>
              </header>
              <main className="flex-1 overflow-auto">
                <Suspense>
                  <div className="container mx-auto p-6">{children}</div>
                </Suspense>
              </main>
            </SidebarInset>
          </SidebarProvider>
        </Providers>
      </body>
    </html>
  )
}
