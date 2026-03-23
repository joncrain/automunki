'use client'

import {
  BookOpen,
  CheckCircle,
  ClipboardList,
  Compass,
  FileText,
  FolderOpen,
  LayoutDashboard,
  ListChecks,
  MonitorSmartphone,
  Package,
  Play,
  Settings,
  Shield,
} from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import type { ComponentType } from 'react'
import { useAuth } from '@/components/auth-provider'
import { SidebarUserMenu } from '@/components/sidebar-user-menu'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { PAGE_KEYS } from '@/lib/page-keys'

const navGroups: {
  label: string
  items: {
    href: string
    label: string
    icon: ComponentType<{ className?: string }>
    pageKey: string
  }[]
}[] = [
  {
    label: 'Overview',
    items: [
      {
        href: '/',
        label: 'Dashboard',
        icon: LayoutDashboard,
        pageKey: PAGE_KEYS.overview,
      },
    ],
  },
  {
    label: 'Munki',
    items: [
      {
        href: '/software',
        label: 'Software',
        icon: Package,
        pageKey: PAGE_KEYS.munkiSoftware,
      },
      {
        href: '/manifests',
        label: 'Manifests',
        icon: FileText,
        pageKey: PAGE_KEYS.munkiManifests,
      },
      {
        href: '/catalogs',
        label: 'Catalogs',
        icon: FolderOpen,
        pageKey: PAGE_KEYS.munkiCatalogs,
      },
    ],
  },
  {
    label: 'AutoPkg',
    items: [
      {
        href: '/autopkg/runs',
        label: 'Runs',
        icon: Play,
        pageKey: PAGE_KEYS.autopkgRuns,
      },
      {
        href: '/autopkg/recipes',
        label: 'Recipes',
        icon: BookOpen,
        pageKey: PAGE_KEYS.autopkgRecipes,
      },
      {
        href: '/autopkg/discover',
        label: 'Discover',
        icon: Compass,
        pageKey: PAGE_KEYS.autopkgDiscover,
      },
      {
        href: '/approvals',
        label: 'Approvals',
        icon: CheckCircle,
        pageKey: PAGE_KEYS.autopkgApprovals,
      },
    ],
  },
  {
    label: 'Reporting',
    items: [
      {
        href: '/reporting',
        label: 'Devices',
        icon: MonitorSmartphone,
        pageKey: PAGE_KEYS.reportingDevices,
      },
      {
        href: '/reporting/installs',
        label: 'Installs',
        icon: ListChecks,
        pageKey: PAGE_KEYS.reportingInstalls,
      },
    ],
  },
  {
    label: 'Admin',
    items: [
      {
        href: '/audit',
        label: 'Audit Log',
        icon: ClipboardList,
        pageKey: PAGE_KEYS.adminAudit,
      },
      {
        href: '/settings',
        label: 'Settings',
        icon: Settings,
        pageKey: PAGE_KEYS.adminSettings,
      },
      {
        href: '/admin/access',
        label: 'Access',
        icon: Shield,
        pageKey: PAGE_KEYS.adminAccess,
      },
    ],
  },
]

function navItemIsActive(
  pathname: string,
  item: { href: string; label: string },
) {
  if (item.href === '/reporting' && item.label === 'Devices') {
    return (
      pathname === '/reporting' || pathname.startsWith('/reporting/devices/')
    )
  }
  if (item.href === '/reporting/installs') {
    return pathname.startsWith('/reporting/installs')
  }
  if (item.href === '/settings') {
    return pathname === '/settings'
  }
  return (
    pathname === item.href ||
    (item.href !== '/' && pathname.startsWith(item.href))
  )
}

export function AppSidebar() {
  const pathname = usePathname()
  const { canRead, loading, me } = useAuth()

  const showItem = (pageKey: string) => {
    // While /auth/me is loading, show full nav (headings + items).
    if (loading) return true
    return canRead(pageKey)
  }

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link href="/">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <Package className="size-4" />
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-semibold">AutoMunki</span>
                  <span className="truncate text-xs text-muted-foreground">
                    Munki Management
                  </span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {navGroups.map((group) => {
          const visibleItems = group.items.filter((item) =>
            showItem(item.pageKey),
          )
          if (visibleItems.length === 0) {
            return null
          }
          return (
            <SidebarGroup key={group.label}>
              <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {visibleItems.map((item) => {
                    const isActive = navItemIsActive(pathname, item)
                    return (
                      <SidebarMenuItem key={item.href}>
                        <SidebarMenuButton asChild isActive={isActive}>
                          <Link href={item.href}>
                            <item.icon className="size-4" />
                            <span>{item.label}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    )
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          )
        })}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          {me ? (
            <SidebarMenuItem>
              <SidebarUserMenu />
            </SidebarMenuItem>
          ) : null}
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}
