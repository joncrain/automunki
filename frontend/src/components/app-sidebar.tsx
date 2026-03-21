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
} from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ThemeToggle } from '@/components/theme-toggle'
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

const navGroups = [
  {
    label: 'Overview',
    items: [{ href: '/', label: 'Dashboard', icon: LayoutDashboard }],
  },
  {
    label: 'Munki',
    items: [
      { href: '/software', label: 'Software', icon: Package },
      { href: '/manifests', label: 'Manifests', icon: FileText },
      { href: '/catalogs', label: 'Catalogs', icon: FolderOpen },
    ],
  },
  {
    label: 'AutoPkg',
    items: [
      { href: '/autopkg/runs', label: 'Runs', icon: Play },
      { href: '/autopkg/recipes', label: 'Recipes', icon: BookOpen },
      { href: '/autopkg/discover', label: 'Discover', icon: Compass },
      { href: '/approvals', label: 'Approvals', icon: CheckCircle },
    ],
  },
  {
    label: 'Reporting',
    items: [
      { href: '/reporting', label: 'Devices', icon: MonitorSmartphone },
      { href: '/reporting/installs', label: 'Installs', icon: ListChecks },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '/audit', label: 'Audit Log', icon: ClipboardList },
      { href: '/settings', label: 'Settings', icon: Settings },
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
  return (
    pathname === item.href ||
    (item.href !== '/' && pathname.startsWith(item.href))
  )
}

export function AppSidebar() {
  const pathname = usePathname()

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
        {navGroups.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => {
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
        ))}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <div className="flex items-center">
              <ThemeToggle />
            </div>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}
