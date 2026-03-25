'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import {
  Activity,
  Code2,
  Download,
  FileText,
  History,
  Package,
  Pencil,
  Plus,
  Save,
  ScanSearch,
  Trash2,
  X,
} from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useCallback, useEffect, useState } from 'react'
import { toast } from 'sonner'
import { useAuth } from '@/components/auth-provider'
import { DataTable } from '@/components/data-table'
import { PkginfoIconUpload } from '@/components/pkginfo-icon-upload'
import { SoftwareInstallTimelineChart } from '@/components/reporting/software-install-timeline-chart'
import { SoftwareIcon } from '@/components/software-icon'
import { Badge } from '@/components/ui/badge'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import {
  type AuditLogRead,
  api,
  type CatalogRead,
  type ClientInstallReportListItem,
  type InstallItem,
  type ItemToCopy,
  type PaginatedResponse,
  type PkgInfoDetail,
  type PkgInfoInstallReportSummary,
  type ReceiptItem,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { PAGE_KEYS } from '@/lib/page-keys'
import { cn } from '@/lib/utils'

function softwareInstallReportStatusVariant(status: string) {
  switch (status) {
    case 'installed':
      return 'default' as const
    case 'failed':
    case 'removal_failed':
      return 'destructive' as const
    case 'removed':
      return 'secondary' as const
    default:
      return 'outline' as const
  }
}

const SOFTWARE_INSTALL_REPORT_COLUMNS: ColumnDef<ClientInstallReportListItem>[] =
  [
    {
      accessorKey: 'created_at',
      header: 'Reported',
      cell: ({ row }) => (
        <span suppressHydrationWarning className="text-sm">
          {formatDateTime(row.original.created_at)}
        </span>
      ),
    },
    {
      accessorKey: 'item_version',
      header: 'Version',
      cell: ({ row }) => row.original.item_version || '—',
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => (
        <Badge
          variant={softwareInstallReportStatusVariant(row.original.status)}
        >
          {row.original.status}
        </Badge>
      ),
    },
    {
      accessorKey: 'hostname',
      header: 'Device',
      cell: ({ row }) => (
        <Link
          href={`/reporting/devices/${row.original.machine_id}`}
          className="text-primary underline-offset-4 hover:underline"
        >
          {row.original.hostname || row.original.serial_number || '—'}
        </Link>
      ),
    },
    {
      accessorKey: 'install_date',
      header: 'Install time',
      cell: ({ row }) =>
        row.original.install_date ? (
          <span suppressHydrationWarning className="text-sm">
            {formatDateTime(row.original.install_date)}
          </span>
        ) : (
          '—'
        ),
    },
    {
      accessorKey: 'error_message',
      header: 'Note',
      cell: ({ row }) => (
        <span className="line-clamp-2 max-w-[240px] text-sm text-muted-foreground">
          {row.original.error_message || '—'}
        </span>
      ),
    },
  ]

const softwareDetailTabContentClass = cn(
  'space-y-4',
  'animate-in fade-in-0 slide-in-from-bottom-1 duration-300',
)

function softwareDetailTabTrigger(activeRing: string) {
  return cn(
    'group/tab flex-none gap-2 px-4 py-2.5 min-h-11 rounded-lg border border-transparent',
    'text-muted-foreground transition-[transform,box-shadow,background-color,border-color,color] duration-200 ease-out will-change-transform',
    'hover:bg-background/80 hover:text-foreground',
    'data-[state=inactive]:hover:scale-[1.03] data-[state=inactive]:hover:-translate-y-0.5',
    'data-[state=inactive]:hover:border-border/35 data-[state=inactive]:hover:shadow-sm',
    'data-[state=active]:scale-[1.02] data-[state=active]:bg-background data-[state=active]:shadow-md',
    'data-[state=active]:border-border/60 data-[state=active]:hover:scale-[1.03]',
    'motion-reduce:data-[state=inactive]:hover:scale-100 motion-reduce:data-[state=inactive]:hover:translate-y-0',
    'motion-reduce:data-[state=active]:scale-100 motion-reduce:data-[state=active]:hover:scale-100',
    activeRing,
  )
}

const softwareTabIconClass =
  'size-4 shrink-0 opacity-70 transition-[opacity,transform] duration-200 ease-out group-hover/tab:opacity-100 group-data-[state=inactive]/tab:group-hover/tab:scale-105 group-data-[state=active]/tab:opacity-100 group-data-[state=active]/tab:scale-110 group-data-[state=active]/tab:group-hover/tab:scale-[1.18] motion-reduce:group-hover/tab:scale-100 motion-reduce:group-data-[state=active]/tab:scale-100 motion-reduce:group-data-[state=active]/tab:group-hover/tab:scale-100'

interface EditableFields {
  display_name: string
  description: string
  category: string
  developer: string
  icon_name: string
  installer_item_location: string
  installer_item_hash: string
  installer_item_size: number | null
  minimum_os_version: string
  maximum_os_version: string
  uninstall_method: string
  unattended_install: boolean
  unattended_uninstall: boolean
  autoremove: boolean
  uninstallable: boolean
  blocking_applications: string[]
  supported_architectures: string[]
  requires: string[]
  update_for: string[]
  installs: InstallItem[]
  receipts: ReceiptItem[]
  items_to_copy: ItemToCopy[]
  installcheck_script: string
  uninstallcheck_script: string
  version_script: string
  preinstall_script: string
  postinstall_script: string
  preuninstall_script: string
  postuninstall_script: string
  notes: string
  restart_action: string
  on_demand: boolean
  force_install_after_date: string
  apple_item: boolean
  installable_condition: string
  package_path: string
  package_complete_url: string
  minimum_munki_version: string
  installer_type: string
  installed_size: number | null
  uninstaller_item_location: string
}

function pkgToEditable(pkg: PkgInfoDetail): EditableFields {
  return {
    display_name: pkg.display_name ?? '',
    description: pkg.description ?? '',
    category: pkg.category ?? '',
    developer: pkg.developer ?? '',
    icon_name: pkg.icon_name ?? '',
    installer_item_location: pkg.installer_item_location ?? '',
    installer_item_hash: pkg.installer_item_hash ?? '',
    installer_item_size: pkg.installer_item_size,
    minimum_os_version: pkg.minimum_os_version ?? '',
    maximum_os_version: pkg.maximum_os_version ?? '',
    uninstall_method: pkg.uninstall_method ?? '',
    unattended_install: pkg.unattended_install,
    unattended_uninstall: pkg.unattended_uninstall,
    autoremove: pkg.autoremove,
    uninstallable: pkg.uninstallable,
    blocking_applications: pkg.blocking_applications ?? [],
    supported_architectures: pkg.supported_architectures ?? [],
    requires: pkg.requires ?? [],
    update_for: pkg.update_for ?? [],
    installs: pkg.installs ?? [],
    receipts: pkg.receipts ?? [],
    items_to_copy: pkg.items_to_copy ?? [],
    installcheck_script: pkg.installcheck_script ?? '',
    uninstallcheck_script: pkg.uninstallcheck_script ?? '',
    version_script: pkg.version_script ?? '',
    preinstall_script: pkg.preinstall_script ?? '',
    postinstall_script: pkg.postinstall_script ?? '',
    preuninstall_script: pkg.preuninstall_script ?? '',
    postuninstall_script: pkg.postuninstall_script ?? '',
    notes: pkg.notes ?? '',
    restart_action: pkg.restart_action ?? '',
    on_demand: pkg.on_demand,
    force_install_after_date: pkg.force_install_after_date ?? '',
    apple_item: pkg.apple_item,
    installable_condition: pkg.installable_condition ?? '',
    package_path: pkg.package_path ?? '',
    package_complete_url: pkg.package_complete_url ?? '',
    minimum_munki_version: pkg.minimum_munki_version ?? '',
    installer_type: pkg.installer_type ?? '',
    installed_size: pkg.installed_size,
    uninstaller_item_location: pkg.uninstaller_item_location ?? '',
  }
}

function buildUpdatePayload(
  original: EditableFields,
  edited: EditableFields,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {}
  for (const key of Object.keys(edited) as (keyof EditableFields)[]) {
    const o = original[key]
    const e = edited[key]
    if (Array.isArray(o) && Array.isArray(e)) {
      if (JSON.stringify(o) !== JSON.stringify(e)) payload[key] = e
    } else if (o !== e) {
      if (typeof e === 'string') {
        payload[key] = e === '' ? null : e
      } else {
        payload[key] = e
      }
    }
  }
  return payload
}

export default function SoftwareDetailPage() {
  const params = useParams()
  const _router = useRouter()
  const queryClient = useQueryClient()
  const id = params.id as string

  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<EditableFields | null>(null)
  const [dirty, setDirty] = useState(false)
  const [iconRevision, setIconRevision] = useState(0)
  const [installReportPage, setInstallReportPage] = useState(1)
  const [installReportPageSize, setInstallReportPageSize] = useState(25)

  const { canWrite } = useAuth()
  const canMutateSoftware = canWrite(PAGE_KEYS.munkiSoftware)
  const effectiveEditing = editing && canMutateSoftware

  useEffect(() => {
    if (!canMutateSoftware) setEditing(false)
  }, [canMutateSoftware])

  const { data: pkg, isLoading } = useQuery({
    queryKey: ['pkginfo', id],
    queryFn: () => api.get<PkgInfoDetail>(`/pkginfo/${id}`),
  })

  const { data: auditTrail } = useQuery({
    queryKey: ['audit', 'pkg_info', id],
    queryFn: () => api.get<AuditLogRead[]>(`/audit/pkg_info/${id}`),
  })

  const { data: installSummary, isLoading: installSummaryLoading } = useQuery({
    queryKey: ['pkg-install-report-summary', id],
    queryFn: () =>
      api.get<PkgInfoInstallReportSummary>(
        `/pkginfo/${id}/install-reports/summary`,
      ),
    enabled: Boolean(id),
  })

  const { data: installReportRows, isLoading: installRowsLoading } = useQuery({
    queryKey: [
      'reports-installs',
      'for-pkg',
      id,
      pkg?.name,
      installReportPage,
      installReportPageSize,
    ],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set('page', String(installReportPage))
      params.set('page_size', String(installReportPageSize))
      params.set('item_name', pkg!.name)
      return api.get<PaginatedResponse<ClientInstallReportListItem>>(
        `/reports/installs?${params.toString()}`,
      )
    },
    enabled: Boolean(pkg?.name),
  })

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.put(`/pkginfo/${id}`, payload),
    onSuccess: () => {
      toast.success('Changes saved')
      queryClient.invalidateQueries({ queryKey: ['pkginfo', id] })
      queryClient.invalidateQueries({ queryKey: ['pkginfo-item-meta'] })
      queryClient.invalidateQueries({ queryKey: ['pkginfo-display-labels'] })
      setEditing(false)
      setDirty(false)
    },
    onError: (err: Error) => {
      toast.error(`Save failed: ${err.message}`)
    },
  })

  useEffect(() => {
    if (pkg && !form) setForm(pkgToEditable(pkg))
  }, [pkg, form])

  const handleBeforeUnload = useCallback(
    (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault()
    },
    [dirty],
  )

  useEffect(() => {
    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => window.removeEventListener('beforeunload', handleBeforeUnload)
  }, [handleBeforeUnload])

  const updateField = <K extends keyof EditableFields>(
    key: K,
    value: EditableFields[K],
  ) => {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev))
    setDirty(true)
  }

  const handleSave = () => {
    if (!form || !pkg) return
    const payload = buildUpdatePayload(pkgToEditable(pkg), form)
    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }
    saveMutation.mutate(payload)
  }

  const handleCancel = () => {
    if (pkg) setForm(pkgToEditable(pkg))
    setEditing(false)
    setDirty(false)
  }

  const handleDownloadPlist = async () => {
    try {
      const token =
        typeof window !== 'undefined' ? localStorage.getItem('token') : null
      const headers: Record<string, string> = {}
      if (token) headers.Authorization = `Bearer ${token}`

      const res = await fetch(`/api/v1/pkginfo/${id}/plist`, { headers })
      if (!res.ok) throw new Error('Failed to fetch plist')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${pkg?.name ?? 'pkginfo'}-${pkg?.version ?? '0'}.plist`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch {
      toast.error('Failed to download plist')
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Loading...
      </div>
    )
  }
  if (!pkg) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Not found
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/software">Software</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>{pkg.display_name || pkg.name}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <SoftwareIcon
            name={pkg.name}
            displayName={pkg.display_name}
            iconName={pkg.icon_name}
            size="lg"
            cacheRevision={iconRevision}
          />
          <div className={cn(munkiAccents.software.pageTitle)}>
            <h1 className="text-3xl font-bold text-pretty">
              {pkg.display_name || pkg.name}
            </h1>
            <p className="text-muted-foreground">
              {pkg.name} &mdash; Version {pkg.version}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <CatalogEditor
            pkgId={id}
            catalogNames={pkg.catalog_names}
            readOnly={!canMutateSoftware}
          />
          <Button
            variant="outline"
            size="sm"
            aria-label="Download plist"
            onClick={handleDownloadPlist}
          >
            <Download className="mr-1 h-4 w-4" />
            Plist
          </Button>
          {canMutateSoftware && effectiveEditing ? (
            <>
              <Button
                size="sm"
                onClick={handleSave}
                disabled={saveMutation.isPending}
              >
                <Save className="mr-1 h-4 w-4" />
                {saveMutation.isPending ? 'Saving...' : 'Save'}
              </Button>
              <Button variant="ghost" size="sm" onClick={handleCancel}>
                <X className="mr-1 h-4 w-4" />
                Cancel
              </Button>
            </>
          ) : canMutateSoftware ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditing(true)}
            >
              <Pencil className="mr-1 h-4 w-4" />
              Edit
            </Button>
          ) : null}
        </div>
      </div>

      <Tabs defaultValue="details" className="gap-4">
        <TabsList
          className={cn(
            'h-auto w-full flex-wrap gap-2 rounded-xl p-2 sm:p-2.5',
            'border border-gruvbox-blue/20 bg-gradient-to-br from-muted/90 via-muted/55 to-muted/25',
            'shadow-sm transition-[border-color,box-shadow] duration-300 ease-out',
            'hover:border-gruvbox-blue/40 hover:shadow-md dark:border-gruvbox-blue/30 dark:hover:border-gruvbox-blue/50',
          )}
        >
          <TabsTrigger
            value="details"
            className={softwareDetailTabTrigger(
              'data-[state=active]:text-gruvbox-blue data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-blue/30',
            )}
          >
            <FileText className={softwareTabIconClass} aria-hidden />
            Details
          </TabsTrigger>
          <TabsTrigger
            value="detection"
            className={softwareDetailTabTrigger(
              'data-[state=active]:text-gruvbox-purple data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-purple/30',
            )}
          >
            <ScanSearch className={softwareTabIconClass} aria-hidden />
            Detection
          </TabsTrigger>
          <TabsTrigger
            value="install"
            className={softwareDetailTabTrigger(
              'data-[state=active]:text-gruvbox-green data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-green/30',
            )}
          >
            <Package className={softwareTabIconClass} aria-hidden />
            Install Info
          </TabsTrigger>
          <TabsTrigger
            value="scripts"
            className={softwareDetailTabTrigger(
              'data-[state=active]:text-gruvbox-orange data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-orange/30',
            )}
          >
            <Code2 className={softwareTabIconClass} aria-hidden />
            Scripts
          </TabsTrigger>
          <TabsTrigger
            value="reports"
            className={softwareDetailTabTrigger(
              'data-[state=active]:text-cyan-700 data-[state=active]:ring-2 data-[state=active]:ring-cyan-500/35 dark:data-[state=active]:text-cyan-400',
            )}
          >
            <Activity className={softwareTabIconClass} aria-hidden />
            Fleet installs
          </TabsTrigger>
          <TabsTrigger
            value="audit"
            className={softwareDetailTabTrigger(
              'data-[state=active]:text-gruvbox-red data-[state=active]:ring-2 data-[state=active]:ring-gruvbox-red/30',
            )}
          >
            <History className={softwareTabIconClass} aria-hidden />
            Audit Trail
          </TabsTrigger>
        </TabsList>

        {/* ── Details Tab ── */}
        <TabsContent value="details" className={softwareDetailTabContentClass}>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>General Information</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-2">
                <ReadOnlyField label="Name" value={pkg.name} />
                <EditableField
                  label="Display Name"
                  value={form?.display_name ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('display_name', v)}
                />
                <ReadOnlyField label="Version" value={pkg.version} />
                <EditableField
                  label="Category"
                  value={form?.category ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('category', v)}
                />
                <EditableField
                  label="Developer"
                  value={form?.developer ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('developer', v)}
                />
                {effectiveEditing ? (
                  <div className="space-y-2">
                    <Label htmlFor="edit-icon_name">Icon Name</Label>
                    <p className="text-xs text-muted-foreground">
                      Stem without .png. The UI loads{' '}
                      <span className="font-mono">/icons/</span> plus icon name
                      or package name plus{' '}
                      <span className="font-mono">.png</span>.
                    </p>
                    <div className="flex flex-wrap items-center gap-2">
                      <Input
                        id="edit-icon_name"
                        className="max-w-md"
                        value={form?.icon_name ?? ''}
                        onChange={(e) =>
                          updateField('icon_name', e.target.value)
                        }
                        placeholder={pkg.name}
                      />
                      <PkginfoIconUpload
                        suggestedBasename={pkg.name}
                        currentIconName={form?.icon_name ?? ''}
                        onIconNameApplied={(v) => {
                          updateField('icon_name', v)
                          setIconRevision((r) => r + 1)
                        }}
                      />
                    </div>
                  </div>
                ) : (
                  <ReadOnlyField
                    label="Icon Name"
                    value={pkg.icon_name || '—'}
                  />
                )}
                {effectiveEditing ? (
                  <div className="col-span-full">
                    <Label>Description</Label>
                    <Textarea
                      className="mt-1"
                      value={form?.description ?? ''}
                      onChange={(e) =>
                        updateField('description', e.target.value)
                      }
                      rows={3}
                    />
                  </div>
                ) : (
                  <div className="col-span-full">
                    <span className="text-sm font-medium text-muted-foreground">
                      Description
                    </span>
                    <p className="mt-1">{pkg.description || '—'}</p>
                  </div>
                )}
                {effectiveEditing ? (
                  <div className="col-span-full">
                    <Label>Notes</Label>
                    <Textarea
                      className="mt-1"
                      value={form?.notes ?? ''}
                      onChange={(e) => updateField('notes', e.target.value)}
                      rows={3}
                    />
                  </div>
                ) : (
                  pkg.notes && (
                    <div className="col-span-full">
                      <span className="text-sm font-medium text-muted-foreground">
                        Notes
                      </span>
                      <p className="mt-1 whitespace-pre-wrap">{pkg.notes}</p>
                    </div>
                  )
                )}
                <EditableField
                  label="Minimum OS"
                  value={form?.minimum_os_version ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('minimum_os_version', v)}
                />
                <EditableField
                  label="Maximum OS"
                  value={form?.maximum_os_version ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('maximum_os_version', v)}
                />
                <EditableField
                  label="Minimum Munki Version"
                  value={form?.minimum_munki_version ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('minimum_munki_version', v)}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Install Configuration</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-2">
                <BooleanField
                  label="Unattended Install"
                  value={form?.unattended_install ?? false}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('unattended_install', v)}
                />
                <BooleanField
                  label="Unattended Uninstall"
                  value={form?.unattended_uninstall ?? false}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('unattended_uninstall', v)}
                />
                <BooleanField
                  label="Auto Remove"
                  value={form?.autoremove ?? false}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('autoremove', v)}
                />
                <BooleanField
                  label="Uninstallable"
                  value={form?.uninstallable ?? true}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('uninstallable', v)}
                />
                <BooleanField
                  label="OnDemand"
                  value={form?.on_demand ?? false}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('on_demand', v)}
                />
                <BooleanField
                  label="Apple Item"
                  value={form?.apple_item ?? false}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('apple_item', v)}
                />
                {effectiveEditing ? (
                  <div>
                    <Label>Restart Action</Label>
                    <Select
                      value={form?.restart_action ?? ''}
                      onValueChange={(v) =>
                        updateField('restart_action', v === 'none' ? '' : v)
                      }
                    >
                      <SelectTrigger className="mt-1">
                        <SelectValue placeholder="None" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">None</SelectItem>
                        <SelectItem value="RequireRestart">
                          RequireRestart
                        </SelectItem>
                        <SelectItem value="RecommendRestart">
                          RecommendRestart
                        </SelectItem>
                        <SelectItem value="RequireLogout">
                          RequireLogout
                        </SelectItem>
                        <SelectItem value="RequireShutdown">
                          RequireShutdown
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                ) : (
                  <ReadOnlyField
                    label="Restart Action"
                    value={pkg.restart_action}
                  />
                )}
                {effectiveEditing ? (
                  <EditableField
                    label="Uninstall Method"
                    value={form?.uninstall_method ?? ''}
                    editing={effectiveEditing}
                    onChange={(v) => updateField('uninstall_method', v)}
                  />
                ) : (
                  <ReadOnlyField
                    label="Uninstall Method"
                    value={pkg.uninstall_method}
                  />
                )}
                {effectiveEditing ? (
                  <EditableField
                    label="Installer Type"
                    value={form?.installer_type ?? ''}
                    editing={effectiveEditing}
                    onChange={(v) => updateField('installer_type', v)}
                  />
                ) : (
                  <ReadOnlyField
                    label="Installer Type"
                    value={pkg.installer_type}
                  />
                )}
                <EditableField
                  label="Force Install After Date"
                  value={form?.force_install_after_date ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('force_install_after_date', v)}
                />
                <EditableField
                  label="Installable Condition"
                  value={form?.installable_condition ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('installable_condition', v)}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Dependencies &amp; Relationships</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {effectiveEditing ? (
                  <>
                    <TagField
                      label="Blocking Applications"
                      values={form?.blocking_applications ?? []}
                      onChange={(v) => updateField('blocking_applications', v)}
                    />
                    <TagField
                      label="Supported Architectures"
                      values={form?.supported_architectures ?? []}
                      onChange={(v) =>
                        updateField('supported_architectures', v)
                      }
                    />
                    <TagField
                      label="Requires"
                      values={form?.requires ?? []}
                      onChange={(v) => updateField('requires', v)}
                    />
                    <TagField
                      label="Update For"
                      values={form?.update_for ?? []}
                      onChange={(v) => updateField('update_for', v)}
                    />
                  </>
                ) : (
                  <div className="grid gap-4 md:grid-cols-2">
                    <TagDisplay
                      label="Blocking Applications"
                      values={pkg.blocking_applications}
                    />
                    <TagDisplay
                      label="Supported Architectures"
                      values={pkg.supported_architectures}
                    />
                    <TagDisplay label="Requires" values={pkg.requires} />
                    <TagDisplay label="Update For" values={pkg.update_for} />
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
        {/* ── Detection Tab ── */}
        <TabsContent
          value="detection"
          className={softwareDetailTabContentClass}
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Installs Items</CardTitle>
              </CardHeader>
              <CardContent>
                {effectiveEditing ? (
                  <InstallsEditor
                    items={form?.installs ?? []}
                    onChange={(v) => updateField('installs', v)}
                  />
                ) : (form?.installs?.length ?? 0) > 0 ? (
                  <div className="space-y-2">
                    {(form?.installs ?? pkg.installs ?? []).map((item, i) => (
                      <div key={i} className="rounded-md border p-3 text-sm">
                        <div className="grid gap-2 md:grid-cols-3">
                          {item.type && (
                            <div>
                              <span className="font-medium text-muted-foreground">
                                Type:
                              </span>{' '}
                              {item.type}
                            </div>
                          )}
                          {item.path && (
                            <div className="md:col-span-2">
                              <span className="font-medium text-muted-foreground">
                                Path:
                              </span>{' '}
                              <code className="text-xs">{item.path}</code>
                            </div>
                          )}
                          {item.CFBundleIdentifier && (
                            <div>
                              <span className="font-medium text-muted-foreground">
                                Bundle ID:
                              </span>{' '}
                              {item.CFBundleIdentifier}
                            </div>
                          )}
                          {item.CFBundleShortVersionString && (
                            <div>
                              <span className="font-medium text-muted-foreground">
                                Version:
                              </span>{' '}
                              {item.CFBundleShortVersionString}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No installs items configured
                  </p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Receipts</CardTitle>
              </CardHeader>
              <CardContent>
                {effectiveEditing ? (
                  <ReceiptsEditor
                    items={form?.receipts ?? []}
                    onChange={(v) => updateField('receipts', v)}
                  />
                ) : (form?.receipts?.length ?? 0) > 0 ? (
                  <div className="space-y-2">
                    {(form?.receipts ?? pkg.receipts ?? []).map((item, i) => (
                      <div key={i} className="rounded-md border p-3 text-sm">
                        <div className="grid gap-2 md:grid-cols-3">
                          {item.packageid && (
                            <div>
                              <span className="font-medium text-muted-foreground">
                                Package ID:
                              </span>{' '}
                              {item.packageid}
                            </div>
                          )}
                          {item.version && (
                            <div>
                              <span className="font-medium text-muted-foreground">
                                Version:
                              </span>{' '}
                              {item.version}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No receipts configured
                  </p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Detection Scripts</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <ScriptField
                  label="installcheck_script"
                  value={
                    effectiveEditing
                      ? (form?.installcheck_script ?? '')
                      : (pkg.installcheck_script ?? '')
                  }
                  editing={effectiveEditing}
                  onChange={(v) => updateField('installcheck_script', v)}
                  description="Runs before install to determine if the item needs to be installed. Exit 0 = needs install."
                />
                <ScriptField
                  label="uninstallcheck_script"
                  value={
                    effectiveEditing
                      ? (form?.uninstallcheck_script ?? '')
                      : (pkg.uninstallcheck_script ?? '')
                  }
                  editing={effectiveEditing}
                  onChange={(v) => updateField('uninstallcheck_script', v)}
                  description="Runs before uninstall to determine if the item is installed. Exit 0 = is installed."
                />
                <ScriptField
                  label="version_script"
                  value={
                    effectiveEditing
                      ? (form?.version_script ?? '')
                      : (pkg.version_script ?? '')
                  }
                  editing={effectiveEditing}
                  onChange={(v) => updateField('version_script', v)}
                  description="Outputs the installed version to stdout for comparison."
                />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Install Info Tab ── */}
        <TabsContent value="install" className={softwareDetailTabContentClass}>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Installer Details</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-2">
                <EditableField
                  label="Location"
                  value={
                    effectiveEditing
                      ? (form?.installer_item_location ?? '')
                      : (pkg.installer_item_location ?? '')
                  }
                  editing={effectiveEditing}
                  onChange={(v) => updateField('installer_item_location', v)}
                />
                <EditableField
                  label="Hash (SHA256)"
                  value={
                    effectiveEditing
                      ? (form?.installer_item_hash ?? '')
                      : (pkg.installer_item_hash ?? '')
                  }
                  editing={effectiveEditing}
                  onChange={(v) => updateField('installer_item_hash', v)}
                />
                <InstallerSizeMbField
                  label="Installer Size"
                  kb={
                    effectiveEditing
                      ? form?.installer_item_size
                      : pkg.installer_item_size
                  }
                  editing={effectiveEditing}
                  onKbChange={(v) => updateField('installer_item_size', v)}
                />
                <ReadOnlyField
                  label="Installed Size"
                  value={
                    pkg.installed_size
                      ? `${Math.round(pkg.installed_size / 1024)} MB`
                      : null
                  }
                />
                <EditableField
                  label="Package Path"
                  value={form?.package_path ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('package_path', v)}
                />
                <EditableField
                  label="Package Complete URL"
                  value={form?.package_complete_url ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('package_complete_url', v)}
                />
                <EditableField
                  label="Uninstaller Item Location"
                  value={form?.uninstaller_item_location ?? ''}
                  editing={effectiveEditing}
                  onChange={(v) => updateField('uninstaller_item_location', v)}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Items to Copy</CardTitle>
              </CardHeader>
              <CardContent>
                {effectiveEditing ? (
                  <ItemsToCopyEditor
                    items={form?.items_to_copy ?? []}
                    onChange={(v) => updateField('items_to_copy', v)}
                  />
                ) : (form?.items_to_copy?.length ?? 0) > 0 ? (
                  <div className="space-y-2">
                    {(form?.items_to_copy ?? pkg.items_to_copy ?? []).map(
                      (item, i) => (
                        <div key={i} className="rounded-md border p-3 text-sm">
                          <div className="grid gap-2 md:grid-cols-2">
                            {item.source_item && (
                              <div>
                                <span className="font-medium text-muted-foreground">
                                  Source:
                                </span>{' '}
                                <code className="text-xs">
                                  {item.source_item}
                                </code>
                              </div>
                            )}
                            {item.destination_path && (
                              <div>
                                <span className="font-medium text-muted-foreground">
                                  Destination:
                                </span>{' '}
                                <code className="text-xs">
                                  {item.destination_path}
                                </code>
                              </div>
                            )}
                          </div>
                        </div>
                      ),
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No items to copy configured
                  </p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Scripts Tab ── */}
        <TabsContent value="scripts" className={softwareDetailTabContentClass}>
          <ScriptField
            label="preinstall_script"
            value={
              effectiveEditing
                ? (form?.preinstall_script ?? '')
                : (pkg.preinstall_script ?? '')
            }
            editing={effectiveEditing}
            onChange={(v) => updateField('preinstall_script', v)}
          />
          <ScriptField
            label="postinstall_script"
            value={
              effectiveEditing
                ? (form?.postinstall_script ?? '')
                : (pkg.postinstall_script ?? '')
            }
            editing={effectiveEditing}
            onChange={(v) => updateField('postinstall_script', v)}
          />
          <ScriptField
            label="preuninstall_script"
            value={
              effectiveEditing
                ? (form?.preuninstall_script ?? '')
                : (pkg.preuninstall_script ?? '')
            }
            editing={effectiveEditing}
            onChange={(v) => updateField('preuninstall_script', v)}
          />
          <ScriptField
            label="postuninstall_script"
            value={
              effectiveEditing
                ? (form?.postuninstall_script ?? '')
                : (pkg.postuninstall_script ?? '')
            }
            editing={effectiveEditing}
            onChange={(v) => updateField('postuninstall_script', v)}
          />
          {!effectiveEditing &&
            !pkg.preinstall_script &&
            !pkg.postinstall_script &&
            !pkg.preuninstall_script &&
            !pkg.postuninstall_script && (
              <p className="text-muted-foreground">No scripts configured</p>
            )}
        </TabsContent>

        {/* ── Fleet install reports (client check-in) ── */}
        <TabsContent value="reports" className={softwareDetailTabContentClass}>
          <p className="text-sm text-muted-foreground">
            Rows match Munki{' '}
            <span className="font-mono text-xs">item_name</span> &mdash;{' '}
            <span className="font-mono text-xs">{pkg.name}</span>. Each device
            keeps only the latest snapshot per check-in.
          </p>

          {installSummaryLoading ? (
            <p className="text-sm text-muted-foreground">Loading reports…</p>
          ) : installSummary ? (
            <>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Total rows
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-semibold tabular-nums">
                      {installSummary.total_reports}
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Devices
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-semibold tabular-nums">
                      {installSummary.unique_machines}
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Installed
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-semibold tabular-nums text-chart-2">
                      {installSummary.by_status.installed ?? 0}
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Failed
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-semibold tabular-nums text-destructive">
                      {(installSummary.by_status.failed ?? 0) +
                        (installSummary.by_status.removal_failed ?? 0)}
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      failed + removal_failed
                    </p>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-base">
                    Activity (last 90 days)
                  </CardTitle>
                  <p className="text-xs text-muted-foreground">
                    By install time, or report time if missing
                  </p>
                </CardHeader>
                <CardContent>
                  <SoftwareInstallTimelineChart
                    history={installSummary.timeline}
                    totalReports={installSummary.total_reports}
                  />
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
                  <CardTitle className="text-base">Recent reports</CardTitle>
                  <Button variant="outline" size="sm" asChild>
                    <Link
                      href={`/reporting/installs?item_name=${encodeURIComponent(pkg.name)}`}
                    >
                      Open in Reporting
                    </Link>
                  </Button>
                </CardHeader>
                <CardContent className="px-0 sm:px-6">
                  <DataTable
                    columns={SOFTWARE_INSTALL_REPORT_COLUMNS}
                    data={installReportRows?.items ?? []}
                    pageCount={installReportRows?.total_pages ?? 1}
                    page={installReportPage}
                    pageSize={installReportPageSize}
                    total={installReportRows?.total}
                    onPageChange={(p) => setInstallReportPage(p)}
                    onPageSizeChange={(size) => {
                      setInstallReportPageSize(size)
                      setInstallReportPage(1)
                    }}
                    isLoading={installRowsLoading}
                    hideColumnPicker
                  />
                </CardContent>
              </Card>
            </>
          ) : null}
        </TabsContent>

        {/* ── Audit Trail Tab ── */}
        <TabsContent value="audit" className={softwareDetailTabContentClass}>
          {auditTrail?.length ? (
            <div className="space-y-2">
              {auditTrail.map((entry) => (
                <div
                  key={entry.id}
                  className="flex items-center justify-between rounded-md border p-3"
                >
                  <div>
                    <Badge variant="outline">{entry.action}</Badge>
                    <span className="ml-2 text-sm">
                      {entry.user_email || 'system'}
                    </span>
                    {entry.notes && (
                      <span className="ml-2 text-sm text-muted-foreground">
                        &mdash; {entry.notes}
                      </span>
                    )}
                  </div>
                  <span
                    suppressHydrationWarning
                    className="text-sm text-muted-foreground"
                  >
                    {formatDateTime(entry.created_at)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground">No audit history</p>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

/* ── Shared Field Components ── */

function ReadOnlyField({
  label,
  value,
}: {
  label: string
  value: string | null | undefined
}) {
  return (
    <div>
      <span className="text-sm font-medium text-muted-foreground">{label}</span>
      <p className="mt-1 truncate">{value || '—'}</p>
    </div>
  )
}

function EditableField({
  label,
  value,
  editing,
  onChange,
}: {
  label: string
  value: string
  editing: boolean
  onChange: (v: string) => void
}) {
  if (!editing) {
    return (
      <div>
        <span className="text-sm font-medium text-muted-foreground">
          {label}
        </span>
        <p className="mt-1 truncate">{value || '—'}</p>
      </div>
    )
  }
  return (
    <div>
      <Label>{label}</Label>
      <Input
        className="mt-1"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  )
}

/** Munki ``installer_item_size`` is in KiB; we edit in MB for readability. */
function InstallerSizeMbField({
  label,
  kb,
  editing,
  onKbChange,
}: {
  label: string
  kb: number | null | undefined
  editing: boolean
  onKbChange: (v: number | null) => void
}) {
  const displayMb = kb != null && kb > 0 ? `${Math.round(kb / 1024)} MB` : '—'
  if (!editing) {
    return (
      <div>
        <span className="text-sm font-medium text-muted-foreground">
          {label}
        </span>
        <p className="mt-1 truncate">{displayMb}</p>
      </div>
    )
  }
  return (
    <div>
      <Label>{label} (MB)</Label>
      <Input
        type="number"
        min={0}
        className="mt-1"
        value={kb != null && kb > 0 ? Math.round(kb / 1024) : ''}
        onChange={(e) => {
          const v = e.target.value
          if (v === '') onKbChange(null)
          else {
            const n = Number.parseInt(v, 10)
            if (!Number.isNaN(n)) onKbChange(n * 1024)
          }
        }}
      />
      <p className="mt-1 text-xs text-muted-foreground">
        Stored as KiB for Munki installer_item_size.
      </p>
    </div>
  )
}

function BooleanField({
  label,
  value,
  editing,
  onChange,
}: {
  label: string
  value: boolean
  editing: boolean
  onChange: (v: boolean) => void
}) {
  if (!editing) {
    return (
      <div>
        <span className="text-sm font-medium text-muted-foreground">
          {label}
        </span>
        <p className="mt-1">
          <Badge variant={value ? 'default' : 'outline'}>
            {value ? 'Yes' : 'No'}
          </Badge>
        </p>
      </div>
    )
  }
  return (
    <div className="flex items-center justify-between">
      <Label>{label}</Label>
      <Switch checked={value} onCheckedChange={onChange} />
    </div>
  )
}

function TagField({
  label,
  values,
  onChange,
}: {
  label: string
  values: string[]
  onChange: (v: string[]) => void
}) {
  const [input, setInput] = useState('')

  const addTag = () => {
    const trimmed = input.trim()
    if (trimmed && !values.includes(trimmed)) {
      onChange([...values, trimmed])
    }
    setInput('')
  }

  return (
    <div>
      <Label>{label}</Label>
      <div className="mt-1 flex flex-wrap gap-1">
        {values.map((v) => (
          <Badge key={v} variant="secondary" className="gap-1">
            {v}
            <button
              type="button"
              aria-label={`Remove ${v}`}
              className="ml-1 hover:text-destructive"
              onClick={() => onChange(values.filter((x) => x !== v))}
            >
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))}
      </div>
      <div className="mt-2 flex gap-2">
        <Input
          placeholder={`Add ${label.toLowerCase()}...`}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              addTag()
            }
          }}
          className="max-w-xs"
        />
        <Button type="button" variant="outline" size="sm" onClick={addTag}>
          Add
        </Button>
      </div>
    </div>
  )
}

function TagDisplay({
  label,
  values,
}: {
  label: string
  values: string[] | null | undefined
}) {
  if (!values?.length) {
    return (
      <div>
        <span className="text-sm font-medium text-muted-foreground">
          {label}
        </span>
        <p className="mt-1 text-sm text-muted-foreground">—</p>
      </div>
    )
  }
  return (
    <div>
      <span className="text-sm font-medium text-muted-foreground">{label}</span>
      <div className="mt-1 flex flex-wrap gap-1">
        {values.map((v) => (
          <Badge key={v} variant="outline">
            {v}
          </Badge>
        ))}
      </div>
    </div>
  )
}

function ScriptField({
  label,
  value,
  editing,
  onChange,
  description,
}: {
  label: string
  value: string
  editing: boolean
  onChange: (v: string) => void
  description?: string
}) {
  if (!editing && !value) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </CardHeader>
      <CardContent>
        {editing ? (
          <Textarea
            className="min-h-[120px] font-mono text-sm"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={`Enter ${label}...`}
            rows={8}
          />
        ) : (
          <pre className="overflow-auto rounded-md bg-muted p-4 font-mono text-sm">
            {value}
          </pre>
        )}
      </CardContent>
    </Card>
  )
}

/* ── Installs Editor ── */

const INSTALL_TYPES = [
  'file',
  'bundle',
  'plist',
  'application',
  'launchd',
  'startup_item',
]

function InstallsEditor({
  items,
  onChange,
}: {
  items: InstallItem[]
  onChange: (items: InstallItem[]) => void
}) {
  const updateItem = (index: number, field: string, value: string) => {
    const updated = [...items]
    updated[index] = { ...updated[index], [field]: value }
    onChange(updated)
  }

  const removeItem = (index: number) => {
    onChange(items.filter((_, i) => i !== index))
  }

  const addItem = () => {
    onChange([...items, { type: 'file', path: '' }])
  }

  return (
    <div className="space-y-3">
      {items.map((item, i) => (
        <div key={i} className="rounded-md border p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium">Item {i + 1}</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-destructive"
              onClick={() => removeItem(i)}
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <div>
              <Label className="text-xs">Type</Label>
              <Select
                value={item.type ?? 'file'}
                onValueChange={(v) => updateItem(i, 'type', v)}
              >
                <SelectTrigger className="mt-1 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INSTALL_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Path</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.path ?? ''}
                onChange={(e) => updateItem(i, 'path', e.target.value)}
                placeholder="/Applications/Example.app"
              />
            </div>
            <div>
              <Label className="text-xs">CFBundleIdentifier</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={(item.CFBundleIdentifier as string) ?? ''}
                onChange={(e) =>
                  updateItem(i, 'CFBundleIdentifier', e.target.value)
                }
                placeholder="com.example.app"
              />
            </div>
            <div>
              <Label className="text-xs">CFBundleShortVersionString</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={(item.CFBundleShortVersionString as string) ?? ''}
                onChange={(e) =>
                  updateItem(i, 'CFBundleShortVersionString', e.target.value)
                }
                placeholder="1.0.0"
              />
            </div>
            <div>
              <Label className="text-xs">version_comparison_key</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={(item.version_comparison_key as string) ?? ''}
                onChange={(e) =>
                  updateItem(i, 'version_comparison_key', e.target.value)
                }
                placeholder="CFBundleShortVersionString"
              />
            </div>
            <div>
              <Label className="text-xs">minosversion</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={(item.minosversion as string) ?? ''}
                onChange={(e) => updateItem(i, 'minosversion', e.target.value)}
                placeholder="10.15"
              />
            </div>
          </div>
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={addItem}>
        <Plus className="mr-1 h-3.5 w-3.5" />
        Add Install Item
      </Button>
    </div>
  )
}

/* ── Receipts Editor ── */

function ReceiptsEditor({
  items,
  onChange,
}: {
  items: ReceiptItem[]
  onChange: (items: ReceiptItem[]) => void
}) {
  const updateItem = (
    index: number,
    field: string,
    value: string | boolean,
  ) => {
    const updated = [...items]
    updated[index] = { ...updated[index], [field]: value }
    onChange(updated)
  }

  const removeItem = (index: number) => {
    onChange(items.filter((_, i) => i !== index))
  }

  const addItem = () => {
    onChange([...items, { packageid: '', version: '' }])
  }

  return (
    <div className="space-y-3">
      {items.map((item, i) => (
        <div key={i} className="rounded-md border p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium">Receipt {i + 1}</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-destructive"
              onClick={() => removeItem(i)}
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
          <div className="grid gap-2 md:grid-cols-3">
            <div>
              <Label className="text-xs">Package ID</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.packageid ?? ''}
                onChange={(e) => updateItem(i, 'packageid', e.target.value)}
                placeholder="com.example.pkg"
              />
            </div>
            <div>
              <Label className="text-xs">Version</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.version ?? ''}
                onChange={(e) => updateItem(i, 'version', e.target.value)}
                placeholder="1.0.0"
              />
            </div>
            <div className="flex items-end gap-2 pb-0.5">
              <div className="flex items-center gap-2">
                <Switch
                  checked={item.optional ?? false}
                  onCheckedChange={(v) => updateItem(i, 'optional', v)}
                />
                <Label className="text-xs">Optional</Label>
              </div>
            </div>
          </div>
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={addItem}>
        <Plus className="mr-1 h-3.5 w-3.5" />
        Add Receipt
      </Button>
    </div>
  )
}

/* ── Items to Copy Editor ── */

function ItemsToCopyEditor({
  items,
  onChange,
}: {
  items: ItemToCopy[]
  onChange: (items: ItemToCopy[]) => void
}) {
  const updateItem = (index: number, field: string, value: string) => {
    const updated = [...items]
    updated[index] = { ...updated[index], [field]: value }
    onChange(updated)
  }

  const removeItem = (index: number) => {
    onChange(items.filter((_, i) => i !== index))
  }

  const addItem = () => {
    onChange([...items, { source_item: '', destination_path: '' }])
  }

  return (
    <div className="space-y-3">
      {items.map((item, i) => (
        <div key={i} className="rounded-md border p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium">Item {i + 1}</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-destructive"
              onClick={() => removeItem(i)}
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <div>
              <Label className="text-xs">Source Item</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.source_item ?? ''}
                onChange={(e) => updateItem(i, 'source_item', e.target.value)}
                placeholder="Example.app"
              />
            </div>
            <div>
              <Label className="text-xs">Destination Path</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.destination_path ?? ''}
                onChange={(e) =>
                  updateItem(i, 'destination_path', e.target.value)
                }
                placeholder="/Applications"
              />
            </div>
            <div>
              <Label className="text-xs">Destination Item</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.destination_item ?? ''}
                onChange={(e) =>
                  updateItem(i, 'destination_item', e.target.value)
                }
              />
            </div>
            <div>
              <Label className="text-xs">User</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.user ?? ''}
                onChange={(e) => updateItem(i, 'user', e.target.value)}
                placeholder="root"
              />
            </div>
            <div>
              <Label className="text-xs">Group</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.group ?? ''}
                onChange={(e) => updateItem(i, 'group', e.target.value)}
                placeholder="admin"
              />
            </div>
            <div>
              <Label className="text-xs">Mode</Label>
              <Input
                className="mt-1 h-8 text-xs"
                value={item.mode ?? ''}
                onChange={(e) => updateItem(i, 'mode', e.target.value)}
                placeholder="o-w"
              />
            </div>
          </div>
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={addItem}>
        <Plus className="mr-1 h-3.5 w-3.5" />
        Add Item to Copy
      </Button>
    </div>
  )
}

/* ── Catalog Editor ── */

function CatalogEditor({
  pkgId,
  catalogNames,
  readOnly = false,
}: {
  pkgId: string
  catalogNames: string[]
  readOnly?: boolean
}) {
  const queryClient = useQueryClient()
  const [popoverOpen, setPopoverOpen] = useState(false)

  const { data: allCatalogs } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
    enabled: popoverOpen,
  })

  const mutation = useMutation({
    mutationFn: (names: string[]) =>
      api.put(`/pkginfo/${pkgId}/catalogs`, { catalog_names: names }),
    onSuccess: () => {
      toast.success('Catalogs updated')
      queryClient.invalidateQueries({ queryKey: ['pkginfo', pkgId] })
      queryClient.invalidateQueries({ queryKey: ['catalogs'] })
    },
    onError: (err: Error) =>
      toast.error(`Failed to update catalogs: ${err.message}`),
  })

  const removeCatalog = (name: string) => {
    mutation.mutate(catalogNames.filter((c) => c !== name))
  }

  const addCatalog = (name: string) => {
    if (catalogNames.includes(name)) return
    mutation.mutate([...catalogNames, name])
    setPopoverOpen(false)
  }

  const available = (allCatalogs ?? []).filter(
    (c) => !catalogNames.includes(c.name),
  )

  if (readOnly) {
    return (
      <div className="flex flex-wrap items-center gap-1.5">
        {catalogNames.length ? (
          catalogNames.map((c) => (
            <Badge key={c} variant="secondary" className="text-sm">
              {c}
            </Badge>
          ))
        ) : (
          <span className="text-sm text-muted-foreground">—</span>
        )}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-1.5">
      {catalogNames.map((c) => (
        <Badge key={c} variant="secondary" className="gap-1 pr-1 text-sm">
          {c}
          <button
            type="button"
            aria-label={`Remove catalog ${c}`}
            className="ml-0.5 rounded-full p-0.5 hover:bg-muted"
            onClick={() => removeCatalog(c)}
            disabled={mutation.isPending}
          >
            <X className="h-3 w-3" />
          </button>
        </Badge>
      ))}
      <Popover open={popoverOpen} onOpenChange={setPopoverOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            className="h-6 w-6"
            aria-label="Add catalog"
          >
            <Plus className="h-3 w-3" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[250px] p-0" align="end">
          <Command>
            <CommandInput placeholder="Search catalogs..." />
            <CommandList>
              <CommandEmpty>No catalogs available.</CommandEmpty>
              <CommandGroup>
                {available.map((cat) => (
                  <CommandItem
                    key={cat.id}
                    value={cat.name}
                    onSelect={() => addCatalog(cat.name)}
                  >
                    {cat.name}
                    {cat.is_production && (
                      <Badge variant="default" className="ml-auto text-xs">
                        Production
                      </Badge>
                    )}
                  </CommandItem>
                ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  )
}
