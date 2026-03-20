'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Pencil, Plus, Save, X } from 'lucide-react'
import { useParams, useRouter } from 'next/navigation'
import { useCallback, useEffect, useState } from 'react'
import { toast } from 'sonner'
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
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import {
  type AuditLogRead,
  api,
  type CatalogRead,
  type PkgInfoDetail,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'

interface EditableFields {
  display_name: string
  description: string
  category: string
  developer: string
  icon_name: string
  minimum_os_version: string
  maximum_os_version: string
  unattended_install: boolean
  unattended_uninstall: boolean
  autoremove: boolean
  uninstallable: boolean
  blocking_applications: string[]
  requires: string[]
  update_for: string[]
}

function pkgToEditable(pkg: PkgInfoDetail): EditableFields {
  return {
    display_name: pkg.display_name ?? '',
    description: pkg.description ?? '',
    category: pkg.category ?? '',
    developer: pkg.developer ?? '',
    icon_name: pkg.icon_name ?? '',
    minimum_os_version: pkg.minimum_os_version ?? '',
    maximum_os_version: pkg.maximum_os_version ?? '',
    unattended_install: pkg.unattended_install,
    unattended_uninstall: pkg.unattended_uninstall,
    autoremove: pkg.autoremove,
    uninstallable: pkg.uninstallable,
    blocking_applications: pkg.blocking_applications ?? [],
    requires: pkg.requires ?? [],
    update_for: pkg.update_for ?? [],
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
      payload[key] = e === '' ? null : e
    }
  }
  return payload
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export default function SoftwareDetailPage() {
  const params = useParams()
  const _router = useRouter()
  const queryClient = useQueryClient()
  const id = params.id as string

  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<EditableFields | null>(null)
  const [dirty, setDirty] = useState(false)

  const { data: pkg, isLoading } = useQuery({
    queryKey: ['pkginfo', id],
    queryFn: () => api.get<PkgInfoDetail>(`/pkginfo/${id}`),
  })

  const { data: auditTrail } = useQuery({
    queryKey: ['audit', 'pkg_info', id],
    queryFn: () => api.get<AuditLogRead[]>(`/audit/pkg_info/${id}`),
  })

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.put(`/pkginfo/${id}`, payload),
    onSuccess: () => {
      toast.success('Changes saved')
      queryClient.invalidateQueries({ queryKey: ['pkginfo', id] })
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

      const res = await fetch(`${API_BASE}/api/v1/pkginfo/${id}/plist`, {
        headers,
      })
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
          />
          <div>
            <h1 className="text-3xl font-bold">
              {pkg.display_name || pkg.name}
            </h1>
            <p className="text-muted-foreground">
              {pkg.name} &mdash; Version {pkg.version}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <CatalogEditor pkgId={id} catalogNames={pkg.catalog_names} />
          <Button
            variant="outline"
            size="sm"
            aria-label="Download plist"
            onClick={handleDownloadPlist}
          >
            <Download className="mr-1 h-4 w-4" />
            Plist
          </Button>
          {editing ? (
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
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditing(true)}
            >
              <Pencil className="mr-1 h-4 w-4" />
              Edit
            </Button>
          )}
        </div>
      </div>

      <Tabs defaultValue="details">
        <TabsList>
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="install">Install Info</TabsTrigger>
          <TabsTrigger value="scripts">Scripts</TabsTrigger>
          <TabsTrigger value="audit">Audit Trail</TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>General Information</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              <InfoField
                label="Name"
                value={pkg.name}
                readOnly
                editing={false}
              />
              <EditableField
                label="Display Name"
                value={form?.display_name ?? ''}
                editing={editing}
                onChange={(v) => updateField('display_name', v)}
              />
              <InfoField
                label="Version"
                value={pkg.version}
                readOnly
                editing={false}
              />
              <EditableField
                label="Category"
                value={form?.category ?? ''}
                editing={editing}
                onChange={(v) => updateField('category', v)}
              />
              <EditableField
                label="Developer"
                value={form?.developer ?? ''}
                editing={editing}
                onChange={(v) => updateField('developer', v)}
              />
              <EditableField
                label="Icon Name"
                value={form?.icon_name ?? ''}
                editing={editing}
                onChange={(v) => updateField('icon_name', v)}
              />
              {editing ? (
                <div className="col-span-full">
                  <Label>Description</Label>
                  <Textarea
                    className="mt-1"
                    value={form?.description ?? ''}
                    onChange={(e) => updateField('description', e.target.value)}
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
              <EditableField
                label="Minimum OS"
                value={form?.minimum_os_version ?? ''}
                editing={editing}
                onChange={(v) => updateField('minimum_os_version', v)}
              />
              <EditableField
                label="Maximum OS"
                value={form?.maximum_os_version ?? ''}
                editing={editing}
                onChange={(v) => updateField('maximum_os_version', v)}
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
                editing={editing}
                onChange={(v) => updateField('unattended_install', v)}
              />
              <BooleanField
                label="Unattended Uninstall"
                value={form?.unattended_uninstall ?? false}
                editing={editing}
                onChange={(v) => updateField('unattended_uninstall', v)}
              />
              <BooleanField
                label="Auto Remove"
                value={form?.autoremove ?? false}
                editing={editing}
                onChange={(v) => updateField('autoremove', v)}
              />
              <BooleanField
                label="Uninstallable"
                value={form?.uninstallable ?? true}
                editing={editing}
                onChange={(v) => updateField('uninstallable', v)}
              />
              <InfoField
                label="Uninstall Method"
                value={pkg.uninstall_method}
                readOnly
                editing={false}
              />
              <InfoField
                label="Installer Type"
                value={pkg.installer_type}
                readOnly
                editing={false}
              />
            </CardContent>
          </Card>

          {editing && (
            <Card>
              <CardHeader>
                <CardTitle>Array Fields</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <TagField
                  label="Blocking Applications"
                  values={form?.blocking_applications ?? []}
                  onChange={(v) => updateField('blocking_applications', v)}
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
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="install" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Installer Details</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <InfoField
                label="Location"
                value={pkg.installer_item_location}
                readOnly
                editing={false}
              />
              <InfoField
                label="Hash (SHA256)"
                value={pkg.installer_item_hash}
                readOnly
                editing={false}
              />
              <InfoField
                label="Size"
                value={
                  pkg.installer_item_size
                    ? `${Math.round(pkg.installer_item_size / 1024)} MB`
                    : null
                }
                readOnly
                editing={false}
              />
              {!editing && pkg.blocking_applications && (
                <div>
                  <span className="text-sm font-medium text-muted-foreground">
                    Blocking Applications
                  </span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {pkg.blocking_applications.map((app) => (
                      <Badge key={app} variant="outline">
                        {app}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {!editing && pkg.requires && (
                <div>
                  <span className="text-sm font-medium text-muted-foreground">
                    Requires
                  </span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {pkg.requires.map((r) => (
                      <Badge key={r} variant="outline">
                        {r}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {pkg.installs != null && (
            <Card>
              <CardHeader>
                <CardTitle>Installs Detection</CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="overflow-auto rounded-md bg-muted p-4 text-sm">
                  {JSON.stringify(pkg.installs, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}

          {pkg.receipts != null && (
            <Card>
              <CardHeader>
                <CardTitle>Receipts</CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="overflow-auto rounded-md bg-muted p-4 text-sm">
                  {JSON.stringify(pkg.receipts, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="scripts" className="space-y-4">
          {pkg.preinstall_script && (
            <ScriptCard
              title="Pre-install Script"
              script={pkg.preinstall_script}
            />
          )}
          {pkg.postinstall_script && (
            <ScriptCard
              title="Post-install Script"
              script={pkg.postinstall_script}
            />
          )}
          {!pkg.preinstall_script && !pkg.postinstall_script && (
            <p className="text-muted-foreground">No scripts configured</p>
          )}
        </TabsContent>

        <TabsContent value="audit" className="space-y-4">
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

function InfoField({
  label,
  value,
}: {
  label: string
  value: string | null | undefined
  readOnly: boolean
  editing: boolean
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

function ScriptCard({ title, script }: { title: string; script: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <pre className="overflow-auto rounded-md bg-muted p-4 font-mono text-sm">
          {script}
        </pre>
      </CardContent>
    </Card>
  )
}

function CatalogEditor({
  pkgId,
  catalogNames,
}: {
  pkgId: string
  catalogNames: string[]
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
