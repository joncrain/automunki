'use client'

import type { ColumnDef } from '@tanstack/react-table'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useAuth } from '@/components/auth-provider'
import { DataTable } from '@/components/data-table'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { api } from '@/lib/api'
import { PAGE_KEYS } from '@/lib/page-keys'
import { cn } from '@/lib/utils'

type RolePermissionRow = { page_key: string; access_level: string }
type RoleRead = {
  id: string
  name: string
  description: string | null
  is_system: boolean
  permissions: RolePermissionRow[]
}
type UserRolesRead = {
  user_id: string
  email: string
  is_superuser: boolean
  role_ids: string[]
}

const ALL_PAGES = Object.values(PAGE_KEYS)

const ROLES_SUMMARY_MAX = 120

/** Grouped sections for the permissions editor (mirrors sidebar areas). */
const PAGE_GROUPS: {
  label: string
  keys: (typeof PAGE_KEYS)[keyof typeof PAGE_KEYS][]
}[] = [
  { label: 'Overview', keys: [PAGE_KEYS.overview] },
  {
    label: 'Munki',
    keys: [
      PAGE_KEYS.munkiSoftware,
      PAGE_KEYS.munkiManifests,
      PAGE_KEYS.munkiCatalogs,
    ],
  },
  {
    label: 'AutoPkg',
    keys: [
      PAGE_KEYS.autopkgRuns,
      PAGE_KEYS.autopkgRecipes,
      PAGE_KEYS.autopkgDiscover,
      PAGE_KEYS.autopkgApprovals,
    ],
  },
  {
    label: 'Reporting',
    keys: [PAGE_KEYS.reportingDevices, PAGE_KEYS.reportingInstalls],
  },
  {
    label: 'Admin',
    keys: [
      PAGE_KEYS.adminAudit,
      PAGE_KEYS.adminSettings,
      PAGE_KEYS.adminAccess,
    ],
  },
]

const PERMISSIONS_SUMMARY_MAX = 100

function formatPermissionsSummary(role: RoleRead): string {
  const s = role.permissions
    .filter((p) => p.access_level !== 'none')
    .map((p) => `${p.page_key}:${p.access_level}`)
    .join(', ')
  return s || '—'
}

function formatUserRolesSummary(
  user: UserRolesRead,
  allRoles: RoleRead[],
): string {
  const names = user.role_ids
    .map((id) => allRoles.find((r) => r.id === id)?.name)
    .filter((n): n is string => Boolean(n))
  if (user.is_superuser) {
    const base = names.length ? names.join(', ') : ''
    return base ? `Superuser; ${base}` : 'Superuser'
  }
  return names.length ? names.join(', ') : '—'
}

function truncateWithEllipsis(s: string, max: number): string {
  if (s.length <= max) return s
  return `${s.slice(0, max)}…`
}

export default function AdminAccessPage() {
  const { canRead, canWrite, loading, me } = useAuth()
  const [roles, setRoles] = useState<RoleRead[]>([])
  const [users, setUsers] = useState<UserRolesRead[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [permissionsDialogRoleId, setPermissionsDialogRoleId] = useState<
    string | null
  >(null)
  const [deleteTarget, setDeleteTarget] = useState<RoleRead | null>(null)
  const [addRoleOpen, setAddRoleOpen] = useState(false)
  const [editUser, setEditUser] = useState<UserRolesRead | null>(null)
  const [deleteUserTarget, setDeleteUserTarget] =
    useState<UserRolesRead | null>(null)

  const load = useCallback(async () => {
    setErr(null)
    try {
      const [r, u] = await Promise.all([
        api.get<RoleRead[]>('/rbac/roles'),
        api.get<UserRolesRead[]>('/rbac/users'),
      ])
      setRoles(r)
      setUsers(u)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to load')
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const canEdit = canWrite(PAGE_KEYS.adminAccess)

  const editingRole = useMemo(
    () => roles.find((r) => r.id === permissionsDialogRoleId) ?? null,
    [roles, permissionsDialogRoleId],
  )

  const handleDeletedRole = useCallback(
    (id: string) => {
      if (permissionsDialogRoleId === id) setPermissionsDialogRoleId(null)
      void load()
    },
    [permissionsDialogRoleId, load],
  )

  const myUserId = me?.user.id

  const userColumns = useMemo<ColumnDef<UserRolesRead>[]>(
    () => [
      {
        accessorKey: 'email',
        header: 'Email',
        cell: ({ row }) => (
          <span className="font-medium">{row.original.email}</span>
        ),
      },
      {
        id: 'roles',
        header: 'Roles',
        enableSorting: false,
        cell: ({ row }) => {
          const u = row.original
          const full = formatUserRolesSummary(u, roles)
          const display =
            full === '—' ? full : truncateWithEllipsis(full, ROLES_SUMMARY_MAX)
          return (
            <span
              className="block max-w-xl text-sm text-muted-foreground"
              title={full !== '—' ? full : undefined}
            >
              {display}
            </span>
          )
        },
      },
      ...(canEdit
        ? [
            {
              id: 'actions',
              header: '',
              enableSorting: false,
              cell: ({ row }) => {
                const u = row.original
                const isSelf = myUserId === u.user_id
                const cannotDeleteSuper =
                  u.is_superuser && !me?.user.is_superuser
                return (
                  <div className="flex items-center justify-end gap-0.5">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          type="button"
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8"
                          onClick={() => setEditUser(u)}
                        >
                          <Pencil className="size-4" />
                          <span className="sr-only">Edit roles</span>
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="left">Edit roles</TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="inline-flex">
                          <Button
                            type="button"
                            size="icon"
                            variant="ghost"
                            className={cn(
                              'h-8 w-8',
                              isSelf || cannotDeleteSuper
                                ? 'pointer-events-none opacity-40'
                                : 'text-destructive hover:bg-destructive/10 hover:text-destructive',
                            )}
                            disabled={isSelf || cannotDeleteSuper}
                            onClick={() => {
                              if (!isSelf && !cannotDeleteSuper) {
                                setDeleteUserTarget(u)
                              }
                            }}
                          >
                            <Trash2 className="size-4" />
                            <span className="sr-only">Delete user</span>
                          </Button>
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="left">
                        {isSelf
                          ? 'You cannot delete your own account here'
                          : cannotDeleteSuper
                            ? 'Only superusers can delete superuser accounts'
                            : 'Delete user'}
                      </TooltipContent>
                    </Tooltip>
                  </div>
                )
              },
            } satisfies ColumnDef<UserRolesRead>,
          ]
        : []),
    ],
    [roles, canEdit, myUserId, me?.user.is_superuser],
  )

  const roleColumns = useMemo<ColumnDef<RoleRead>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Name',
        cell: ({ row }) => (
          <span className="font-medium">{row.original.name}</span>
        ),
      },
      {
        accessorKey: 'is_system',
        header: 'System',
        cell: ({ row }) => (row.original.is_system ? 'Yes' : 'No'),
      },
      {
        id: 'permissions',
        header: 'Permissions',
        enableSorting: false,
        cell: ({ row }) => {
          const full = formatPermissionsSummary(row.original)
          const display =
            full === '—'
              ? full
              : truncateWithEllipsis(full, PERMISSIONS_SUMMARY_MAX)
          return (
            <span
              className="block max-w-xl text-xs text-muted-foreground"
              title={full !== '—' ? full : undefined}
            >
              {display}
            </span>
          )
        },
      },
      ...(canEdit
        ? [
            {
              id: 'actions',
              header: '',
              enableSorting: false,
              cell: ({ row }) => {
                const r = row.original
                return (
                  <div className="flex items-center justify-end gap-0.5">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          type="button"
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8"
                          onClick={() => setPermissionsDialogRoleId(r.id)}
                        >
                          <Pencil className="size-4" />
                          <span className="sr-only">Edit permissions</span>
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="left">
                        Edit permissions
                      </TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="inline-flex">
                          <Button
                            type="button"
                            size="icon"
                            variant="ghost"
                            className={cn(
                              'h-8 w-8',
                              r.is_system
                                ? 'pointer-events-none opacity-40'
                                : 'text-destructive hover:bg-destructive/10 hover:text-destructive',
                            )}
                            disabled={r.is_system}
                            onClick={() => {
                              if (!r.is_system) setDeleteTarget(r)
                            }}
                          >
                            <Trash2 className="size-4" />
                            <span className="sr-only">Delete role</span>
                          </Button>
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="left">
                        {r.is_system
                          ? 'System roles cannot be deleted'
                          : 'Delete role'}
                      </TooltipContent>
                    </Tooltip>
                  </div>
                )
              },
            } satisfies ColumnDef<RoleRead>,
          ]
        : []),
    ],
    [canEdit],
  )

  if (!loading && !canRead(PAGE_KEYS.adminAccess)) {
    return (
      <p className="text-destructive">You do not have access to this page.</p>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">Access control</h1>
        <p className="text-sm text-muted-foreground">
          Manage roles and which users have them. Changes apply on next API
          request.
        </p>
      </div>
      {err ? <p className="text-destructive">{err}</p> : null}

      <Tabs defaultValue="users" className="min-h-0 flex flex-col">
        <TabsList>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="roles">Roles</TabsTrigger>
        </TabsList>
        <TabsContent value="users" className="mt-4 min-h-0 flex-1">
          <div className="h-[min(28rem,calc(100vh-14rem))]">
            <DataTable
              columns={userColumns}
              data={users}
              getRowId={(row) => row.user_id}
              isLoading={false}
            />
          </div>
          <UserEditRolesDialog
            user={editUser}
            allRoles={roles}
            open={editUser != null}
            onOpenChange={(open) => {
              if (!open) setEditUser(null)
            }}
            onSaved={() => void load()}
            onError={setErr}
          />
          <DeleteUserDialog
            user={deleteUserTarget}
            open={deleteUserTarget != null}
            onOpenChange={(open) => {
              if (!open) setDeleteUserTarget(null)
            }}
            onDeleted={() => void load()}
            onError={setErr}
          />
        </TabsContent>
        <TabsContent value="roles" className="mt-4 space-y-3">
          {canEdit ? (
            <div className="flex justify-end">
              <Button type="button" onClick={() => setAddRoleOpen(true)}>
                <Plus className="size-4" />
                Add role
              </Button>
            </div>
          ) : null}
          <div className="h-[min(28rem,calc(100vh-14rem))]">
            <DataTable
              columns={roleColumns}
              data={roles}
              getRowId={(r) => r.id}
            />
          </div>
          <RolePermissionsDialog
            open={permissionsDialogRoleId != null}
            onOpenChange={(open) => {
              if (!open) setPermissionsDialogRoleId(null)
            }}
            role={editingRole}
            allPages={ALL_PAGES}
            onSaved={load}
          />
          <AddRoleDialog
            open={addRoleOpen}
            onOpenChange={setAddRoleOpen}
            onCreated={(id) => {
              void load().then(() => setPermissionsDialogRoleId(id))
            }}
            onError={setErr}
          />
          <DeleteRoleDialog
            role={deleteTarget}
            open={deleteTarget != null}
            onOpenChange={(open) => {
              if (!open) setDeleteTarget(null)
            }}
            onDeleted={handleDeletedRole}
            onError={setErr}
          />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function UserEditRolesDialog({
  user,
  allRoles,
  open,
  onOpenChange,
  onSaved,
  onError,
}: {
  user: UserRolesRead | null
  allRoles: RoleRead[]
  open: boolean
  onOpenChange: (open: boolean) => void
  onSaved: () => void
  onError: (msg: string | null) => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (user) setSelected([...user.role_ids])
  }, [user])

  async function save() {
    if (!user) return
    setPending(true)
    onError(null)
    try {
      await api.put(`/rbac/users/${user.user_id}/roles`, {
        role_ids: selected,
      })
      onOpenChange(false)
      onSaved()
    } catch (e) {
      onError(e instanceof Error ? e.message : 'Failed to save roles')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" showCloseButton>
        <DialogHeader>
          <DialogTitle>User roles</DialogTitle>
          <DialogDescription>
            {user ? (
              <>
                Assign roles for{' '}
                <span className="font-medium text-foreground">
                  {user.email}
                </span>
                .
                {user.is_superuser ? (
                  <span className="mt-2 block text-muted-foreground">
                    Superusers have full access; role assignments still apply
                    for non-superuser checks where relevant.
                  </span>
                ) : null}
              </>
            ) : null}
          </DialogDescription>
        </DialogHeader>
        <div className="grid max-h-[min(50vh,20rem)] gap-2 overflow-y-auto py-2">
          {allRoles.map((r) => (
            <label
              key={r.id}
              className="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm"
            >
              <input
                type="checkbox"
                className="rounded border"
                checked={selected.includes(r.id)}
                onChange={(e) => {
                  if (e.target.checked) setSelected([...selected, r.id])
                  else setSelected(selected.filter((x) => x !== r.id))
                }}
              />
              <span>{r.name}</span>
            </label>
          ))}
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button type="button" disabled={pending} onClick={() => void save()}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DeleteUserDialog({
  user,
  open,
  onOpenChange,
  onDeleted,
  onError,
}: {
  user: UserRolesRead | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted: () => void
  onError: (msg: string | null) => void
}) {
  const [pending, setPending] = useState(false)

  async function confirmDelete() {
    if (!user) return
    setPending(true)
    onError(null)
    try {
      await api.delete(`/rbac/users/${user.user_id}`)
      onOpenChange(false)
      onDeleted()
    } catch (e) {
      onError(e instanceof Error ? e.message : 'Failed to delete user')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" showCloseButton>
        <DialogHeader>
          <DialogTitle>Delete user?</DialogTitle>
          <DialogDescription>
            This permanently removes{' '}
            <span className="font-medium text-foreground">{user?.email}</span>{' '}
            and their login. This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2 sm:gap-0">
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={pending || !user}
            onClick={() => void confirmDelete()}
          >
            Delete user
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function AccessLevelSelect({
  value,
  onChange,
  id,
}: {
  value: string
  onChange: (v: string) => void
  id: string
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger id={id} size="sm" className="h-8 w-[7.5rem] shrink-0">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="none">None</SelectItem>
        <SelectItem value="read">Read</SelectItem>
        <SelectItem value="write">Write</SelectItem>
      </SelectContent>
    </Select>
  )
}

function RolePermissionsDialog({
  open,
  onOpenChange,
  role,
  allPages,
  onSaved,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  role: RoleRead | null
  allPages: string[]
  onSaved: () => void
}) {
  const [levels, setLevels] = useState<Record<string, string>>({})
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!role) return
    const m: Record<string, string> = {}
    for (const pk of allPages) {
      const row = role.permissions.find((p) => p.page_key === pk)
      m[pk] = row?.access_level ?? 'none'
    }
    setLevels(m)
  }, [role, allPages])

  async function savePerms() {
    if (!role) return
    setPending(true)
    try {
      const permissions = allPages.map((page_key) => ({
        page_key,
        access_level: levels[page_key] ?? 'none',
      }))
      await api.put(`/rbac/roles/${role.id}/permissions`, { permissions })
      onSaved()
    } finally {
      setPending(false)
    }
  }

  const pageSet = new Set(allPages)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="flex max-h-[min(90vh,44rem)] min-h-0 w-full max-w-[calc(100%-2rem)] flex-col gap-0 overflow-hidden p-0 sm:max-w-2xl"
        showCloseButton
      >
        <div className="shrink-0 border-b bg-muted/30 px-6 py-5 pr-14">
          <DialogHeader className="gap-1.5 text-left">
            <DialogTitle className="text-xl">Role permissions</DialogTitle>
            <DialogDescription className="text-sm">
              {role ? (
                <>
                  Set access for each page for{' '}
                  <span className="font-medium text-foreground">
                    {role.name}
                  </span>
                  .
                </>
              ) : null}
            </DialogDescription>
          </DialogHeader>
        </div>
        {role ? (
          <>
            <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-6 py-4">
              <div className="space-y-6">
                {PAGE_GROUPS.map((group) => {
                  const keys = group.keys.filter((k) => pageSet.has(k))
                  if (keys.length === 0) return null
                  return (
                    <div key={group.label}>
                      <h3 className="mb-2.5 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                        {group.label}
                      </h3>
                      <div className="space-y-2">
                        {keys.map((pk) => (
                          <div
                            key={pk}
                            className="flex items-center justify-between gap-3 rounded-lg border bg-card px-3 py-2.5 shadow-xs"
                          >
                            <code className="truncate text-xs leading-snug text-muted-foreground">
                              {pk}
                            </code>
                            <AccessLevelSelect
                              id={`perm-${pk}`}
                              value={levels[pk] ?? 'none'}
                              onChange={(v) =>
                                setLevels((prev) => ({ ...prev, [pk]: v }))
                              }
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
            <div className="shrink-0 border-t bg-muted/20 px-6 py-4">
              <DialogFooter className="flex w-full flex-row justify-end gap-2 sm:justify-end">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => onOpenChange(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  disabled={pending}
                  onClick={() => void savePerms()}
                >
                  Save permissions
                </Button>
              </DialogFooter>
            </div>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function AddRoleDialog({
  open,
  onOpenChange,
  onCreated,
  onError,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (roleId: string) => void
  onError: (msg: string | null) => void
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (open) {
      setName('')
      setDescription('')
    }
  }, [open])

  async function submit() {
    const trimmed = name.trim()
    if (!trimmed) return
    setPending(true)
    onError(null)
    try {
      const created = await api.post<RoleRead>('/rbac/roles', {
        name: trimmed,
        description: description.trim() || null,
      })
      onOpenChange(false)
      onCreated(created.id)
    } catch (e) {
      onError(e instanceof Error ? e.message : 'Failed to create role')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" showCloseButton>
        <DialogHeader>
          <DialogTitle>Add role</DialogTitle>
          <DialogDescription>
            Create a new role. You can set page permissions after it is created.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="new-role-name">Name</Label>
            <Input
              id="new-role-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Support"
              autoComplete="off"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="new-role-desc">Description (optional)</Label>
            <Input
              id="new-role-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Short summary"
              autoComplete="off"
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            disabled={pending || !name.trim()}
            onClick={() => void submit()}
          >
            Create role
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DeleteRoleDialog({
  role,
  open,
  onOpenChange,
  onDeleted,
  onError,
}: {
  role: RoleRead | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted: (id: string) => void
  onError: (msg: string | null) => void
}) {
  const [pending, setPending] = useState(false)

  async function confirmDelete() {
    if (!role) return
    setPending(true)
    onError(null)
    try {
      await api.delete(`/rbac/roles/${role.id}`)
      onOpenChange(false)
      onDeleted(role.id)
    } catch (e) {
      onError(e instanceof Error ? e.message : 'Failed to delete role')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" showCloseButton>
        <DialogHeader>
          <DialogTitle>Delete role?</DialogTitle>
          <DialogDescription>
            This removes the role{' '}
            <span className="font-medium text-foreground">{role?.name}</span>.
            Users who only had this role may lose access until you assign
            another role.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2 sm:gap-0">
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={pending || !role}
            onClick={() => void confirmDelete()}
          >
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
