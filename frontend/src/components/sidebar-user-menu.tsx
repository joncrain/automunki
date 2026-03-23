'use client'

import {
  ChevronDown,
  LogOut,
  Monitor,
  Moon,
  Palette,
  Sun,
  User,
} from 'lucide-react'
import { useTheme } from 'next-themes'
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useAuth } from '@/components/auth-provider'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { SidebarMenuButton } from '@/components/ui/sidebar'
import { useUserAvatarBlobUrl } from '@/hooks/use-user-avatar-blob'
import { api, deleteUserAvatar, uploadUserAvatar } from '@/lib/api'

type UserRead = {
  id: string
  email: string
  display_name: string | null
  is_active: boolean
  is_superuser: boolean
  is_verified: boolean
  role: string
}

function initialsFromUser(
  displayName: string | null | undefined,
  email: string,
): string {
  const s = displayName?.trim()
  if (s) {
    const parts = s.split(/\s+/).filter(Boolean)
    if (parts.length >= 2) {
      const a = parts[0][0]
      const b = parts[parts.length - 1][0]
      return `${a ?? ''}${b ?? ''}`.toUpperCase()
    }
    return s.slice(0, 2).toUpperCase()
  }
  if (email.length >= 2) return email.slice(0, 2).toUpperCase()
  return '?'
}

function profileLabel(displayName: string | null | undefined, email: string) {
  if (displayName?.trim()) return displayName.trim()
  const local = email.split('@')[0]
  return local || email
}

const HOVER_CLOSE_MS = 220

export function SidebarUserMenu() {
  const { me, loading, refresh, logout } = useAuth()
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    setMounted(true)
  }, [])

  const clearCloseTimer = useCallback(() => {
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current)
      closeTimerRef.current = null
    }
  }, [])

  const scheduleClose = useCallback(() => {
    clearCloseTimer()
    closeTimerRef.current = setTimeout(() => {
      setMenuOpen(false)
      closeTimerRef.current = null
    }, HOVER_CLOSE_MS)
  }, [clearCloseTimer])

  const openMenu = useCallback(() => {
    clearCloseTimer()
    setMenuOpen(true)
  }, [clearCloseTimer])

  useEffect(() => {
    return () => clearCloseTimer()
  }, [clearCloseTimer])

  const avatarBlobUrl = useUserAvatarBlobUrl(
    me?.user.has_avatar,
    me?.user.updated_at,
  )

  if (loading || !me) {
    return null
  }

  const label = profileLabel(me.user.display_name, me.user.email)
  const initials = initialsFromUser(me.user.display_name, me.user.email)
  const authEnabled = me.auth_mode !== 'disabled'

  return (
    <>
      <DropdownMenu
        modal={false}
        open={menuOpen}
        onOpenChange={(o) => {
          if (!o) clearCloseTimer()
          setMenuOpen(o)
        }}
      >
        <DropdownMenuTrigger asChild>
          <SidebarMenuButton
            size="lg"
            className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            tooltip={label}
            onMouseEnter={openMenu}
            onMouseLeave={scheduleClose}
          >
            <Avatar size="sm" className="shrink-0">
              {avatarBlobUrl ? (
                <AvatarImage src={avatarBlobUrl} alt="" />
              ) : null}
              <AvatarFallback className="text-xs">{initials}</AvatarFallback>
            </Avatar>
            <div className="grid min-w-0 flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
              <span className="truncate font-medium">{label}</span>
              <span className="truncate text-xs text-muted-foreground">
                {me.user.email}
              </span>
            </div>
            <ChevronDown className="size-4 shrink-0 opacity-60 group-data-[collapsible=icon]:hidden" />
          </SidebarMenuButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          className="w-56"
          side="right"
          align="end"
          onMouseEnter={openMenu}
          onMouseLeave={scheduleClose}
        >
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col space-y-0.5">
              <span className="text-sm font-medium">{label}</span>
              <span className="text-xs text-muted-foreground">
                {me.user.email}
              </span>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {mounted ? (
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>
                <Palette className="size-4" />
                Appearance
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent className="w-44">
                <DropdownMenuRadioGroup
                  value={theme ?? 'system'}
                  onValueChange={(v) => setTheme(v)}
                >
                  <DropdownMenuRadioItem value="light">
                    <Sun className="size-4" />
                    Light
                  </DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="dark">
                    <Moon className="size-4" />
                    Dark
                  </DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="system">
                    <Monitor className="size-4" />
                    System
                  </DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
          ) : null}
          {authEnabled ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onSelect={() => {
                  setMenuOpen(false)
                  setProfileOpen(true)
                }}
              >
                <User className="size-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem
                variant="destructive"
                onSelect={() => {
                  setMenuOpen(false)
                  logout()
                }}
              >
                <LogOut className="size-4" />
                Log out
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>

      <ProfileDialog
        open={profileOpen}
        onOpenChange={setProfileOpen}
        me={me}
        refresh={refresh}
        avatarBlobUrl={avatarBlobUrl}
      />
    </>
  )
}

function ProfileDialog({
  open,
  onOpenChange,
  me,
  refresh,
  avatarBlobUrl,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  me: NonNullable<ReturnType<typeof useAuth>['me']>
  refresh: () => Promise<void>
  avatarBlobUrl: string | null
}) {
  const formId = useId()
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState(false)
  const [avatarPending, setAvatarPending] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (open && me.user) {
      setDisplayName(me.user.display_name ?? '')
      setPassword('')
      setConfirm('')
      setError(null)
      setMessage(null)
    }
  }, [open, me.user])

  const disabled = me.auth_mode === 'disabled'
  const initials = initialsFromUser(me.user.display_name, me.user.email)

  async function onAvatarFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || disabled) return
    setError(null)
    setMessage(null)
    setAvatarPending(true)
    try {
      await uploadUserAvatar(file)
      setMessage('Avatar updated.')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to upload avatar')
    } finally {
      setAvatarPending(false)
    }
  }

  async function onRemoveAvatar() {
    if (disabled || !me.user.has_avatar) return
    setError(null)
    setMessage(null)
    setAvatarPending(true)
    try {
      await deleteUserAvatar()
      setMessage('Avatar removed.')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove avatar')
    } finally {
      setAvatarPending(false)
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setMessage(null)
    if (password || confirm) {
      if (password !== confirm) {
        setError('Passwords do not match.')
        return
      }
      if (password.length < 8) {
        setError('Password must be at least 8 characters.')
        return
      }
    }
    setPending(true)
    try {
      const body: {
        display_name?: string | null
        password?: string
      } = {}
      const trimmed = displayName.trim()
      if (trimmed !== (me.user.display_name ?? '')) {
        body.display_name = trimmed || null
      }
      if (password) {
        body.password = password
      }
      if (Object.keys(body).length === 0) {
        setMessage('No changes to save.')
        return
      }
      await api.patch<UserRead>('/users/me', body)
      setPassword('')
      setConfirm('')
      setMessage('Saved.')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="flex max-h-[min(90vh,36rem)] flex-col gap-0 overflow-hidden p-0 sm:max-w-md"
        showCloseButton
      >
        <DialogHeader className="shrink-0 border-b px-6 py-4 text-left">
          <DialogTitle>Profile</DialogTitle>
          <DialogDescription>
            Update your display name, profile photo, and password. Email cannot
            be changed.
          </DialogDescription>
        </DialogHeader>
        {disabled ? (
          <p className="px-6 py-4 text-sm text-muted-foreground">
            Profile and password are not available while authentication is
            disabled on the server.
          </p>
        ) : (
          <form
            id={formId}
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={(e) => void onSubmit(e)}
          >
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-4">
              <div className="flex flex-wrap items-center gap-4">
                <Avatar className="size-16 shrink-0">
                  {avatarBlobUrl ? (
                    <AvatarImage src={avatarBlobUrl} alt="" />
                  ) : null}
                  <AvatarFallback className="text-lg">
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="flex min-w-0 flex-1 flex-col gap-2">
                  <Label htmlFor={`${formId}-avatar`}>Profile photo</Label>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={avatarPending || pending}
                      onClick={() =>
                        document.getElementById(`${formId}-avatar`)?.click()
                      }
                    >
                      {avatarPending ? 'Working…' : 'Upload image'}
                    </Button>
                    {me.user.has_avatar ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={avatarPending || pending}
                        onClick={() => void onRemoveAvatar()}
                      >
                        Remove
                      </Button>
                    ) : null}
                  </div>
                  <input
                    id={`${formId}-avatar`}
                    type="file"
                    accept="image/png,image/jpeg"
                    className="sr-only"
                    onChange={(e) => void onAvatarFile(e)}
                  />
                  <p className="text-xs text-muted-foreground">
                    PNG or JPEG, up to 1&nbsp;MB.
                  </p>
                </div>
              </div>
              <Separator />
              <div className="grid gap-2">
                <Label htmlFor={`${formId}-email`}>Email</Label>
                <Input
                  id={`${formId}-email`}
                  readOnly
                  value={me.user.email}
                  autoComplete="email"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor={`${formId}-name`}>Display name</Label>
                <Input
                  id={`${formId}-name`}
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Your name"
                  autoComplete="name"
                />
              </div>
              <Separator />
              <p className="text-xs text-muted-foreground">
                Leave password fields blank to keep your current password.
              </p>
              <div className="grid gap-2">
                <Label htmlFor={`${formId}-pw`}>New password</Label>
                <Input
                  id={`${formId}-pw`}
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor={`${formId}-pw2`}>Confirm new password</Label>
                <Input
                  id={`${formId}-pw2`}
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              {error ? (
                <p className="text-sm text-destructive">{error}</p>
              ) : null}
              {message ? (
                <p className="text-sm text-muted-foreground">{message}</p>
              ) : null}
            </div>
            <DialogFooter className="shrink-0 border-t bg-muted/20 px-6 py-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Close
              </Button>
              <Button type="submit" form={formId} disabled={pending}>
                {pending ? 'Saving…' : 'Save changes'}
              </Button>
            </DialogFooter>
          </form>
        )}
        {disabled ? (
          <DialogFooter className="border-t px-6 py-4">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Close
            </Button>
          </DialogFooter>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
