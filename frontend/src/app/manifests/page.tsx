'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileText, Plus, Trash2 } from 'lucide-react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { useAuth } from '@/components/auth-provider'
import { SoftwareNameAvatarCircles } from '@/components/software-avatar-circles'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { api, type ManifestRead } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { parseManifestItemRef } from '@/lib/manifest-item-ref'
import { manifestTitle, manifestTitleForName } from '@/lib/manifest-title'
import { munkiAccents } from '@/lib/munki-accents'
import { PAGE_KEYS } from '@/lib/page-keys'
import { cn } from '@/lib/utils'

const MANIFEST_CARD_AVATAR_MAX = 8

export default function ManifestsPage() {
  const { canWrite } = useAuth()
  const canEditManifests = canWrite(PAGE_KEYS.munkiManifests)

  const queryClient = useQueryClient()
  const router = useRouter()
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [displayName, setDisplayName] = useState('')

  const [deleteManifest, setDeleteManifest] = useState<ManifestRead | null>(
    null,
  )

  const { data: manifests, isLoading } = useQuery({
    queryKey: ['manifests'],
    queryFn: () => api.get<ManifestRead[]>('/manifests'),
  })

  const createMutation = useMutation({
    mutationFn: (payload: { name: string; display_name?: string }) =>
      api.post<ManifestRead>('/manifests', payload),
    onSuccess: (created) => {
      toast.success(`Manifest "${manifestTitle(created)}" created`)
      queryClient.invalidateQueries({ queryKey: ['manifests'] })
      setCreateOpen(false)
      setName('')
      setDisplayName('')
      router.push(`/manifests/${created.id}`)
    },
    onError: (err: Error) => toast.error(`Failed to create: ${err.message}`),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/manifests/${id}`),
    onSuccess: () => {
      toast.success('Manifest deleted')
      queryClient.invalidateQueries({ queryKey: ['manifests'] })
      setDeleteManifest(null)
    },
    onError: (err: Error) => toast.error(`Failed to delete: ${err.message}`),
  })

  const manifestByName = useMemo(() => {
    const m = new Map<string, ManifestRead>()
    for (const man of manifests ?? []) {
      m.set(man.name, man)
    }
    return m
  }, [manifests])

  const handleCreate = () => {
    const trimmed = name.trim()
    if (!trimmed) return
    createMutation.mutate({
      name: trimmed,
      display_name: displayName.trim() || undefined,
    })
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Loading…
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1
          className={cn(
            'text-3xl font-bold text-pretty',
            munkiAccents.manifests.pageTitle,
          )}
        >
          Manifests
        </h1>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          {canEditManifests ? (
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-1 h-4 w-4" />
                New Manifest
              </Button>
            </DialogTrigger>
          ) : null}
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Manifest</DialogTitle>
              <DialogDescription>
                Create a new Munki manifest. You can add catalogs and software
                after creation.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="manifest-name">Name</Label>
                <Input
                  id="manifest-name"
                  placeholder="e.g. site_default"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleCreate()
                  }}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="manifest-display-name">
                  Display Name (optional)
                </Label>
                <Input
                  id="manifest-display-name"
                  placeholder="e.g. Default Site Manifest"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleCreate()
                  }}
                />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={handleCreate}
                disabled={!name.trim() || createMutation.isPending}
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={!!deleteManifest}
        onOpenChange={(v) => {
          if (!v) setDeleteManifest(null)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Manifest</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &ldquo;
              {deleteManifest ? manifestTitle(deleteManifest) : ''}
              &rdquo;? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteManifest(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteManifest && deleteMutation.mutate(deleteManifest.id)
              }
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
        {manifests?.map((manifest) => (
          <Card
            key={manifest.id}
            className={cn(
              'relative h-full overflow-hidden',
              munkiAccents.manifests.manifestGridCard,
            )}
          >
            <Link
              href={`/manifests/${manifest.id}`}
              className="absolute inset-0 z-[1] cursor-pointer rounded-xl outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              aria-label={`Edit manifest ${manifestTitle(manifest)}`}
            />
            <CardHeader className="relative z-[2] pointer-events-none">
              <CardTitle className="flex items-center justify-between">
                <div className="flex min-w-0 flex-col gap-0.5">
                  <div className="flex items-center gap-3">
                    <FileText
                      className={cn(
                        'h-5 w-5 shrink-0',
                        munkiAccents.manifests.icon,
                      )}
                      aria-hidden
                    />
                    <span className="truncate">{manifestTitle(manifest)}</span>
                  </div>
                  {manifestTitle(manifest) !== manifest.name && (
                    <span className="truncate pl-8 text-sm font-normal text-muted-foreground">
                      {manifest.name}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {manifest.catalog_names.map((c) => (
                    <Badge key={c} variant="secondary">
                      {c}
                    </Badge>
                  ))}
                  {canEditManifests ? (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="pointer-events-auto h-8 w-8 text-muted-foreground hover:text-destructive"
                      aria-label={`Delete ${manifestTitle(manifest)}`}
                      onClick={() => setDeleteManifest(manifest)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  ) : null}
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="relative z-[2] flex min-h-0 flex-1 flex-col pointer-events-none">
              <div className="flex min-h-0 flex-1 flex-col gap-4">
                {manifest.managed_installs.length > 0 && (
                  <div>
                    <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                      Managed Installs
                    </h4>
                    <SoftwareNameAvatarCircles
                      names={manifest.managed_installs.map(
                        (n) => parseManifestItemRef(n).baseName,
                      )}
                      maxVisible={MANIFEST_CARD_AVATAR_MAX}
                      interactive={false}
                    />
                  </div>
                )}

                {manifest.managed_uninstalls.length > 0 && (
                  <div>
                    <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                      Managed Uninstalls
                    </h4>
                    <SoftwareNameAvatarCircles
                      names={manifest.managed_uninstalls.map(
                        (n) => parseManifestItemRef(n).baseName,
                      )}
                      maxVisible={MANIFEST_CARD_AVATAR_MAX}
                      interactive={false}
                    />
                  </div>
                )}

                {manifest.optional_installs.length > 0 && (
                  <div>
                    <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                      Optional Installs
                    </h4>
                    <SoftwareNameAvatarCircles
                      names={manifest.optional_installs.map(
                        (n) => parseManifestItemRef(n).baseName,
                      )}
                      maxVisible={MANIFEST_CARD_AVATAR_MAX}
                      interactive={false}
                    />
                  </div>
                )}

                {manifest.included_manifest_names.length > 0 && (
                  <>
                    <Separator />
                    <div>
                      <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                        Included Manifests
                      </h4>
                      <div className="flex flex-wrap gap-1">
                        {manifest.included_manifest_names.map((n) => (
                          <Badge key={n} variant="secondary">
                            {manifestTitleForName(manifestByName, n)}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </>
                )}

                <p
                  suppressHydrationWarning
                  className="mt-auto pt-2 text-xs text-muted-foreground"
                >
                  Updated {formatDateTime(manifest.updated_at)}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}

        {!manifests?.length && (
          <p className="text-muted-foreground">
            No manifests found. Click &ldquo;New Manifest&rdquo; to create one.
          </p>
        )}
      </div>
    </div>
  )
}
