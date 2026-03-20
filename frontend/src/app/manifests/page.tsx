'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileText, Pencil, Plus, Trash2 } from 'lucide-react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'
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
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

export default function ManifestsPage() {
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
      toast.success(`Manifest "${created.name}" created`)
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
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-1 h-4 w-4" />
              New Manifest
            </Button>
          </DialogTrigger>
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
              Are you sure you want to delete &ldquo;{deleteManifest?.name}
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
            className={cn(munkiAccents.manifests.manifestGridCard)}
          >
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <FileText
                    className={cn('h-5 w-5', munkiAccents.manifests.icon)}
                    aria-hidden
                  />
                  <span>{manifest.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  {manifest.catalog_names.map((c) => (
                    <Badge key={c} variant="secondary">
                      {c}
                    </Badge>
                  ))}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    aria-label={`Edit ${manifest.name}`}
                    asChild
                  >
                    <Link href={`/manifests/${manifest.id}`}>
                      <Pencil className="h-4 w-4" />
                    </Link>
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-muted-foreground hover:text-destructive"
                    aria-label={`Delete ${manifest.name}`}
                    onClick={() => setDeleteManifest(manifest)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {manifest.managed_installs.length > 0 && (
                <div>
                  <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                    Managed Installs
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {manifest.managed_installs.map((item) => (
                      <Badge key={item} variant="outline">
                        {item}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {manifest.managed_uninstalls.length > 0 && (
                <div>
                  <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                    Managed Uninstalls
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {manifest.managed_uninstalls.map((item) => (
                      <Badge key={item} variant="destructive">
                        {item}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {manifest.optional_installs.length > 0 && (
                <div>
                  <h4 className="mb-2 text-sm font-medium text-muted-foreground">
                    Optional Installs
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {manifest.optional_installs.map((item) => (
                      <Badge key={item} variant="outline">
                        {item}
                      </Badge>
                    ))}
                  </div>
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
                          {n}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}

              <p
                suppressHydrationWarning
                className="text-xs text-muted-foreground"
              >
                Updated {formatDateTime(manifest.updated_at)}
              </p>
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
