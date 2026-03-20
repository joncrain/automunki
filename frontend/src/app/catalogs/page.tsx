'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FolderOpen, Pencil, Plus, Trash2 } from 'lucide-react'
import Link from 'next/link'
import { useState } from 'react'
import { toast } from 'sonner'
import { SoftwareIcon } from '@/components/software-icon'
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
import { Switch } from '@/components/ui/switch'
import { api, type CatalogRead, type PkgInfoSummary } from '@/lib/api'
import { formatDate } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

export default function CatalogsPage() {
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isProduction, setIsProduction] = useState(false)

  const [editCatalog, setEditCatalog] = useState<CatalogRead | null>(null)
  const [editDescription, setEditDescription] = useState('')
  const [editIsProduction, setEditIsProduction] = useState(false)

  const [deleteCatalog, setDeleteCatalog] = useState<CatalogRead | null>(null)
  const [viewCatalog, setViewCatalog] = useState<CatalogRead | null>(null)

  const { data: catalogs, isLoading } = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.get<CatalogRead[]>('/catalogs'),
  })

  const createMutation = useMutation({
    mutationFn: (payload: {
      name: string
      description?: string
      is_production: boolean
    }) => api.post<CatalogRead>('/catalogs', payload),
    onSuccess: (created) => {
      toast.success(`Catalog "${created.name}" created`)
      queryClient.invalidateQueries({ queryKey: ['catalogs'] })
      setCreateOpen(false)
      resetCreateForm()
    },
    onError: (err: Error) => toast.error(`Failed to create: ${err.message}`),
  })

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      ...payload
    }: {
      id: string
      description?: string
      is_production?: boolean
    }) => api.put<CatalogRead>(`/catalogs/${id}`, payload),
    onSuccess: (updated) => {
      toast.success(`Catalog "${updated.name}" updated`)
      queryClient.invalidateQueries({ queryKey: ['catalogs'] })
      setEditCatalog(null)
    },
    onError: (err: Error) => toast.error(`Failed to update: ${err.message}`),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/catalogs/${id}`),
    onSuccess: () => {
      toast.success('Catalog deleted')
      queryClient.invalidateQueries({ queryKey: ['catalogs'] })
      setDeleteCatalog(null)
    },
    onError: (err: Error) => toast.error(`Failed to delete: ${err.message}`),
  })

  function resetCreateForm() {
    setName('')
    setDescription('')
    setIsProduction(false)
  }

  const handleCreate = () => {
    const trimmed = name.trim()
    if (!trimmed) return
    createMutation.mutate({
      name: trimmed,
      description: description.trim() || undefined,
      is_production: isProduction,
    })
  }

  const openEdit = (catalog: CatalogRead) => {
    setEditCatalog(catalog)
    setEditDescription(catalog.description ?? '')
    setEditIsProduction(catalog.is_production)
  }

  const handleUpdate = () => {
    if (!editCatalog) return
    updateMutation.mutate({
      id: editCatalog.id,
      description: editDescription.trim() || undefined,
      is_production: editIsProduction,
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
            munkiAccents.catalogs.pageTitle,
          )}
        >
          Catalogs
        </h1>
        <Dialog
          open={createOpen}
          onOpenChange={(v) => {
            setCreateOpen(v)
            if (!v) resetCreateForm()
          }}
        >
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-1 h-4 w-4" />
              New Catalog
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Catalog</DialogTitle>
              <DialogDescription>
                Create a new Munki catalog. Software can be assigned to it
                afterwards.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="catalog-name">Name</Label>
                <Input
                  id="catalog-name"
                  placeholder="e.g. production"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleCreate()
                  }}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="catalog-description">
                  Description (optional)
                </Label>
                <Input
                  id="catalog-description"
                  placeholder="e.g. Production software catalog"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleCreate()
                  }}
                />
              </div>
              <div className="flex items-center gap-3">
                <Switch
                  id="catalog-production"
                  checked={isProduction}
                  onCheckedChange={setIsProduction}
                />
                <Label htmlFor="catalog-production">Production catalog</Label>
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

      {/* Edit Dialog */}
      <Dialog
        open={!!editCatalog}
        onOpenChange={(v) => {
          if (!v) setEditCatalog(null)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Catalog: {editCatalog?.name}</DialogTitle>
            <DialogDescription>
              Update catalog settings. The name cannot be changed.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="edit-catalog-description">Description</Label>
              <Input
                id="edit-catalog-description"
                placeholder="e.g. Production software catalog"
                value={editDescription}
                onChange={(e) => setEditDescription(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleUpdate()
                }}
              />
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="edit-catalog-production"
                checked={editIsProduction}
                onCheckedChange={setEditIsProduction}
              />
              <Label htmlFor="edit-catalog-production">
                Production catalog
              </Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditCatalog(null)}>
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? 'Saving...' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={!!deleteCatalog}
        onOpenChange={(v) => {
          if (!v) setDeleteCatalog(null)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Catalog</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &ldquo;{deleteCatalog?.name}
              &rdquo;? This action cannot be undone.
              {(deleteCatalog?.item_count ?? 0) > 0 && (
                <span className="mt-2 block font-medium text-destructive">
                  This catalog has {deleteCatalog?.item_count} assigned items
                  and cannot be deleted until they are removed.
                </span>
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteCatalog(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteCatalog && deleteMutation.mutate(deleteCatalog.id)
              }
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* View Items Dialog */}
      {viewCatalog && (
        <CatalogItemsDialog
          catalog={viewCatalog}
          onClose={() => setViewCatalog(null)}
        />
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {catalogs?.map((catalog) => (
          <Card
            key={catalog.id}
            className={cn(munkiAccents.catalogs.catalogGridCard)}
            onClick={() => setViewCatalog(catalog)}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <CardTitle className="flex items-center gap-2">
                <FolderOpen
                  className={cn('h-5 w-5', munkiAccents.catalogs.icon)}
                  aria-hidden
                />
                {catalog.name}
              </CardTitle>
              <div className="flex items-center gap-2">
                {catalog.is_production && (
                  <Badge variant="default">Production</Badge>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label={`Edit ${catalog.name}`}
                  onClick={(e) => {
                    e.stopPropagation()
                    openEdit(catalog)
                  }}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-muted-foreground hover:text-destructive"
                  aria-label={`Delete ${catalog.name}`}
                  onClick={(e) => {
                    e.stopPropagation()
                    setDeleteCatalog(catalog)
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <p
                className="text-2xl font-bold"
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {catalog.item_count}
              </p>
              <p className="text-sm text-muted-foreground">software titles</p>
              {catalog.description && (
                <p className="mt-2 text-sm">{catalog.description}</p>
              )}
              <p
                suppressHydrationWarning
                className="mt-2 text-xs text-muted-foreground"
              >
                Created {formatDate(catalog.created_at)}
              </p>
            </CardContent>
          </Card>
        ))}

        {!catalogs?.length && (
          <p className="col-span-full text-muted-foreground">
            No catalogs found. Click &ldquo;New Catalog&rdquo; to create one.
          </p>
        )}
      </div>
    </div>
  )
}

function CatalogItemsDialog({
  catalog,
  onClose,
}: {
  catalog: CatalogRead
  onClose: () => void
}) {
  const { data: items, isLoading } = useQuery({
    queryKey: ['catalog-items', catalog.id],
    queryFn: () => api.get<PkgInfoSummary[]>(`/catalogs/${catalog.id}/items`),
  })

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-h-[80vh] sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderOpen className={cn('h-5 w-5', munkiAccents.catalogs.icon)} />
            {catalog.name}
            {catalog.is_production && (
              <Badge variant="default" className="ml-2">
                Production
              </Badge>
            )}
          </DialogTitle>
          <DialogDescription>
            {catalog.item_count} software title
            {catalog.item_count !== 1 ? 's' : ''} in this catalog
          </DialogDescription>
        </DialogHeader>
        <div className="max-h-[55vh] overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              Loading…
            </div>
          ) : items?.length ? (
            <div className="divide-y">
              {items.map((item) => (
                <Link
                  key={item.id}
                  href={`/software/${item.id}`}
                  className="flex items-center gap-3 px-2 py-2.5 transition-colors hover:bg-accent/50 rounded-md"
                >
                  <SoftwareIcon
                    name={item.name}
                    displayName={item.display_name}
                    size="sm"
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium text-sm">
                      {item.display_name || item.name}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      {item.name} — {item.version}
                    </p>
                  </div>
                  {item.category && (
                    <Badge variant="outline" className="shrink-0 text-xs">
                      {item.category}
                    </Badge>
                  )}
                </Link>
              ))}
            </div>
          ) : (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No software titles in this catalog.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
