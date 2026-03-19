'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  BookOpen,
  ChevronRight,
  ExternalLink,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Star,
  X,
} from 'lucide-react'
import { parseAsString, useQueryState } from 'nuqs'
import { useState } from 'react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import {
  type AutoPkgRecipeRead,
  api,
  type CachedGitHubRepo,
  type DiscoveredRecipe,
  type SearchedRecipe,
} from '@/lib/api'

export default function DiscoverRecipesPage() {
  const [search, setSearch] = useQueryState(
    'search',
    parseAsString.withDefault(''),
  )
  const [selectedRepo, setSelectedRepo] = useState<CachedGitHubRepo | null>(
    null,
  )
  const queryClient = useQueryClient()
  const trimmed = search.trim()
  const isSearching = trimmed.length >= 2

  const { data: repos, isLoading: reposLoading } = useQuery({
    queryKey: ['discover-repos'],
    queryFn: () => api.get<CachedGitHubRepo[]>('/autopkg/recipes/discover'),
  })

  const { data: searchData, isFetching: searchFetching } = useQuery({
    queryKey: ['search-recipes', trimmed],
    queryFn: () =>
      api.get<{ results: SearchedRecipe[]; total: number }>(
        `/autopkg/recipes/search?q=${encodeURIComponent(trimmed)}`,
      ),
    enabled: isSearching,
  })

  const { data: existingRecipes } = useQuery({
    queryKey: ['autopkg-recipes'],
    queryFn: () => api.get<AutoPkgRecipeRead[]>('/autopkg/recipes'),
  })

  const existingIdentifiers = new Set(
    (existingRecipes ?? []).map((r) => r.identifier),
  )

  const syncReposMutation = useMutation({
    mutationFn: () =>
      api.post<Record<string, number>>('/autopkg/cache/sync-repos'),
    onSuccess: (data) => {
      toast.success(
        `Synced repos: ${data.added} added, ${data.updated} updated, ${data.total} total`,
      )
      queryClient.invalidateQueries({ queryKey: ['discover-repos'] })
    },
    onError: (err: Error) => toast.error(`Sync failed: ${err.message}`),
  })

  const syncRecipesMutation = useMutation({
    mutationFn: () =>
      api.post<Record<string, number>>('/autopkg/cache/sync-recipes'),
    onSuccess: (data) => {
      toast.success(
        `Synced recipes for ${data.repos_synced} repos (${data.total_recipes} recipes)`,
      )
      queryClient.invalidateQueries({ queryKey: ['discover-repos'] })
    },
    onError: (err: Error) => toast.error(`Sync failed: ${err.message}`),
  })

  const addMutation = useMutation({
    mutationFn: (recipe: SearchedRecipe | DiscoveredRecipe) =>
      api.post<AutoPkgRecipeRead>('/autopkg/recipes/add-override', {
        identifier: recipe.identifier_guess,
        name: recipe.name,
        is_enabled: true,
        is_override: true,
        github_repo: recipe.repo_full_name,
        recipe_path: recipe.path,
      }),
    onSuccess: (_data, recipe) => {
      toast.success(`Added override for ${recipe.name}`)
      queryClient.invalidateQueries({ queryKey: ['autopkg-recipes'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const searchResults = searchData?.results ?? []
  const searchByRepo = new Map<string, SearchedRecipe[]>()
  for (const r of searchResults) {
    const list = searchByRepo.get(r.repo_full_name) ?? []
    list.push(r)
    searchByRepo.set(r.repo_full_name, list)
  }

  const allRepos = repos ?? []
  const isEmpty = allRepos.length === 0 && !reposLoading

  const sorted = isSearching
    ? [...allRepos].sort((a, b) => {
        const aHas = searchByRepo.has(a.full_name) ? 0 : 1
        const bHas = searchByRepo.has(b.full_name) ? 0 : 1
        if (aHas !== bHas) return aHas - bHas
        return a.name.localeCompare(b.name)
      })
    : allRepos

  const isSyncing = syncReposMutation.isPending || syncRecipesMutation.isPending

  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <div>
        <h1 className="text-3xl font-bold">Discover Recipes</h1>
        <p className="mt-1 text-muted-foreground">
          Browse cached AutoPkg recipe repos or search for specific recipes.
          Click a repo to see all its recipes.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search for recipes (e.g. Firefox, Unity, Chrome)..."
            value={search}
            onChange={(e) => setSearch(e.target.value || null)}
            className="pl-9"
          />
        </div>
        {search && (
          <Button
            variant="ghost"
            size="sm"
            aria-label="Clear search"
            onClick={() => setSearch(null)}
          >
            <X className="mr-1 h-4 w-4" />
            Clear
          </Button>
        )}
        {searchFetching && (
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        )}
        {isSearching && searchData && !searchFetching && (
          <span className="text-sm text-muted-foreground">
            {searchData.total} recipe
            {searchData.total !== 1 ? 's' : ''} found in {searchByRepo.size}{' '}
            repo
            {searchByRepo.size !== 1 ? 's' : ''}
          </span>
        )}
        {!isSearching && allRepos.length > 0 && !reposLoading && (
          <span className="text-sm text-muted-foreground">
            {allRepos.length} repos cached
          </span>
        )}

        <div className="ml-auto flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={isSyncing}
            onClick={() => syncReposMutation.mutate()}
          >
            <RefreshCw
              className={`mr-1 h-4 w-4 ${syncReposMutation.isPending ? 'animate-spin' : ''}`}
            />
            Sync Repos
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={isSyncing || allRepos.length === 0}
            onClick={() => syncRecipesMutation.mutate()}
          >
            <RefreshCw
              className={`mr-1 h-4 w-4 ${syncRecipesMutation.isPending ? 'animate-spin' : ''}`}
            />
            Sync All Recipes
          </Button>
        </div>
      </div>

      {reposLoading ? (
        <div className="flex items-center justify-center py-12 text-muted-foreground">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
          Loading cached repos...
        </div>
      ) : isEmpty ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground gap-4">
          <BookOpen className="h-12 w-12" />
          <p className="text-lg">No repos cached yet.</p>
          <p className="text-sm">
            Click &quot;Sync Repos&quot; to fetch the list of AutoPkg recipe
            repos from GitHub, then &quot;Sync All Recipes&quot; to index their
            recipes.
          </p>
          <Button
            onClick={() => syncReposMutation.mutate()}
            disabled={syncReposMutation.isPending}
          >
            <RefreshCw
              className={`mr-2 h-4 w-4 ${syncReposMutation.isPending ? 'animate-spin' : ''}`}
            />
            Sync Repos from GitHub
          </Button>
        </div>
      ) : (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {sorted.map((repo) => {
              const recipes = searchByRepo.get(repo.full_name)
              const hasRecipeResults =
                isSearching && recipes && recipes.length > 0
              const cachedCount = repo.cached_recipes?.length ?? 0

              return (
                <Card
                  key={repo.full_name}
                  className={`border-l-4 transition-colors ${
                    hasRecipeResults
                      ? 'border-l-emerald-500/50'
                      : 'border-l-blue-500/30 hover:border-l-blue-500/60'
                  } ${!hasRecipeResults ? 'cursor-pointer' : ''}`}
                  onClick={
                    !hasRecipeResults ? () => setSelectedRepo(repo) : undefined
                  }
                >
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2 truncate">
                        <BookOpen
                          className={`h-4 w-4 shrink-0 ${hasRecipeResults ? 'text-emerald-500' : 'text-blue-500'}`}
                        />
                        <span className="truncate">{repo.name}</span>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {hasRecipeResults && (
                          <Badge variant="default" className="text-xs">
                            {recipes.length} match
                            {recipes.length !== 1 ? 'es' : ''}
                          </Badge>
                        )}
                        {cachedCount > 0 && !hasRecipeResults && (
                          <Badge
                            variant="secondary"
                            className="text-xs tabular-nums"
                          >
                            {cachedCount}
                          </Badge>
                        )}
                        {repo.stars > 0 && (
                          <Badge variant="outline" className="text-xs">
                            <Star className="mr-1 h-3 w-3" />
                            {repo.stars}
                          </Badge>
                        )}
                        {!hasRecipeResults && (
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        )}
                        {hasRecipeResults && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 px-1"
                            aria-label={`Browse all recipes in ${repo.name}`}
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedRepo(repo)
                            }}
                          >
                            <ChevronRight className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </CardTitle>
                    {repo.description && (
                      <CardDescription className="line-clamp-2 text-xs">
                        {repo.description}
                      </CardDescription>
                    )}
                  </CardHeader>

                  {hasRecipeResults && (
                    <CardContent className="space-y-1 pt-0">
                      {recipes.map((recipe) => {
                        const alreadyAdded = existingIdentifiers.has(
                          recipe.identifier_guess,
                        )
                        return (
                          <div
                            key={recipe.path}
                            className="flex items-center justify-between rounded-md border bg-background px-3 py-2"
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium">
                                  {recipe.name}
                                </span>
                                {alreadyAdded && (
                                  <Badge
                                    variant="secondary"
                                    className="text-xs"
                                  >
                                    Added
                                  </Badge>
                                )}
                              </div>
                              <p className="truncate text-xs text-muted-foreground">
                                {recipe.path}
                              </p>
                            </div>
                            <div className="flex shrink-0 items-center gap-2">
                              <a
                                href={recipe.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-muted-foreground hover:text-foreground"
                              >
                                <ExternalLink className="h-4 w-4" />
                              </a>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={alreadyAdded || addMutation.isPending}
                                aria-label={`Add override for ${recipe.name}`}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  addMutation.mutate(recipe)
                                }}
                              >
                                <Plus className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        )
                      })}
                    </CardContent>
                  )}
                </Card>
              )
            })}
          </div>
        </div>
      )}

      {selectedRepo && (
        <RepoRecipesDialog
          repo={selectedRepo}
          existingIdentifiers={existingIdentifiers}
          onClose={() => setSelectedRepo(null)}
          onAdded={() =>
            queryClient.invalidateQueries({
              queryKey: ['autopkg-recipes'],
            })
          }
        />
      )}
    </div>
  )
}

function RepoRecipesDialog({
  repo,
  existingIdentifiers,
  onClose,
  onAdded,
}: {
  repo: CachedGitHubRepo
  existingIdentifiers: Set<string>
  onClose: () => void
  onAdded: () => void
}) {
  const [recipeSearch, setRecipeSearch] = useState('')
  const queryClient = useQueryClient()

  const hasCachedRecipes = (repo.cached_recipes?.length ?? 0) > 0

  const { data, isLoading } = useQuery({
    queryKey: ['discover-repo-recipes', repo.full_name],
    queryFn: () =>
      api.get<{ recipes: DiscoveredRecipe[]; total: number }>(
        `/autopkg/recipes/discover/${repo.full_name}`,
      ),
    enabled: !hasCachedRecipes,
  })

  const syncMutation = useMutation({
    mutationFn: () =>
      api.post<{ recipes_synced: number }>(
        `/autopkg/cache/sync-repo/${repo.full_name}`,
      ),
    onSuccess: (data) => {
      toast.success(`Synced ${data.recipes_synced} recipes for ${repo.name}`)
      queryClient.invalidateQueries({ queryKey: ['discover-repos'] })
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const addMutation = useMutation({
    mutationFn: (recipe: DiscoveredRecipe) =>
      api.post<AutoPkgRecipeRead>('/autopkg/recipes/add-override', {
        identifier: recipe.identifier_guess,
        name: recipe.name,
        is_enabled: true,
        is_override: true,
        github_repo: recipe.repo_full_name,
        recipe_path: recipe.path,
      }),
    onSuccess: (_data, recipe) => {
      toast.success(`Added override for ${recipe.name}`)
      onAdded()
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const recipesToShow = hasCachedRecipes
    ? repo.cached_recipes
        .filter((r) =>
          recipeSearch
            ? r.name.toLowerCase().includes(recipeSearch.toLowerCase())
            : true,
        )
        .map((r) => ({
          name: r.name,
          filename: r.filename,
          path: r.path,
          identifier_guess: r.identifier_guess,
          repo_full_name: repo.full_name,
          url: r.url,
        }))
    : (data?.recipes ?? []).filter((r) =>
        recipeSearch
          ? r.name.toLowerCase().includes(recipeSearch.toLowerCase())
          : true,
      )

  const totalCount = hasCachedRecipes
    ? repo.cached_recipes.length
    : (data?.total ?? 0)

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-h-[80vh] sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-blue-500" />
            {repo.name}
          </DialogTitle>
          <DialogDescription>
            Munki recipes in this repo. Click + to add an override.
            <a
              href={repo.html_url}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-2 inline-flex items-center gap-1 text-primary hover:underline"
            >
              View on GitHub
              <ExternalLink className="h-3 w-3" />
            </a>
          </DialogDescription>
        </DialogHeader>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Filter recipes..."
            value={recipeSearch}
            onChange={(e) => setRecipeSearch(e.target.value)}
            className="pl-9"
          />
        </div>

        <div className="max-h-[50vh] space-y-1 overflow-y-auto rounded-md border p-2">
          {!hasCachedRecipes && isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning repo...
            </div>
          ) : recipesToShow.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No .munki.recipe files found.
              {!hasCachedRecipes && " Try syncing this repo's recipes."}
            </p>
          ) : (
            recipesToShow.map((recipe) => {
              const alreadyAdded = existingIdentifiers.has(
                recipe.identifier_guess,
              )
              return (
                <div
                  key={recipe.path}
                  className="flex items-center justify-between rounded-md px-3 py-2 hover:bg-accent"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{recipe.name}</span>
                      {alreadyAdded && (
                        <Badge variant="secondary" className="text-xs">
                          Added
                        </Badge>
                      )}
                    </div>
                    <p className="truncate text-xs text-muted-foreground">
                      {recipe.path}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <a
                      href={recipe.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={alreadyAdded || addMutation.isPending}
                      aria-label={`Add override for ${recipe.name}`}
                      onClick={() => addMutation.mutate(recipe)}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )
            })
          )}
        </div>

        <DialogFooter className="flex-row items-center justify-between sm:justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">
              {totalCount > 0 ? `${totalCount} recipes` : ''}
            </span>
            <Button
              variant="ghost"
              size="sm"
              disabled={syncMutation.isPending}
              onClick={() => syncMutation.mutate()}
            >
              <RefreshCw
                className={`mr-1 h-3 w-3 ${syncMutation.isPending ? 'animate-spin' : ''}`}
              />
              Sync
            </Button>
          </div>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
