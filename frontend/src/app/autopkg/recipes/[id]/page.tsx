'use client'

import { useQuery } from '@tanstack/react-query'
import { ArrowLeft } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useAuth } from '@/components/auth-provider'
import { RecipeOverrideEditor } from '@/components/autopkg-recipe-override-editor'
import { SoftwareIcon } from '@/components/software-icon'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Button } from '@/components/ui/button'
import {
  type PkginfoItemMeta,
  usePkginfoItemMeta,
} from '@/hooks/use-pkginfo-display-labels'
import { type AutoPkgRecipeRead, api } from '@/lib/api'
import { recipeListIconName, recipePkginfoKey } from '@/lib/autopkg-recipe'
import { munkiAccents } from '@/lib/munki-accents'
import { PAGE_KEYS } from '@/lib/page-keys'
import { cn } from '@/lib/utils'

export default function RecipeOverrideEditPage() {
  const { canWrite } = useAuth()
  const canEditRecipes = canWrite(PAGE_KEYS.autopkgRecipes)

  const params = useParams()
  const router = useRouter()
  const id = params.id as string

  const {
    data: recipe,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ['autopkg-recipe', id],
    queryFn: async () => {
      const list = await api.get<AutoPkgRecipeRead[]>('/autopkg/recipes')
      const r = list.find((x) => x.id === id)
      if (!r) throw new Error('Recipe not found')
      return r
    },
  })

  const pkgKey = recipe ? recipePkginfoKey(recipe) : ''
  const { data: pkgMeta } = usePkginfoItemMeta(recipe ? [pkgKey] : [])
  const meta: PkginfoItemMeta | undefined = pkgMeta?.[pkgKey]

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        Loading...
      </div>
    )
  }

  if (isError || !recipe) {
    return (
      <div className="space-y-4">
        <p className="text-muted-foreground">Recipe not found.</p>
        <Button variant="outline" asChild>
          <Link href="/autopkg/recipes">Back to recipes</Link>
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/autopkg/recipes">Recipes</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage className="max-w-[min(100%,48ch)] truncate">
              {recipe.name}
            </BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4 min-w-0">
          <SoftwareIcon
            name={pkgKey || recipe.name}
            displayName={meta?.displayName ?? null}
            iconName={recipeListIconName(meta?.iconName, recipe)}
            size="lg"
          />
          <div className={cn('min-w-0', munkiAccents.autopkg.pageTitle)}>
            <h1 className="text-3xl font-bold text-pretty truncate">
              {meta?.displayName ?? recipe.name}
            </h1>
            <p className="text-muted-foreground font-mono text-sm truncate">
              {recipe.identifier}
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="shrink-0 self-start sm:self-center"
          asChild
        >
          <Link href="/autopkg/recipes">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to list
          </Link>
        </Button>
      </div>

      <p className="text-sm text-muted-foreground max-w-3xl">
        {canEditRecipes
          ? 'Modify the recipe override settings. Changes are saved to the database.'
          : 'Recipe override settings (read-only).'}
      </p>

      <RecipeOverrideEditor
        recipe={recipe}
        readOnly={!canEditRecipes}
        onDeleted={() => router.push('/autopkg/recipes')}
      />
    </div>
  )
}
