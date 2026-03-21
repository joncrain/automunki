'use client'

import { useQuery } from '@tanstack/react-query'
import { Copy, Play } from 'lucide-react'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  type AutoPkgRecipeRead,
  type AutoPkgRunRead,
  api,
  type UiSettingsRead,
} from '@/lib/api'

/** Trust failed / pending approval: excluded from runner config and cannot be selected. */
export function canTriggerRunRecipe(recipe: AutoPkgRecipeRead): boolean {
  return (
    recipe.trust_status !== 'failed' &&
    recipe.trust_status !== 'pending_approval'
  )
}

export const RUNNER_STORAGE_KEY = 'automunki.autopkg_runner'

/** Safe for zsh/bash single-quoted strings */
export function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

export function getApiOrigin(): string {
  const fromEnv = (process.env.NEXT_PUBLIC_API_URL || '')
    .trim()
    .replace(/\/$/, '')
  if (fromEnv) return fromEnv
  if (typeof window !== 'undefined') return window.location.origin
  return ''
}

/** Command to run from the automunki repo root (see AutoPkg/scripts/run_local_autopkg.sh) */
export function buildLocalRunnerShellCommand(run: AutoPkgRunRead): string {
  const origin = getApiOrigin()
  const originArg = origin || '<your-api-origin>'
  let line = `./AutoPkg/scripts/run_local_autopkg.sh --backend-url ${shellSingleQuote(originArg)} --run-id ${run.id}`
  if (run.recipe_filter?.length) {
    line += ` --recipes ${shellSingleQuote(run.recipe_filter.join(','))}`
  }
  return line
}

export function LocalRunnerToastBody({ cmd }: { cmd: string }) {
  return (
    <div className="mt-2 space-y-2">
      <pre className="max-h-40 overflow-auto break-all rounded-md border bg-muted/50 p-2 text-left font-mono text-xs whitespace-pre-wrap">
        {cmd}
      </pre>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          size="sm"
          variant="secondary"
          className="shrink-0"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(cmd)
              toast.success('Copied to clipboard', { duration: 2500 })
            } catch {
              toast.error('Could not copy to clipboard')
            }
          }}
        >
          <Copy className="mr-1.5 h-3.5 w-3.5" />
          Copy command
        </Button>
      </div>
      <p className="text-muted-foreground text-xs leading-snug">
        Add <code className="text-xs">--token</code> if your API requires JWT.
        See <code className="text-xs">docs/local-autopkg-runner.md</code>.
      </p>
    </div>
  )
}

export function QuickRunDialog({
  open,
  onOpenChange,
  recipe,
  isPending,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** When null, triggers a run for all enabled recipes (``recipe_names`` omitted). */
  recipe: AutoPkgRecipeRead | null
  isPending: boolean
  onConfirm: (runner: 'github' | 'local') => void
}) {
  const [runner, setRunner] = useState<'github' | 'local'>('github')

  const { data: uiSettings } = useQuery({
    queryKey: ['settings', 'ui'],
    queryFn: () => api.get<UiSettingsRead>('/settings/ui'),
    enabled: open,
  })

  useEffect(() => {
    if (!open) return
    const saved =
      typeof window !== 'undefined'
        ? localStorage.getItem(RUNNER_STORAGE_KEY)
        : null
    if (saved === 'github' || saved === 'local') {
      setRunner(saved)
      return
    }
    if (
      uiSettings?.autopkg_runner_mode === 'github' ||
      uiSettings?.autopkg_runner_mode === 'local'
    ) {
      setRunner(uiSettings.autopkg_runner_mode)
    }
  }, [open, uiSettings])

  const singleBlocked = recipe !== null && !canTriggerRunRecipe(recipe)

  const handleRun = () => {
    if (singleBlocked) return
    localStorage.setItem(RUNNER_STORAGE_KEY, runner)
    onConfirm(runner)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {recipe ? `Run recipe: ${recipe.name}` : 'Run all enabled recipes'}
          </DialogTitle>
          <DialogDescription>
            {recipe ? (
              <>
                Choose whether AutoPkg runs on GitHub Actions or locally on a
                Mac (see{' '}
                <code className="text-xs">docs/local-autopkg-runner.md</code>).
              </>
            ) : (
              <>
                Triggers AutoPkg for every <strong>enabled</strong> recipe
                override, same as choosing no recipes on the Runs page. Recipes
                with failed or pending trust are handled by the runner workflow.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-2 py-2">
          <Label htmlFor="quick-run-runner">Runner</Label>
          <Select
            value={runner}
            onValueChange={(v) => setRunner(v as 'github' | 'local')}
          >
            <SelectTrigger id="quick-run-runner" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="github">GitHub Actions</SelectItem>
              <SelectItem value="local">Local Mac (manual script)</SelectItem>
            </SelectContent>
          </Select>
          {runner === 'local' && (
            <p className="text-xs text-muted-foreground">
              After confirming, copy the shell command from the toast and run it
              in your clone.
            </p>
          )}
        </div>

        {singleBlocked && (
          <p className="rounded-md border border-dashed bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
            This recipe cannot run until trust is verified or approved (failed
            or pending).
          </p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleRun} disabled={isPending || singleBlocked}>
            <Play className="mr-1 h-4 w-4" />
            {isPending ? 'Starting…' : recipe ? 'Run' : 'Run all enabled'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
