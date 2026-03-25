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

/** What the quick-run dialog should trigger (single recipe, all enabled, or table multi-select). */
export type RecipeQuickRunTarget =
  | { mode: 'single'; recipe: AutoPkgRecipeRead }
  | { mode: 'all' }
  | { mode: 'selected'; recipes: AutoPkgRecipeRead[] }

export const RUNNER_STORAGE_KEY = 'automunki.autopkg_runner'

/** When runner is local: ``manual`` = copy shell command; ``daemon`` = poll script picks up. */
export const RUNNER_LOCAL_DELIVERY_KEY = 'automunki.autopkg_local_delivery'

export type LocalDeliveryMode = 'manual' | 'daemon'

export function getLocalDeliveryMode(): LocalDeliveryMode {
  if (typeof window === 'undefined') return 'manual'
  return localStorage.getItem(RUNNER_LOCAL_DELIVERY_KEY) === 'daemon'
    ? 'daemon'
    : 'manual'
}

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

export function LocalDaemonToastBody() {
  return (
    <p className="mt-2 text-muted-foreground text-xs leading-snug">
      If <code className="text-xs">poll_local_autopkg.sh</code> is running with{' '}
      <code className="text-xs">LOCAL_RUNNER_TOKEN</code>, it will claim and run
      this automatically. See{' '}
      <code className="text-xs">docs/local-autopkg-runner.md</code>.
    </p>
  )
}

/** Call after a successful local run registration; reads delivery mode from localStorage. */
export function toastLocalRunRegistered(run: AutoPkgRunRead) {
  if (getLocalDeliveryMode() === 'daemon') {
    toast.success('Local run queued', {
      description: <LocalDaemonToastBody />,
      duration: 14_000,
      closeButton: true,
    })
    return
  }
  const cmd = buildLocalRunnerShellCommand(run)
  toast.success('Local run registered — run from your clone', {
    description: <LocalRunnerToastBody cmd={cmd} />,
    duration: Infinity,
    closeButton: true,
  })
}

export function QuickRunDialog({
  open,
  onOpenChange,
  target,
  isPending,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  target: RecipeQuickRunTarget | null
  isPending: boolean
  /** ``recipeNames`` null = all enabled recipes; otherwise explicit list for the run. */
  onConfirm: (runner: 'github' | 'local', recipeNames: string[] | null) => void
}) {
  const [runnerChoice, setRunnerChoice] = useState<
    'github' | 'local-manual' | 'local-daemon'
  >('github')

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
    const delivery =
      typeof window !== 'undefined'
        ? localStorage.getItem(RUNNER_LOCAL_DELIVERY_KEY)
        : null
    if (saved === 'github') {
      setRunnerChoice('github')
      return
    }
    if (saved === 'local') {
      setRunnerChoice(delivery === 'daemon' ? 'local-daemon' : 'local-manual')
      return
    }
    if (
      uiSettings?.autopkg_runner_mode === 'github' ||
      uiSettings?.autopkg_runner_mode === 'local'
    ) {
      setRunnerChoice(
        uiSettings.autopkg_runner_mode === 'local'
          ? delivery === 'daemon'
            ? 'local-daemon'
            : 'local-manual'
          : 'github',
      )
    }
  }, [open, uiSettings])

  const singleBlocked =
    target?.mode === 'single' && !canTriggerRunRecipe(target.recipe)

  const blockedInSelection =
    target?.mode === 'selected'
      ? target.recipes.filter((r) => !canTriggerRunRecipe(r))
      : []

  const cannotRun = singleBlocked || blockedInSelection.length > 0

  const handleRun = () => {
    if (!target || cannotRun) return
    const apiRunner = runnerChoice === 'github' ? 'github' : 'local'
    localStorage.setItem(RUNNER_STORAGE_KEY, apiRunner)
    if (apiRunner === 'local') {
      localStorage.setItem(
        RUNNER_LOCAL_DELIVERY_KEY,
        runnerChoice === 'local-daemon' ? 'daemon' : 'manual',
      )
    }
    const recipeNames =
      target.mode === 'all'
        ? null
        : target.mode === 'single'
          ? [target.recipe.name]
          : target.recipes.map((r) => r.name)
    onConfirm(apiRunner, recipeNames)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {target?.mode === 'single'
              ? `Run recipe: ${target.recipe.name}`
              : target?.mode === 'selected'
                ? `Run ${target.recipes.length} selected recipe${target.recipes.length === 1 ? '' : 's'}`
                : 'Run all enabled recipes'}
          </DialogTitle>
          <DialogDescription>
            {target?.mode === 'single' ? (
              <>
                Choose whether AutoPkg runs on GitHub Actions or locally on a
                Mac (see{' '}
                <code className="text-xs">docs/local-autopkg-runner.md</code>).
              </>
            ) : target?.mode === 'selected' ? (
              <>
                Runs only the recipes you selected in the table (not necessarily
                every enabled recipe). Choose GitHub Actions or a local Mac
                runner.
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
            value={runnerChoice}
            onValueChange={(v) =>
              setRunnerChoice(v as 'github' | 'local-manual' | 'local-daemon')
            }
          >
            <SelectTrigger id="quick-run-runner" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="github">GitHub Actions</SelectItem>
              <SelectItem value="local-manual">
                Local Mac (copy shell command)
              </SelectItem>
              <SelectItem value="local-daemon">
                Local Mac (automated daemon)
              </SelectItem>
            </SelectContent>
          </Select>
          {runnerChoice === 'local-manual' && (
            <p className="text-xs text-muted-foreground">
              After confirming, copy the shell command from the toast and run it
              in your clone.
            </p>
          )}
          {runnerChoice === 'local-daemon' && (
            <p className="text-xs text-muted-foreground">
              Use <code className="text-xs">poll_local_autopkg.sh</code> with{' '}
              <code className="text-xs">LOCAL_RUNNER_TOKEN</code> on the Mac
              that runs AutoPkg.
            </p>
          )}
        </div>

        {singleBlocked && (
          <p className="rounded-md border border-dashed bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
            This recipe cannot run until trust is verified or approved (failed
            or pending).
          </p>
        )}

        {blockedInSelection.length > 0 && (
          <p className="rounded-md border border-dashed bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
            Cannot run while selection includes recipes with failed or pending
            trust:{' '}
            <span className="font-medium">
              {blockedInSelection.map((r) => r.name).join(', ')}
            </span>
          </p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleRun} disabled={isPending || cannotRun}>
            <Play className="mr-1 h-4 w-4" />
            {isPending
              ? 'Starting…'
              : target?.mode === 'single'
                ? 'Run'
                : target?.mode === 'selected'
                  ? `Run ${target.recipes.length} selected`
                  : 'Run all enabled'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
