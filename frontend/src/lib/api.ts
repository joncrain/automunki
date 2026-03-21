const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers,
  })

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(error.detail || `API error: ${res.status}`)
  }

  if (res.status === 204) return {} as T
  return res.json()
}

export const api = {
  get: <T>(path: string) => apiFetch<T>(path),
  post: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, { method: 'POST', body: JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: <T>(path: string) => apiFetch<T>(path, { method: 'DELETE' }),
}

export interface IconUploadResult {
  icon_name: string
  filename: string
}

/** Upload a PNG to the UI icons directory (``frontend/public/icons`` by default). */
export async function uploadSoftwareIcon(
  file: File,
  iconName: string,
): Promise<IconUploadResult> {
  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null
  const fd = new FormData()
  fd.append('file', file)
  fd.append('icon_name', iconName)
  const headers: Record<string, string> = {}
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  const res = await fetch(`${API_BASE}/api/v1/icons/upload`, {
    method: 'POST',
    headers,
    body: fd,
  })
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({ detail: res.statusText }))
    const d = errBody.detail
    const msg =
      typeof d === 'string'
        ? d
        : Array.isArray(d)
          ? d
              .map((x: { msg?: string }) => x?.msg)
              .filter(Boolean)
              .join('; ')
          : res.statusText
    throw new Error(msg || `API error: ${res.status}`)
  }
  return res.json()
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface PkgInfoSummary {
  id: string
  name: string
  display_name: string | null
  version: string
  category: string | null
  developer: string | null
  catalog_names: string[]
  unattended_install: boolean
  unattended_uninstall: boolean
  minimum_os_version: string | null
  installer_type: string | null
  restart_action: string | null
  created_at: string
  updated_at: string
}

export interface PkgInfoDetail extends PkgInfoSummary {
  description: string | null
  icon_name: string | null
  installer_item_location: string | null
  installer_item_hash: string | null
  installer_item_size: number | null
  installed_size: number | null
  installer_type: string | null
  minimum_os_version: string | null
  maximum_os_version: string | null
  uninstall_method: string | null
  unattended_uninstall: boolean
  autoremove: boolean
  uninstallable: boolean
  installs: InstallItem[] | null
  receipts: ReceiptItem[] | null
  blocking_applications: string[] | null
  items_to_copy: ItemToCopy[] | null
  supported_architectures: string[] | null
  requires: string[] | null
  update_for: string[] | null
  preinstall_script: string | null
  postinstall_script: string | null
  preuninstall_script: string | null
  postuninstall_script: string | null
  installcheck_script: string | null
  uninstallcheck_script: string | null
  version_script: string | null
  notes: string | null
  restart_action: string | null
  on_demand: boolean
  force_install_after_date: string | null
  apple_item: boolean
  installable_condition: string | null
  package_path: string | null
  package_complete_url: string | null
  minimum_munki_version: string | null
  uninstaller_item_location: string | null
  is_deleted: boolean
}

export interface InstallItem {
  type?: string
  path?: string
  CFBundleIdentifier?: string
  CFBundleName?: string
  CFBundleShortVersionString?: string
  CFBundleVersion?: string
  minosversion?: string
  version_comparison_key?: string
  [key: string]: unknown
}

export interface ReceiptItem {
  packageid?: string
  version?: string
  installed_size?: number
  optional?: boolean
  [key: string]: unknown
}

export interface ItemToCopy {
  source_item?: string
  destination_path?: string
  destination_item?: string
  user?: string
  group?: string
  mode?: string
  [key: string]: unknown
}

export interface CatalogRead {
  id: string
  name: string
  display_name: string | null
  description: string | null
  is_production: boolean
  sort_order: number
  created_at: string
  item_count: number
}

export interface ManifestRead {
  id: string
  name: string
  display_name: string | null
  notes: string | null
  conditional_items: unknown
  catalog_names: string[]
  managed_installs: string[]
  managed_uninstalls: string[]
  managed_updates: string[]
  optional_installs: string[]
  featured_items: string[]
  default_installs: string[]
  included_manifest_names: string[]
  created_at: string
  updated_at: string
}

export interface AutoPkgRunRead {
  id: string
  status: string
  trigger_type: string
  triggered_by: string | null
  /** github = GitHub Actions; local = run script on your Mac */
  runner_type: string
  github_run_id: string | null
  github_run_url: string | null
  recipe_filter: string[] | null
  total_recipes: number | null
  recipes_succeeded: number | null
  recipes_failed: number | null
  recipes_imported: number | null
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
  results: RunResultRead[]
}

export interface RunResultRead {
  id: string
  recipe_identifier: string
  recipe_name: string
  status: string
  imported_version: string | null
  imported_display_name: string | null
  imported_pkg_path: string | null
  imported_pkginfo_path: string | null
  imported_catalogs: string[] | null
  virustotal_results: unknown
  trust_info_diff: unknown
  approval_status: string
  approved_by: string | null
  approved_at: string | null
  approval_comment: string | null
  log_output: string | null
  error_message: string | null
  duration_seconds: number | null
  created_at: string
}

export interface AutoPkgRecipeRead {
  id: string
  identifier: string
  name: string
  parent_recipe: string | null
  source_repo_full_name: string | null
  is_enabled: boolean
  is_override: boolean
  auto_promote: boolean
  override_data: unknown
  trust_info: unknown
  input_variables: unknown
  trust_status: string
  trust_verified_at: string | null
  trust_approved_by: string | null
  trust_approved_at: string | null
  last_run_at: string | null
  last_run_status: string | null
  created_at: string
  updated_at: string
}

export interface TrustChangeRequestRead {
  id: string
  recipe_id: string
  old_trust_info: unknown
  new_trust_info: unknown
  diff: unknown
  status: string
  requested_at: string
  reviewed_by: string | null
  reviewed_at: string | null
  comment: string | null
}

export interface TrustCommitResolveResponse {
  commit_sha: string | null
  commit_url: string | null
}

export interface CachedGitHubRecipe {
  id: string
  repo_id: string
  name: string
  filename: string
  path: string
  identifier_guess: string
  url: string
}

export interface CachedGitHubRepo {
  id: string
  full_name: string
  name: string
  html_url: string
  clone_url: string | null
  description: string | null
  stars: number
  updated_at: string | null
  default_branch: string | null
  synced_at: string
  /** When true, repo is not dropped by “Sync Repos” (autopkg org list). */
  is_custom: boolean
  cached_recipes: CachedGitHubRecipe[]
}

export interface DiscoveredRecipe {
  name: string
  filename: string
  path: string
  identifier_guess: string
  repo_full_name: string
  url: string
}

export interface SearchedRecipe {
  name: string
  filename: string
  path: string
  identifier_guess: string
  repo_full_name: string
  repo_name: string
  repo_url: string
  url: string
}

export interface AuditLogRead {
  id: string
  user_id: string | null
  user_email: string | null
  action: string
  entity_type: string
  entity_id: string
  entity_name: string | null
  before_snapshot: unknown
  after_snapshot: unknown
  changes: unknown
  ip_address: string | null
  notes: string | null
  created_at: string
}

export interface UiSettingsRead {
  github_repo: string
  /** Server default when the trigger dialog does not override */
  autopkg_runner_mode: string
}

export interface ClientMachineSummary {
  id: string
  serial_number: string
  hostname: string | null
  os_version: string | null
  machine_model: string | null
  munki_version: string | null
  manifest_name: string | null
  last_checkin_at: string | null
  disk_free_gb: number | null
  install_report_count: number
}

export interface CheckinHistoryPoint {
  date: string
  count: number
}

/** GET /pkginfo/{id}/install-reports/summary */
export interface PkgInfoInstallReportSummary {
  item_name: string
  total_reports: number
  unique_machines: number
  by_status: Record<string, number>
  timeline: CheckinHistoryPoint[]
}

export interface ClientInstallReportRow {
  id: string
  item_name: string
  item_version: string | null
  status: string
  error_message: string | null
  install_date: string | null
  created_at: string
}

/** Flat list row from GET /reports/installs (includes machine). */
export interface ClientInstallReportListItem extends ClientInstallReportRow {
  machine_id: string
  hostname: string | null
  serial_number: string | null
}

export interface ClientMachineDetail {
  id: string
  serial_number: string
  hostname: string | null
  /** Marketing name from Munki MachineInfo when agent sends it (e.g. MacBook Pro). */
  product_name?: string | null
  /** Apple FMIP-style PNG (same CDN as MunkiReport). */
  device_image_url?: string | null
  platform_uuid?: string | null
  os_version: string | null
  os_build: string | null
  machine_model: string | null
  cpu_type: string | null
  cpu_arch?: string | null
  physical_cpus?: number | null
  logical_cpus?: number | null
  ram_mb: number | null
  disk_size_gb: number | null
  disk_free_gb: number | null
  munki_version: string | null
  manifest_name: string | null
  client_identifier: string | null
  hardware_info: unknown
  installed_software: unknown
  last_checkin_at: string | null
  first_checkin_at: string | null
  /** All-time count of POST /reports/checkin for this machine. */
  checkin_total?: number
  /** Daily buckets for the last ~90 days (including zeros). */
  checkin_history?: CheckinHistoryPoint[]
  install_reports: ClientInstallReportRow[]
}

export interface FleetComplianceOverview {
  total_machines: number
  checked_in_last_7_days: number
  stale_over_30_days: number
  compliance_percentage: number
}
