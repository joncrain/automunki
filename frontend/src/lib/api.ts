const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `API error: ${res.status}`);
  }

  if (res.status === 204) return {} as T;
  return res.json();
}

export const api = {
  get: <T>(path: string) => apiFetch<T>(path),
  post: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, { method: "POST", body: JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  delete: <T>(path: string) => apiFetch<T>(path, { method: "DELETE" }),
};

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface PkgInfoSummary {
  id: string;
  name: string;
  display_name: string | null;
  version: string;
  category: string | null;
  developer: string | null;
  catalog_names: string[];
  unattended_install: boolean;
  created_at: string;
  updated_at: string;
}

export interface PkgInfoDetail extends PkgInfoSummary {
  description: string | null;
  icon_name: string | null;
  installer_item_location: string | null;
  installer_item_hash: string | null;
  installer_item_size: number | null;
  installed_size: number | null;
  installer_type: string | null;
  minimum_os_version: string | null;
  maximum_os_version: string | null;
  uninstall_method: string | null;
  unattended_uninstall: boolean;
  autoremove: boolean;
  uninstallable: boolean;
  installs: unknown;
  receipts: unknown;
  blocking_applications: string[] | null;
  items_to_copy: unknown;
  supported_architectures: string[] | null;
  requires: string[] | null;
  update_for: string[] | null;
  preinstall_script: string | null;
  postinstall_script: string | null;
  is_deleted: boolean;
}

export interface CatalogRead {
  id: string;
  name: string;
  display_name: string | null;
  description: string | null;
  is_production: boolean;
  sort_order: number;
  created_at: string;
  item_count: number;
}

export interface ManifestRead {
  id: string;
  name: string;
  display_name: string | null;
  notes: string | null;
  conditional_items: unknown;
  catalog_names: string[];
  managed_installs: string[];
  managed_uninstalls: string[];
  managed_updates: string[];
  optional_installs: string[];
  featured_items: string[];
  default_installs: string[];
  included_manifest_names: string[];
  created_at: string;
  updated_at: string;
}

export interface AutoPkgRunRead {
  id: string;
  status: string;
  trigger_type: string;
  triggered_by: string | null;
  github_run_id: string | null;
  github_run_url: string | null;
  recipe_filter: string[] | null;
  total_recipes: number | null;
  recipes_succeeded: number | null;
  recipes_failed: number | null;
  recipes_imported: number | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  results: RunResultRead[];
}

export interface RunResultRead {
  id: string;
  recipe_identifier: string;
  recipe_name: string;
  status: string;
  imported_version: string | null;
  imported_pkg_path: string | null;
  imported_pkginfo_path: string | null;
  imported_catalogs: string[] | null;
  virustotal_results: unknown;
  trust_info_diff: unknown;
  approval_status: string;
  approved_by: string | null;
  approved_at: string | null;
  approval_comment: string | null;
  log_output: string | null;
  error_message: string | null;
  duration_seconds: number | null;
  created_at: string;
}

export interface AutoPkgRecipeRead {
  id: string;
  identifier: string;
  name: string;
  parent_recipe: string | null;
  repo_id: string | null;
  is_enabled: boolean;
  is_override: boolean;
  auto_promote: boolean;
  target_catalogs: string[] | null;
  override_data: unknown;
  trust_info: unknown;
  input_variables: unknown;
  last_run_at: string | null;
  last_run_status: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutoPkgRepoRead {
  id: string;
  url: string;
  name: string;
  description: string | null;
  is_active: boolean;
  last_synced_at: string | null;
  created_at: string;
}

export interface DiscoveredRepo {
  name: string;
  full_name: string;
  url: string;
  html_url: string;
  description: string | null;
  stars: number;
  updated_at: string | null;
}

export interface DiscoveredRecipe {
  name: string;
  filename: string;
  path: string;
  identifier_guess: string;
  repo_full_name: string;
  url: string;
}

export interface SearchedRecipe {
  name: string;
  filename: string;
  path: string;
  identifier_guess: string;
  repo_full_name: string;
  repo_name: string;
  repo_url: string;
  url: string;
}

export interface AuditLogRead {
  id: string;
  user_id: string | null;
  user_email: string | null;
  action: string;
  entity_type: string;
  entity_id: string;
  entity_name: string | null;
  before_snapshot: unknown;
  after_snapshot: unknown;
  changes: unknown;
  ip_address: string | null;
  notes: string | null;
  created_at: string;
}

export interface SyncJobRead {
  id: string;
  status: string;
  triggered_by: string | null;
  trigger_type: string | null;
  files_synced: number | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
}
