/** Mirrors backend `PageKey` for sidebar RBAC. */
export const PAGE_KEYS = {
  overview: 'overview',
  munkiSoftware: 'munki.software',
  munkiManifests: 'munki.manifests',
  munkiCatalogs: 'munki.catalogs',
  autopkgRuns: 'autopkg.runs',
  autopkgRecipes: 'autopkg.recipes',
  autopkgDiscover: 'autopkg.discover',
  autopkgApprovals: 'autopkg.approvals',
  reportingDevices: 'reporting.devices',
  reportingInstalls: 'reporting.installs',
  adminAudit: 'admin.audit',
  adminSettings: 'admin.settings',
  adminAccess: 'admin.access',
} as const

export type PageKey = (typeof PAGE_KEYS)[keyof typeof PAGE_KEYS]
