import { redirect } from 'next/navigation'

/** Profile lives in the sidebar user menu (dialog). */
export default function AccountSettingsRedirectPage() {
  redirect('/settings')
}
