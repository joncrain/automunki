'use client'

import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import {
  ArrowLeft,
  CalendarClock,
  Copy,
  Cpu,
  FileText,
  Fingerprint,
  HardDrive,
  Layers,
  Microchip,
  Package,
} from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import type { ComponentType, ReactNode } from 'react'
import { useMemo } from 'react'
import { toast } from 'sonner'
import { DataTable } from '@/components/data-table'
import { DeviceCheckinsChart } from '@/components/reporting/device-checkins-chart'
import { MacDeviceHeroVisual } from '@/components/reporting/mac-device-visual'
import { Badge } from '@/components/ui/badge'
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
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  api,
  type ClientInstallReportRow,
  type ClientMachineDetail,
} from '@/lib/api'
import { formatDateTime, formatRelativeTimeAgo } from '@/lib/format'
import { munkiAccents } from '@/lib/munki-accents'
import { cn } from '@/lib/utils'

function reportStatusVariant(status: string) {
  switch (status) {
    case 'installed':
      return 'default' as const
    case 'failed':
    case 'removal_failed':
      return 'destructive' as const
    case 'removed':
      return 'secondary' as const
    default:
      return 'outline' as const
  }
}

const reportColumns: ColumnDef<ClientInstallReportRow>[] = [
  {
    accessorKey: 'item_name',
    header: 'Item',
    cell: ({ row }) => (
      <span className="font-medium">{row.original.item_name || '—'}</span>
    ),
  },
  {
    accessorKey: 'item_version',
    header: 'Version',
    cell: ({ row }) => row.original.item_version || '—',
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => (
      <Badge variant={reportStatusVariant(row.original.status)}>
        {row.original.status}
      </Badge>
    ),
  },
  {
    accessorKey: 'install_date',
    header: 'Install time',
    cell: ({ row }) =>
      row.original.install_date ? (
        <span suppressHydrationWarning className="text-sm">
          {formatDateTime(row.original.install_date)}
        </span>
      ) : (
        '—'
      ),
  },
  {
    accessorKey: 'error_message',
    header: 'Note',
    cell: ({ row }) => (
      <span className="line-clamp-2 max-w-xs text-sm text-muted-foreground md:max-w-md">
        {row.original.error_message || '—'}
      </span>
    ),
  },
]

function SpecRow({
  icon: Icon,
  label,
  children,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  children: ReactNode
}) {
  return (
    <div className="flex gap-3 py-2.5 sm:grid sm:grid-cols-[minmax(8rem,11rem)_1fr] sm:items-start sm:gap-4">
      <dt className="flex shrink-0 items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        <Icon className="size-3.5 opacity-70" aria-hidden />
        {label}
      </dt>
      <dd className="min-w-0 text-sm text-foreground">{children}</dd>
    </div>
  )
}

export default function ReportingDevicePage() {
  const params = useParams()
  const id = typeof params.id === 'string' ? params.id : ''

  const { data, isLoading, error } = useQuery({
    queryKey: ['reports-machine', id],
    queryFn: () => api.get<ClientMachineDetail>(`/reports/machines/${id}`),
    enabled: Boolean(id),
  })

  const copySerial = () => {
    if (!data?.serial_number) return
    void navigator.clipboard.writeText(data.serial_number)
    toast.success('Serial copied')
  }

  const activeCheckinDays = useMemo(
    () => data?.checkin_history?.filter((d) => d.count > 0).length ?? 0,
    [data?.checkin_history],
  )

  if (error) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/reporting">
            <ArrowLeft className="mr-2 size-4" aria-hidden />
            Devices
          </Link>
        </Button>
        <p className="text-destructive">
          {error instanceof Error ? error.message : 'Device not found'}
        </p>
      </div>
    )
  }

  const displayName =
    data?.hostname || data?.product_name || data?.serial_number || 'Device'
  const subtitle =
    data?.product_name && data?.hostname !== data?.product_name
      ? data.product_name
      : null

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8 pb-10">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/reporting">Devices</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage className="max-w-[12rem] truncate sm:max-w-md">
              {isLoading ? (
                <Skeleton className="inline-block h-4 w-32" />
              ) : (
                displayName
              )}
            </BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:gap-10">
        <div className="min-w-0 flex-1 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1
                className={cn(
                  'text-3xl font-bold tracking-tight text-pretty',
                  munkiAccents.reporting.pageTitle,
                )}
              >
                {isLoading ? <Skeleton className="h-9 w-56" /> : displayName}
              </h1>
              {subtitle ? (
                <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
              ) : null}
              <div className="mt-3">
                {isLoading ? (
                  <Skeleton className="h-9 w-52 max-w-full rounded-md" />
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    className={cn(
                      'h-auto max-w-full gap-2 rounded-md border bg-muted/40 py-1.5 pr-2 pl-2.5',
                      'text-xs font-normal tabular-nums tracking-tight text-foreground',
                      'hover:bg-muted/70',
                      '[font-family:var(--font-geist-mono),ui-monospace,monospace]',
                    )}
                    onClick={copySerial}
                    disabled={!data?.serial_number}
                    aria-label="Copy serial number"
                  >
                    <span className="min-w-0 flex-1 truncate text-left">
                      {data?.serial_number ?? '—'}
                    </span>
                    <Copy
                      className="size-3.5 shrink-0 text-muted-foreground"
                      aria-hidden
                    />
                  </Button>
                )}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {isLoading ? (
                <Skeleton className="h-6 w-24" />
              ) : (
                <>
                  {data?.munki_version ? (
                    <Badge variant="secondary">
                      Munki {data.munki_version}
                    </Badge>
                  ) : null}
                  {data?.last_checkin_at ? (
                    <Badge variant="outline" className="font-normal">
                      Seen {formatRelativeTimeAgo(data.last_checkin_at)}
                    </Badge>
                  ) : (
                    <Badge variant="outline">No check-in yet</Badge>
                  )}
                </>
              )}
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-1 lg:items-start">
            <Card className="gap-0 overflow-hidden border-l-4 border-l-gruvbox-blue/40 py-0 shadow-sm">
              <CardHeader className="border-b bg-muted px-4 py-3 sm:px-6">
                <CardTitle className="text-base font-semibold">
                  System Details
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0 px-4 pt-1 pb-6 sm:px-6">
                {isLoading ? (
                  <div className="space-y-3 py-4">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-3/4" />
                  </div>
                ) : (
                  <dl className="divide-y">
                    <SpecRow icon={Cpu} label="Model ID">
                      <span className="font-mono text-xs sm:text-sm">
                        {data?.machine_model || '—'}
                      </span>
                    </SpecRow>
                    <SpecRow icon={Layers} label="Manifest">
                      <span>{data?.manifest_name || '—'}</span>
                    </SpecRow>
                    {data?.cpu_arch ? (
                      <SpecRow icon={Microchip} label="Architecture">
                        <span className="font-mono text-xs sm:text-sm">
                          {data.cpu_arch}
                        </span>
                      </SpecRow>
                    ) : null}
                    {(data?.physical_cpus != null ||
                      data?.logical_cpus != null) && (
                      <SpecRow icon={Cpu} label="CPU cores">
                        <span>
                          {[
                            data.physical_cpus != null
                              ? `${data.physical_cpus} physical`
                              : null,
                            data.logical_cpus != null
                              ? `${data.logical_cpus} logical`
                              : null,
                          ]
                            .filter(Boolean)
                            .join(' · ')}
                        </span>
                      </SpecRow>
                    )}
                    {data?.platform_uuid ? (
                      <SpecRow icon={Fingerprint} label="Hardware UUID">
                        <span className="break-all font-mono text-xs sm:text-sm">
                          {data.platform_uuid}
                        </span>
                      </SpecRow>
                    ) : null}
                    <SpecRow icon={FileText} label="Client ID">
                      <span className="break-all">
                        {data?.client_identifier || '—'}
                      </span>
                    </SpecRow>
                    <SpecRow icon={Package} label="macOS">
                      {data?.os_version || '—'}
                      {data?.os_build ? (
                        <span className="ml-2 text-muted-foreground">
                          ({data.os_build})
                        </span>
                      ) : null}
                    </SpecRow>
                    <SpecRow icon={HardDrive} label="Memory / disk">
                      {data?.ram_mb != null
                        ? `${data.ram_mb.toLocaleString()} MB`
                        : '—'}
                      {data?.disk_free_gb != null ||
                      data?.disk_size_gb != null ? (
                        <span className="mt-1 block text-muted-foreground sm:mt-0 sm:ml-2 sm:inline">
                          {data?.disk_size_gb != null
                            ? `${data.disk_size_gb} GB volume`
                            : ''}
                          {data?.disk_free_gb != null
                            ? ` · ${data.disk_free_gb} GB free`
                            : ''}
                        </span>
                      ) : null}
                    </SpecRow>
                    <SpecRow icon={CalendarClock} label="Check-ins">
                      <div className="space-y-1">
                        <div>
                          <span className="text-muted-foreground">Last: </span>
                          {data?.last_checkin_at ? (
                            <span suppressHydrationWarning>
                              {formatDateTime(data.last_checkin_at)} (
                              {formatRelativeTimeAgo(data.last_checkin_at)})
                            </span>
                          ) : (
                            '—'
                          )}
                        </div>
                        <div>
                          <span className="text-muted-foreground">First: </span>
                          {data?.first_checkin_at ? (
                            <span suppressHydrationWarning>
                              {formatDateTime(data.first_checkin_at)}
                            </span>
                          ) : (
                            '—'
                          )}
                        </div>
                      </div>
                    </SpecRow>
                    {data?.cpu_type ? (
                      <SpecRow icon={Cpu} label="CPU">
                        <span className="text-muted-foreground">
                          {data.cpu_type}
                        </span>
                      </SpecRow>
                    ) : null}
                  </dl>
                )}
              </CardContent>
            </Card>

            {/* <Card className="gap-0 overflow-hidden border py-0 shadow-sm">
              <CardHeader className="border-b bg-muted px-4 py-3 sm:px-6">
                <CardTitle className="text-base font-semibold">
                  Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-5 px-4 py-4 text-sm sm:px-6">
                {isLoading ? (
                  <div className="space-y-4">
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                  </div>
                ) : (
                  <>
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Total check-ins
                      </p>
                      <p className="mt-1 text-2xl font-semibold tabular-nums">
                        {(data?.checkin_total ?? 0).toLocaleString()}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {activeCheckinDays} day
                        {activeCheckinDays === 1 ? '' : 's'} with activity in
                        the last 90 days
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Current install report
                      </p>
                      <p className="mt-1 text-2xl font-semibold tabular-nums">
                        {(data?.install_reports?.length ?? 0).toLocaleString()}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Rows from the latest{' '}
                        <code className="rounded bg-muted px-1 py-0.5 text-[0.7rem]">
                          ManagedInstallReport
                        </code>
                      </p>
                    </div>
                  </>
                )}
              </CardContent>
            </Card> */}
          </div>
        </div>

        <div className="mx-auto flex w-full max-w-md shrink-0 flex-col gap-4 lg:mx-0 lg:w-[min(100%,26rem)]">
          {isLoading ? (
            <Skeleton className="aspect-[5/3] w-full rounded-2xl" />
          ) : (
            <MacDeviceHeroVisual
              machineModel={data?.machine_model}
              productName={data?.product_name}
              imageUrl={data?.device_image_url}
            />
          )}
          <Card className="gap-0 overflow-hidden border py-0 shadow-sm">
            <CardHeader className="border-b bg-muted px-3 py-2.5 sm:px-4">
              <CardTitle className="text-sm font-semibold">
                Check-ins over time
              </CardTitle>
              <CardDescription className="text-xs">
                Last 90 days (per day)
              </CardDescription>
            </CardHeader>
            <CardContent className="px-1 pb-2 pt-2 sm:px-2">
              {isLoading ? (
                <Skeleton className="mx-auto h-[200px] w-full max-w-full rounded-md" />
              ) : (
                <DeviceCheckinsChart
                  history={data?.checkin_history}
                  total={data?.checkin_total}
                />
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <Separator />

      <section>
        <div className="mb-4 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold tracking-tight">
              Latest install report
            </h2>
          </div>
        </div>
        <div className="min-h-[200px]">
          <DataTable
            columns={reportColumns}
            data={data?.install_reports ?? []}
            pageCount={1}
            page={1}
            pageSize={100}
            isLoading={isLoading}
          />
        </div>
      </section>
    </div>
  )
}
