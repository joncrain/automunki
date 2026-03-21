'use client'

import { format, parseISO } from 'date-fns'
import { useId, useMemo } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { CheckinHistoryPoint } from '@/lib/api'

function enrich(points: CheckinHistoryPoint[]) {
  return points.map((p) => ({
    ...p,
    shortLabel: format(parseISO(p.date), 'MMM d'),
  }))
}

export function DeviceCheckinsChart({
  history,
  total,
}: {
  history: CheckinHistoryPoint[] | undefined
  total: number | undefined
}) {
  const gradId = useId().replace(/:/g, '')
  const data = useMemo(() => enrich(history ?? []), [history])

  if (!total) {
    return (
      <p className="px-2 py-6 text-center text-sm text-muted-foreground">
        No check-in history yet. Data appears after the next client POST to{' '}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">
          /reports/checkin
        </code>
        .
      </p>
    )
  }

  return (
    <div className="h-[200px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 8, right: 4, left: 0, bottom: 0 }}
        >
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--chart-1)" stopOpacity={0.35} />
              <stop
                offset="95%"
                stopColor="var(--chart-1)"
                stopOpacity={0.02}
              />
            </linearGradient>
          </defs>
          <CartesianGrid
            strokeDasharray="3 3"
            vertical={false}
            className="stroke-border/60"
          />
          <XAxis
            dataKey="shortLabel"
            tickLine={false}
            axisLine={false}
            tickMargin={8}
            minTickGap={24}
            className="fill-muted-foreground text-[10px]"
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            width={26}
            allowDecimals={false}
            className="fill-muted-foreground text-[10px]"
          />
          <Tooltip
            contentStyle={{
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border)',
              background: 'var(--card)',
            }}
            labelFormatter={(_, payload) => {
              const row = payload?.[0]?.payload as { date?: string } | undefined
              return row?.date ? format(parseISO(row.date), 'MMM d, yyyy') : ''
            }}
            formatter={(value: number) => [value, 'Check-ins']}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke="var(--chart-1)"
            fill={`url(#${gradId})`}
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
