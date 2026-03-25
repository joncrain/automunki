'use client'

import { format, parseISO } from 'date-fns'
import { useMemo } from 'react'
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

type FleetTimeseriesChartProps = {
  points: CheckinHistoryPoint[]
  seriesLabel: string
  gradientId: string
  strokeVar: string
  emptyMessage: string
}

export function FleetTimeseriesChart({
  points,
  seriesLabel,
  gradientId,
  strokeVar,
  emptyMessage,
}: FleetTimeseriesChartProps) {
  const data = useMemo(
    () =>
      points.map((p) => ({
        ...p,
        shortLabel: format(parseISO(p.date), 'MMM d'),
      })),
    [points],
  )

  const hasActivity = useMemo(() => points.some((p) => p.count > 0), [points])

  if (!points.length || !hasActivity) {
    return <p className="text-sm text-muted-foreground">{emptyMessage}</p>
  }

  return (
    <div className="h-[220px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={strokeVar} stopOpacity={0.35} />
              <stop offset="95%" stopColor={strokeVar} stopOpacity={0.02} />
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
            minTickGap={16}
            className="text-[11px] fill-muted-foreground"
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            width={28}
            allowDecimals={false}
            className="text-[11px] fill-muted-foreground"
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
            formatter={(value: number) => [value, seriesLabel]}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke={strokeVar}
            fill={`url(#${gradientId})`}
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
