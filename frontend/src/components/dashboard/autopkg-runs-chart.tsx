'use client'

import {
  eachDayOfInterval,
  format,
  parseISO,
  startOfDay,
  subDays,
} from 'date-fns'
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
import type { AutoPkgRunRead } from '@/lib/api'

const DAYS = 30

function buildSeries(runs: AutoPkgRunRead[]) {
  const end = startOfDay(new Date())
  const start = subDays(end, DAYS - 1)
  const keys = eachDayOfInterval({ start, end }).map((d) =>
    format(d, 'yyyy-MM-dd'),
  )
  const counts = new Map<string, number>()
  for (const k of keys) counts.set(k, 0)
  for (const run of runs) {
    const k = format(parseISO(run.created_at), 'yyyy-MM-dd')
    if (counts.has(k)) counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  return keys.map((date) => ({
    date,
    shortLabel: format(parseISO(date), 'MMM d'),
    runs: counts.get(date) ?? 0,
  }))
}

export function AutoPkgRunsChart({ runs }: { runs: AutoPkgRunRead[] }) {
  const data = useMemo(() => buildSeries(runs), [runs])

  if (!runs.length) {
    return (
      <p className="text-sm text-muted-foreground">
        No AutoPkg runs yet — activity will appear here after the first run.
      </p>
    )
  }

  return (
    <div className="h-[220px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
        >
          <defs>
            <linearGradient id="fillAutopkgRuns" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--chart-2)" stopOpacity={0.35} />
              <stop
                offset="95%"
                stopColor="var(--chart-2)"
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
            formatter={(value: number) => [value, 'Runs']}
          />
          <Area
            type="monotone"
            dataKey="runs"
            stroke="var(--chart-2)"
            fill="url(#fillAutopkgRuns)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
