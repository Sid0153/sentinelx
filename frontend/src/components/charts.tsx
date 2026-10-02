import { useId, useState } from "react";

import type { Level } from "../types/api";

// Colors follow the data-viz method (validated on the dark panel surface #0f172a):
// severity is ordinal (swapping the order changes the meaning), so it takes one hue in
// monotone lightness steps, the most severe the most salient. A single series takes slot 1.
export const SEVERITY_COLOR: Record<Level, string> = {
  critical: "#9ec5f4",
  high: "#6da7ec",
  medium: "#3987e5",
  low: "#256abf",
};
export const SERIES_COLOR = "#3987e5";

const LEVEL_ORDER: Level[] = ["critical", "high", "medium", "low"];

export interface Series {
  key: string;
  label: string;
  color: string;
}

/** Per-day columns, stacked when there is more than one series. One y-axis only; different
 * measures (alerts, events) get their own chart. Hover or focus a day for its values; the
 * same numbers are in the table view. */
export function DailyColumns({
  title,
  days,
  series,
  values,
}: {
  title: string;
  days: string[];
  series: Series[];
  values: number[][]; // [day][series]
}) {
  const [active, setActive] = useState<number | null>(null);
  const tableId = useId();
  const width = 600;
  const height = 160;
  const top = 12;
  const bottom = 22;
  const plot = height - top - bottom;
  const totals = values.map((row) => row.reduce((a, b) => a + b, 0));
  const max = Math.max(1, ...totals);
  const slot = width / Math.max(days.length, 1);
  const bar = Math.max(4, Math.min(28, slot * 0.6));
  const labelEvery = Math.ceil(days.length / 7);
  const empty = totals.every((t) => t === 0);

  return (
    <figure className="min-w-0">
      <figcaption className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-semibold text-slate-200">{title}</span>
        {series.length > 1 && (
          <span className="flex flex-wrap gap-3 text-xs text-slate-300" aria-hidden="true">
            {series.map((s) => (
              <span key={s.key} className="inline-flex items-center gap-1">
                <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
                {s.label}
              </span>
            ))}
          </span>
        )}
      </figcaption>
      <div className="relative">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-40 w-full"
          role="group"
          aria-label={`${title}: ${empty ? "nothing in this period" : `peak ${max} on one day`}. The table view lists every value.`}
          aria-describedby={tableId}
          onMouseLeave={() => setActive(null)}
        >
          <line x1={0} x2={width} y1={top + plot} y2={top + plot} stroke="#334155" strokeWidth={1} />
          <line x1={0} x2={width} y1={top} y2={top} stroke="#1e293b" strokeWidth={1} strokeDasharray="3 3" />
          <text x={2} y={top - 3} fontSize={10} fill="#94a3b8">
            {max}
          </text>
          {days.map((day, i) => {
            const x = i * slot + (slot - bar) / 2;
            let y = top + plot;
            const segments = series.map((s, j) => {
              const h = (values[i][j] / max) * plot;
              const gap = h > 0 && j > 0 ? 2 : 0; // 2px surface gap between stacked segments
              y -= h;
              return h > 0 ? (
                <rect
                  key={s.key}
                  x={x}
                  y={y}
                  width={bar}
                  height={Math.max(h - gap, 1)}
                  rx={j === series.length - 1 || values[i].slice(j + 1).every((v) => v === 0) ? 3 : 0}
                  fill={s.color}
                  opacity={active === null || active === i ? 1 : 0.45}
                />
              ) : null;
            });
            return (
              <g
                key={day}
                tabIndex={0}
                role="button"
                aria-label={`${day}: ${series.map((s, j) => `${s.label} ${values[i][j]}`).join(", ")}`}
                onMouseEnter={() => setActive(i)}
                onFocus={() => setActive(i)}
                onBlur={() => setActive(null)}
                className="outline-none"
              >
                {/* Hit target: the whole column, taller than the bar. */}
                <rect x={i * slot} y={0} width={slot} height={top + plot} fill="transparent" />
                {segments}
                {i % labelEvery === 0 && (
                  <text x={i * slot + slot / 2} y={height - 6} fontSize={10} fill="#94a3b8" textAnchor="middle">
                    {day.slice(5)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
        {active !== null && (
          <div
            className="pointer-events-none absolute top-0 z-10 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200 shadow"
            style={{ left: `${Math.min(((active + 0.5) / days.length) * 100, 80)}%` }}
            role="status"
          >
            <div className="font-mono text-slate-400">{days[active]}</div>
            {series.map((s, j) => (
              <div key={s.key} className="flex items-center gap-1">
                <span className="inline-block h-2 w-2 rounded-sm" style={{ background: s.color }} />
                {s.label}: {values[active][j]}
              </div>
            ))}
          </div>
        )}
      </div>
      <details className="mt-1 text-xs text-slate-400">
        <summary className="cursor-pointer">Table view</summary>
        <table id={tableId} className="mt-1 w-full text-left">
          <thead>
            <tr>
              <th className="pr-3 font-medium">Day (UTC)</th>
              {series.map((s) => (
                <th key={s.key} className="pr-3 text-right font-medium">
                  {s.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {days.map((day, i) => (
              <tr key={day} className="border-t border-slate-800">
                <td className="pr-3 font-mono">{day}</td>
                {series.map((s, j) => (
                  <td key={s.key} className="pr-3 text-right font-mono">
                    {values[i][j]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

/** Open alerts by severity as labelled horizontal bars (the label and number carry the
 * meaning; the bar length and ordinal shade support it). */
export function SeverityBars({ counts }: { counts: { severity: Level; count: number }[] }) {
  const byLevel = new Map(counts.map((c) => [c.severity, c.count]));
  const max = Math.max(1, ...counts.map((c) => c.count));
  return (
    <ul className="space-y-1.5" aria-label="Open alerts by severity">
      {LEVEL_ORDER.map((level) => {
        const count = byLevel.get(level) ?? 0;
        return (
          <li key={level} className="grid grid-cols-[4.5rem_1fr_2.5rem] items-center gap-2 text-sm">
            <span className="capitalize text-slate-300">{level}</span>
            <span className="h-2.5 rounded-sm bg-slate-800">
              <span
                className="block h-2.5 rounded-sm"
                style={{ width: `${(count / max) * 100}%`, background: SEVERITY_COLOR[level] }}
              />
            </span>
            <span className="text-right font-mono text-slate-200">{count}</span>
          </li>
        );
      })}
    </ul>
  );
}
