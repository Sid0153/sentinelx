import type { AlertStatus, Level } from "../types/api";

const LEVEL_STYLE: Record<Level, string> = {
  critical: "border-rose-700 bg-rose-950 text-rose-200",
  high: "border-orange-700 bg-orange-950 text-orange-200",
  medium: "border-amber-700 bg-amber-950 text-amber-200",
  low: "border-slate-600 bg-slate-800 text-slate-300",
};

const STATUS_STYLE: Record<AlertStatus, string> = {
  NEW: "text-sky-300",
  TRIAGED: "text-violet-300",
  IN_PROGRESS: "text-amber-300",
  RESOLVED: "text-emerald-300",
  FALSE_POSITIVE: "text-slate-400",
};

export const STATUS_LABEL: Record<AlertStatus, string> = {
  NEW: "New",
  TRIAGED: "Triaged",
  IN_PROGRESS: "In progress",
  RESOLVED: "Resolved",
  FALSE_POSITIVE: "False positive",
};

/** The SentinelX priority score with its band. Text carries the meaning; colour only helps. */
export function PriorityBadge({ score, band }: { score: number; band: Level }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-xs ${LEVEL_STYLE[band]}`}
      title="SentinelX priority score (0–100), not an industry standard"
    >
      {score}
      <span className="uppercase">{band}</span>
    </span>
  );
}

export function LevelBadge({ level, label }: { level: Level; label: string }) {
  return (
    <span className={`rounded border px-1.5 py-0.5 text-xs ${LEVEL_STYLE[level]}`}>
      {label}: {level}
    </span>
  );
}

export function StatusText({ status }: { status: AlertStatus }) {
  return <span className={`text-xs font-medium ${STATUS_STYLE[status]}`}>{STATUS_LABEL[status]}</span>;
}

export function SimulatedTag() {
  return (
    <span
      className="rounded border border-fuchsia-800 bg-fuchsia-950 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-fuchsia-200"
      title="Built from simulated log records (demo data), not from a real system"
    >
      SIMULATED
    </span>
  );
}
