export type Condition = "ok" | "degraded" | "down" | "unknown";

const STYLES: Record<Condition, { dot: string; text: string }> = {
  ok: { dot: "bg-emerald-400", text: "text-emerald-300" },
  degraded: { dot: "bg-amber-400", text: "text-amber-300" },
  down: { dot: "bg-rose-500", text: "text-rose-300" },
  unknown: { dot: "bg-slate-500", text: "text-slate-400" },
};

/** A coloured dot plus a text label: the colour is never the only signal. */
export function StatusIndicator({ condition, label }: { condition: Condition; label: string }) {
  const style = STYLES[condition];
  return (
    <span className={`inline-flex items-center gap-2 text-sm font-medium ${style.text}`}>
      <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-full ${style.dot}`} />
      {label}
    </span>
  );
}
