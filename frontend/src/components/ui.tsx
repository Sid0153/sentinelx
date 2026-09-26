import {
  cloneElement,
  isValidElement,
  useId,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";

export const inputClass =
  "w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 " +
  "placeholder:text-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500";

export const selectClass =
  "rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100 " +
  "focus:border-sky-500 focus:outline-none";

type Variant = "primary" | "secondary" | "danger";

const VARIANTS: Record<Variant, string> = {
  primary: "bg-sky-600 text-white hover:bg-sky-500",
  secondary: "border border-slate-700 text-slate-200 hover:bg-slate-800",
  danger: "border border-rose-800 text-rose-300 hover:bg-rose-950",
};

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      {...props}
      className={`rounded px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${VARIANTS[variant]} ${className}`}
    />
  );
}

/**
 * A label wrapping its control, so the two are associated without IDs. The hint sits outside
 * the label (otherwise it becomes part of the control's accessible name) and is linked to the
 * control with aria-describedby.
 */
export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  const hintId = useId();
  const control =
    hint && isValidElement<{ "aria-describedby"?: string }>(children)
      ? cloneElement(children, { "aria-describedby": hintId })
      : children;
  return (
    <div>
      <label className="block">
        <span className="mb-1 block text-sm text-slate-300">{label}</span>
        {control}
      </label>
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-slate-500">
          {hint}
        </p>
      )}
    </div>
  );
}

export function ErrorMessage({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="text-sm text-rose-300">
      {children}
    </p>
  );
}

export function PageHeader({ title, description }: { title: string; description?: string }) {
  return (
    <div className="mb-4">
      <h1 className="text-lg font-semibold text-slate-100">{title}</h1>
      {description && <p className="mt-1 text-sm text-slate-400">{description}</p>}
    </div>
  );
}

export function Pagination({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number;
  limit: number;
  total: number;
  onChange: (offset: number) => void;
}) {
  if (total === 0) return null;
  const last = Math.min(offset + limit, total);
  return (
    <nav aria-label="Pagination" className="mt-3 flex items-center justify-between text-sm">
      <span className="text-slate-400">
        {offset + 1}–{last} of {total}
      </span>
      <span className="flex gap-2">
        <Button
          variant="secondary"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </Button>
        <Button variant="secondary" disabled={last >= total} onClick={() => onChange(offset + limit)}>
          Next
        </Button>
      </span>
    </nav>
  );
}

/** A titled box on detail pages. `min-w-0` keeps wide content (tables, logs) from widening
 * the page on phones. */
export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-2 text-sm font-semibold text-slate-200">{title}</h2>
      {children}
    </section>
  );
}

/** Timestamps are shown in UTC everywhere, so analysts compare times without conversion. */
export function formatUtc(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}
