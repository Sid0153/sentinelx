import { useCallback } from "react";
import { Link } from "react-router-dom";

import { LevelBadge } from "../components/alerts";
import { ErrorMessage, PageHeader, formatUtc } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listRules } from "../services/inventory";

export function DetectionsPage() {
  const load = useCallback((signal: AbortSignal) => listRules(signal), []);
  const { data, error } = useApi(load);

  return (
    <section>
      <PageHeader
        title="Detection rules"
        description="The rule library (security-rules/). Rule logic changes only through a reviewed change to the library; administrators can tune the safe fields each rule declares, and every change is versioned and audited."
      />
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 px-4">
        {error ? (
          <div className="py-3">
            <ErrorMessage>{error.message}</ErrorMessage>
          </div>
        ) : !data ? (
          <p className="py-3 text-sm text-slate-400">Loading rules…</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Rule</th>
                <th className="py-2 pr-4 font-medium">Severity</th>
                <th className="py-2 pr-4 font-medium">State</th>
                <th className="py-2 pr-4 font-medium">ATT&CK</th>
                <th className="py-2 pr-4 text-right font-medium">Matches</th>
                <th className="py-2 font-medium">Last match</th>
              </tr>
            </thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.rule_id} className="border-t border-slate-800 align-top">
                  <td className="py-2 pr-4">
                    <Link to={`/detections/${r.rule_id}`} className="text-slate-100 hover:text-sky-300">
                      <span className="font-mono text-xs text-slate-500">{r.rule_id}</span> {r.name}
                    </Link>
                    <div className="text-xs text-slate-500">
                      {r.category} · {r.kind} · v{r.version}
                    </div>
                  </td>
                  <td className="py-2 pr-4">
                    <LevelBadge level={r.severity} label="severity" />
                  </td>
                  <td className="py-2 pr-4 text-xs">
                    {!r.in_library ? (
                      <span className="text-slate-500">removed from library</span>
                    ) : r.enabled ? (
                      <span className="text-emerald-300">enabled</span>
                    ) : (
                      <span className="text-amber-300">disabled</span>
                    )}
                    {r.error_count > 0 && <div className="text-rose-300">{r.error_count} errors</div>}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs text-slate-400">{r.techniques.join(", ")}</td>
                  <td className="py-2 pr-4 text-right font-mono text-slate-200">{r.match_count}</td>
                  <td className="whitespace-nowrap py-2 font-mono text-xs text-slate-400">
                    {r.last_match_at ? formatUtc(r.last_match_at) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
