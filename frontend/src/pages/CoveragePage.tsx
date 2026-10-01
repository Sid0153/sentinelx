import { useCallback, useState } from "react";
import { Link } from "react-router-dom";

import { LevelBadge } from "../components/alerts";
import { ErrorMessage, Field, Panel, formatUtc, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { getCoverage } from "../services/inventory";
import type { Coverage, CoverageTechnique } from "../types/inventory";
import { PERIODS } from "./DetectionsPage";

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-900 p-3">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 font-mono text-2xl text-slate-100">{value}</div>
      {detail && <div className="mt-0.5 text-xs text-slate-500">{detail}</div>}
    </div>
  );
}

/** "1 rule", "2 rules", or "1 rule (2 indicators)" when one rule maps through several. */
export function ruleCount(t: CoverageTechnique): string {
  const rules = new Set(t.rules.map((r) => r.rule_id)).size;
  const label = `${rules} rule${rules === 1 ? "" : "s"}`;
  return t.rules.length > rules ? `${label} (${t.rules.length} indicators)` : label;
}

function techniqueState(t: CoverageTechnique): string {
  return t.active ? "covered" : "rules disabled";
}

/** Every ATT&CK tactic in order, with the techniques SentinelX's rules cover under it. An
 * empty tactic is a gap and is shown as one. */
function TacticGrid({
  coverage,
  selected,
  onSelect,
}: {
  coverage: Coverage;
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const byId = new Map(coverage.techniques.map((t) => [t.technique_id, t]));
  return (
    <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5" aria-label="ATT&CK tactics">
      {coverage.tactics.map((tactic) => (
        <li
          key={tactic.id}
          className={`min-w-0 rounded-lg border p-2 ${
            tactic.active ? "border-sky-800 bg-slate-900" : "border-dashed border-slate-800 bg-slate-950"
          }`}
        >
          <div className="flex items-baseline justify-between gap-2">
            <a href={tactic.url} target="_blank" rel="noreferrer noopener" className="text-sm font-semibold text-slate-200 hover:text-sky-300">
              {tactic.name}
            </a>
            <span className="text-xs text-slate-500">{tactic.id}</span>
          </div>
          {tactic.techniques.length === 0 ? (
            <p className="mt-1 text-xs text-slate-500">No SentinelX rule</p>
          ) : (
            <ul className="mt-1 space-y-1">
              {tactic.techniques.map((id) => {
                const t = byId.get(id);
                if (!t) return null;
                return (
                  <li key={id}>
                    <button
                      type="button"
                      onClick={() => onSelect(id)}
                      aria-pressed={selected === id}
                      className={`w-full rounded border px-2 py-1 text-left text-xs ${
                        selected === id ? "border-sky-500 bg-slate-800" : t.active ? "border-slate-700 hover:border-slate-500" : "border-dashed border-amber-800"
                      }`}
                    >
                      <span className="font-mono text-slate-400">{id}</span>{" "}
                      <span className="text-slate-100">{t.name}</span>
                      <span className="block text-slate-500">
                        {ruleCount(t)} · {t.alerts} alert{t.alerts === 1 ? "" : "s"}
                        {!t.active && <span className="text-amber-300"> · rules disabled</span>}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </li>
      ))}
    </ol>
  );
}

function TechniqueDetail({ technique }: { technique: CoverageTechnique }) {
  return (
    <Panel title={`${technique.technique_id} ${technique.name}`}>
      <p className="mb-2 text-sm text-slate-400">
        {technique.tactics.join(", ")} · {techniqueState(technique)} ·{" "}
        <a href={technique.url} target="_blank" rel="noreferrer noopener" className="text-sky-300">
          MITRE ATT&CK page
        </a>
      </p>
      <ul className="space-y-3 text-sm">
        {technique.rules.map((r) => (
          <li key={`${r.rule_id}-${r.indicator ?? ""}`}>
            <div className="flex flex-wrap items-center gap-2">
              <Link to={`/detections/${r.rule_id}`} className="text-sky-300">
                <span className="font-mono">{r.rule_id}</span> {r.name}
              </Link>
              <LevelBadge level={r.severity} label="severity" />
              <span className={r.enabled ? "text-xs text-emerald-300" : "text-xs text-amber-300"}>
                {r.enabled ? "enabled" : "disabled"}
              </span>
              {r.indicator && <span className="font-mono text-xs text-slate-400">indicator {r.indicator}</span>}
            </div>
            <p className="text-xs text-slate-400">{r.reason}</p>
            <p className="text-xs text-slate-500">
              {r.alerts} alert{r.alerts === 1 ? "" : "s"} in the period · last triggered{" "}
              {r.last_triggered_at ? formatUtc(r.last_triggered_at) : "never"}
            </p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function CoveragePage() {
  const [days, setDays] = useState(30);
  const [selected, setSelected] = useState<string | null>(null);
  const load = useCallback((signal: AbortSignal) => getCoverage(days, signal), [days]);
  const { data, error } = useApi(load);

  if (error) return <ErrorMessage>{error.message}</ErrorMessage>;
  if (!data) return <p className="text-sm text-slate-400">Loading coverage…</p>;
  const chosen = data.techniques.find((t) => t.technique_id === selected) ?? null;
  const s = data.summary;

  return (
    <section className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-100">{data.label}</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          The MITRE ATT&CK (Enterprise, v{data.attack_version}) techniques that SentinelX&apos;s own
          detection rules are mapped to, under every tactic. This is what is implemented, not a
          claim of complete ATT&CK coverage: a tactic without a rule is a gap, and a mapped
          technique is only as good as the rule behind it.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Tactics with a rule" value={`${s.tactics_covered} / ${s.tactics_total}`} detail="enabled rules only" />
        <Stat label="Techniques covered" value={String(s.techniques_covered)} detail={`mapped in ATT&CK v${data.attack_version}`} />
        <Stat label="Active rules" value={`${s.rules_enabled} / ${s.rules_in_library}`} detail="enabled / in the library" />
        <Stat
          label="Rule categories"
          value={String(Object.keys(s.categories).length)}
          detail={Object.entries(s.categories)
            .map(([category, count]) => `${category} ${count}`)
            .join(" · ")}
        />
      </div>
      <Field label="Alert counts for">
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} className={selectClass}>
          {PERIODS.map((d) => (
            <option key={d} value={d}>
              the last {d} days
            </option>
          ))}
        </select>
      </Field>
      <TacticGrid coverage={data} selected={selected} onSelect={setSelected} />
      {chosen && <TechniqueDetail technique={chosen} />}
      <Panel title="Techniques (table view)">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-3 font-medium">Technique</th>
                <th className="py-2 pr-3 font-medium">Tactics</th>
                <th className="py-2 pr-3 font-medium">Rules</th>
                <th className="py-2 pr-3 text-right font-medium">Alerts</th>
                <th className="py-2 font-medium">Last triggered</th>
              </tr>
            </thead>
            <tbody>
              {data.techniques.map((t) => (
                <tr key={t.technique_id} className="border-t border-slate-800 align-top">
                  <td className="py-1.5 pr-3">
                    <span className="font-mono text-xs text-slate-400">{t.technique_id}</span>{" "}
                    <span className="text-slate-100">{t.name}</span>
                    {!t.active && <span className="ml-1 text-xs text-amber-300">(rules disabled)</span>}
                  </td>
                  <td className="py-1.5 pr-3 text-xs text-slate-400">{t.tactics.join(", ")}</td>
                  <td className="py-1.5 pr-3 text-xs">
                    {t.rules.map((r, i) => (
                      <span key={`${r.rule_id}-${r.indicator ?? ""}`}>
                        {i > 0 && ", "}
                        <Link to={`/detections/${r.rule_id}`} className="font-mono text-sky-300">
                          {r.rule_id}
                        </Link>
                        {r.indicator && <span className="text-slate-500"> ({r.indicator})</span>}
                      </span>
                    ))}
                  </td>
                  <td className="py-1.5 pr-3 text-right font-mono text-slate-200">{t.alerts}</td>
                  <td className="whitespace-nowrap py-1.5 font-mono text-xs text-slate-400">
                    {t.last_triggered_at ? formatUtc(t.last_triggered_at) : "never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </section>
  );
}
