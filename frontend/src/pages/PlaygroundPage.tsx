import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { LevelBadge } from "../components/alerts";
import { Button, ErrorMessage, Field, PageHeader, Panel, formatUtc, inputClass, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/http";
import { getRule, listRules, testRule } from "../services/inventory";
import type { PlaygroundResult, RuleDetail } from "../types/inventory";
import { isoSeconds, shortDuration } from "./DetectionDetailPage";

const SOURCE_TYPES = ["linux_auth", "windows_security", "http_access", "app_json", "generic_json"];

/** RFC 3339 syslog lines (the linux_auth format the demo scenarios use), ending now. */
function syslog(lines: [number, string, string][]): string {
  const now = Date.now();
  return lines
    .map(([secondsAgo, program, message]) => {
      const at = new Date(now - secondsAgo * 1000).toISOString().replace(/\.\d{3}Z$/, "+00:00");
      return `${at} web-01 ${program}: ${message}`;
    })
    .join("\n");
}

const EXAMPLES: { name: string; build: () => string }[] = [
  {
    name: "Brute force: 8 failed logons",
    build: () =>
      syslog(
        Array.from({ length: 8 }, (_, i) => [
          120 - i * 4,
          `sshd[${4100 + i}]`,
          `Failed password for root from 203.0.113.45 port ${50400 + i} ssh2`,
        ]),
      ),
  },
  {
    name: "Failures, then a successful logon",
    build: () =>
      syslog([
        ...Array.from({ length: 4 }, (_, i): [number, string, string] => [
          90 - i * 5,
          `sshd[${4200 + i}]`,
          `Failed password for deploy from 198.51.100.7 port ${51000 + i} ssh2`,
        ]),
        [60, "sshd[4210]", "Accepted password for deploy from 198.51.100.7 port 51100 ssh2"],
      ]),
  },
  {
    name: "Password spray: one source, many accounts",
    build: () =>
      syslog(
        ["admin", "oracle", "postgres", "test", "ubuntu", "git"].map((user, i) => [
          100 - i * 5,
          `sshd[${4300 + i}]`,
          `Failed password for invalid user ${user} from 192.0.2.80 port ${52000 + i} ssh2`,
        ]),
      ),
  },
  {
    name: "Root shell through sudo",
    build: () =>
      syslog([[30, "sudo", "  deploy : TTY=pts/2 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"]]),
  },
];

function Results({ result }: { result: PlaygroundResult }) {
  const s = result.summary;
  const tried = Object.entries(result.rule.tried);
  return (
    <div className="space-y-4">
      <div
        role="status"
        className={`rounded-lg border p-3 text-sm ${
          result.triggered ? "border-amber-700 bg-amber-950/40 text-amber-100" : "border-slate-700 bg-slate-900 text-slate-200"
        }`}
      >
        <strong>
          {result.triggered
            ? `${result.rule.rule_id} fired: ${s.detections} detection${s.detections === 1 ? "" : "s"}.`
            : `${result.rule.rule_id} did not fire.`}
        </strong>{" "}
        {s.lines} line{s.lines === 1 ? "" : "s"}: {s.parsed} parsed, {s.skipped} skipped, {s.failed} failed · {s.matched} matched the rule ·{" "}
        {s.excluded} excluded or suppressed.
        {result.rule.threshold !== null && (
          <span className="block text-xs opacity-80">
            The rule needs {result.rule.threshold} within {result.rule.time_window}
            {tried.length > 0 && ` (what-if: ${tried.map(([k, v]) => `${k} ${JSON.stringify(v)}`).join(", ")})`}.
          </span>
        )}
        <span className="block text-xs opacity-80">Nothing was stored: no events, no alerts.</span>
      </div>
      {result.detections.map((d, i) => (
        <Panel key={i} title={`Detection ${i + 1}${d.indicator ? `: ${d.indicator}` : ""}`}>
          <p className="text-sm text-slate-100">{d.explanation}</p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <LevelBadge level={d.severity} label="severity" />
            <span>confidence {d.confidence}</span>
            <span>· {d.event_count} events</span>
            <span>· ATT&CK {d.mitre.join(", ")}</span>
          </div>
          <p className="mt-2 text-xs text-slate-400">Evidence lines: {d.evidence_lines.join(", ")}</p>
        </Panel>
      ))}
      <Panel title="Lines">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-1 pr-3 font-medium">#</th>
                <th className="py-1 pr-3 font-medium">Result</th>
                <th className="py-1 pr-3 font-medium">Event</th>
                <th className="py-1 font-medium">Who</th>
              </tr>
            </thead>
            <tbody>
              {result.lines.map((line) => (
                <tr key={line.line} className={`border-t border-slate-800 align-top ${line.evidence ? "bg-amber-950/30" : ""}`}>
                  <td className="py-1 pr-3 font-mono text-slate-400">{line.line}</td>
                  <td className="py-1 pr-3">
                    {line.status !== "parsed" ? (
                      <span className="text-slate-500">
                        {line.status} ({line.code})
                      </span>
                    ) : line.excluded ? (
                      <span className="text-slate-400">excluded</span>
                    ) : line.evidence ? (
                      <span className="text-amber-300">evidence</span>
                    ) : line.matched || line.steps.length > 0 ? (
                      <span className="text-sky-300">matched{line.steps.length > 0 && ` (${line.steps.join(", ")})`}</span>
                    ) : (
                      <span className="text-slate-500">no match</span>
                    )}
                  </td>
                  <td className="py-1 pr-3 font-mono text-slate-300">
                    {line.event ?? "—"}
                    {line.timestamp && <div className="text-slate-500">{formatUtc(line.timestamp)}</div>}
                  </td>
                  <td className="py-1 font-mono text-slate-400">
                    {[line.username && `user ${line.username}`, line.target_username && `→ ${line.target_username}`, line.source_ip && `from ${line.source_ip}`, line.host && `on ${line.host}`, line.process_name]
                      .filter(Boolean)
                      .join(" · ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

export function PlaygroundPage() {
  const [params, setParams] = useSearchParams();
  const ruleId = params.get("rule") ?? "AUTH-001";
  const loadRules = useCallback((signal: AbortSignal) => listRules(signal), []);
  const loadRule = useCallback((signal: AbortSignal) => getRule(ruleId, signal), [ruleId]);
  const rules = useApi(loadRules);
  const rule = useApi(loadRule);
  const [sourceType, setSourceType] = useState("linux_auth");
  const [timezone, setTimezone] = useState("UTC");
  const [defaultHost, setDefaultHost] = useState("");
  const [text, setText] = useState("");
  const [threshold, setThreshold] = useState("");
  const [window, setWindow] = useState("");
  const [result, setResult] = useState<PlaygroundResult | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    // A different rule: start its what-if values from the rule as it runs.
    setResult(null);
    setThreshold("");
    setWindow("");
  }, [ruleId]);

  const records = text.split("\n").filter((line) => line.trim() !== "");

  async function run(e: FormEvent) {
    e.preventDefault();
    const changes: Record<string, unknown> = {};
    if (threshold.trim()) changes.threshold = Number(threshold);
    if (window.trim()) changes.time_window = window.trim();
    setRunning(true);
    setError(null);
    try {
      setResult(
        await testRule(ruleId, {
          source_type: sourceType,
          records,
          timezone,
          default_host: defaultHost.trim() || null,
          changes: Object.keys(changes).length ? changes : null,
        }),
      );
    } catch (err) {
      setResult(null);
      setError(err);
    } finally {
      setRunning(false);
    }
  }

  const detail: RuleDetail | null = rule.data;
  const tunable = detail?.tunable;
  const message =
    error instanceof ApiError
      ? [error.message, ...error.details.map((d) => `${d.loc.filter((p) => p !== "body").join(" → ")}: ${d.msg.replace(/^Value error, /, "")}`)].join(". ")
      : error
        ? "Could not run the test."
        : null;

  return (
    <section className="space-y-4">
      <PageHeader
        title="Detection playground"
        description="Test a rule on sample log lines before trusting or tuning it. The lines go through the real parser, enrichment and rule evaluator; nothing is stored, and no alert is created. The rule sees only these lines."
      />
      <form onSubmit={(e) => void run(e)} aria-label="Test a rule" className="space-y-3">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Rule">
            <select
              value={ruleId}
              onChange={(e) => setParams({ rule: e.target.value })}
              className={`${selectClass} w-full max-w-xs sm:max-w-md`}
            >
              {(rules.data ?? []).filter((r) => r.in_library).map((r) => (
                <option key={r.rule_id} value={r.rule_id}>
                  {r.rule_id} {r.name}
                </option>
              ))}
              {!rules.data && <option value={ruleId}>{ruleId}</option>}
            </select>
          </Field>
          <Field label="Log format">
            <select value={sourceType} onChange={(e) => setSourceType(e.target.value)} className={selectClass}>
              {SOURCE_TYPES.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </Field>
          <Field label="Time zone of the lines">
            <input value={timezone} onChange={(e) => setTimezone(e.target.value)} className={`${inputClass} w-36`} maxLength={64} />
          </Field>
          <Field label="Host (formats without one)">
            <input value={defaultHost} onChange={(e) => setDefaultHost(e.target.value)} className={`${inputClass} w-40`} maxLength={253} />
          </Field>
        </div>
        {detail && (
          <p className="text-sm text-slate-400">
            {detail.description}{" "}
            <Link to={`/detections/${detail.rule_id}`} className="text-sky-300">
              Rule page
            </Link>
          </p>
        )}
        <Field label="Sample lines (one record per line, at most 500)">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={10}
            spellCheck={false}
            className={`${inputClass} font-mono text-xs`}
          />
        </Field>
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          Examples (linux_auth, ending now):
          {EXAMPLES.map((example) => (
            <button
              key={example.name}
              type="button"
              className="rounded border border-slate-700 px-2 py-0.5 text-sky-300 hover:bg-slate-800"
              onClick={() => {
                setSourceType("linux_auth");
                setText(example.build());
              }}
            >
              {example.name}
            </button>
          ))}
        </div>
        {(tunable?.threshold || tunable?.time_window) && (
          <fieldset className="flex flex-wrap items-end gap-3">
            <legend className="mb-1 text-sm text-slate-300">What if (optional, within the rule&apos;s bounds; nothing is saved)</legend>
            {tunable?.threshold && (
              <Field label="Threshold" hint={`${tunable.threshold.min}–${tunable.threshold.max}; now ${String(detail?.definition.threshold ?? "—")}`}>
                <input type="number" value={threshold} onChange={(e) => setThreshold(e.target.value)} className={`${inputClass} w-28`} />
              </Field>
            )}
            {tunable?.time_window && (
              <Field
                label="Time window"
                hint={`${shortDuration(isoSeconds(tunable.time_window.min))}–${shortDuration(isoSeconds(tunable.time_window.max))}, like 10m`}
              >
                <input value={window} onChange={(e) => setWindow(e.target.value)} className={`${inputClass} w-28`} maxLength={8} />
              </Field>
            )}
          </fieldset>
        )}
        {message && <ErrorMessage>{message}</ErrorMessage>}
        {rule.error && <ErrorMessage>{rule.error.message}</ErrorMessage>}
        <Button type="submit" disabled={running || records.length === 0}>
          {running ? "Running…" : "Run the rule"}
        </Button>
      </form>
      {result && <Results result={result} />}
    </section>
  );
}
