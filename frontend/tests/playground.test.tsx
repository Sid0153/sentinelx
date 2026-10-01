import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { diffDefinitions, suppressionLabel } from "../src/pages/DetectionDetailPage";
import type { PlaygroundResult, RuleDetail, RuleSummary } from "../src/types/inventory";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

const SUMMARY: RuleSummary = {
  rule_id: "AUTH-001",
  name: "Repeated failed logons",
  category: "authentication",
  kind: "threshold",
  severity: "medium",
  confidence: "medium",
  enabled: true,
  in_library: true,
  version: 1,
  techniques: ["T1110.001"],
  match_count: 0,
  error_count: 0,
  last_run_at: null,
  last_match_at: null,
};

const DETAIL: RuleDetail = {
  ...SUMMARY,
  description: "Many failed logons for one account from one source.",
  definition: { id: "AUTH-001", threshold: 5, time_window: "PT5M", exclusions: [] },
  overrides: {},
  tunable: {
    threshold: { min: 2, max: 1000 },
    time_window: { min: "PT1M", max: "P1D" },
    severity: true,
    confidence: true,
    enabled: true,
    exclusions: true,
  },
  mitre: [],
};

function result(triggered: boolean): PlaygroundResult {
  return {
    triggered,
    rule: {
      rule_id: "AUTH-001",
      name: "Repeated failed logons",
      kind: "threshold",
      version: 1,
      severity: "medium",
      confidence: "medium",
      threshold: 5,
      time_window: "5 min",
      tried: triggered ? {} : { threshold: 10 },
    },
    summary: { lines: 3, parsed: 2, skipped: 0, failed: 1, excluded: 0, matched: 2, detections: triggered ? 1 : 0 },
    detections: triggered
      ? [
          {
            explanation: '8 failed SSH logons for "root" on web-01 from 203.0.113.45 within 28 s.',
            severity: "medium",
            confidence: "medium",
            indicator: null,
            event_count: 8,
            first_seen: "2026-10-01T08:00:00Z",
            last_seen: "2026-10-01T08:00:28Z",
            evidence_lines: [1, 2],
            group: {},
            mitre: ["T1110.001"],
            investigation: [],
            response: [],
          },
        ]
      : [],
    lines: [
      { line: 1, status: "parsed", code: null, timestamp: "2026-10-01T08:00:00Z", event: "authentication/logon failure", host: "web-01", username: "root", target_username: null, source_ip: "203.0.113.45", process_name: null, excluded: false, matched: true, steps: [], evidence: triggered },
      { line: 2, status: "parsed", code: null, timestamp: "2026-10-01T08:00:04Z", event: "authentication/logon failure", host: "web-01", username: "root", target_username: null, source_ip: "203.0.113.45", process_name: null, excluded: false, matched: true, steps: [], evidence: triggered },
      { line: 3, status: "failed", code: "unrecognized_line", timestamp: null, event: null, host: null, username: null, target_username: null, source_ip: null, process_name: null, excluded: false, matched: null, steps: [], evidence: false },
    ],
  };
}

function routes(role: "ANALYST" | "VIEWER", extra = {}) {
  return mockApi({
    ...signedInAs(role),
    "GET /api/detections": { body: [SUMMARY] },
    "GET /api/detections/AUTH-001": { body: DETAIL },
    ...extra,
  });
}

describe("Detection playground", () => {
  it("runs a rule on example lines and shows why it fired", async () => {
    const api = routes("ANALYST", { "POST /api/detections/AUTH-001/test": { body: result(true) } });
    renderApp("/playground?rule=AUTH-001");
    const form = await screen.findByRole("form", { name: "Test a rule" });
    fireEvent.click(within(form).getByRole("button", { name: "Brute force: 8 failed logons" }));
    fireEvent.click(within(form).getByRole("button", { name: "Run the rule" }));

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("AUTH-001 fired: 1 detection.");
    expect(status).toHaveTextContent("Nothing was stored");
    expect(screen.getByText(/8 failed SSH logons for "root"/)).toBeInTheDocument();
    expect(screen.getByText("Evidence lines: 1, 2")).toBeInTheDocument();
    expect(screen.getByText("failed (unrecognized_line)")).toBeInTheDocument();

    const body = api.callsTo("POST /api/detections/AUTH-001/test")[0].body as {
      source_type: string;
      records: string[];
      changes: unknown;
    };
    expect(body.source_type).toBe("linux_auth");
    expect(body.records).toHaveLength(8);
    expect(body.records[0]).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00 web-01 sshd\[\d+\]: Failed password for root/);
    expect(body.changes).toBeNull();
  });

  it("sends what-if values and explains a refusal", async () => {
    let attempt = 0;
    const api = routes("ANALYST", {
      "POST /api/detections/AUTH-001/test": () => {
        attempt += 1;
        return attempt === 1
          ? {
              status: 400,
              body: { error: { code: "bad_request", message: "threshold must be between 2 and 1000", request_id: "r" } },
            }
          : { body: result(false) };
      },
    });
    renderApp("/playground?rule=AUTH-001");
    const form = await screen.findByRole("form", { name: "Test a rule" });
    fireEvent.change(within(form).getByLabelText(/Sample lines/), { target: { value: "line one\nline two" } });
    fireEvent.change(await within(form).findByLabelText("Threshold"), { target: { value: "1" } });
    fireEvent.click(within(form).getByRole("button", { name: "Run the rule" }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("threshold must be between 2 and 1000");

    fireEvent.change(within(form).getByLabelText("Threshold"), { target: { value: "10" } });
    fireEvent.change(within(form).getByLabelText("Time window"), { target: { value: "15m" } });
    fireEvent.click(within(form).getByRole("button", { name: "Run the rule" }));
    expect(await screen.findByRole("status")).toHaveTextContent("AUTH-001 did not fire.");
    expect(screen.getByRole("status")).toHaveTextContent("what-if: threshold 10");
    expect((api.callsTo("POST /api/detections/AUTH-001/test")[1].body as { changes: unknown }).changes).toEqual({
      threshold: 10,
      time_window: "15m",
    });
  });

  it("is for analysts: viewers see neither the page nor the link", async () => {
    routes("VIEWER");
    renderApp("/playground");
    expect(await screen.findByRole("heading", { name: "Not authorized" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Playground" })).not.toBeInTheDocument();
  });
});

describe("Rule versions and suppressions", () => {
  it("lists the fields that differ between two definitions", () => {
    expect(
      diffDefinitions(
        { threshold: 5, time_window: "PT5M", exclusions: [] },
        { threshold: 10, time_window: "PT5M", exclusions: [{ field: "host", value: "scanner" }] },
      ),
    ).toEqual([
      { path: "exclusions", from: "[]", to: null },
      { path: "exclusions.0.field", from: null, to: '"host"' },
      { path: "exclusions.0.value", from: null, to: '"scanner"' },
      { path: "threshold", from: "5", to: "10" },
    ]);
    expect(diffDefinitions({ a: 1 }, { a: 1 })).toEqual([]);
  });

  it("labels suppression windows by where now falls", () => {
    const now = Date.parse("2026-10-01T12:00:00Z");
    const window = (from: string, until: string) => ({
      field: "host" as const,
      value: "web-01",
      active_from: from,
      active_until: until,
    });
    expect(suppressionLabel({ field: "host", value: "web-01" }, now)).toBe("");
    expect(suppressionLabel(window("2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z"), now)).toBe("suppression expired");
    expect(suppressionLabel(window("2026-10-01T10:00:00Z", "2026-10-01T14:00:00Z"), now)).toMatch(/^suppressed /);
    expect(suppressionLabel(window("2026-10-02T10:00:00Z", "2026-10-02T14:00:00Z"), now)).toMatch(/^suppression from /);
  });

  it("compares two versions on the rule page", async () => {
    mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/detections/AUTH-001": { body: DETAIL },
      "GET /api/detections/metrics": { body: { days: 30, from: "", to: "", items: [] } },
      "GET /api/detections/AUTH-001/versions": {
        body: [
          { version: 2, source: "admin", changed_by: null, change_reason: "noisy", overrides: { threshold: 10 }, definition: { threshold: 10, time_window: "PT5M" }, created_at: "2026-10-01T09:00:00Z" },
          { version: 1, source: "library", changed_by: null, change_reason: null, overrides: {}, definition: { threshold: 5, time_window: "PT5M" }, created_at: "2026-09-01T09:00:00Z" },
        ],
      },
    });
    renderApp("/detections/AUTH-001");
    const table = await screen.findByRole("table", { name: "Changed fields" });
    const row = within(table).getByText("threshold").closest("tr") as HTMLElement;
    expect(row).toHaveTextContent("threshold510");
    fireEvent.change(screen.getByLabelText("Older version"), { target: { value: "2" } });
    await waitFor(() => expect(screen.getByText("Choose two different versions.")).toBeInTheDocument());
  });

  it("adds a time-boxed suppression with both dates", async () => {
    const api = mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/detections/AUTH-001": { body: DETAIL },
      "GET /api/detections/metrics": { body: { days: 30, from: "", to: "", items: [] } },
      "GET /api/detections/AUTH-001/versions": { body: [] },
      "PATCH /api/detections/AUTH-001": { body: DETAIL },
    });
    renderApp("/detections/AUTH-001");
    fireEvent.click(await screen.findByRole("button", { name: "Tune rule" }));
    const form = screen.getByRole("form", { name: "Tune rule" });
    fireEvent.change(within(form).getByLabelText("Exclusion value"), { target: { value: "203.0.113.0/24" } });
    fireEvent.change(within(form).getByLabelText("Suppression from"), { target: { value: "2026-10-02T08:00" } });
    const add = within(form).getByRole("button", { name: "Add exclusion" });
    expect(add).toBeDisabled(); // one date only
    expect(form).toHaveTextContent("Give both dates, or neither.");
    fireEvent.change(within(form).getByLabelText("Suppression until"), { target: { value: "2026-10-02T12:00" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add suppression" }));
    fireEvent.change(within(form).getByLabelText("Reason for the change"), { target: { value: "announced pen test" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save new version" }));
    await waitFor(() => expect(api.callsTo("PATCH /api/detections/AUTH-001")).toHaveLength(1));
    expect(api.callsTo("PATCH /api/detections/AUTH-001")[0].body).toEqual({
      exclusions: [
        {
          field: "source_ip",
          value: "203.0.113.0/24",
          comment: null,
          active_from: "2026-10-02T08:00:00Z",
          active_until: "2026-10-02T12:00:00Z",
        },
      ],
      reason: "announced pen test",
    });
  });
});
