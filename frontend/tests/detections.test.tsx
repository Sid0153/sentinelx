import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { isoSeconds, shortDuration } from "../src/pages/DetectionDetailPage";
import type { RuleDetail, RuleMetrics, RuleSummary, RuleVersion } from "../src/types/inventory";
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
  match_count: 14,
  error_count: 0,
  last_run_at: "2026-09-27T09:00:00Z",
  last_match_at: "2026-09-27T08:55:00Z",
};

const DETAIL: RuleDetail = {
  ...SUMMARY,
  description: "Many failed logons for one account from one source.",
  definition: {
    id: "AUTH-001",
    threshold: 5,
    time_window: "PT5M",
    exclusions: [{ field: "source_ip", value: "10.20.0.0/16", comment: "vulnerability scanner" }],
  },
  overrides: {},
  tunable: {
    threshold: { min: 2, max: 1000 },
    time_window: { min: "PT1M", max: "P1D" },
    severity: true,
    confidence: true,
    enabled: true,
    exclusions: true,
  },
  mitre: [
    {
      technique_id: "T1110.001",
      name: "Password Guessing",
      tactics: ["credential-access"],
      url: "https://attack.mitre.org/techniques/T1110/001/",
      reason: "Repeated guesses against one account.",
      indicator: null,
    },
  ],
};

const VERSIONS: RuleVersion[] = [
  {
    version: 1,
    source: "library",
    changed_by: null,
    change_reason: null,
    overrides: {},
    definition: DETAIL.definition,
    created_at: "2026-09-01T08:00:00Z",
  },
];

function metrics(overrides: Partial<RuleMetrics> = {}): RuleMetrics {
  return {
    rule_id: "AUTH-001",
    name: "Repeated failed logons",
    category: "authentication",
    severity: "medium",
    enabled: true,
    in_library: true,
    alerts: 12,
    open: 2,
    confirmed: 6,
    benign: 1,
    false_positives: 3,
    closed: 10,
    false_positive_rate: 0.3,
    median_triage_seconds: 300,
    median_resolve_seconds: 5400,
    match_count: 14,
    last_match_at: "2026-09-27T08:55:00Z",
    ...overrides,
  };
}

const METRICS = {
  "GET /api/detections/metrics": (call: { url: URL }) => ({
    body: {
      days: Number(call.url.searchParams.get("days")),
      from: "2026-09-01T00:00:00Z",
      to: "2026-10-01T00:00:00Z",
      items: [
        metrics(),
        metrics({ rule_id: "PROC-001", alerts: 0, open: 0, confirmed: 0, benign: 0, false_positives: 0, closed: 0, false_positive_rate: null, median_triage_seconds: null, median_resolve_seconds: null }),
      ],
    },
  }),
};

function rule(role: "ADMIN" | "VIEWER", extra = {}) {
  return mockApi({
    ...signedInAs(role),
    ...METRICS,
    "GET /api/detections/AUTH-001": { body: DETAIL },
    "GET /api/detections/AUTH-001/versions": { body: VERSIONS },
    ...extra,
  });
}

describe("Detection rules", () => {
  it("converts stored ISO durations to the short form", () => {
    expect(isoSeconds("PT5M")).toBe(300);
    expect(isoSeconds("P1D")).toBe(86400);
    expect(isoSeconds("PT300S")).toBe(300);
    expect(shortDuration(300)).toBe("5m");
    expect(shortDuration(10)).toBe("10s");
    expect(shortDuration(7200)).toBe("2h");
  });

  it("lists rules with their state and how analysts closed their alerts", async () => {
    const api = mockApi({
      ...signedInAs("VIEWER"),
      ...METRICS,
      "GET /api/detections": { body: [SUMMARY, { ...SUMMARY, rule_id: "PROC-001", name: "Odd process", enabled: false }] },
    });
    renderApp("/detections");
    const row = (await screen.findByRole("link", { name: /AUTH-001/ })).closest("tr") as HTMLElement;
    expect(row).toHaveTextContent("enabled");
    await waitFor(() => expect(row).toHaveTextContent("12"));
    expect(row).toHaveTextContent("2 open");
    expect(row).toHaveTextContent("30 %");
    expect(row).toHaveTextContent("3 of 10 closed");
    expect(row).toHaveTextContent("1.5 h"); // median time to close: 5,400 s
    const other = screen.getByRole("link", { name: /PROC-001/ }).closest("tr") as HTMLElement;
    expect(other).toHaveTextContent("disabled");
    expect(other).toHaveTextContent("—"); // no closed alerts: no rate, not 0 %
    expect(api.callsTo("GET /api/detections/metrics")[0].url.searchParams.get("days")).toBe("30");
    fireEvent.change(screen.getByLabelText("Alerts created in"), { target: { value: "90" } });
    await waitFor(() => expect(api.callsTo("GET /api/detections/metrics")).toHaveLength(2));
    expect(api.callsTo("GET /api/detections/metrics")[1].url.searchParams.get("days")).toBe("90");
  });

  it("shows a rule's analyst outcomes", async () => {
    rule("VIEWER");
    renderApp("/detections/AUTH-001");
    const panel = (await screen.findByRole("heading", { name: "Analyst outcomes" })).parentElement as HTMLElement;
    await waitFor(() => expect(panel).toHaveTextContent("12 (2 open)"));
    expect(panel).toHaveTextContent("Confirmed malicious6");
    expect(panel).toHaveTextContent("False positives3 · 30 % of closed");
    expect(panel).toHaveTextContent("Median time to triage5 min");
  });

  it("shows the definition, ATT&CK mapping and history; viewers cannot tune", async () => {
    rule("VIEWER");
    renderApp("/detections/AUTH-001");
    expect(await screen.findByRole("link", { name: "T1110.001 Password Guessing" })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1110/001/",
    );
    expect(screen.getByText(/"time_window": "PT5M"/)).toBeInTheDocument();
    expect(await screen.findByText("from the library", { exact: false })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Alerts from this rule" })).toHaveAttribute("href", "/alerts?rule_id=AUTH-001");
    expect(screen.queryByRole("button", { name: "Tune rule" })).not.toBeInTheDocument();
  });

  it("sends only changed fields with the reason, and reloads the new version", async () => {
    const api = rule("ADMIN", { "PATCH /api/detections/AUTH-001": { body: { ...DETAIL, version: 2 } } });
    renderApp("/detections/AUTH-001");
    fireEvent.click(await screen.findByRole("button", { name: "Tune rule" }));
    const form = screen.getByRole("form", { name: "Tune rule" });
    expect(within(form).getByLabelText("Time window")).toHaveValue("5m");

    fireEvent.change(within(form).getByLabelText("Threshold"), { target: { value: "10" } });
    fireEvent.change(within(form).getByLabelText("Time window"), { target: { value: "15m" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save new version" }));
    // The reason is required before anything is sent.
    expect(await within(form).findByRole("alert")).toHaveTextContent("Give a reason");
    expect(api.callsTo("PATCH /api/detections/AUTH-001")).toHaveLength(0);

    fireEvent.change(within(form).getByLabelText("Reason for the change"), {
      target: { value: "Too noisy on the VPN gateway" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Save new version" }));
    expect(await screen.findByRole("button", { name: "Tune rule" })).toBeInTheDocument();
    expect(api.callsTo("PATCH /api/detections/AUTH-001")[0].body).toEqual({
      threshold: 10,
      time_window: "15m",
      reason: "Too noisy on the VPN gateway",
    });
    expect(api.callsTo("GET /api/detections/AUTH-001")).toHaveLength(2);
    expect(api.callsTo("GET /api/detections/AUTH-001/versions")).toHaveLength(2);
  });

  it("refuses values outside the rule's bounds before sending", async () => {
    const api = rule("ADMIN");
    renderApp("/detections/AUTH-001");
    fireEvent.click(await screen.findByRole("button", { name: "Tune rule" }));
    const form = screen.getByRole("form", { name: "Tune rule" });
    fireEvent.change(within(form).getByLabelText("Time window"), { target: { value: "2d" } });
    fireEvent.change(within(form).getByLabelText("Reason for the change"), { target: { value: "testing bounds" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save new version" }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("from 1m to 1d");
    expect(api.callsTo("PATCH /api/detections/AUTH-001")).toHaveLength(0);
  });
  it("edits the exclusions as one list and shows why a value is refused", async () => {
    let attempt = 0;
    const api = rule("ADMIN", {
      "PATCH /api/detections/AUTH-001": () => {
        attempt += 1;
        return attempt === 1
          ? {
              status: 422,
              body: {
                error: {
                  code: "validation_error",
                  message: "Request validation failed",
                  request_id: "r",
                  details: [{ loc: ["body", "exclusions", 1, "value"], msg: "Value error, does not appear to be an IPv4 or IPv6 network", type: "value_error" }],
                },
              },
            }
          : { body: { ...DETAIL, version: 2 } };
      },
    });
    renderApp("/detections/AUTH-001");
    // Read view lists the current allowlist.
    expect(await screen.findByText(/source_ip = 10.20.0.0\/16 \(vulnerability scanner\)/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Tune rule" }));
    const form = screen.getByRole("form", { name: "Tune rule" });

    fireEvent.change(within(form).getByLabelText("Exclusion field"), { target: { value: "username" } });
    fireEvent.change(within(form).getByLabelText("Exclusion value"), { target: { value: "svc-backup" } });
    fireEvent.change(within(form).getByLabelText("Exclusion comment"), { target: { value: "nightly job" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add exclusion" }));
    fireEvent.change(within(form).getByLabelText("Reason for the change"), { target: { value: "backup job is noisy" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save new version" }));

    expect(await within(form).findByRole("alert")).toHaveTextContent("exclusions → 1 → value: does not appear to be an IPv4 or IPv6 network");
    expect(api.callsTo("PATCH /api/detections/AUTH-001")[0].body).toEqual({
      exclusions: [
        { field: "source_ip", value: "10.20.0.0/16", comment: "vulnerability scanner" },
        { field: "username", value: "svc-backup", comment: "nightly job" },
      ],
      reason: "backup job is noisy",
    });

    // Removing the scanner entry sends the list without it.
    fireEvent.click(within(form).getByRole("button", { name: "Remove exclusion source_ip 10.20.0.0/16" }));
    fireEvent.click(within(form).getByRole("button", { name: "Save new version" }));
    await waitFor(() => expect(api.callsTo("PATCH /api/detections/AUTH-001")).toHaveLength(2));
    expect((api.callsTo("PATCH /api/detections/AUTH-001")[1].body as { exclusions: unknown[] }).exclusions).toEqual([
      { field: "username", value: "svc-backup", comment: "nightly job" },
    ]);
  });
});
