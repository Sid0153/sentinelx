import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { isoSeconds, shortDuration } from "../src/pages/DetectionDetailPage";
import type { RuleDetail, RuleSummary, RuleVersion } from "../src/types/inventory";
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
  definition: { id: "AUTH-001", threshold: 5, time_window: "PT5M" },
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

function rule(role: "ADMIN" | "VIEWER", extra = {}) {
  return mockApi({
    ...signedInAs(role),
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

  it("lists rules with their state and statistics", async () => {
    mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/detections": { body: [SUMMARY, { ...SUMMARY, rule_id: "PROC-001", name: "Odd process", enabled: false }] },
    });
    renderApp("/detections");
    const row = (await screen.findByRole("link", { name: /AUTH-001/ })).closest("tr") as HTMLElement;
    expect(row).toHaveTextContent("enabled");
    expect(row).toHaveTextContent("14");
    const other = screen.getByRole("link", { name: /PROC-001/ }).closest("tr") as HTMLElement;
    expect(other).toHaveTextContent("disabled");
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
});
