import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AlertDetail, AlertSummary, EvidenceEvent } from "../src/types/api";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

function page<T>(items: T[], total = items.length) {
  return { body: { items, total, limit: 50, offset: 0 } };
}

function summary(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    id: "a-1",
    rule_id: "AUTH-002",
    title: "Successful authentication after repeated failures (203.0.113.45, root, web-01)",
    severity: "high",
    confidence: "medium",
    status: "NEW",
    disposition: null,
    priority_score: 58,
    priority_band: "high",
    host: "web-01",
    username: "root",
    source_ip: "203.0.113.45",
    destination_ip: null,
    event_count: 13,
    evidence_truncated: false,
    detection_count: 1,
    first_event_at: "2026-09-26T10:00:00Z",
    last_event_at: "2026-09-26T10:00:39Z",
    created_at: "2026-09-26T10:01:00Z",
    updated_at: "2026-09-26T10:01:00Z",
    simulated: true,
    ...overrides,
  };
}

function detail(overrides: Partial<AlertDetail> = {}): AlertDetail {
  return {
    ...summary(),
    rule_version: 1,
    indicator: null,
    kind: "sequence",
    category: "authentication",
    description: "Several failed logons followed by a successful one from the same source.",
    target_username: null,
    asset_id: "as-1",
    asset_hostname: "web-01",
    identity_id: null,
    identity_username: null,
    priority_breakdown: [
      { factor: "severity", value: "high", points: 40 },
      { factor: "confidence", value: "medium", points: 8 },
      { factor: "asset", value: "web-01 high", points: 10 },
    ],
    risk_model_version: "1",
    group_values: { source_ip: "203.0.113.45", username: "root", host: "web-01" },
    explanation:
      '12 failed logons for "root" on web-01 from 203.0.113.45 (external), then a successful logon 3 s after the last failure.',
    facts: { count: 13, threshold: 3, time_window: 600 },
    entities: { host: ["web-01"], username: ["root"], source_ip: ["203.0.113.45"] },
    investigation: ["Check what root did on web-01 after the logon."],
    response: ["Reset the password of root and end its sessions."],
    mitre: [
      {
        technique: "T1110",
        name: "Brute Force",
        tactics: ["Credential Access"],
        reason: "The failures that preceded the success.",
        attack_version: "19.2",
        url: "https://attack.mitre.org/techniques/T1110/",
      },
    ],
    history: [
      {
        run_id: "r-1",
        at: "2026-09-26T10:01:00Z",
        first_seen: "2026-09-26T10:00:00Z",
        last_seen: "2026-09-26T10:00:39Z",
        event_count: 13,
        new_evidence: 13,
        explanation: "12 failed logons …",
      },
    ],
    peak_count: 13,
    previous_alert_id: null,
    triaged_at: null,
    resolved_at: null,
    resolved_by: null,
    status_changed_at: null,
    status_changed_by: null,
    status_note: null,
    allowed_transitions: ["TRIAGED", "IN_PROGRESS", "FALSE_POSITIVE"],
    activity: [],
    related: [
      {
        id: "a-2",
        rule_id: "AUTH-001",
        title: "Repeated SSH authentication failures (203.0.113.45, web-01, root)",
        status: "NEW",
        priority_score: 43,
        priority_band: "medium",
        last_event_at: "2026-09-26T10:00:36Z",
        shared: ["host web-01", "source 203.0.113.45"],
      },
    ],
    incident_id: null,
    incident_number: null,
    ...overrides,
  };
}

const HOSTILE = '<img src=x onerror="alert(1)"> Failed password for root';

function evidence(): EvidenceEvent {
  return {
    id: "e-1",
    timestamp: "2026-09-26T10:00:00Z",
    source_type: "linux_auth",
    event_category: "authentication",
    event_action: "logon",
    event_outcome: "failure",
    host: "web-01",
    username: "root",
    target_username: null,
    source_ip: "203.0.113.45",
    source_port: 50412,
    destination_ip: null,
    destination_port: null,
    process_name: null,
    command_line: null,
    message: null,
    simulated: true,
    raw_text: HOSTILE,
    raw_truncated: false,
  };
}

describe("Alert queue", () => {
  it("lists open alerts by priority with their entities", async () => {
    const api = mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/alerts": page([summary(), summary({ id: "a-2", rule_id: "AUTH-001", priority_score: 43, priority_band: "medium", title: "Repeated SSH authentication failures" })]),
    });
    renderApp("/alerts");
    const link = await screen.findByRole("link", { name: /Successful authentication after/ });
    expect(link).toHaveAttribute("href", "/alerts/a-1");
    expect(screen.getAllByText("SIMULATED")).toHaveLength(2);
    expect(screen.getAllByText("host web-01 · user root · from 203.0.113.45")).toHaveLength(2);
    const query = api.callsTo("GET /api/alerts")[0].url.searchParams;
    expect(query.getAll("status")).toEqual(["NEW", "TRIAGED", "IN_PROGRESS"]);
    expect(query.get("sort")).toBe("priority");
  });

  it("changes the view and severity through the query", async () => {
    const api = mockApi({ ...signedInAs("VIEWER"), "GET /api/alerts": page([summary()]) });
    renderApp("/alerts");
    await screen.findByText(/Successful authentication after/);
    fireEvent.change(screen.getByLabelText("View"), { target: { value: "resolved" } });
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
    await waitFor(() => {
      const last = api.callsTo("GET /api/alerts").at(-1)!.url.searchParams;
      expect(last.getAll("status")).toEqual(["RESOLVED"]);
      expect(last.get("severity")).toBe("high");
    });
  });

  it("explains an empty queue", async () => {
    mockApi({ ...signedInAs("VIEWER"), "GET /api/alerts": page([]) });
    renderApp("/alerts");
    expect(await screen.findByText(/No open alerts/)).toBeInTheDocument();
  });
});

describe("Alert page", () => {
  const routes = (alert: AlertDetail) => ({
    "GET /api/alerts/a-1": { body: alert },
    "GET /api/alerts/a-1/events": page([evidence()], 13),
  });

  it("shows what happened, why, the priority sum, ATT&CK and related alerts", async () => {
    mockApi({ ...signedInAs("VIEWER"), ...routes(detail()) });
    renderApp("/alerts/a-1");
    expect(await screen.findByText(/12 failed logons for "root" on web-01/)).toBeInTheDocument();
    expect(screen.getByText(/Several failed logons followed/)).toBeInTheDocument();
    const priority = screen.getByRole("heading", { name: "Priority" }).parentElement!;
    expect(within(priority).getByText("+40")).toBeInTheDocument();
    expect(within(priority).getByText("58")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "T1110 Brute Force" })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1110/",
    );
    expect(screen.getByText(/shares host web-01, source 203.0.113.45/)).toBeInTheDocument();
    expect(screen.getByText(/Not part of an incident/)).toBeInTheDocument();
    // Viewers see no workflow buttons.
    expect(screen.getByText("Analysts and admins can change the status.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Triage" })).not.toBeInTheDocument();
  });

  it("shows raw evidence as text, never as HTML", async () => {
    mockApi({ ...signedInAs("VIEWER"), ...routes(detail()) });
    const { container } = renderApp("/alerts/a-1");
    fireEvent.click(await screen.findByRole("button", { name: "Raw" }));
    expect(screen.getByText(HOSTILE)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("lets an analyst resolve an alert with a disposition", async () => {
    const triaged = detail({ status: "TRIAGED", allowed_transitions: ["IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"] });
    let current = triaged;
    const api = mockApi({
      ...signedInAs("ANALYST"),
      "GET /api/alerts/a-1": () => ({ body: current }),
      "GET /api/alerts/a-1/events": page([evidence()]),
      "POST /api/alerts/a-1/transition": () => {
        current = detail({
          status: "RESOLVED",
          disposition: "benign_expected",
          allowed_transitions: ["TRIAGED"],
          status_note: "Pen test agreed with IT",
          status_changed_by: "analyst@example.com",
          activity: [
            {
              at: "2026-09-26T10:05:00Z",
              actor: "analyst@example.com",
              from_status: "TRIAGED",
              to_status: "RESOLVED",
              disposition: "benign_expected",
              reason: "Pen test agreed with IT",
            },
          ],
        });
        return { body: current };
      },
    });
    renderApp("/alerts/a-1");
    fireEvent.click(await screen.findByRole("button", { name: "Resolve" }));
    const form = screen.getByRole("form", { name: "Change status" });
    fireEvent.change(within(form).getByLabelText("Disposition"), { target: { value: "benign_expected" } });
    fireEvent.change(within(form).getByLabelText("Note (optional)"), {
      target: { value: "Pen test agreed with IT" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Resolve" }));

    expect(await screen.findByRole("button", { name: "Reopen" })).toBeInTheDocument();
    expect(api.callsTo("POST /api/alerts/a-1/transition")[0].body).toEqual({
      status: "RESOLVED",
      disposition: "benign_expected",
      reason: "Pen test agreed with IT",
    });
    expect(screen.getByText(/analyst@example.com: Triaged → Resolved \(benign expected\)/)).toBeInTheDocument();
  });

  it("requires a reason for a false positive and shows the server's refusal", async () => {
    const api = mockApi({
      ...signedInAs("ANALYST"),
      ...routes(detail()),
      "POST /api/alerts/a-1/transition": {
        status: 409,
        body: { error: { code: "conflict", message: "An alert cannot go from RESOLVED to FALSE_POSITIVE", request_id: null } },
      },
    });
    renderApp("/alerts/a-1");
    fireEvent.click(await screen.findByRole("button", { name: "False positive" }));
    const form = screen.getByRole("form", { name: "Change status" });
    const submit = within(form).getByRole("button", { name: "False positive" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(form).getByLabelText("Reason (required)"), {
      target: { value: "Our scanner" },
    });
    fireEvent.click(submit);
    expect(await screen.findByText(/cannot go from RESOLVED/)).toBeInTheDocument();
    expect(api.callsTo("POST /api/alerts/a-1/transition")[0].body).toEqual({
      status: "FALSE_POSITIVE",
      reason: "Our scanner",
    });
  });

  it("says so when an alert does not exist", async () => {
    mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/alerts/nope": {
        status: 404,
        body: { error: { code: "not_found", message: "Alert not found", request_id: null } },
      },
    });
    renderApp("/alerts/nope");
    expect(await screen.findByText("This alert does not exist.")).toBeInTheDocument();
  });
});
