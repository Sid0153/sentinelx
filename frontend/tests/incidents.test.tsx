import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { IncidentDetail, IncidentSummary, TimelineEntry } from "../src/types/api";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

function page<T>(items: T[]) {
  return { body: { items, total: items.length, limit: 50, offset: 0 } };
}

function summary(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  return {
    id: "i-1",
    number: 7,
    title: "Multi-stage activity on web-01 (deploy from 203.0.113.45)",
    status: "OPEN",
    severity: "high",
    risk_score: 88,
    risk_band: "critical",
    alert_count: 4,
    hosts: ["web-01"],
    usernames: ["deploy", "root", "svc-backup2"],
    source_ips: ["203.0.113.45"],
    tactics: ["Credential Access", "Persistence", "Privilege Escalation"],
    first_activity_at: "2026-09-26T10:00:00Z",
    last_activity_at: "2026-09-26T10:02:08Z",
    created_at: "2026-09-26T10:03:00Z",
    updated_at: "2026-09-26T10:03:00Z",
    simulated: true,
    assigned_to: null,
    ...overrides,
  };
}

const ALERT = {
  id: "a-4",
  rule_id: "ACCT-001",
  title: "Privileged account created (web-01, svc-backup2)",
  severity: "high" as const,
  confidence: "high" as const,
  status: "NEW" as const,
  disposition: null,
  priority_score: 70,
  priority_band: "high" as const,
  host: "web-01",
  username: null,
  source_ip: null,
  destination_ip: null,
  event_count: 2,
  evidence_truncated: false,
  detection_count: 1,
  first_event_at: "2026-09-26T10:02:06Z",
  last_event_at: "2026-09-26T10:02:08Z",
  created_at: "2026-09-26T10:03:00Z",
  updated_at: "2026-09-26T10:03:00Z",
  simulated: true,
};

function detail(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    ...summary(),
    summary: "4 alert(s) from 4 rule(s) (ACCT-001, AUTH-001, AUTH-002, PRIV-001).",
    created_reason: "Multi-stage activity: Repeated SSH authentication failures with 3 related alert(s)",
    risk_breakdown: [
      { factor: "highest alert", value: "73 (…)", points: 73 },
      { factor: "attack stages", value: "4 kinds of finding", points: 15 },
    ],
    risk_model_version: "2",
    techniques: ["T1136.001"],
    disposition: null,
    resolution: null,
    resolved_at: null,
    resolved_by: null,
    closed_at: null,
    title_edited: false,
    related_incident: null,
    alerts: [
      {
        alert: ALERT,
        link_strength: "MEDIUM",
        shared_entities: ["host web-01"],
        reason: "Same host web-01 and a new kind of finding (T1098.007, T1136.001) 90 s apart.",
        link_source: "engine",
        linked_at: "2026-09-26T10:03:00Z",
      },
    ],
    notes: [],
    evidence: [],
    activity: [],
    mitre: [
      {
        technique: "T1136.001",
        name: "Create Account: Local Account",
        tactics: ["Persistence"],
        attack_version: "19.2",
        url: "https://attack.mitre.org/techniques/T1136/001/",
        rules: ["ACCT-001"],
        reasons: ["A local account is created."],
      },
    ],
    response: [{ rule_id: "ACCT-001", title: ALERT.title, steps: ["Remove the account."] }],
    allowed_transitions: ["TRIAGED", "RESOLVED"],
    ...overrides,
  };
}

const HOSTILE = '<img src=x onerror="alert(1)"> Failed password for deploy';

function event(id: string, at: string): TimelineEntry {
  return {
    at,
    kind: "event",
    id,
    event: {
      category: "authentication",
      action: "logon",
      outcome: "failure",
      host: "web-01",
      username: "deploy",
      target_username: null,
      source_ip: "203.0.113.45",
      process_name: null,
      command_line: null,
      raw_text: HOSTILE,
      rules: ["AUTH-001", "AUTH-002"],
      simulated: true,
    },
    alert: null,
    activity: null,
  };
}

const TIMELINE = {
  "GET /api/incidents/i-1/timeline": (call: { url: URL }) =>
    call.url.searchParams.get("cursor")
      ? { body: { items: [event("e-2", "2026-09-26T10:00:03Z")], next_cursor: null, limit: 100 } }
      : { body: { items: [event("e-1", "2026-09-26T10:00:00Z")], next_cursor: "c1", limit: 100 } },
};

describe("Incident queue", () => {
  it("lists open incidents with their reference, risk and scope", async () => {
    const api = mockApi({ ...signedInAs("VIEWER"), "GET /api/incidents": page([summary()]) });
    renderApp("/incidents");
    const link = await screen.findByRole("link", { name: /INC-7 Multi-stage activity/ });
    expect(link).toHaveAttribute("href", "/incidents/i-1");
    expect(screen.getByText(/hosts web-01 · accounts deploy, root, svc-backup2/)).toBeInTheDocument();
    const query = api.callsTo("GET /api/incidents")[0].url.searchParams;
    expect(query.getAll("status")).toEqual(["OPEN", "TRIAGED", "INVESTIGATING", "CONTAINED"]);
    fireEvent.change(screen.getByLabelText("Assigned"), { target: { value: "me" } });
    await waitFor(() =>
      expect(api.callsTo("GET /api/incidents").at(-1)!.url.searchParams.get("assigned")).toBe("me"),
    );
  });

  it("keeps a campaign with many sources readable", async () => {
    const sources = Array.from({ length: 20 }, (_, i) => `203.0.113.${150 + i}`);
    mockApi({ ...signedInAs("VIEWER"), "GET /api/incidents": page([summary({ source_ips: sources })]) });
    renderApp("/incidents");
    expect(
      await screen.findByText(/from 203.0.113.150, 203.0.113.151, 203.0.113.152 and 17 more/),
    ).toBeInTheDocument();
  });

  it("explains an empty queue", async () => {
    mockApi({ ...signedInAs("VIEWER"), "GET /api/incidents": page([]) });
    renderApp("/incidents");
    expect(await screen.findByText(/No open incidents/)).toBeInTheDocument();
  });
});

describe("Incident workspace", () => {
  it("shows why each alert is linked, the risk sum, ATT&CK and response; viewers only read", async () => {
    mockApi({ ...signedInAs("VIEWER"), "GET /api/incidents/i-1": { body: detail() }, ...TIMELINE });
    renderApp("/incidents/i-1");
    expect(await screen.findByText(/a new kind of finding \(T1098.007, T1136.001\)/)).toBeInTheDocument();
    expect(screen.getByText("medium link")).toBeInTheDocument();
    const risk = screen.getByRole("heading", { name: "Risk" }).parentElement!;
    expect(within(risk).getByText("88")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "T1136.001 Create Account: Local Account" })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1136/001/",
    );
    expect(screen.getByText(/never changes anything on monitored systems/)).toBeInTheDocument();
    expect(screen.getByText("Analysts and admins can change the status.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rename" })).not.toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Add note" })).not.toBeInTheDocument();
  });

  it("pages the timeline and shows raw evidence as text only", async () => {
    const api = mockApi({ ...signedInAs("VIEWER"), "GET /api/incidents/i-1": { body: detail() }, ...TIMELINE });
    const { container } = renderApp("/incidents/i-1");
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    await waitFor(() => expect(screen.getAllByRole("button", { name: "Raw" })).toHaveLength(2));
    expect(api.callsTo("GET /api/incidents/i-1/timeline").at(-1)!.url.searchParams.get("cursor")).toBe("c1");
    fireEvent.click(screen.getAllByRole("button", { name: "Raw" })[0]);
    expect(screen.getByText(HOSTILE)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("lets an analyst resolve with a disposition and a resolution", async () => {
    let current = detail();
    const api = mockApi({
      ...signedInAs("ANALYST"),
      "GET /api/incidents/i-1": () => ({ body: current }),
      "GET /api/incidents/assignees": { body: [{ id: "u-1", email: "analyst@example.com" }] },
      "POST /api/incidents/i-1/transition": () => {
        current = detail({
          status: "RESOLVED",
          disposition: "confirmed_malicious",
          resolution: "Account removed, host rebuilt",
          allowed_transitions: ["CLOSED", "INVESTIGATING"],
        });
        return { body: current };
      },
      ...TIMELINE,
    });
    renderApp("/incidents/i-1");
    fireEvent.click(await screen.findByRole("button", { name: "Resolve" }));
    const form = screen.getByRole("form", { name: "Change incident status" });
    const submit = within(form).getByRole("button", { name: "Resolve" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(form).getByLabelText("Resolution summary (required)"), {
      target: { value: "Account removed, host rebuilt" },
    });
    fireEvent.click(submit);
    expect(await screen.findByRole("button", { name: "Reopen" })).toBeInTheDocument();
    expect(api.callsTo("POST /api/incidents/i-1/transition")[0].body).toEqual({
      status: "RESOLVED",
      disposition: "confirmed_malicious",
      resolution: "Account removed, host rebuilt",
    });
  });

  it("adds notes, pins evidence from the timeline, and unlinks with a reason", async () => {
    const api = mockApi({
      ...signedInAs("ANALYST"),
      "GET /api/incidents/i-1": { body: detail() },
      "GET /api/incidents/assignees": { body: [] },
      "POST /api/incidents/i-1/notes": {
        status: 201,
        body: { id: "n-1", author: "analyst@example.com", body: "x", created_at: "2026-09-26T10:05:00Z" },
      },
      "POST /api/incidents/i-1/evidence": { status: 201, body: detail() },
      "POST /api/incidents/i-1/alerts/a-4/unlink": { body: detail({ alerts: [] }) },
      ...TIMELINE,
    });
    renderApp("/incidents/i-1");
    const form = await screen.findByRole("form", { name: "Add note" });
    fireEvent.change(within(form).getByLabelText("New note"), { target: { value: "VPS source." } });
    fireEvent.click(within(form).getByRole("button", { name: "Add note" }));
    await waitFor(() =>
      expect(api.callsTo("POST /api/incidents/i-1/notes")[0].body).toEqual({ body: "VPS source." }),
    );

    fireEvent.click(await screen.findByRole("button", { name: "Pin…" }));
    fireEvent.change(screen.getByLabelText("Evidence tag"), { target: { value: "initial_access" } });
    fireEvent.click(screen.getByRole("button", { name: "Pin" }));
    await waitFor(() =>
      expect(api.callsTo("POST /api/incidents/i-1/evidence")[0].body).toEqual({
        event_id: "e-1",
        action: "PIN",
        tag: "initial_access",
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: "Unlink…" }));
    const unlink = screen.getByRole("form", { name: "Unlink alert" });
    expect(within(unlink).getByRole("button", { name: "Unlink" })).toBeDisabled();
    fireEvent.change(within(unlink).getByLabelText("Why it does not belong"), {
      target: { value: "separate admin task" },
    });
    fireEvent.click(within(unlink).getByRole("button", { name: "Unlink" }));
    await waitFor(() =>
      expect(api.callsTo("POST /api/incidents/i-1/alerts/a-4/unlink")[0].body).toEqual({
        reason: "separate admin task",
      }),
    );
  });
});

describe("Escalation and settings", () => {
  it("escalates a standalone alert into an incident", async () => {
    const alert = {
      ...ALERT,
      id: "a-9",
      rule_version: 1,
      indicator: null,
      kind: "threshold",
      category: "authentication",
      description: "d",
      target_username: null,
      asset_id: null,
      asset_hostname: null,
      identity_id: null,
      identity_username: null,
      priority_breakdown: [],
      risk_model_version: "2",
      group_values: {},
      explanation: "6 failed SSH logons",
      facts: {},
      entities: {},
      investigation: [],
      response: [],
      mitre: [],
      history: [],
      peak_count: 6,
      previous_alert_id: null,
      triaged_at: null,
      resolved_at: null,
      resolved_by: null,
      status_changed_at: null,
      status_changed_by: null,
      status_note: null,
      allowed_transitions: [],
      activity: [],
      related: [],
      incident_id: null,
      incident_number: null,
    };
    const api = mockApi({
      ...signedInAs("ANALYST"),
      "GET /api/alerts/a-9": { body: alert },
      "GET /api/alerts/a-9/events": page([]),
      "POST /api/alerts/a-9/escalate": { status: 201, body: detail() },
    });
    renderApp("/alerts/a-9");
    fireEvent.click(await screen.findByRole("button", { name: "Escalate to incident…" }));
    const form = screen.getByRole("form", { name: "Escalate to incident" });
    fireEvent.change(within(form).getByLabelText("Why it needs an incident"), {
      target: { value: "Targets our database server" },
    });
    fireEvent.click(within(form).getByRole("button", { name: "Open incident" }));
    await waitFor(() =>
      expect(api.callsTo("POST /api/alerts/a-9/escalate")[0].body).toEqual({
        reason: "Targets our database server",
      }),
    );
  });

  it("lets admins change the correlation windows and shows refusals", async () => {
    const api = mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/settings": { body: { correlation_window_minutes: 120, sequence_window_minutes: 30 } },
      "PATCH /api/settings": {
        status: 400,
        body: {
          error: {
            code: "bad_request",
            message: "The sequence window cannot be longer than the correlation window",
            request_id: null,
          },
        },
      },
    });
    renderApp("/correlation");
    fireEvent.change(await screen.findByLabelText("Correlation window (minutes)"), {
      target: { value: "20" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/cannot be longer/)).toBeInTheDocument();
    expect(api.callsTo("PATCH /api/settings")[0].body).toEqual({
      correlation_window_minutes: 20,
      sequence_window_minutes: 30,
    });
  });
});
