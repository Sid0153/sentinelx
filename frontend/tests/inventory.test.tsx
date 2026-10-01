import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { Asset, ContextActivity, EventDetail, EventRecord, Identity } from "../src/types/inventory";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

function page<T>(items: T[], total = items.length) {
  return { body: { items, total, limit: 50, offset: 0 } };
}

function event(overrides: Partial<EventRecord> = {}): EventRecord {
  return {
    id: "ev-1",
    raw_event_id: "raw-1",
    source_id: "src-1",
    source_type: "linux_auth",
    timestamp: "2026-09-27T09:00:00Z",
    ingested_at: "2026-09-27T09:00:02Z",
    host: "web-01",
    host_ip: null,
    event_category: "authentication",
    event_action: "logon",
    event_outcome: "failure",
    username: "root",
    user_domain: null,
    target_username: null,
    source_ip: "203.0.113.45",
    source_port: 50522,
    destination_ip: null,
    destination_port: null,
    protocol: "ssh",
    service: "sshd",
    process_name: null,
    parent_process_name: null,
    command_line: null,
    session_id: null,
    message: null,
    attributes: {},
    source_ip_scope: "external",
    asset_id: "as-1",
    asset_criticality: "high",
    identity_id: null,
    identity_privileged: null,
    simulated: false,
    ...overrides,
  };
}

const ASSET: Asset = {
  id: "as-1",
  hostname: "web-01",
  ip_addresses: ["10.0.0.5"],
  asset_type: "server",
  environment: "production",
  criticality: "high",
  owner: "Platform team",
  description: null,
  tags: ["dmz"],
  status: "active",
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-01T08:00:00Z",
};

const IDENTITY: Identity = {
  id: "id-1",
  username: "deploy",
  display_name: "Deploy bot",
  department: null,
  title: null,
  privilege_level: "service",
  status: "active",
  tags: [],
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-01T08:00:00Z",
};

const NO_ACTIVITY: ContextActivity = {
  open_alerts: 0,
  total_alerts: 0,
  open_incidents: 0,
  total_incidents: 0,
  last_seen_at: null,
  recent_alerts: [],
  incidents: [],
};

describe("Event explorer", () => {
  it("lists events with filters taken from the URL, and pages with a cursor", async () => {
    const api = mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/events": (call) =>
        call.url.searchParams.get("cursor")
          ? { body: { items: [event({ id: "ev-2", event_outcome: "success" })], next_cursor: null, limit: 50 } }
          : { body: { items: [event()], next_cursor: "c-2", limit: 50 } },
    });
    renderApp("/events?source_ip=203.0.113.45&range=7d");
    expect(await screen.findByText("from 203.0.113.45 (external)", { exact: false })).toBeInTheDocument();

    const first = api.callsTo("GET /api/events")[0].url.searchParams;
    expect(first.get("source_ip")).toBe("203.0.113.45");
    const span = Date.parse(first.get("to") as string) - Date.parse(first.get("from") as string);
    expect(span).toBe(7 * 24 * 3600 * 1000);
    expect(screen.getByLabelText("Source address")).toHaveValue("203.0.113.45");

    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    expect(await screen.findByRole("link", { name: "authentication/logon success" })).toBeInTheDocument();
    expect(api.callsTo("GET /api/events")[1].url.searchParams.get("cursor")).toBe("c-2");
    expect(screen.getByRole("button", { name: "Older" })).toBeDisabled();

    // A new filter starts again from the newest events.
    fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "failure" } });
    await waitFor(() => expect(api.callsTo("GET /api/events")).toHaveLength(3));
    const third = api.callsTo("GET /api/events")[2].url.searchParams;
    expect(third.get("outcome")).toBe("failure");
    expect(third.get("cursor")).toBeNull();
  });

  it("shows an event with its raw record as text and the alerts citing it", async () => {
    const detail: EventDetail = {
      ...event(),
      raw: {
        id: "raw-1",
        batch_id: "b-1",
        received_at: "2026-09-27T09:00:02Z",
        parse_status: "parsed",
        parse_detail: null,
        size_bytes: 80,
        text: "Sep 27 09:00:00 web-01 sshd[1]: Failed password for root <img src=x onerror=alert(1)>",
        truncated: false,
        simulated: false,
      },
      source_name: "web-01 auth.log",
      alerts: [{ id: "a-1", title: "Repeated failed logons", status: "NEW", priority_band: "high" }],
    };
    mockApi({ ...signedInAs("VIEWER"), "GET /api/events/ev-1": { body: detail } });
    renderApp("/events/ev-1");
    expect(await screen.findByText(/onerror=alert\(1\)/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull(); // log text is never rendered as HTML
    expect(screen.getByRole("link", { name: "Repeated failed logons" })).toHaveAttribute("href", "/alerts/a-1");
    expect(screen.getByRole("link", { name: "web-01 (high)" })).toHaveAttribute("href", "/assets/as-1");
  });
});

describe("Assets and identities", () => {
  it("lists assets with their open alerts and last event", async () => {
    mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/assets": page([{ ...ASSET, open_alerts: 3, last_seen_at: "2026-09-27T09:00:00Z" }]),
    });
    renderApp("/assets");
    const row = (await screen.findByRole("link", { name: "web-01" })).closest("tr") as HTMLElement;
    expect(row).toHaveTextContent("3");
    expect(row).toHaveTextContent("2026-09-27 09:00:00");
    // Viewers see no admin controls.
    expect(screen.queryByRole("button", { name: "New asset" })).not.toBeInTheDocument();
  });

  it("lets an admin register an asset", async () => {
    const api = mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/assets": page([]),
      "POST /api/assets": { status: 201, body: ASSET },
      "GET /api/assets/as-1": { body: ASSET },
      "GET /api/assets/as-1/activity": { body: NO_ACTIVITY },
    });
    renderApp("/assets");
    fireEvent.click(await screen.findByRole("button", { name: "New asset" }));
    const form = screen.getByRole("form", { name: "Add asset" });
    fireEvent.change(within(form).getByLabelText("Hostname"), { target: { value: "web-01" } });
    fireEvent.change(within(form).getByLabelText("Criticality"), { target: { value: "high" } });
    fireEvent.change(within(form).getByLabelText("IP addresses"), { target: { value: "10.0.0.5, 10.0.0.6" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add asset" }));

    expect(await screen.findByRole("heading", { name: "web-01" })).toBeInTheDocument();
    expect(api.callsTo("POST /api/assets")[0].body).toEqual({
      hostname: "web-01",
      asset_type: "server",
      environment: "production",
      criticality: "high",
      ip_addresses: ["10.0.0.5", "10.0.0.6"],
      tags: [],
    });
  });

  it("sends only the changed fields when an admin edits, and shows API errors", async () => {
    const api = mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/assets/as-1": { body: ASSET },
      "GET /api/assets/as-1/activity": { body: NO_ACTIVITY },
      "PATCH /api/assets/as-1": {
        status: 422,
        body: { error: { code: "validation_error", message: "owner is too long", request_id: "r" } },
      },
    });
    renderApp("/assets/as-1");
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const form = screen.getByRole("form", { name: "Save changes" });
    expect(within(form).queryByLabelText("Hostname")).not.toBeInTheDocument(); // fixed identity
    fireEvent.change(within(form).getByLabelText("Owner"), { target: { value: "" } });
    fireEvent.change(within(form).getByLabelText("Status"), { target: { value: "retired" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save changes" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("owner is too long");
    expect(api.callsTo("PATCH /api/assets/as-1")[0].body).toEqual({ owner: null, status: "retired" });
  });

  it("shows an identity's alerts and incidents, read-only for a viewer", async () => {
    mockApi({
      ...signedInAs("VIEWER"),
      "GET /api/identities/id-1": { body: IDENTITY },
      "GET /api/identities/id-1/activity": {
        body: { ...NO_ACTIVITY, open_alerts: 2, total_alerts: 5, last_seen_at: "2026-09-27T09:00:00Z" },
      },
    });
    renderApp("/identities/id-1");
    expect(await screen.findByText("2 of 5")).toBeInTheDocument();
    expect(screen.getByText("No incidents involve it.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Events by this account" })).toHaveAttribute(
      "href",
      "/events?username=deploy&range=7d",
    );
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
  });

  it("filters identities by privilege level through the URL", async () => {
    const api = mockApi({
      ...signedInAs("ANALYST"),
      "GET /api/identities": page([{ ...IDENTITY, open_alerts: 0, last_seen_at: null }]),
    });
    renderApp("/identities");
    await screen.findByRole("link", { name: "deploy" });
    fireEvent.change(screen.getByLabelText("Privilege level"), { target: { value: "privileged" } });
    await waitFor(() => expect(api.callsTo("GET /api/identities")).toHaveLength(2));
    const query = api.callsTo("GET /api/identities")[1].url.searchParams;
    expect(query.get("privilege_level")).toBe("privileged");
    expect(query.get("status")).toBe("active");
  });
});
