import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { filterFromRow } from "../src/components/hunt";
import { huntUrl, parseHunt, pivotUrl } from "../src/services/hunt";
import type { HuntFields, HuntResult, SavedHunt, TemplateInfo, TemplateResult } from "../src/types/hunt";
import type { EventRecord } from "../src/types/inventory";
import { mockApi, signedInAs, type Routes } from "./mockApi";
import { renderApp } from "./renderApp";

const FIELDS: HuntFields = {
  fields: [
    { field: "event_outcome", kind: "text", operators: ["eq", "ne", "in", "not_in", "contains", "startswith", "endswith", "exists"] },
    { field: "username", kind: "text", operators: ["eq", "ne", "in", "not_in", "contains", "startswith", "endswith", "exists"] },
    { field: "source_ip", kind: "ip", operators: ["eq", "ne", "in", "not_in", "cidr", "exists"] },
    { field: "destination_port", kind: "number", operators: ["eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"] },
  ],
  attribute_operators: ["eq", "ne", "contains", "exists"],
  max_filters: 20,
  max_range_days: 31,
};

function event(overrides: Partial<EventRecord> = {}): EventRecord {
  return {
    id: "ev-1",
    raw_event_id: "raw-1",
    source_id: "src-1",
    source_type: "linux_auth",
    timestamp: "2026-09-30T10:00:39Z",
    ingested_at: "2026-09-30T10:00:40Z",
    host: "web-01",
    host_ip: null,
    event_category: "authentication",
    event_action: "logon",
    event_outcome: "success",
    username: "root",
    user_domain: null,
    target_username: null,
    source_ip: "203.0.113.45",
    source_port: 50999,
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
    asset_id: null,
    asset_criticality: null,
    identity_id: null,
    identity_privileged: null,
    simulated: false,
    ...overrides,
  };
}

function result(items: EventRecord[], overrides: Partial<HuntResult> = {}): HuntResult {
  return {
    items,
    next_cursor: null,
    total: items.length,
    total_capped: false,
    from: "2026-09-29T12:00:00Z",
    to: "2026-09-30T12:00:00Z",
    limit: 50,
    ...overrides,
  };
}

const TEMPLATES: TemplateInfo[] = [
  {
    id: "success_after_failures",
    name: "Successful logon after repeated failures",
    question: "Successful logons preceded by at least N failed logons within M minutes.",
    technique: "T1110",
    mirrors_rule: "AUTH-002",
    params: [
      { name: "min_failures", description: "Failed logons before it", default: 3, minimum: 1, maximum: 1000 },
      { name: "within_minutes", description: "Looking back from it", default: 10, minimum: 1, maximum: 1440 },
    ],
    columns: [
      { key: "timestamp", label: "Successful logon", kind: "time" },
      { key: "username", label: "Account", kind: "user" },
      { key: "source_ip", label: "Source", kind: "ip" },
      { key: "failures", label: "Failures before", kind: "number" },
      { key: "event_id", label: "Event", kind: "event" },
    ],
  },
];

function routes(extra: Routes = {}): Routes {
  return {
    "GET /api/hunt/fields": { body: FIELDS },
    "GET /api/hunt/templates": { body: TEMPLATES },
    "GET /api/hunt/saved": { body: [] },
    ...extra,
  };
}

const SUCCESSFUL_LOGONS = huntUrl({
  kind: "query",
  query: {
    time_range: { last: "24h" },
    filters: [
      { field: "source_ip", op: "eq", value: "203.0.113.45" },
      { field: "event_outcome", op: "eq", value: "success" },
    ],
  },
});

describe("Threat hunting", () => {
  it("keeps the whole hunt in the URL, and ignores a broken link", () => {
    const url = SUCCESSFUL_LOGONS;
    const parsed = parseHunt(new URL(url, "http://x").searchParams.get("q"));
    expect(parsed?.kind).toBe("query");
    expect(parseHunt("{not json")).toBeNull();
    expect(parseHunt('{"kind":"sql"}')).toBeNull();
    // A pivot around an activity covers it with an hour either side.
    const pivot = parseHunt(
      new URL(pivotUrl([{ field: "host", op: "eq", value: "web-01" }], { from: "2026-09-30T10:00:00Z", to: "2026-09-30T10:05:00Z" }), "http://x").searchParams.get("q"),
    );
    expect(pivot).toEqual({
      kind: "query",
      query: {
        time_range: { from: "2026-09-30T09:00:00.000Z", to: "2026-09-30T11:05:00.000Z" },
        filters: [{ field: "host", op: "eq", value: "web-01" }],
      },
    });
  });

  it("runs the brief's example hunt from a link, and shows the matching events", async () => {
    const api = mockApi({
      ...signedInAs("VIEWER"),
      ...routes({ "POST /api/hunt/query": { body: result([event()]) } }),
    });
    renderApp(SUCCESSFUL_LOGONS);
    expect(await screen.findByText("matching event", { exact: false })).toHaveTextContent("1 matching event ·");
    expect(api.callsTo("POST /api/hunt/query")[0].body).toEqual({
      time_range: { last: "24h" },
      filters: [
        { field: "source_ip", op: "eq", value: "203.0.113.45" },
        { field: "event_outcome", op: "eq", value: "success" },
      ],
      limit: 50,
      cursor: null,
    });
    // The form shows the hunt it ran.
    const query = screen.getByRole("form", { name: "Hunt query" });
    expect(within(query).getByLabelText("Filter 1 value")).toHaveValue("203.0.113.45");
    expect(within(query).getByLabelText("Filter 2 field")).toHaveValue("event_outcome");
    // Viewers hunt but cannot save.
    expect(screen.queryByRole("form", { name: "Save this hunt" })).not.toBeInTheDocument();
  });

  it("builds a query with typed values and alert filters", async () => {
    const api = mockApi({
      ...signedInAs("ANALYST"),
      ...routes({ "POST /api/hunt/query": { body: result([]) } }),
    });
    renderApp("/hunt");
    const form = await screen.findByRole("form", { name: "Hunt query" });
    fireEvent.click(within(form).getByRole("button", { name: "Add filter" }));
    fireEvent.change(within(form).getByLabelText("Filter 1 operator"), { target: { value: "cidr" } });
    fireEvent.change(within(form).getByLabelText("Filter 1 value"), { target: { value: "10.0.0.0/8" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add filter" }));
    fireEvent.change(within(form).getByLabelText("Filter 2 field"), { target: { value: "destination_port" } });
    fireEvent.change(within(form).getByLabelText("Filter 2 operator"), { target: { value: "in" } });
    fireEvent.change(within(form).getByLabelText("Filter 2 value"), { target: { value: "22, 3389" } });
    fireEvent.change(within(form).getByLabelText("Time range"), { target: { value: "7d" } });
    fireEvent.change(within(form).getByLabelText("Detection rules"), { target: { value: "auth-002" } });
    fireEvent.click(within(form).getByLabelText("high"));
    fireEvent.click(within(form).getByRole("button", { name: "Run hunt" }));

    expect(await screen.findByText(/No events match/)).toBeInTheDocument();
    expect(api.callsTo("POST /api/hunt/query")[0].body).toEqual({
      time_range: { last: "7d" },
      filters: [
        { field: "source_ip", op: "cidr", value: "10.0.0.0/8" },
        { field: "destination_port", op: "in", value: [22, 3389] },
      ],
      alert: { rule_ids: ["AUTH-002"], severities: ["high"] },
      limit: 50,
      cursor: null,
    });
  });

  it("explains which filter the server refused", async () => {
    mockApi({
      ...signedInAs("VIEWER"),
      ...routes({
        "POST /api/hunt/query": {
          status: 422,
          body: {
            error: {
              code: "validation_error",
              message: "Request validation failed",
              request_id: "r-1",
              details: [{ loc: ["body", "filters", 0], msg: "Value error, 'x' is not an IP address", type: "value_error" }],
            },
          },
        },
      }),
    });
    renderApp(SUCCESSFUL_LOGONS);
    expect(await screen.findByRole("alert")).toHaveTextContent("Filter 1: 'x' is not an IP address");
  });

  it("pivots: a value in the results narrows or excludes, and pages with a cursor", async () => {
    const api = mockApi({
      ...signedInAs("VIEWER"),
      ...routes({
        "POST /api/hunt/query": (call) => {
          const body = call.body as { cursor: string | null; filters: unknown[] };
          if (body.cursor) return { body: result([event({ id: "ev-2", username: "admin" })], { total: 2 }) };
          return { body: result([event()], { total: 2, next_cursor: "c-2" }) };
        },
      }),
    });
    renderApp(SUCCESSFUL_LOGONS);
    expect(await screen.findByText("matching events", { exact: false })).toHaveTextContent("2 matching events");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByRole("button", { name: "Pivot on username admin" })).toBeInTheDocument();
    expect((api.callsTo("POST /api/hunt/query")[1].body as { cursor: string }).cursor).toBe("c-2");

    fireEvent.click(screen.getByRole("button", { name: "Pivot on username admin" }));
    expect(screen.getByRole("menuitem", { name: /New hunt on this username/ })).toHaveAttribute(
      "href",
      expect.stringContaining("%22username%22"),
    );
    fireEvent.click(screen.getByRole("menuitem", { name: "Exclude this username" }));
    await waitFor(() => expect(api.callsTo("POST /api/hunt/query")).toHaveLength(3));
    const third = api.callsTo("POST /api/hunt/query")[2].body as { filters: unknown[]; cursor: unknown };
    expect(third.filters).toContainEqual({ field: "username", op: "ne", value: "admin" });
    expect(third.cursor).toBeNull(); // a changed hunt starts again from the first page
  });

  it("runs a template with its parameters and links each result row", async () => {
    const rows: TemplateResult = {
      template_id: "success_after_failures",
      columns: TEMPLATES[0].columns,
      rows: [{ timestamp: "2026-09-30T10:00:39Z", username: "root", source_ip: "203.0.113.45", failures: 12, event_id: "ev-1" }],
      truncated: false,
      from: "2026-09-23T12:00:00Z",
      to: "2026-09-30T12:00:00Z",
    };
    const api = mockApi({
      ...signedInAs("VIEWER"),
      ...routes({ "POST /api/hunt/templates/success_after_failures/run": { body: rows } }),
    });
    renderApp("/hunt");
    fireEvent.click(await screen.findByRole("tab", { name: "Templates" }));
    const form = await screen.findByRole("form", { name: "Hunt template" });
    expect(within(form).getByText(/mirrors rule AUTH-002/)).toBeInTheDocument();
    fireEvent.change(within(form).getByLabelText("Failed logons before it"), { target: { value: "10" } });
    fireEvent.click(within(form).getByRole("button", { name: "Run template" }));

    expect(await screen.findByText("12")).toBeInTheDocument();
    expect(api.callsTo("POST /api/hunt/templates/success_after_failures/run")[0].body).toEqual({
      params: { min_failures: 10, within_minutes: 10 },
      time_range: { last: "7d" },
    });
    expect(screen.getByRole("link", { name: "Open event" })).toHaveAttribute("href", "/events/ev-1");
    expect(screen.getByRole("button", { name: "Pivot on source_ip 203.0.113.45" })).toBeInTheDocument();
  });

  it("saves, shares and deletes a hunt (analysts), and lists others' shared hunts", async () => {
    const mine: SavedHunt = {
      id: "h-1",
      name: "Outside logons",
      description: null,
      kind: "query",
      definition: parseHunt(new URL(SUCCESSFUL_LOGONS, "http://x").searchParams.get("q"))!,
      shared: false,
      owner_id: "user-analyst",
      owner_email: "analyst@example.com",
      is_owner: true,
      valid: true,
      problem: null,
      created_at: "2026-09-30T12:00:00Z",
      updated_at: "2026-09-30T12:00:00Z",
    };
    const theirs: SavedHunt = { ...mine, id: "h-2", name: "Team hunt", shared: true, is_owner: false, owner_email: "other@example.com" };
    const broken: SavedHunt = { ...mine, id: "h-3", name: "Old hunt", valid: false, problem: "This saved hunt no longer matches the hunt format and cannot be run." };
    const api = mockApi({
      ...signedInAs("ANALYST"),
      ...routes({
        "POST /api/hunt/query": { body: result([]) },
        "GET /api/hunt/saved": { body: [mine, theirs, broken] },
        "POST /api/hunt/saved": { status: 201, body: mine },
        "PATCH /api/hunt/saved/h-1": { body: { ...mine, shared: true } },
        "DELETE /api/hunt/saved/h-1": { status: 204 },
      }),
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderApp(SUCCESSFUL_LOGONS);
    const form = await screen.findByRole("form", { name: "Save this hunt" });
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "Outside logons" } });
    fireEvent.click(within(form).getByLabelText(/Share with everyone/));
    fireEvent.click(within(form).getByRole("button", { name: "Save hunt" }));
    await waitFor(() => expect(api.callsTo("POST /api/hunt/saved")).toHaveLength(1));
    expect(api.callsTo("POST /api/hunt/saved")[0].body).toEqual({
      name: "Outside logons",
      description: null,
      definition: mine.definition,
      shared: true,
    });

    expect(screen.getByText("by other@example.com")).toBeInTheDocument();
    expect(screen.getByText(/no longer matches/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Old hunt" })).not.toBeInTheDocument(); // not runnable
    expect(screen.getByRole("link", { name: "Team hunt" })).toHaveAttribute("href", huntUrl(theirs.definition));

    fireEvent.click(screen.getAllByRole("button", { name: "Share with everyone" })[0]);
    await waitFor(() => expect(api.callsTo("PATCH /api/hunt/saved/h-1")[0].body).toEqual({ shared: true }));
    fireEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
    await waitFor(() => expect(api.callsTo("DELETE /api/hunt/saved/h-1")).toHaveLength(1));
  });
});

describe("Hunt builder values (Phase 14)", () => {
  const row = (field: string, op: string, text: string, attribute = "") =>
    filterFromRow({ field, attribute, op: op as never, text }, [
      ...FIELDS.fields,
      { field: "is_admin", kind: "boolean", operators: ["eq", "exists"] },
    ]);

  it("turns form text into the typed values the API expects", () => {
    expect(row("destination_port", "eq", " 22 ")).toEqual({ field: "destination_port", op: "eq", value: 22 });
    // A number field with text that is not a number is sent as typed: the server explains.
    expect(row("destination_port", "eq", "ssh")).toEqual({ field: "destination_port", op: "eq", value: "ssh" });
    expect(row("destination_port", "in", "22, ,3389,")).toEqual({
      field: "destination_port",
      op: "in",
      value: [22, 3389],
    });
    expect(row("username", "not_in", " root , admin ")).toEqual({
      field: "username",
      op: "not_in",
      value: ["root", "admin"],
    });
    expect(row("is_admin", "eq", "false")).toEqual({ field: "is_admin", op: "eq", value: false });
    expect(row("username", "exists", "true")).toEqual({ field: "username", op: "exists", value: true });
    expect(row("username", "exists", "false")).toEqual({ field: "username", op: "exists", value: false });
    expect(row("attributes", "eq", "10", " logon_type ")).toEqual({
      field: "attributes.logon_type",
      op: "eq",
      value: "10", // attribute values have no declared type: kept as text
    });
  });

  it("maps every kind of server validation message to the part of the form it is about", async () => {
    mockApi({
      ...signedInAs("ANALYST"),
      ...routes({
        "POST /api/hunt/query": {
          status: 422,
          body: {
            error: {
              code: "validation_error",
              message: "Invalid request",
              request_id: null,
              details: [
                { loc: ["body", "time_range", "from"], msg: "Value error, the range is longer than 31 days", type: "value_error" },
                { loc: ["body", "alert", "status"], msg: "unknown status", type: "value_error" },
                { loc: ["body", "limit"], msg: "too large", type: "value_error" },
              ],
            },
          },
        },
      }),
    });
    renderApp("/hunt");
    fireEvent.click(await screen.findByRole("button", { name: "Run hunt" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Time range: the range is longer than 31 days");
    expect(alert).toHaveTextContent("Alert filters: unknown status");
    expect(alert).toHaveTextContent("limit: too large");
  });
});
