import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { Coverage, CoverageTechnique } from "../src/types/inventory";
import { ruleCount } from "../src/pages/CoveragePage";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

const TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Stealth",
  "Defense Impairment",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

function technique(overrides: Partial<CoverageTechnique>): CoverageTechnique {
  return {
    technique_id: "T1110.001",
    name: "Brute Force: Password Guessing",
    url: "https://attack.mitre.org/techniques/T1110/001/",
    tactics: ["Credential Access"],
    active: true,
    alerts: 3,
    last_triggered_at: "2026-09-30T10:00:00Z",
    rules: [
      {
        rule_id: "AUTH-001",
        name: "Repeated failed logons",
        category: "authentication",
        severity: "medium",
        enabled: true,
        indicator: null,
        reason: "Many guesses against one account.",
        alerts: 3,
        last_triggered_at: "2026-09-30T10:00:00Z",
      },
    ],
    ...overrides,
  };
}

const COVERAGE: Coverage = {
  label: "Implemented coverage",
  attack_version: "19.2",
  checked_on: "2026-09-25",
  days: 30,
  from: "2026-09-01T00:00:00Z",
  to: "2026-10-01T00:00:00Z",
  summary: {
    tactics_total: 15,
    tactics_covered: 1,
    techniques_covered: 1,
    rules_in_library: 2,
    rules_enabled: 1,
    categories: { authentication: 1 },
  },
  tactics: TACTICS.map((name, i) => ({
    id: `TA${String(i).padStart(4, "0")}`,
    name,
    url: `https://attack.mitre.org/tactics/TA${String(i).padStart(4, "0")}/`,
    techniques: name === "Credential Access" ? ["T1110.001"] : name === "Discovery" ? ["T1046"] : [],
    active: name === "Credential Access",
  })),
  techniques: [
    technique({}),
    technique({
      technique_id: "T1046",
      name: "Network Service Discovery",
      tactics: ["Discovery"],
      active: false,
      alerts: 0,
      last_triggered_at: null,
      rules: [
        {
          rule_id: "NET-001",
          name: "Port scan",
          category: "network",
          severity: "medium",
          enabled: false,
          indicator: null,
          reason: "Connections to many ports.",
          alerts: 0,
          last_triggered_at: null,
        },
      ],
    }),
  ],
};

describe("Implemented coverage", () => {
  it("counts rules, not mappings, when one rule maps through several indicators", () => {
    const base = technique({});
    const twice = technique({
      rules: [
        { ...base.rules[0], rule_id: "PROC-001", indicator: "certutil_download" },
        { ...base.rules[0], rule_id: "PROC-001", indicator: "download_pipe_shell" },
      ],
    });
    expect(ruleCount(base)).toBe("1 rule");
    expect(ruleCount(twice)).toBe("1 rule (2 indicators)");
  });

  it("labels the view, shows every tactic in order and gaps as gaps", async () => {
    mockApi({ ...signedInAs("VIEWER"), "GET /api/mitre/coverage": { body: COVERAGE } });
    renderApp("/coverage");
    expect(await screen.findByRole("heading", { name: "Implemented coverage" })).toBeInTheDocument();
    expect(screen.getByText(/not a\s+claim of complete ATT&CK coverage/)).toBeInTheDocument();
    const tactics = within(screen.getByRole("list", { name: "ATT&CK tactics" })).getAllByRole("listitem");
    const names = tactics.filter((t) => t.parentElement?.getAttribute("aria-label") === "ATT&CK tactics");
    expect(names).toHaveLength(15);
    expect(names[0]).toHaveTextContent("Reconnaissance");
    expect(names[13]).toHaveTextContent("ExfiltrationTA0013No SentinelX rule");
    expect(screen.getByText("1 / 15")).toBeInTheDocument();
    // A technique whose only rule is disabled is shown, but not as covered.
    expect(screen.getByRole("button", { name: /T1046 Network Service Discovery/ })).toHaveTextContent(
      "rules disabled",
    );
  });

  it("opens a technique with its rules, severity, trigger count and last trigger", async () => {
    const api = mockApi({ ...signedInAs("VIEWER"), "GET /api/mitre/coverage": { body: COVERAGE } });
    renderApp("/coverage");
    fireEvent.click(await screen.findByRole("button", { name: /T1110.001/ }));
    const detail = screen.getByRole("heading", { name: "T1110.001 Brute Force: Password Guessing" })
      .parentElement as HTMLElement;
    expect(within(detail).getByRole("link", { name: /AUTH-001 Repeated failed logons/ })).toHaveAttribute(
      "href",
      "/detections/AUTH-001",
    );
    expect(detail).toHaveTextContent("severity: medium");
    expect(detail).toHaveTextContent("3 alerts in the period · last triggered 2026-09-30 10:00:00 UTC");
    fireEvent.change(screen.getByLabelText("Alert counts for"), { target: { value: "7" } });
    await screen.findByRole("heading", { name: "Implemented coverage" });
    expect(api.callsTo("GET /api/mitre/coverage").at(-1)!.url.searchParams.get("days")).toBe("7");
  });
});
