# MITRE ATT&CK mapping

> Status: **DESIGN (Phase 1)**. Reference data and mapping: Phase 6/8. Coverage view: Phase 11.

## Rules for mapping

- Map a rule only to techniques whose description matches what the rule actually observes. If
  the rule cannot tell sub-techniques apart, map the parent.
- Every mapping stores `technique_id`, `technique_name`, `tactic(s)` and a `reason` written for
  that rule.
- The reference data is a checked-in file with the **pinned ATT&CK version**. The app refuses
  to start if a rule references a technique that is not in it. Updating the version is a
  deliberate change reviewed against the MITRE changelog.
- The UI says **"Implemented coverage"** and shows only mapped techniques. It never shows a
  full ATT&CK matrix with implied gaps or implied completeness.

## Verified mappings (attack.mitre.org, checked 2026-09-25, ATT&CK v19.2)

| Rule | Technique | Name | Tactic(s) | Reason |
|---|---|---|---|---|
| AUTH-001 | T1110.001 | Brute Force: Password Guessing | Credential Access | Repeated failed password attempts against one account from one source |
| AUTH-002 | T1110 | Brute Force | Credential Access | The failures that preceded the success. The parent is used because the rule does not know whether it was guessing, spraying or stuffing |
| AUTH-002 | T1078 | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | The success means a working credential was used |
| AUTH-003 | T1110.003 | Brute Force: Password Spraying | Credential Access | One source, many accounts, failed logons in a short window |
| PRIV-001 | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation | Uses sudo to obtain a root shell, or attempts sudo without being allowed |
| ACCT-001 | T1136.001 | Create Account: Local Account | Persistence | A local account is created (useradd / 4720) |
| ACCT-001 | T1098.007 | Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | The new account is added to a privileged group (usermod -aG sudo / 4732 Administrators) |
| AUTH-004 | T1078 | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | A valid credential used from a source never seen for that user; possible misuse of a legitimate account |
| PROC-001 (encoded PowerShell) | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | PowerShell execution |
| PROC-001 (encoded PowerShell) | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Stealth | Base64 `-EncodedCommand` hides the command text |
| PROC-001 (download piped to shell) | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | Output of curl/wget run by sh/bash |
| PROC-001 (download piped to shell, certutil) | T1105 | Ingress Tool Transfer | Command and Control | Downloads content onto the host with curl/wget/certutil |
| PROC-001 (`/dev/tcp` shell) | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | Interactive shell redirected over a network socket |
| NET-001 | T1046 | Network Service Discovery | Discovery | One host probing many ports/hosts in a short window |

Notes from checking the source (things memory alone would have got wrong):
- ATT&CK **v19 renamed the "Defense Evasion" tactic (TA0005) to "Stealth"**. The table uses the
  current name.
- **T1548.003** now lists only **Privilege Escalation** as its tactic.
- **T1098.007** (Additional Local or Domain Groups) exists and explicitly names
  `usermod` and the sudoers/Administrators groups, so it fits ACCT-001 better than the T1098
  parent.

The tactic names shown for T1078 come from the technique page. The re-check when the
reference file is built in Phase 6 must confirm the full tactic list for every row.

## Coverage view (Phase 11)

For each mapped technique: rules, enabled/disabled, trigger count, last triggered, and
false-positive count. Tactics are grouped in ATT&CK order. The view is labelled
"Implemented coverage: N techniques across M tactics mapped by SentinelX's own rules".
