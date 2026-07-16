# Endpoint Threat Detection Lab — Wazuh SIEM + Sysmon + Atomic Red Team

A home-lab project simulating adversary behaviour on a Windows endpoint and validating
that a self-hosted SIEM correctly detects it — built to practice practical detection
engineering rather than just theory.

## Overview

Security tools are only as good as the telemetry feeding them and the rules parsing
that telemetry. Rather than just reading about SOC workflows, I built one:

1. Deployed **Wazuh** (open-source SIEM/XDR) as a manager + agent.
2. Installed **Sysmon** on a Windows endpoint for high-fidelity process/network telemetry.
3. Used **Atomic Red Team** to safely simulate a real MITRE ATT&CK technique on the endpoint.
4. Verified in Wazuh that the simulated attacker activity was collected, indexed, and
   visible for investigation.

This mirrors the "purple team" loop used in real SOCs: simulate → detect → validate → tune.

## Architecture

```
 Windows 10/11 Endpoint
 ┌─────────────────────────────┐
 │ Atomic Red Team (simulator) │  → executes real ATT&CK technique procedures
 │ Sysmon (telemetry sensor)   │  → logs Process Create, network, registry, etc.
 │ Wazuh Agent                 │  → forwards Windows Event Log + Sysmon channel
 └───────────────┬─────────────┘
                 │ encrypted agent-manager protocol
                 ▼
 ┌─────────────────────────────┐
 │ Wazuh Manager                │  → rule engine, decoders, rootcheck, SCA
 │ Wazuh Indexer (OpenSearch)   │  → stores/searches events
 │ Wazuh Dashboard (Kibana-like)│  → alerts, Discover, agent health
 └─────────────────────────────┘
```

## Components & Configuration

**Sysmon** — configured to log Event ID 1 (Process Create) with full command-line,
parent process, and hash data, giving far more detail than default Windows auditing.

**Wazuh agent (`ossec.conf`)** — configured to:
- Ingest the Sysmon `Operational` event channel (`eventchannel` log format)
- Ingest active-response logs for visibility into automated actions
- Run **rootcheck** (Windows application/malware inventory checks)
- Run **SCA (Security Configuration Assessment)** on a 12-hour interval to catch
  configuration drift against hardening baselines

**Atomic Red Team** — used `Invoke-AtomicTest` to execute **T1518.001 – Security
Software Discovery**, a real-world reconnaissance technique adversaries use post-
compromise to enumerate firewall state, AV, and EDR products before deciding how to
proceed (e.g. whether to attempt evasion). The test enumerated Windows Firewall
profile settings (domain/private/public) via `netsh advfirewall`-equivalent calls.

## Detection Results

After running the atomic test, the Wazuh Discover view showed the technique's activity
landing in the SIEM within the ingestion window — 694 hits captured over the prior 24
hours, including a logged execution of `sdbinst.exe` (Apply Compatibility Database).
That binary is worth flagging on its own merits: it's a legitimate Windows utility but
is also a documented technique for application-shim-based persistence
(MITRE ATT&CK **T1546.011**), so seeing it fire in the timeline is a good real-world
example of why analysts triage "living-off-the-land" binaries rather than ignoring them.

The Wazuh Overview dashboard confirmed the pipeline was healthy end-to-end:

| Metric | Result |
|---|---|
| Active agents | 1 active / 2 disconnected |
| Critical alerts (last 24h) | 26 (rule level ≥ 15) |
| High severity | 11 (rule level 12–14) |
| Medium severity | 94 (rule level 7–11) |
| Low severity | 369 (rule level 0–6) |

## What This Demonstrates

- **Telemetry engineering** — configuring Sysmon and Wazuh agents to capture the right
  data instead of relying on default, low-fidelity Windows logging.
- **Adversary emulation** — using an ATT&CK-mapped framework (Atomic Red Team) to
  generate realistic attacker behaviour instead of synthetic test data.
- **Detection validation** — closing the loop by confirming simulated activity is
  actually visible and searchable in the SIEM, not just assuming the pipeline works.
- **Alert triage fundamentals** — reading Wazuh rule severity levels and recognising
  dual-use binaries (like `sdbinst.exe`) that warrant investigation even when they
  appear "normal."

## Possible Next Steps

- Write a **custom Wazuh detection rule** specifically for `sdbinst.exe` shim database
  installation to reduce reliance on generic Sysmon decoders.
- Expand testing to a broader ATT&CK technique set (e.g. T1055 process injection,
  T1003 credential dumping) to build a small detection coverage matrix.
- Add **Wazuh active response** to automatically isolate or kill processes matching
  high-confidence malicious indicators.
- Map completed detections against the **MITRE ATT&CK Navigator** to visualise
  coverage gaps.

## Tools Used

`Wazuh` · `Sysmon` · `Atomic Red Team` · `Windows Event Viewer` · `MITRE ATT&CK`

## Screenshots

- `ossec-conf.png` — Wazuh agent configuration (Sysmon ingestion, rootcheck, SCA)
- `sysmon-eventviewer.png` — Sysmon Event ID 1 process creation logging
- `atomic-test-execution.png` — Atomic Red Team executing T1518.001
- `wazuh-discover.png` — Simulated activity indexed and searchable in Wazuh
- `wazuh-overview.png` — Dashboard: agent health + 24h alert severity breakdown
- `wazuh-login.png` — Wazuh platform login screen

---
*Built as a personal/final-year detection engineering lab. No production or third-party
systems were involved — all testing was performed on an isolated local VM environment.*
