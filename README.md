# Threat Hunting Labs

A curated collection of threat hunting and detection queries across multiple platforms and formats.

---

## Overview

This repository focuses on identifying adversary behavior through endpoint, log, and telemetry analysis. It includes practical detection logic built using different query languages and rule formats such as KQL, Sigma, SPL, and others.

The goal is to simulate real-world attack techniques and translate them into actionable detections.

---

## Coverage

* Process and command-line activity
* Living-off-the-Land binaries (LOLBins)
* Persistence and privilege escalation
* Defense evasion techniques
* Network and C2 indicators
* Anomaly-based hunting

*Coverage is continuously evolving as new techniques and detections are added.*

---

## Query Types

* KQL (Microsoft Defender / Sentinel)
* Sigma rules
* SPL (Splunk)
* Wazuh / OSSEC rules
* Other platform-specific detections

---

## Example

```kql
logs_edr_labs_CL
| where event_action_s == "process-start"
| where process_name_s =~ "regsvr32.exe"
| project timestamp, user_name_s, process_name_s,
          process_parent_name_s, body_s
| sort by timestamp asc
```

---

## Structure

```
/Execution
/Persistence
/DefenseEvasion
/Discovery
/CredentialAccess
/CommandAndControl
```

Queries are organized by technique and may include mappings to MITRE ATT&CK where relevant.

---

## Goal

Develop practical detection engineering and threat hunting skills by working with real-world techniques across different platforms.

---

## Notes

* Queries are tested in lab environments
* Field names and schemas may vary by platform
* Designed for both learning and practical detection use cases
