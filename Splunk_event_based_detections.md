# Splunk Enterprise Security 8.0 — Event-Based Detection Creation: Complete Reference Guide

> **Document Purpose:** A fully self-contained reference for security engineers building, tuning, and managing detections in Splunk Enterprise Security 8.0. Primary depth on event-based detections; all other detection types covered for completeness.

---

## Table of Contents

1. [Detection Types Overview](#1-detection-types-overview)
   - 1.1 [Comparison of All Detection Types](#11-comparison-of-all-detection-types)
   - 1.2 [When to Choose Each Type](#12-when-to-choose-each-type)
2. [Event-Based Detection Deep Dive](#2-event-based-detection-deep-dive)
   - 2.1 [What Is an Event-Based Detection?](#21-what-is-an-event-based-detection)
   - 2.2 [Navigating to the Detection Creation UI](#22-navigating-to-the-detection-creation-ui)
3. [Event-Based Detection UI — Field-by-Field Reference](#3-event-based-detection-ui--field-by-field-reference)
   - 3.1 [Detection Name](#31-detection-name)
   - 3.2 [Description](#32-description)
   - 3.3 [Detection Search (SPL)](#33-detection-search-spl)
   - 3.4 [Earliest / Latest Time Range](#34-earliest--latest-time-range)
   - 3.5 [Scheduling — Run Every](#35-scheduling--run-every)
   - 3.6 [Cron Schedule (Custom)](#36-cron-schedule-custom)
   - 3.7 [Schedule Window](#37-schedule-window)
   - 3.8 [Schedule Priority](#38-schedule-priority)
   - 3.9 [Dispatch Earliest / Latest Offsets](#39-dispatch-earliest--latest-offsets)
   - 3.10 [Security Domain](#310-security-domain)
   - 3.11 [Severity / Urgency](#311-severity--urgency)
   - 3.12 [Default Owner](#312-default-owner)
   - 3.13 [Default Status](#313-default-status)
   - 3.14 [Next Steps](#314-next-steps)
   - 3.15 [Drilldown Name & Search](#315-drilldown-name--search)
   - 3.16 [Drilldown Earliest / Latest](#316-drilldown-earliest--latest)
   - 3.17 [Investigation Profile](#317-investigation-profile)
   - 3.18 [Throttling — Suppress Results](#318-throttling--suppress-results)
   - 3.19 [Suppress Fields](#319-suppress-fields)
   - 3.20 [Suppress Period](#320-suppress-period)
   - 3.21 [MITRE ATT&CK Technique IDs](#321-mitre-attck-technique-ids)
   - 3.22 [Kill Chain Phase(s)](#322-kill-chain-phases)
   - 3.23 [Asset / Identity Correlation](#323-asset--identity-correlation)
   - 3.24 [Annotations (Custom Key-Value Pairs)](#324-annotations-custom-key-value-pairs)
4. [Risk Scoring Configuration](#4-risk-scoring-configuration)
   - 4.1 [Enable Risk Scoring](#41-enable-risk-scoring)
   - 4.2 [Risk Object Field](#42-risk-object-field)
   - 4.3 [Risk Object Type](#43-risk-object-type)
   - 4.4 [Risk Score](#44-risk-score)
   - 4.5 [Risk Message](#45-risk-message)
   - 4.6 [Threat Object Field](#46-threat-object-field)
   - 4.7 [Threat Object Type](#47-threat-object-type)
   - 4.8 [Risk Score Modifier Rules](#48-risk-score-modifier-rules)
5. [Notable Event Settings](#5-notable-event-settings)
   - 5.1 [Notable Event Generation Toggle](#51-notable-event-generation-toggle)
   - 5.2 [Title Field](#52-title-field)
   - 5.3 [Description Field Mapping](#53-description-field-mapping)
   - 5.4 [Security Domain (Notable)](#54-security-domain-notable)
   - 5.5 [Urgency Mapping Logic](#55-urgency-mapping-logic)
   - 5.6 [Asset / Identity Lookup Fields](#56-asset--identity-lookup-fields)
6. [Adaptive Response Actions](#6-adaptive-response-actions)
   - 6.1 [Risk Modifier Action](#61-risk-modifier-action)
   - 6.2 [Notable Event Creation Action](#62-notable-event-creation-action)
   - 6.3 [Email Action](#63-email-action)
   - 6.4 [Run a Script Action](#64-run-a-script-action)
   - 6.5 [Webhook Action](#65-webhook-action)
   - 6.6 [PagerDuty / ServiceNow / SOAR Integrations](#66-pagerduty--servicenow--soar-integrations)
   - 6.7 [Threat Intelligence Action](#67-threat-intelligence-action)
   - 6.8 [ESCU Action Runner (Enterprise Content)](#68-escu-action-runner-enterprise-content)
7. [Threat Intelligence Integration](#7-threat-intelligence-integration)
   - 7.1 [TI Lookups and `threat_match`](#71-ti-lookups-and-threat_match)
   - 7.2 [Indicator Matching in SPL](#72-indicator-matching-in-spl)
   - 7.3 [TI-Driven Detection Patterns](#73-ti-driven-detection-patterns)
8. [Asset & Identity Correlation](#8-asset--identity-correlation)
   - 8.1 [How ES Enriches Events](#81-how-es-enriches-events)
   - 8.2 [Key Asset Fields](#82-key-asset-fields)
   - 8.3 [Key Identity Fields](#83-key-identity-fields)
   - 8.4 [Using Asset/Identity in SPL](#84-using-assetidentity-in-spl)
9. [Backend Configuration — savedsearches.conf](#9-backend-configuration--savedsearchesconf)
   - 9.1 [Core Stanza Structure](#91-core-stanza-structure)
   - 9.2 [Notable Event Stanza Parameters](#92-notable-event-stanza-parameters)
   - 9.3 [Risk Scoring Stanza Parameters](#93-risk-scoring-stanza-parameters)
   - 9.4 [Throttle / Suppression Parameters](#94-throttle--suppression-parameters)
   - 9.5 [Scheduling Parameters](#95-scheduling-parameters)
   - 9.6 [MITRE and Annotation Parameters](#96-mitre-and-annotation-parameters)
   - 9.7 [Full Annotated Example Stanza](#97-full-annotated-example-stanza)
10. [SPL Patterns for Event-Based Detections](#10-spl-patterns-for-event-based-detections)
    - 10.1 [Basic Threshold Detection](#101-basic-threshold-detection)
    - 10.2 [Field Comparison / Allowlist Detection](#102-field-comparison--allowlist-detection)
    - 10.3 [Sequence / Transaction Detection](#103-sequence--transaction-detection)
    - 10.4 [Rare / Anomaly Detection with stats](#104-rare--anomaly-detection-with-stats)
    - 10.5 [Threat Intel Matching Detection](#105-threat-intel-matching-detection)
    - 10.6 [Asset / Identity Enriched Detection](#106-asset--identity-enriched-detection)
    - 10.7 [Multi-Index Detection with union / append](#107-multi-index-detection-with-union--append)
    - 10.8 [Risk Notables Trigger Pattern](#108-risk-notables-trigger-pattern)
11. [Other Detection Types — Reference](#11-other-detection-types--reference)
    - 11.1 [Correlation Search](#111-correlation-search)
    - 11.2 [Risk-Based Alerting (RBA) Notable](#112-risk-based-alerting-rba-notable)
    - 11.3 [Anomaly Detection](#113-anomaly-detection)
    - 11.4 [TI-Based Detections](#114-ti-based-detections)
12. [Detection Tuning and Lifecycle](#12-detection-tuning-and-lifecycle)
    - 12.1 [Baselining and False Positive Reduction](#121-baselining-and-false-positive-reduction)
    - 12.2 [Using `makeresults` for Testing](#122-using-makeresults-for-testing)
    - 12.3 [Suppression Management in ES](#123-suppression-management-in-es)
    - 12.4 [Version Control via REST API](#124-version-control-via-rest-api)
13. [Permissions and Role-Based Access](#13-permissions-and-role-based-access)
14. [Glossary](#14-glossary)

---

## 1. Detection Types Overview

### 1.1 Comparison of All Detection Types

| Detection Type | Primary Mechanism | Output | Best For | ES Feature Set |
|---|---|---|---|---|
| **Event-Based Detection** | SPL search returning individual events or aggregated rows | Notable Events, Risk Events, or both | Direct event matching, threshold detection, threat intel correlation | Full — throttling, risk scoring, MITRE mapping, AR actions |
| **Correlation Search** (legacy) | SPL search scheduled via `savedsearches.conf` | Notable Events | Backward-compatible complex correlations; custom aggregation | Full, but no UI wizard; manual `conf` editing |
| **Risk-Based Alerting (RBA) Notable** | Aggregation of risk events over a risk object | Risk Notable (high-priority notable from risk score) | Reducing alert fatigue; multi-signal fusion | Requires Risk Index populated by other detections |
| **Anomaly Detection** | ML-based or statistical deviation models | Anomaly events fed to Notable or Risk | User/entity behavior baselines, outlier detection | MLTK integration; `anomalydetection` command |
| **TI-Based Detection** | Lookup match against threat intelligence feeds | Notable Events or Risk Events | IOC matching (IPs, domains, hashes, URLs) | TI framework; `threat_match` command; automatic feed refresh |

---

### 1.2 When to Choose Each Type

**Choose Event-Based Detection when:**
- You have a specific, deterministic condition that should fire on individual or aggregated events (e.g., "more than 10 failed logins in 5 minutes from the same source IP").
- You want full control over scheduling, throttling, risk scores, notable event output, and MITRE mapping through the ES UI wizard.
- You are building net-new detections aligned to ESCU (Enterprise Security Content Update) patterns.
- You need to correlate across CIM-normalized data models with asset/identity enrichment baked into the detection.
- You want a single pane of glass: one detection, configurable to produce both a notable event AND a risk event simultaneously.

**Choose Correlation Search (legacy) when:**
- You are migrating content from ES versions before 8.0 and the correlation search paradigm is already embedded in your content pipeline.
- Your logic is too complex for the ES UI wizard (e.g., requires subsearches with `join`, multi-level lookups) and you prefer direct `savedsearches.conf` manipulation.
- You need to use `| sendalert` with custom alert actions not exposed in the wizard.

**Choose RBA Notable when:**
- You have already built a library of risk-scoring event-based detections and want to aggregate risk across a common entity (user, host, IP) before firing a high-priority alert.
- You are operationalizing the Risk Index and want to reduce mean time-to-triage by surfacing correlated, entity-centric alerts rather than per-event noise.
- Your organization has defined risk thresholds (e.g., "fire a notable when a host accumulates >100 risk score in 24 hours").

**Choose Anomaly Detection when:**
- You lack specific IOCs or known-bad signatures and need to detect deviation from baseline behavior.
- You have sufficient historical data to train ML models (typically 2–4 weeks minimum).
- You are detecting insider threats, compromised credentials, or slow-and-low attacks that don't match threshold rules.

**Choose TI-Based Detection when:**
- You receive structured threat intelligence (STIX/TAXII, CSV, commercial feeds) and want automated IOC matching.
- You want the TI framework to handle feed refresh, deduplication, and expiry automatically.
- Your detections should automatically update as threat intel updates, without modifying SPL.

---

## 2. Event-Based Detection Deep Dive

### 2.1 What Is an Event-Based Detection?

An **event-based detection** in Splunk ES 8.0 is a scheduled SPL search that:

1. Runs on a defined schedule (interval or cron).
2. Searches across one or more indexes, data models, or lookups.
3. Produces result rows — each row can represent an individual raw event or an aggregated summary.
4. Optionally generates a **Notable Event** (written to `notable` index) for analyst triage.
5. Optionally generates a **Risk Event** (written to `risk` index) to contribute to Risk-Based Alerting.
6. Can trigger **Adaptive Response Actions** (email, webhook, SOAR, scripts).
7. Stores all configuration in `savedsearches.conf` under `$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/` (or a custom app).

**Architectural distinction from raw Splunk alerts:**
A standard Splunk saved search alert generates one alert per trigger. An ES event-based detection generates one **notable event per result row** (unless throttled), enriches each with asset/identity data, maps to MITRE ATT&CK, assigns urgency based on asset priority × detection severity, and feeds the Incident Review workflow — all as part of the detection's inherent configuration.

**The detection is stored as a saved search with ES-specific metadata.** Every option you configure in the UI maps directly to parameters in `savedsearches.conf` and ES-specific configuration files. Understanding this mapping is essential for programmatic deployment (e.g., GitOps, REST API deployment).

---

### 2.2 Navigating to the Detection Creation UI

**Path in ES 8.0:**
```
Splunk ES → Security Content → Detections → Create New Detection
```

Alternatively:
```
ES Menu → Configure → Content Management → Create New Content → Detection
```

When you select **Detection Type: Event**, the UI presents the event-based detection wizard. The wizard has the following logical sections, each mapped to a tab or expanded panel:

1. **General** — Name, Description, SPL, Time Range
2. **Schedule** — Frequency, Cron, Window, Priority
3. **Notable Event** — Toggle, Title, Urgency, Domain, Owner, Status, Next Steps, Drilldown
4. **Risk Score** — Toggle, Risk Object, Risk Score, Risk Message, Threat Object
5. **Response Actions** — Adaptive Response actions list
6. **Annotations** — MITRE ATT&CK, Kill Chain, Custom Key-Value Pairs
7. **Throttling** — Suppress fields and period

---

## 3. Event-Based Detection UI — Field-by-Field Reference

### 3.1 Detection Name

**What it controls:** The human-readable name displayed in Incident Review, Content Management, and all ES dashboards. Also becomes the saved search name in `savedsearches.conf`.

**Field type:** Free-text string, required.

**Naming conventions (recommended):**
```
[Source Technology] - [Behavior Description] - [Detection Type]
```
Example: `Windows - Multiple Failed Logons From Single Source - Rule`

**Options:** Free text. ES does not enforce naming patterns, but ESCU uses the convention above. Spaces are allowed; they are URL-encoded and converted to underscores in the internal stanza name.

**`savedsearches.conf` mapping:**
```ini
[Windows - Multiple Failed Logons From Single Source - Rule]
```
The stanza header IS the detection name.

**Use Cases:**
- Use a consistent naming schema across your content library to enable sorted filtering in Content Management.
- Including the source technology prefix (e.g., `Windows -`, `Linux -`, `AWS -`, `Okta -`) allows faceted filtering.
- Append `- Rule` for threshold/signature-based, `- Anomaly` for behavioral, `- TI` for threat-intel-based to distinguish detection logic type at a glance.

---

### 3.2 Description

**What it controls:** A prose description displayed in the detection's detail view, in notable events, and surfaced to analysts during triage. Should explain the detection's intent, data sources, and analyst guidance.

**Field type:** Multi-line free text, optional but strongly recommended.

**`savedsearches.conf` mapping:**
```ini
description = Detects multiple authentication failures from a single source IP against multiple accounts within a 5-minute window, which may indicate a password spray attack.
```

**Best Practice Content:**
A high-quality description contains:
1. **What** the detection fires on (the behavior).
2. **Why** it matters (the threat scenario).
3. **Data sources** required (e.g., Windows Security Event Log, `wineventlog` or `Authentication` data model).
4. **False positive scenarios** (e.g., "legitimate batch authentication from service accounts").
5. **Analyst action** (what to do when this fires).

**Use Cases:**
- Analysts opening a notable event in Incident Review see the description inline. A well-written description reduces mean time-to-triage significantly.
- ESCU descriptions follow a structured format including Splunk Threat Research attribution, references, and CVE/technique links.

---

### 3.3 Detection Search (SPL)

**What it controls:** The core SPL query that executes on schedule. Its results determine whether and how many notable/risk events are generated.

**Field type:** Multi-line SPL text editor with syntax highlighting in ES 8.0.

**Critical constraints:**
- The search must be **transforming** (end in a stats, table, or similar command that produces tabular results) OR return raw events — both are valid.
- Each **result row** generates one notable event (unless throttled).
- Fields in the result set become available for notable event title templating, risk object mapping, drilldown, and annotations.
- Time modifiers in the SPL (`earliest=`, `latest=`) are overridden by the **Earliest/Latest** scheduling fields — do not hardcode time ranges in the SPL itself.

**`savedsearches.conf` mapping:**
```ini
search = `datamodel("Authentication","Authentication")` | search Authentication.action="failure" \
| stats count as failure_count values(Authentication.user) as users by Authentication.src \
| where failure_count > 10
```

**SPL Structure Best Practices:**
```spl
`datamodel("Authentication","Authentication")`
| rename "Authentication.*" as "*"
| search action="failure"
| stats count as failure_count dc(user) as unique_users values(user) as user_list by src
| where failure_count >= 10 AND unique_users >= 3
| eval risk_score=60
| table src, failure_count, unique_users, user_list, risk_score
```

**Use Cases:**

| SPL Pattern | When to Use |
|---|---|
| `datamodel()` macro with CIM fields | Any detection that should work across heterogeneous data sources normalized to CIM |
| `index=* sourcetype=<specific>` | When targeting a specific, non-normalized data source |
| `| inputlookup` | Lookup-based detections (e.g., checking against a watchlist or allowlist) |
| `tstats` | High-performance summary-index or accelerated data model queries; best for high-volume environments |
| `| from datamodel:` | Alternative to `| tstats` for data model access in newer Splunk versions |

---

### 3.4 Earliest / Latest Time Range

**What it controls:** The time window the detection searches over on each execution. These values define how far back (`earliest`) and up to what point (`latest`) each scheduled run searches.

**Field type:** Splunk relative time modifier strings.

**Options for Earliest:**

| Value | Meaning | Use Case |
|---|---|---|
| `-5m` | Last 5 minutes | Near-real-time detection on high-frequency events |
| `-15m` | Last 15 minutes | Standard interval for most event-based detections |
| `-1h` | Last 1 hour | Detections with hourly scheduling |
| `-24h` | Last 24 hours | Daily-scheduled detections (e.g., "user created account yesterday") |
| `-7d` | Last 7 days | Weekly scheduled detections (e.g., "no login in 7 days but account active") |
| `@d` | Beginning of current day (midnight) | Day-boundary calculations |
| `-60m@h` | 60 minutes ago snapped to hour boundary | Avoiding time-boundary overlaps when running hourly |
| `rt` | Real-time (continuous) | Not recommended for event-based detections; use only with explicit approval due to resource overhead |

**Options for Latest:**

| Value | Meaning | Use Case |
|---|---|---|
| `now` | Current time of execution | Default; catches events up to run time |
| `-5m` | 5 minutes before now | Leaves an ingestion buffer to avoid missing late-arriving events |
| `@h` | Snap to current hour boundary | Clean hourly time window alignment |
| `+0s` | Same as `now` | Explicit "now" designation |

**`savedsearches.conf` mapping:**
```ini
dispatch.earliest_time = -15m
dispatch.latest_time = now
```

**Use Cases:**
- **Standard 5-minute rolling window:** Use `earliest=-5m`, `latest=now` with a 5-minute schedule — overlaps by design to prevent missing events at window edges.
- **Overlap buffer pattern (recommended):** Use `earliest=-20m`, `latest=now` with a 15-minute schedule — provides a 5-minute overlap buffer for late-arriving data without missing events.
- **24-hour daily detection:** Use `earliest=-24h@h`, `latest=@h` with a daily cron (`0 6 * * *`) — searches exactly the previous day's data aligned to hour boundaries.

---

### 3.5 Scheduling — Run Every

**What it controls:** The preset scheduling interval for the detection. Selecting a preset automatically populates the cron expression field.

**Field type:** Dropdown (preset intervals) + optional cron override.

**Options:**

| Preset Label | Cron Expression Generated | Use Case |
|---|---|---|
| `1 minute` | `*/1 * * * *` | Highest-frequency polling; use only for critical, narrow-scope detections — significant scheduler load |
| `5 minutes` | `*/5 * * * *` | Standard for near-real-time event detections; most ESCU rules use this |
| `10 minutes` | `*/10 * * * *` | Slightly reduced frequency for moderate-volume detections |
| `15 minutes` | `*/15 * * * *` | Common default; balances timeliness and scheduler load |
| `30 minutes` | `*/30 * * * *` | Useful for detections scanning wider time windows where 30-min latency is acceptable |
| `1 hour` | `0 * * * *` | Hourly aggregation patterns; endpoint detections, inventory checks |
| `2 hours` | `0 */2 * * *` | Lower-priority detections or high-cost searches |
| `4 hours` | `0 */4 * * *` | Quarterly-day checks; asset compliance, persistence mechanism sweeps |
| `6 hours` | `0 */6 * * *` | Semi-daily; configuration drift detection, account audit |
| `12 hours` | `0 */12 * * *` | Twice daily; threat hunting scheduled jobs |
| `24 hours` | `0 6 * * *` | Daily; best suited for behavioral patterns requiring full-day context |
| `Custom` | User-defined cron | Complex scheduling requirements (see Section 3.6) |

**`savedsearches.conf` mapping:**
```ini
cron_schedule = */5 * * * *
enableSched = 1
```

**Use Cases:**
- **Brute force / spray detections:** Use `5 minutes` with `earliest=-10m` to catch rapid bursts.
- **Persistence mechanism detections (scheduled tasks, services):** Use `1 hour` — these rarely change by the minute.
- **Data exfiltration detections (large outbound transfers):** Use `15 minutes` — gives enough aggregation time while remaining timely.
- **Compliance and audit detections:** Use `24 hours` — run overnight to summarize the day's activity.

---

### 3.6 Cron Schedule (Custom)

**What it controls:** Overrides the preset interval with a custom cron expression for precise scheduling requirements.

**Field type:** Standard 5-field cron string (`minute hour day month weekday`).

**Cron Field Reference:**

```
┌──────────── minute (0-59)
│ ┌────────── hour (0-23)
│ │ ┌──────── day of month (1-31)
│ │ │ ┌────── month (1-12)
│ │ │ │ ┌──── day of week (0-6, Sunday=0)
│ │ │ │ │
* * * * *
```

**Special Characters:**

| Character | Meaning | Example |
|---|---|---|
| `*` | Every unit | `* * * * *` = every minute |
| `*/n` | Every n units | `*/5 * * * *` = every 5 minutes |
| `n` | Specific value | `0 8 * * *` = 8:00 AM every day |
| `n,m` | List of values | `0 8,20 * * *` = 8 AM and 8 PM |
| `n-m` | Range | `0 8-18 * * *` = every hour 8 AM–6 PM |
| `n-m/s` | Range with step | `0 8-18/2 * * *` = every 2 hours between 8 and 18 |

**Common Custom Cron Examples:**

```bash
# Run at 6:00 AM every weekday (Mon-Fri)
0 6 * * 1-5

# Run at 2:30 AM on the 1st of every month
30 2 1 * *

# Run every 5 minutes during business hours (8 AM - 6 PM), weekdays only
*/5 8-18 * * 1-5

# Run at 11:55 PM daily (for end-of-day summary detections)
55 23 * * *

# Run every 15 minutes, offset by 7 minutes (e.g., to stagger from other detections)
7,22,37,52 * * * *

# Run on weekends only at midnight
0 0 * * 0,6

# Run at the top of every hour but only in Q4 (Oct, Nov, Dec)
0 * * 10-12 *
```

**`savedsearches.conf` mapping:**
```ini
cron_schedule = 7,22,37,52 * * * *
```

**Use Cases:**
- **Staggered scheduling:** If you have 50 detections all set to `*/5`, they may create scheduler storms. Offset by 1–2 minutes using custom cron (e.g., `1,6,11,16,21,26,31,36,41,46,51,56`).
- **Business-hours detection:** Some detections (e.g., "VPN login outside business hours") only make sense running during specific hours.
- **Monthly compliance checks:** Use `0 0 1 * *` to run first of each month.
- **Weekend-specific behavioral detection:** Account activity on weekends when office is closed.

---

### 3.7 Schedule Window

**What it controls:** Allows Splunk's scheduler to delay the detection's execution by up to N minutes after its scheduled time if the scheduler is under heavy load. Sacrifices exact timeliness for overall scheduler health.

**Field type:** Dropdown or integer (minutes).

**Options:**

| Value | Behavior | Use Case |
|---|---|---|
| `0` (Auto) | Splunk decides the window automatically based on scheduler load; default and recommended for most detections | General use; let the scheduler optimize |
| `1` | Allow up to 1-minute delay | Near-real-time detections where minimal latency matters but some flexibility is OK |
| `5` | Allow up to 5-minute delay | Standard detections that run every 5–15 minutes |
| `10` | Allow up to 10-minute delay | Hourly detections; accepting up to 10 min drift |
| `30` | Allow up to 30-minute delay | Daily/weekly detections where exact timing is not critical |
| `60` | Allow up to 1-hour delay | Overnight compliance/audit jobs; scheduler load resilience |
| Custom (integer) | Any integer minutes | Fine-tuned environments with specific SLA requirements |

**`savedsearches.conf` mapping:**
```ini
schedule_window = auto
# or
schedule_window = 5
```

**Use Cases:**
- **High-concurrency environments:** If you have 500+ scheduled searches, setting `schedule_window = 5` on non-critical detections significantly reduces scheduler contention and skipped searches.
- **Critical real-time detections:** Set `schedule_window = 0` to force execution at scheduled time — use sparingly as it increases scheduler pressure.
- **Large environment tuning:** Splunk recommends `auto` as the default; the scheduler uses search history to auto-calculate an appropriate window.

---

### 3.8 Schedule Priority

**What it controls:** Determines the relative priority of this detection in the search scheduler queue. Higher-priority detections are executed first when the scheduler has more searches than available slots.

**Field type:** Dropdown.

**Options:**

| Priority Level | Internal Value | Behavior | Use Case |
|---|---|---|---|
| `Default` | `default` | Standard scheduler priority; most detections should use this | General purpose event-based detections |
| `Higher` | `higher` | Elevated in the queue; runs before `default` priority searches | Detections for critical assets, high-severity threat scenarios |
| `Highest` | `highest` | Runs before all other non-`highest` searches; reserved for the most critical detections | Ransomware indicators, active breach scenarios, C2 communication detection |

**`savedsearches.conf` mapping:**
```ini
schedule_priority = default
# or
schedule_priority = higher
# or
schedule_priority = highest
```

**Important Notes:**
- Setting too many detections to `highest` defeats the purpose — prioritize only the top 5–10% of your detection library.
- Schedule priority interacts with `schedule_window`: a `highest` priority search with `schedule_window = 0` will always run on time but consumes dedicated scheduler slots.
- Splunk enforces role-based access to set priority above `default` — requires the `schedule_priority_validation` capability.

**Use Cases:**
- **`highest`:** Detection for `process = mimikatz.exe`, `service creation + lsass memory access`, `ransomware file extension flood` — anything that is an unambiguous, active compromise indicator.
- **`higher`:** Lateral movement detections, C2 beaconing patterns, privilege escalation alerts on Tier 1 assets.
- **`default`:** All routine detections: suspicious login times, unusual outbound ports, new user account creation.

---

### 3.9 Dispatch Earliest / Latest Offsets

**What it controls:** Fine-grained overrides for the time picker values used when an analyst clicks "View Events" in Incident Review from a notable event generated by this detection. These do not affect when the detection searches — they affect the drilldown time window.

**Field type:** Splunk relative time modifier strings.

**`savedsearches.conf` mapping:**
```ini
action.notable.param.drilldown_earliest_offset = $info_min_time$
action.notable.param.drilldown_latest_offset = $info_max_time$+1
```

**Options:**
- Any Splunk relative time modifier (e.g., `-24h`, `-1h`, `now`, `$info_min_time$`).
- The special tokens `$info_min_time$` and `$info_max_time$` refer to the detection's search window boundaries and are most commonly used.

**Use Cases:**
- Use `$info_min_time$` / `$info_max_time$` to scope drilldown exactly to the detection's search window — the analyst sees only the events the detection evaluated.
- Use `-24h` / `now` for detections where you want the analyst to see a full day of context during triage, even if the detection only searched 5 minutes.

---

### 3.10 Security Domain

**What it controls:** Categorizes the detection into a high-level security domain. This field is used for filtering in Incident Review, Content Management, and the Security Posture dashboard. It does NOT affect detection logic.

**Field type:** Dropdown (single select).

**Options:**

| Value | Description | Typical Detection Types |
|---|---|---|
| `access` | Access control: authentication, authorization, identity | Failed logins, privilege escalation, account creation/deletion, MFA bypass |
| `endpoint` | Host/endpoint activity: processes, files, registry, services | Malware execution, persistence mechanisms, memory injection, lateral movement tools |
| `network` | Network traffic: connections, flows, DNS, proxy | C2 beaconing, port scans, data exfiltration, unusual outbound traffic |
| `threat` | Threat intelligence: IOC matches, known-bad indicators | TI feed hits, blacklisted IPs/domains, malware hashes |
| `audit` | Audit and compliance: configuration changes, policy violations | Firewall rule changes, admin account modifications, audit log clearing |
| `identity` | Identity and access management (overlaps with `access`) | SSO anomalies, directory changes, privileged account abuse |

**`savedsearches.conf` mapping:**
```ini
action.notable.param.security_domain = endpoint
```

**Use Cases:**
- Assign `endpoint` to process execution, file system, and registry detections.
- Assign `access` to all authentication-related detections.
- Assign `network` to NetFlow, DNS, proxy, and firewall-based detections.
- Assign `threat` to any detection driven primarily by threat intelligence feeds.
- Filtering by domain in Incident Review lets analysts specialize by their area (e.g., network SOC analyst filters to `network` domain).

---

### 3.11 Severity / Urgency

**What it controls:** The **Severity** field sets the base severity of the detection. Splunk ES then calculates the actual **Urgency** of generated notable events using the formula:

```
Urgency = f(Severity, Asset_Priority or Identity_Priority)
```

The urgency matrix produces the final priority shown in Incident Review.

**Field type:** Dropdown (single select for Severity).

**Severity Options:**

| Value | Meaning | When to Use |
|---|---|---|
| `informational` | Lowest priority; primarily for logging and awareness | Detections that generate high volume, low-fidelity signals; telemetry collection |
| `low` | Minor risk; warrants investigation only if patterns emerge | Unusual but not necessarily malicious behavior; context-gathering detections |
| `medium` | Moderate risk; should be investigated | Suspicious behaviors consistent with attack patterns but with plausible benign explanations |
| `high` | Significant risk; requires prompt investigation | Strong indicators of compromise; techniques with limited benign use cases |
| `critical` | Immediate response required | Confirmed or near-confirmed malicious activity; ransomware, active lateral movement, data exfiltration |

**Urgency Calculation Matrix:**

| Severity ↓ / Asset Priority → | Unknown | Low | Medium | High | Critical |
|---|---|---|---|---|---|
| `informational` | informational | informational | informational | low | medium |
| `low` | low | low | low | medium | high |
| `medium` | medium | low | medium | high | critical |
| `high` | high | medium | high | critical | critical |
| `critical` | critical | high | critical | critical | critical |

**`savedsearches.conf` mapping:**
```ini
action.notable.param.severity = high
```

**Use Cases:**
- A detection for "login from a Tor exit node" might be `medium` severity. If it fires against a `critical` asset (e.g., a domain controller), the urgency escalates to `critical` automatically.
- Use `informational` for detections intended to populate the Risk Index only (no immediate analyst action needed).
- Use `critical` sparingly — a detection library where 30% of rules are `critical` creates alert fatigue and desensitizes analysts.

---

### 3.12 Default Owner

**What it controls:** The Splunk user account that is automatically assigned as the owner of notable events generated by this detection. Analysts can reassign ownership after creation.

**Field type:** Dropdown listing Splunk ES user accounts or a free-text field for the username.

**Options:**
- Any valid Splunk user account in the ES environment.
- `unassigned` — Notable event has no owner until manually assigned (default if left blank).
- Specific user account (e.g., `jsmith` or `soc-team@company.com` if using email-based user IDs).
- Role-based assignment is not natively supported in this field (one specific user only); use workflow automation (SOAR) for round-robin or skill-based routing.

**`savedsearches.conf` mapping:**
```ini
action.notable.param.owner = unassigned
```

**Use Cases:**
- Assign to a team lead's account for high-severity detections that need immediate escalation routing.
- Leave as `unassigned` for most detections to allow the SOC queue management system (or SOAR) to handle routing.
- Assign to a service account (e.g., `soc-tier1`) for detections that feed a specific analyst tier.

---

### 3.13 Default Status

**What it controls:** The initial status assigned to notable events generated by this detection. Defines the starting point in the analyst triage workflow.

**Field type:** Dropdown.

**Options:**

| Status Value | Meaning | Use Case |
|---|---|---|
| `new` | Unreviewed; requires triage | Default for all live detections entering the SOC queue |
| `in progress` | Analyst has picked up and is actively investigating | Pre-set for detections that auto-enrich via SOAR before analyst sees them |
| `pending` | Waiting on external input or action before further investigation | Detections that require data from another team before triage |
| `resolved` | Investigation complete; no further action needed | Not recommended as a default; defeats the purpose of alerting |
| `closed` | Permanently closed; used for FP suppression or completed investigations | Not recommended as a default |

**`savedsearches.conf` mapping:**
```ini
action.notable.param.status = 1
```
*(Status is stored as an integer: 1=new, 2=in progress, 3=pending, 4=resolved, 5=closed)*

**Use Cases:**
- **`new`** for all standard detections — the analyst starts fresh triage.
- **`in progress`** for detections integrated with SOAR where automated playbooks have already begun enrichment before the analyst is notified.

---

### 3.14 Next Steps

**What it controls:** Free-text instructions displayed to analysts in the Incident Review panel when they open a notable event. Should contain investigation steps, triage guidance, and escalation criteria.

**Field type:** Multi-line free text; supports Markdown-like formatting.

**`savedsearches.conf` mapping:**
```ini
action.notable.param.next_steps = [{"investigationName":"Windows Privilege Escalation","investigationTeamId":""}]
```

**Recommended Content Structure:**
```
1. Verify the source IP ($src$) against known-good asset inventory (use Asset Investigator).
2. Check if user ($user$) has a recent password reset or access review.
3. Review Authentication events for $src$ in the past 24 hours.
4. If source IP is external, check against threat intelligence (TI lookup).
5. Escalate to Tier 2 if: (a) source IP is blacklisted, (b) user is a privileged account, (c) >5 distinct targets.
```

**Token Substitution in Next Steps:**
Fields from the detection's result set can be inserted using `$fieldname$` tokens, which resolve to the actual values from the triggering event in Incident Review.

**Use Cases:**
- Standardize triage procedures across the SOC — each analyst follows the same investigation steps.
- Reference SOC runbook links (e.g., `Refer to runbook: https://wiki.company.com/runbooks/brute-force-triage`).
- Provide decision criteria for escalation vs. false-positive closure.

---

### 3.15 Drilldown Name & Search

**What it controls:** The **Drilldown Name** is the label shown on the "View Events" button in Incident Review. The **Drilldown Search** is the SPL query that executes when an analyst clicks that button, providing raw event context for the triggering condition.

**Field type:** 
- Drilldown Name: Free text string.
- Drilldown Search: SPL query string (supports `$field$` token substitution from the notable event's fields).

**`savedsearches.conf` mapping:**
```ini
action.notable.param.drilldown_name = View Authentication Failures for $src$
action.notable.param.drilldown_search = index=wineventlog EventCode=4625 src_ip="$src$" | table _time, user, src_ip, dest, failure_reason
```

**Token Reference:**
Any field in the notable event (which inherits all fields from the detection's result row) can be referenced as `$fieldname$`. Common tokens:

| Token | Typical Source |
|---|---|
| `$src$` | Source IP field |
| `$dest$` | Destination host/IP |
| `$user$` | Username field |
| `$host$` | Host generating the event |
| `$process$` | Process name |
| `$signature$` | Detection/alert signature name |
| `$info_min_time$` | Start of detection's time window |
| `$info_max_time$` | End of detection's time window |

**Use Cases:**
- **Drilldown Name:** `"View Failed Logins for $src$ ($failure_count$ events)"` — displays the specific source IP and count in the button label, giving the analyst context before they click.
- **Drilldown Search:** Return the raw Windows Security events (EventCode=4625) for the triggering source IP to show the analyst every individual failure attempt.
- **Advanced Drilldown:** Link to a pre-built investigation dashboard: `| search src="$src$" | pivot Authentication src limit=100` — sends the analyst directly to a pivot view.

---

### 3.16 Drilldown Earliest / Latest

**What it controls:** Time range for the drilldown search executed when an analyst clicks "View Events." These control the window of raw events the analyst sees during triage.

**Field type:** Splunk relative time modifier strings, same as Section 3.4.

**Common Patterns:**

```ini
# Show exactly the window the detection searched (most precise)
action.notable.param.drilldown_earliest_offset = $info_min_time$
action.notable.param.drilldown_latest_offset = $info_max_time$

# Show a wider context window for investigation
action.notable.param.drilldown_earliest_offset = -24h
action.notable.param.drilldown_latest_offset = now
```

**Use Cases:**
- Use `$info_min_time$` / `$info_max_time$` when the detection has a narrow window and you want the drilldown to show exactly the events that triggered it.
- Use `-2h` / `now` for detections where you want analysts to see broader context (e.g., what happened in the 2 hours leading up to the alert).

---

### 3.17 Investigation Profile

**What it controls:** Associates the detection with a pre-built **Investigation Profile** in ES — a named set of investigation steps, recommended actions, and linked playbooks stored in the ES content library. In ES 8.0, this replaces the legacy "investigation guide" field.

**Field type:** Dropdown listing available investigation profiles defined in the environment.

**`savedsearches.conf` mapping:**
```ini
action.notable.param.investigation_profiles = ["Default Investigation Profile","Malware Investigation"]
```

**Use Cases:**
- Link ransomware detections to a "Ransomware Response" investigation profile that includes isolation steps, stakeholder notification, and forensic collection guidance.
- Apply a "Credential Theft Investigation" profile to all Kerberos abuse and LSASS access detections.
- Use when your SOC has formalized investigation procedures that should be consistently applied.

---

### 3.18 Throttling — Suppress Results

**What it controls:** The master toggle for throttling/suppression. When enabled, ES will not generate duplicate notable events for the same triggering condition within the defined suppression window.

**Field type:** Checkbox / toggle (boolean).

**`savedsearches.conf` mapping:**
```ini
alert.suppress = 1
```

**Use Cases:**
- Enable for detections that generate repeating events for the same condition (e.g., a C2 beacon that fires every 5 minutes for the same host). Without suppression, the analyst queue fills with duplicates.
- Disable for detections where every event instance matters independently (e.g., each ransomware file encryption event should generate its own notable for forensic tracking).

---

### 3.19 Suppress Fields

**What it controls:** Defines the field(s) whose combination uniquely identifies a "duplicate" condition. If a new result has the same values in these fields as a previously suppressed result, it is suppressed.

**Field type:** Comma-separated list of field names from the detection's result set.

**`savedsearches.conf` mapping:**
```ini
alert.suppress.fields = src,user
```

**Options:**
- Any field or combination of fields returned by the detection's SPL.
- Multi-field suppression (e.g., `src,dest,user`) creates a composite key — all three fields must match for suppression to apply.
- Single-field suppression (e.g., `src`) suppresses all subsequent alerts from the same source IP regardless of user or destination.

**Common Suppression Field Patterns:**

| Detection Type | Suppress Fields | Rationale |
|---|---|---|
| Brute force / spray | `src` | Suppress per source IP — one alert per attacking IP per window |
| Malware execution | `host,process_hash` | Suppress per host + specific malware hash — each unique malware on each host gets one alert |
| Data exfiltration | `src_ip,dest_ip` | Suppress per source-destination pair |
| TI feed match | `indicator_value` | Suppress per specific IOC — one alert per unique IOC |
| Privilege escalation | `user,dest` | Suppress per user attempting escalation on a specific target |
| Lateral movement | `src,dest` | Suppress per source-to-destination hop |

**Use Cases:**
- **Single field (`src`):** You have a detection for "high outbound bytes to rare external IP." Set suppress to `src` so that if the same host fires 100 times in an hour, you get 1 notable instead of 100.
- **Multi-field (`user,src`):** Password spray detection — suppress per user-from-source combination. If the same user-from-source triggers again within the window, suppress it; a different user from the same source generates a new notable.

---

### 3.20 Suppress Period

**What it controls:** The duration of the suppression window. Once a notable is generated for a suppressed field combination, no additional notables for the same combination are generated for this many seconds.

**Field type:** Integer (seconds).

**Options:**

| Value (seconds) | Human-Readable | Use Case |
|---|---|---|
| `300` | 5 minutes | High-frequency detections where you want rapid re-alerting if condition persists |
| `900` | 15 minutes | Standard suppression; matches common detection scheduling interval |
| `1800` | 30 minutes | Moderate suppression for hourly detections |
| `3600` | 1 hour | Standard for most detections; prevents re-alert for 1 hour |
| `7200` | 2 hours | Extended suppression for detections prone to prolonged condition persistence |
| `14400` | 4 hours | Half-day suppression |
| `28800` | 8 hours | Business-day suppression — one alert per workday shift |
| `43200` | 12 hours | Twice-daily maximum |
| `86400` | 24 hours | Once-daily suppression; use for low-priority compliance detections |

**`savedsearches.conf` mapping:**
```ini
alert.suppress.period = 3600s
```

**Important:** The suppression period is stored and evaluated by ES in seconds. The `s` suffix is required in `savedsearches.conf`.

**Use Cases:**
- **Ransomware detection + 1-hour suppress:** Once you've alerted that host X is encrypting files, don't re-alert for 1 hour. The analyst should be working the incident.
- **C2 beacon + 24-hour suppress:** A beaconing host fires every 5 minutes. After the first alert, suppress for 24 hours — the analyst will work the investigation and the daily summary will capture persistence.
- **Brute force + 15-minute suppress:** You want to know if the attack is still ongoing after 15 minutes, so a lower suppression window makes sense.

---

### 3.21 MITRE ATT&CK Technique IDs

**What it controls:** Maps the detection to one or more MITRE ATT&CK technique or sub-technique IDs. This mapping is used in the ES MITRE ATT&CK Matrix view, detection coverage reports, and is embedded in notable events for analyst context.

**Field type:** Multi-select dropdown or free-text entry (ES 8.0 provides a searchable dropdown with all ATT&CK Enterprise techniques).

**Format:** `TXXXX` for techniques, `TXXXX.XXX` for sub-techniques.

**Examples:**

```
T1078       - Valid Accounts
T1078.001   - Valid Accounts: Default Accounts
T1078.002   - Valid Accounts: Domain Accounts
T1078.003   - Valid Accounts: Local Accounts
T1078.004   - Valid Accounts: Cloud Accounts
T1110       - Brute Force
T1110.001   - Brute Force: Password Guessing
T1110.002   - Brute Force: Password Cracking
T1110.003   - Brute Force: Password Spraying
T1110.004   - Brute Force: Credential Stuffing
T1059.001   - Command and Scripting Interpreter: PowerShell
T1055       - Process Injection
T1003.001   - OS Credential Dumping: LSASS Memory
T1566.001   - Phishing: Spearphishing Attachment
T1021.001   - Remote Services: Remote Desktop Protocol
```

**`savedsearches.conf` mapping:**
```ini
action.notable.param.mitre_attack_id = ["T1110.003","T1078.002"]
```

**Use Cases:**
- Map to **sub-techniques** when available — they provide more specific ATT&CK coverage tracking and give analysts more precise context.
- A single detection can map to multiple technique IDs if the detection's SPL could detect multiple related behaviors (e.g., a generic "excessive authentication failures" detection maps to both T1110.001 and T1110.003).
- ATT&CK mapping feeds the **MITRE ATT&CK Matrix coverage dashboard** in ES — teams use this to identify coverage gaps across tactics.

---

### 3.22 Kill Chain Phase(s)

**What it controls:** Maps the detection to one or more phases of the Lockheed Martin Cyber Kill Chain. This is an alternative or complementary framework to MITRE ATT&CK for categorizing attack stage.

**Field type:** Multi-select dropdown.

**Options (all 7 Kill Chain phases):**

| Phase | Description | Example Detections |
|---|---|---|
| `reconnaissance` | Attacker collects information about the target | DNS enumeration, port scanning, OSINT harvesting |
| `weaponization` | Attacker creates a weapon (malware, exploit) | Rarely detectable in network/endpoint data; more relevant to malware analysis |
| `delivery` | Attack vector is used to deliver the weapon | Phishing email delivery, malicious attachment download, exploit kit traffic |
| `exploitation` | Attacker exploits a vulnerability or trusted process | CVE exploitation attempts, macro execution, memory corruption |
| `installation` | Malware or backdoor is installed | Persistence mechanisms, scheduled tasks, service creation, registry run keys |
| `command-and-control` | Attacker establishes communication with compromised system | Beaconing, DNS tunneling, C2 protocol detection, unusual outbound connections |
| `actions-on-objectives` | Attacker achieves goal (data theft, destruction, espionage) | Data staging, exfiltration, ransomware execution, lateral movement, privilege escalation |

**`savedsearches.conf` mapping:**
```ini
action.notable.param.kill_chain_phases = ["installation","command-and-control"]
```

**Use Cases:**
- Use Kill Chain phase mapping alongside MITRE ATT&CK — they serve different audiences (Kill Chain for executive/strategic view, ATT&CK for technical/tactical view).
- Filtering Incident Review by Kill Chain phase helps analysts prioritize: `actions-on-objectives` incidents are active breaches; `delivery` incidents may still be pre-exploitation.
- Map detections to multiple phases when a single behavior can indicate different stages (e.g., PowerShell execution can be `exploitation`, `installation`, or `actions-on-objectives` depending on context).

---

### 3.23 Asset / Identity Correlation

**What it controls:** Instructs ES to automatically enrich notable events generated by this detection with asset data (from the Asset Center) and identity data (from the Identity Center). Enriched fields are appended to the notable event and used for urgency calculation.

**Field type:** Checkboxes / toggles for enabling asset and identity correlation independently.

**Fields affected:**

When asset correlation is enabled and the detection returns a field matching an asset identifier (IP, hostname, MAC):

| Enriched Asset Field | Source | Use in Urgency |
|---|---|---|
| `asset_tag` | Asset lookup | Classification/filtering |
| `bunit` | Asset lookup | Business unit context |
| `category` | Asset lookup | Asset type context |
| `city`, `country` | Asset lookup | Geographic context |
| `dns` | Asset lookup | Canonical hostname |
| `ip` | Asset lookup | IP address |
| `lat`, `long` | Asset lookup | Geographic coordinates |
| `mac` | Asset lookup | MAC address |
| `nt_host` | Asset lookup | Windows NT hostname |
| `owner` | Asset lookup | Asset owner contact |
| `pci_domain` | Asset lookup | PCI compliance zone |
| `priority` | Asset lookup | **Critical for urgency calculation** — values: `unknown`, `low`, `medium`, `high`, `critical` |
| `should_timesync` | Asset lookup | NTP compliance flag |
| `should_update` | Asset lookup | Patch management flag |

When identity correlation is enabled and the detection returns a username field:

| Enriched Identity Field | Source | Use in Urgency |
|---|---|---|
| `bunit` | Identity lookup | Business unit |
| `category` | Identity lookup | User category |
| `email` | Identity lookup | Contact for notification |
| `endDate` | Identity lookup | Account end date |
| `first`, `last` | Identity lookup | Full name |
| `managedBy` | Identity lookup | Manager |
| `nick` | Identity lookup | Nickname/alias |
| `phone` | Identity lookup | Contact phone |
| `prefix` | Identity lookup | Title/prefix |
| `priority` | Identity lookup | **Critical for urgency calculation** — same values as asset priority |
| `startDate` | Identity lookup | Account start date |
| `watchlist` | Identity lookup | Flagged for monitoring |
| `work_city`, `work_country` | Identity lookup | Location context |

**`savedsearches.conf` mapping:**
```ini
# Asset and identity correlation is controlled via the notable event action
action.notable = 1
# ES automatically performs lookup enrichment based on src, dest, user fields in results
```

**Use Cases:**
- A detection for "login from unusual country" that flags `user=jsmith` will automatically enrich with `jsmith`'s department, manager, and email — helping the analyst immediately understand who the affected user is.
- A malware execution alert that includes `src_ip=10.1.1.50` will resolve to the asset owner, business unit, and priority — if the host is `priority=critical` (e.g., a domain controller), the urgency escalates automatically.

---

### 3.24 Annotations (Custom Key-Value Pairs)

**What it controls:** Allows adding arbitrary metadata key-value pairs to the detection and its generated notable events. These annotations are searchable in Splunk and can be used for filtering, reporting, and integration with external tools.

**Field type:** Dynamic key-value pair editor (add/remove pairs).

**`savedsearches.conf` mapping:**
```ini
action.notable.param.annotations = {"custom_key":"custom_value","cve":["CVE-2021-44228"],"cis_controls":["CIS-4","CIS-16"]}
```

**Common Annotation Keys:**

| Key | Values | Use Case |
|---|---|---|
| `cve` | CVE IDs (e.g., `CVE-2021-44228`) | Link detection to specific vulnerabilities |
| `cis_controls` | CIS Control IDs (e.g., `CIS-4`) | Map to CIS Controls compliance framework |
| `nist` | NIST SP800-53 control IDs (e.g., `AC-2`) | NIST compliance mapping |
| `confidence` | `low`, `medium`, `high` | Detection fidelity rating |
| `impact` | `low`, `medium`, `high`, `critical` | Estimated business impact if true positive |
| `data_source` | Data source name | What log source drives this detection |
| `playbook_id` | Playbook identifier | Link to SOAR playbook |
| `author` | Team or individual | Detection author for provenance |
| `version` | Semantic version string | Detection version tracking |
| `detection_id` | UUID or sequential ID | Unique identifier for tracking across systems |

**Use Cases:**
- Add `cve=CVE-2021-44228` to Log4Shell detections — when an analyst opens the notable, the CVE link immediately provides vulnerability context.
- Add `confidence=low` to behavioral detections with high FP rates — helps analysts calibrate their triage approach.
- Add `playbook_id=PB-042` to auto-link the notable event to the appropriate SOAR playbook for automated enrichment/response.

---

## 4. Risk Scoring Configuration

### 4.1 Enable Risk Scoring

**What it controls:** Toggles whether this detection writes risk events to the `risk` index in addition to (or instead of) generating notable events. Risk events feed the Risk-Based Alerting (RBA) framework.

**Field type:** Checkbox / toggle (boolean).

**`savedsearches.conf` mapping:**
```ini
action.risk = 1
```

**Architecture Note:**
When risk scoring is enabled:
1. Each result row from the detection generates one risk event in the `risk` index.
2. Risk events accumulate against Risk Objects (users, hosts, IPs) over a rolling time window.
3. When a Risk Object's cumulative risk score exceeds a threshold, a **Risk Notable** is generated.
4. Risk events contain: risk object, risk object type, risk score, risk message, source detection name, and all result fields.

**Use Cases:**
- Enable risk scoring on all detections that represent **contributing signals** rather than definitive compromise indicators — they accumulate evidence.
- Disable risk scoring (notable only) for definitive compromise indicators (e.g., ransomware file extension flood, confirmed malware hash execution) where you want immediate triage regardless of accumulated risk.
- Enable BOTH risk scoring AND notable generation for mid-confidence detections where you want both an immediate alert AND long-term risk accumulation.

---

### 4.2 Risk Object Field

**What it controls:** Specifies which field from the detection's result set identifies the entity being scored. The value in this field becomes the Risk Object identifier (e.g., an IP address, hostname, or username).

**Field type:** Dropdown listing fields available in the detection's result set, OR free-text entry of the field name.

**Common Risk Object Fields:**

| Field Name | Risk Object Identity | Example Value |
|---|---|---|
| `src` | Source IP address | `192.168.1.100` |
| `dest` | Destination host/IP | `dc01.company.local` |
| `user` | Username | `jsmith` |
| `src_user` | Source user | `jsmith@domain.com` |
| `dest_user` | Destination user | `admin` |
| `host` | Host generating event | `workstation-42` |
| `src_ip` | Explicit source IP | `10.0.0.50` |
| `process_name` | Process as risk object | `powershell.exe` |

**`savedsearches.conf` mapping:**
```ini
action.risk.param.risk_object = src
```

**Use Cases:**
- Use `src` for network-based detections — accumulate risk against source IPs performing suspicious activity.
- Use `user` for identity-based detections — build a risk profile per user across authentication, endpoint, and network detections.
- Use `host` for endpoint detections — accumulate risk per machine regardless of which user is logged in.
- Use `dest` for targeting/impact analysis — identify which assets are being attacked.

---

### 4.3 Risk Object Type

**What it controls:** Defines the category of the Risk Object. This field affects how ES groups and displays risk in the Risk Center and determines which asset/identity lookups are applied for enrichment.

**Field type:** Dropdown (fixed options).

**Options:**

| Value | Description | When to Use |
|---|---|---|
| `system` | A host, server, workstation, or network device | Use when the Risk Object field contains a hostname or IP (`dest`, `host`, `src`) |
| `user` | A user account (human or service) | Use when the Risk Object field contains a username (`user`, `src_user`) |
| `other` | Any other entity type not fitting system or user | Use for custom entities: process names, file hashes, URL patterns; note: no asset/identity enrichment applies |

**`savedsearches.conf` mapping:**
```ini
action.risk.param.risk_object_type = system
```

**Use Cases:**
- `system` for endpoint detections (malware execution on `dest_host`), lateral movement detections (targeting `dest`).
- `user` for credential attacks, privilege escalation, insider threat detections.
- `other` for threat intel IOC tracking (risk-score per malware hash or C2 domain).

---

### 4.4 Risk Score

**What it controls:** The numeric risk score value added to the Risk Object's cumulative total when this detection fires. Scores are additive across detections over a rolling time window (typically 24 hours, configurable in RBA settings).

**Field type:** Integer (1–100 recommended; technically any positive integer).

**Scoring Guidelines:**

| Score Range | Fidelity Level | Example Detections |
|---|---|---|
| `10–20` | Low-confidence, high-volume signals | Unusual login time, single failed login, uncommon user agent |
| `25–40` | Medium-confidence behavioral indicators | Multiple failed logins, access to rare system, PowerShell with encoded command |
| `50–60` | High-confidence suspicious behavior | Pass-the-hash attempt, LSASS access, known evil tool signature |
| `70–80` | Near-definitive malicious behavior | Mimikatz execution, Cobalt Strike beacon, malware hash match |
| `90–100` | Definitive malicious activity | Ransomware file flood, confirmed C2 connection, active exfiltration |

**`savedsearches.conf` mapping:**
```ini
action.risk.param.risk_score = 40
```

**Dynamic Risk Scoring (via SPL):**
Rather than a static score, you can calculate the risk score dynamically in your detection SPL and use the calculated field as the risk score:

```spl
| eval risk_score = case(
    failure_count > 100, 80,
    failure_count > 50, 60,
    failure_count > 10, 40,
    true(), 20
)
```
Then set the Risk Score field to use the `risk_score` field from results.

**Use Cases:**
- Assign `score=20` to "login outside business hours" — on its own it's weak, but combined with 3 other detections against the same user, it contributes to a meaningful risk total.
- Assign `score=80` to "Mimikatz process name detected" — this is a near-definitive indicator and should contribute heavily to the risk profile.
- Use dynamic scoring to weight risk based on event count (more failures = higher risk contribution).

---

### 4.5 Risk Message

**What it controls:** A human-readable message template associated with each risk event, explaining why risk was added to this object. Displayed in the Risk Center and in Risk Notable events to help analysts understand risk accumulation.

**Field type:** Free text string; supports `$field$` token substitution from the detection's result fields.

**`savedsearches.conf` mapping:**
```ini
action.risk.param.risk_message = Excessive authentication failures detected from $src$ against $unique_users$ user accounts (count: $failure_count$)
```

**Token Substitution:**
Same `$fieldname$` syntax as Next Steps and Drilldown Name. All fields from the detection's result row are available.

**Best Practice Format:**
```
[Behavior description] observed: [specific values from event] on [time context]
```

Examples:
```
PowerShell with encoded command executed by $user$ on $dest$ (process: $process$)
LSASS memory access from $src_process$ on $dest$ — possible credential dumping
$failure_count$ authentication failures from $src$ targeting $unique_users$ accounts
DNS query for known C2 domain $query$ from $src$
```

**Use Cases:**
- Rich risk messages in the Risk Center let analysts quickly understand what activity accumulated risk without drilling into each source detection separately.
- Use field tokens extensively — a risk message that says "Suspicious activity detected" is useless; "47 failed logins from 192.168.10.5 targeting 12 user accounts" gives immediate context.

---

### 4.6 Threat Object Field

**What it controls:** Specifies a field from the detection's results that identifies the **threat** (the attacker's tool/indicator) as opposed to the victim (the risk object). Threat objects are stored alongside risk events and displayed in the Risk Center.

**Field type:** Dropdown of fields in the detection result set, or free text.

**Common Threat Object Fields:**

| Field | Represents | Example Value |
|---|---|---|
| `process` | Malicious process | `mimikatz.exe` |
| `file_hash` | Malware hash | `44d88612fea8a8f36de82e1278abb02f` |
| `url` | Malicious URL | `http://evil.com/payload` |
| `query` | Malicious DNS query | `c2.badactor.com` |
| `signature` | IDS/AV signature | `Trojan.Gen.2` |
| `indicator` | Threat intel IOC | `185.220.101.5` |

**`savedsearches.conf` mapping:**
```ini
action.risk.param.threat_object = process
```

**Use Cases:**
- When you detect mimikatz by process name, set the Risk Object to the `host` (victim) and the Threat Object to `process` (the tool used). This allows the Risk Center to show "which tools are being used against which hosts."

---

### 4.7 Threat Object Type

**What it controls:** Categorizes the Threat Object for display and filtering in the Risk Center.

**Field type:** Dropdown (fixed options).

**Options:**

| Value | Description | Use Case |
|---|---|---|
| `ip_address` | An IP address as the threat indicator | C2 server IPs, scan source IPs |
| `url` | A URL as the threat indicator | Malicious download URLs, phishing links |
| `process` | A process name or path | Known malicious executables |
| `file_name` | A filename | Malware filenames, suspicious scripts |
| `file_hash` | A file hash (MD5/SHA1/SHA256) | Malware hash IOCs |
| `domain` | A domain name | C2 domains, DGA domains |
| `user` | A username as the threat actor | Compromised or malicious insider accounts |
| `other` | Any other type | Custom threat indicator types |

**`savedsearches.conf` mapping:**
```ini
action.risk.param.threat_object_type = process
```

---

### 4.8 Risk Score Modifier Rules

Beyond static scoring, ES supports **Risk Score Modifier** rules in the Risk Framework that dynamically adjust scores based on asset/identity attributes at risk event write time:

```spl
# Example: Boost risk score if the risk object is a domain controller
| inputlookup asset_lookup_by_str where nt_host="$risk_object$"
| eval adjusted_score = if(category="domain_controller", risk_score * 2, risk_score)
```

This is typically configured in the Risk Framework settings rather than per-detection, but detection-level dynamic scoring (Section 4.4) is the simpler approach.

---

## 5. Notable Event Settings

### 5.1 Notable Event Generation Toggle

**What it controls:** Determines whether this detection generates notable events in addition to (or instead of) risk events. Notable events appear in Incident Review for analyst triage.

**Field type:** Checkbox / toggle.

**`savedsearches.conf` mapping:**
```ini
action.notable = 1
```

**Architectural note:** A detection can have:
- **Notable only** (`action.notable=1, action.risk=0`): Direct alert; analyst triage immediately.
- **Risk only** (`action.notable=0, action.risk=1`): Silent signal; contributes to RBA.
- **Both** (`action.notable=1, action.risk=1`): Immediate alert AND risk accumulation.
- **Neither** (`action.notable=0, action.risk=0`): The detection runs and can execute other AR actions (email, webhook) but doesn't create ES-visible events — rare edge case.

---

### 5.2 Title Field

**What it controls:** The title displayed in Incident Review for each notable event. Supports `$field$` token substitution from the detection result fields.

**Field type:** Free text string with token support.

**`savedsearches.conf` mapping:**
```ini
action.notable.param.rule_title = Excessive Authentication Failures from $src$ ($failure_count$ attempts)
```

**Best Practice:**
Include dynamic values that immediately distinguish this alert from others:
```
[Detection Name] — [Key Context Field] — [Quantifier if applicable]
```

Examples:
```
Password Spray Detected — Source: $src$ — $failure_count$ failures against $unique_users$ accounts
PowerShell Encoded Command — Host: $dest$ — User: $user$
C2 Beacon — Destination: $dest_ip$:$dest_port$ — Process: $process$
```

**Use Cases:**
- Titles with field tokens allow analysts to differentiate alerts at a glance in the Incident Review queue without opening each one.
- Include the most security-relevant field first — for network alerts, this is usually the source IP; for endpoint alerts, the host or user.

---

### 5.3 Description Field Mapping

**What it controls:** The description text associated with each notable event. Can be the static detection description or a dynamically computed field from the result set.

**Field type:** Free text with optional `$field$` token substitution, OR a field reference (`$description$`) that maps to a computed field in the SPL.

**`savedsearches.conf` mapping:**
```ini
action.notable.param.rule_description = Detected $failure_count$ authentication failures from source $src$ targeting $unique_users$ distinct user accounts over $time_window$ minutes. This pattern is consistent with a password spray attack.
```

---

### 5.4 Security Domain (Notable)

Same as Section 3.10. The security domain selection flows through to the notable event and is visible in Incident Review filters.

---

### 5.5 Urgency Mapping Logic

The urgency of a notable event is computed at runtime when the notable is written to the `notable` index. The computation uses:

1. **Detection Severity** (from field 3.11): `informational`, `low`, `medium`, `high`, `critical`
2. **Asset Priority** (from asset lookup, if the `dest` or `src` field maps to a known asset): `unknown`, `low`, `medium`, `high`, `critical`
3. **Identity Priority** (from identity lookup, if the `user` field maps to a known identity): same values

**Urgency Matrix** (reproduced from Section 3.11 for reference):

| Severity ↓ / Priority → | unknown | low | medium | high | critical |
|---|---|---|---|---|---|
| informational | informational | informational | informational | low | medium |
| low | low | low | low | medium | high |
| medium | medium | low | medium | high | critical |
| high | high | medium | high | critical | critical |
| critical | critical | high | critical | critical | critical |

**Urgency values in ES (ordered lowest to highest):**
`informational` → `low` → `medium` → `high` → `critical`

**`savedsearches.conf` configuration for urgency overrides:**
```ini
# These are set in transforms.conf / urgency lookup, not savedsearches.conf directly
# The default urgency lookup is: $SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/lookups/urgency.csv
```

---

### 5.6 Asset / Identity Lookup Fields

ES performs asset and identity enrichment by matching the following fields from the detection result against the Asset and Identity lookup tables:

**Asset Lookup Match Fields (in priority order):**

| Field | Lookup Key | Notes |
|---|---|---|
| `src` | IP, hostname | Matched against `ip`, `nt_host`, `dns` columns |
| `dest` | IP, hostname | Same lookup, different direction |
| `dvc` | Device identifier | Network devices |
| `orig_host` | Source host | Raw host field before normalization |
| `src_ip` | IP address | Explicit IP field |
| `dest_ip` | IP address | Explicit destination IP |

**Identity Lookup Match Fields:**

| Field | Lookup Key | Notes |
|---|---|---|
| `user` | Username | Primary identity lookup field |
| `src_user` | Source username | Authentication source user |
| `dest_user` | Destination username | Authentication target user |

**Lookup Tables Location:**
```
$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/lookups/asset_lookup_by_str.csv
$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/lookups/asset_lookup_by_cidr.csv
$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/lookups/identity_lookup_expanded.csv
```

---

## 6. Adaptive Response Actions

Adaptive Response Actions (AR Actions) are triggered by the detection at execution time, in addition to or instead of notable/risk event generation.

### 6.1 Risk Modifier Action

**Purpose:** The built-in risk scoring action. Writes risk events to the `risk` index.

**Key Parameters (UI):**

| Parameter | Description |
|---|---|
| Risk Object | Field name from results containing the entity to score |
| Risk Object Type | `system`, `user`, or `other` |
| Risk Score | Numeric score to add |
| Risk Message | Human-readable description of the risk event |
| Threat Object | Field name identifying the threat indicator |
| Threat Object Type | Category of the threat object |

**`savedsearches.conf` mapping:**
```ini
action.risk = 1
action.risk.param.risk_object = src
action.risk.param.risk_object_type = system
action.risk.param.risk_score = 40
action.risk.param.risk_message = Brute force attempt from $src$
action.risk.param.threat_object = src
action.risk.param.threat_object_type = ip_address
```

---

### 6.2 Notable Event Creation Action

**Purpose:** The built-in notable event generation action. Creates events in the `notable` index for Incident Review.

**Key Parameters (UI):** Covered in full in Sections 3.10–3.17 and Section 5.

**`savedsearches.conf` mapping:**
```ini
action.notable = 1
action.notable.param.rule_title = $detection_name$ — $src$
action.notable.param.rule_description = $description$
action.notable.param.security_domain = access
action.notable.param.severity = high
action.notable.param.owner = unassigned
action.notable.param.status = 1
```

---

### 6.3 Email Action

**Purpose:** Sends an email notification when the detection fires.

**Key Parameters:**

| Parameter | Description | Example |
|---|---|---|
| To | Recipient email addresses (comma-separated) | `soc-team@company.com` |
| Subject | Email subject (supports `$field$` tokens) | `[ALERT] $rule_name$ fired on $src$` |
| Message | Email body (supports tokens and basic HTML) | Full event details |
| Include Results | Attach CSV of detection results | Checkbox |
| Max Results | Maximum rows to include in attachment | `10` |

**`savedsearches.conf` mapping:**
```ini
action.email = 1
action.email.to = soc-team@company.com
action.email.subject = [Splunk ES Alert] $name$ triggered
action.email.message.alert = Detection $name$ fired. Source: $result.src$
action.email.sendresults = 1
action.email.maxresults = 10
```

**Use Cases:**
- Send email for `critical` severity detections to on-call security staff.
- Use for executive-facing detections that require immediate notification outside the SOC queue.
- **Caution:** Email notifications scale poorly in high-volume detection environments — use SOAR or notable events for primary workflow; email for critical escalations only.

---

### 6.4 Run a Script Action

**Purpose:** Executes a custom shell script or Python script on the Splunk search head when the detection fires.

**Key Parameters:**

| Parameter | Description |
|---|---|
| Filename | Name of the script in `$SPLUNK_HOME/bin/scripts/` |
| Arguments | Optional arguments passed to the script |

**`savedsearches.conf` mapping:**
```ini
action.script = 1
action.script.filename = block_ip.sh
```

**Security Note:** Scripts run as the Splunk process user. Validate all input — field token values passed as arguments are attacker-controlled if the detection operates on external data.

**Use Cases:**
- Auto-block a source IP on a firewall via API call when a high-confidence C2 detection fires.
- Push a host isolation command to an EDR platform.
- Write alert data to a custom database or ticketing system without a formal integration.

---

### 6.5 Webhook Action

**Purpose:** Sends an HTTP POST request to a specified URL when the detection fires. Used for integrations with external systems.

**Key Parameters:**

| Parameter | Description | Example |
|---|---|---|
| URL | Webhook endpoint | `https://hooks.slack.com/services/xxx/yyy/zzz` |
| Body | JSON payload (supports `$field$` tokens) | `{"text": "Alert: $name$ fired on $src$"}` |

**`savedsearches.conf` mapping:**
```ini
action.webhook = 1
action.webhook.param.url = https://hooks.slack.com/services/xxx/yyy/zzz
```

**Use Cases:**
- Post critical alerts to a Slack security channel.
- Trigger a SOAR webhook to kick off an automated investigation playbook.
- Integrate with PagerDuty, Opsgenie, or similar on-call notification platforms without a full integration.

---

### 6.6 PagerDuty / ServiceNow / SOAR Integrations

These are provided as add-on AR Actions via Splunkbase apps. When installed, they appear in the AR Action list in the detection creation UI.

**Common Integration AR Actions:**

| Integration | App Required | Use Case |
|---|---|---|
| Splunk SOAR (Phantom) | Splunk SOAR on-premises or cloud connector | Full automated response playbooks; rich bidirectional integration |
| ServiceNow | Splunk Add-on for ServiceNow | Auto-create ITSM incidents from notables |
| PagerDuty | PagerDuty add-on | On-call alerting for critical detections |
| JIRA | JIRA add-on | Create security tickets in JIRA from notable events |
| Slack | Slack Alert Action add-on | Rich Slack notifications with context |
| Cisco XDR / SecureX | Cisco add-on | Automated threat response in Cisco ecosystem |

**`savedsearches.conf` mapping (SOAR example):**
```ini
action.phantom = 1
action.phantom.param.phantom_server = https://soar.company.com
action.phantom.param.playbook_name = brute_force_investigation
action.phantom.param.sensitivity = red
action.phantom.param.severity = high
```

---

### 6.7 Threat Intelligence Action

**Purpose:** Adds indicators from detection results to Threat Intelligence collections, enabling future automatic IOC matching.

**Key Parameters:**

| Parameter | Description |
|---|---|
| Intel Type | Type of IOC being added (`ip_intel`, `domain_intel`, `file_intel`, `url_intel`, etc.) |
| Field | Field from results containing the IOC value |
| Collection | Target TI collection name |
| TTL | Time-to-live for the indicator (seconds) |

**Use Cases:**
- When a detection fires on a confirmed malicious IP, automatically add it to a local IP blocklist collection for future TI-driven detection.
- Auto-populate a "confirmed C2 domains" collection from domain-based C2 detections.

---

### 6.8 ESCU Action Runner (Enterprise Content)

**Purpose:** Executes post-detection enrichment using the Splunk Attack Analyzer or ESCU-defined automated response steps.

**Use Cases:**
- Used by Splunk-authored ESCU content to standardize enrichment steps.
- Typically involves lookups against additional data sources, submission of file hashes to sandboxes, and enrichment of the notable event with additional context.

---

## 7. Threat Intelligence Integration

### 7.1 TI Lookups and `threat_match`

ES 8.0 ships with a Threat Intelligence Framework that maintains TI collections in KV Store and flat-file lookups. The relevant collections:

| Collection / Lookup | Content | Fields |
|---|---|---|
| `ip_intel` | IP address indicators | `ip`, `description`, `source`, `sev`, `expiration` |
| `domain_intel` | Domain name indicators | `domain`, `description`, `source`, `sev` |
| `url_intel` | URL indicators | `url`, `description`, `source`, `sev` |
| `file_intel` | File hash indicators | `file_hash`, `description`, `source`, `sev` |
| `certificate_intel` | SSL certificate indicators | `ssl_hash`, `description`, `source`, `sev` |
| `user_intel` | Compromised username indicators | `user`, `description`, `source`, `sev` |
| `email_intel` | Malicious email indicators | `src_user`, `description`, `source`, `sev` |
| `process_intel` | Process-based indicators | `process`, `description`, `source`, `sev` |

### 7.2 Indicator Matching in SPL

```spl
`datamodel("Network_Traffic","All_Traffic")`
| rename "All_Traffic.*" as "*"
| lookup ip_intel ip as dest_ip OUTPUT description as intel_description, sev as intel_severity
| where isnotnull(intel_description)
| table _time, src_ip, dest_ip, dest_port, bytes, intel_description, intel_severity
```

**Using `| threat_match` command (ES built-in):**
```spl
index=proxy
| fields src_ip, dest_url, dest_domain
| threat_match match_fields="dest_domain,domain_intel:domain" 
               output_fields="description,sev" 
               prefix="ti_"
| where isnotnull(ti_description)
```

### 7.3 TI-Driven Detection Patterns

**Pattern 1: DNS-based C2 detection:**
```spl
`datamodel("Network_Resolution","DNS")`
| rename "DNS.*" as "*"
| lookup domain_intel domain as query OUTPUT description, sev
| where isnotnull(description)
| eval threat_category="C2_Domain"
| table _time, src, query, answer, description, sev, threat_category
```

**Pattern 2: Multi-field TI matching:**
```spl
index=firewall action=allowed
| eval dest_ip_clean = replace(dest_ip, "/\d+$", "")
| lookup ip_intel ip as dest_ip_clean OUTPUT description as ip_description, sev as ip_sev
| lookup domain_intel domain as dest_hostname OUTPUT description as domain_description, sev as domain_sev
| eval ti_match = coalesce(ip_description, domain_description)
| where isnotnull(ti_match)
```

---

## 8. Asset & Identity Correlation

### 8.1 How ES Enriches Events

ES performs asset and identity enrichment automatically at notable event creation time via the `lookup` transforms defined in `transforms.conf`. The enrichment pipeline:

1. Detection fires → result row contains `src`, `dest`, `user` fields.
2. ES notable event action runs `asset_lookup_by_str` and `asset_lookup_by_cidr` lookups against `src` and `dest`.
3. ES notable event action runs `identity_lookup_expanded` against `user`.
4. Matched fields are appended to the notable event record.
5. Urgency is computed from the severity × priority matrix.

### 8.2 Key Asset Fields

```spl
# Asset lookup table fields (asset_lookup_by_str.csv):
ip, mac, nt_host, dns, owner, priority, lat, long, city, country, 
bunit, category, pci_domain, is_expected, should_timesync, should_update, 
requires_av
```

**Priority values (critical for urgency calculation):** `unknown`, `low`, `medium`, `high`, `critical`

### 8.3 Key Identity Fields

```spl
# Identity lookup table fields (identity_lookup_expanded.csv):
identity, prefix, first, last, suffix, email, phone, phone2, 
managedBy, priority, bunit, category, watchlist, startDate, endDate,
work_city, work_country, work_lat, work_long
```

### 8.4 Using Asset/Identity in SPL

You can proactively enrich your detection SPL with asset/identity data to use in thresholds, filters, or risk scoring:

```spl
`datamodel("Authentication","Authentication")`
| rename "Authentication.*" as "*"
| search action="failure"
| stats count as failures by src, user
| lookup identity_lookup_expanded identity as user OUTPUT priority as user_priority, bunit, watchlist
| lookup asset_lookup_by_str nt_host as src OUTPUT priority as src_priority, category as src_category
| where failures > 5 OR watchlist="true" OR user_priority="high"
| eval urgency_boost = if(user_priority="critical" OR src_priority="critical", "yes", "no")
| table src, user, failures, user_priority, src_priority, src_category, bunit, watchlist, urgency_boost
```

---

## 9. Backend Configuration — savedsearches.conf

### 9.1 Core Stanza Structure

All event-based detections are stored as stanzas in `savedsearches.conf`. The file is located at:

```
# ES app context (recommended for custom content):
$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/local/savedsearches.conf

# Dedicated custom content app (best practice):
$SPLUNK_HOME/etc/apps/<your_custom_app>/local/savedsearches.conf
```

**Minimal valid event-based detection stanza:**
```ini
[My Detection Name]
search = index=main | stats count by src | where count > 10
dispatch.earliest_time = -15m
dispatch.latest_time = now
cron_schedule = */15 * * * *
enableSched = 1
action.notable = 1
action.notable.param.rule_title = Detection fired: $src$
action.notable.param.severity = medium
action.notable.param.security_domain = access
action.notable.param.status = 1
action.notable.param.owner = unassigned
```

---

### 9.2 Notable Event Stanza Parameters

| Parameter | Type | Description | Example Value |
|---|---|---|---|
| `action.notable` | bool (0/1) | Enable notable event generation | `1` |
| `action.notable.param.rule_title` | string | Notable event title (supports `$field$`) | `Failed Logins from $src$` |
| `action.notable.param.rule_description` | string | Notable event description | `Password spray detected` |
| `action.notable.param.security_domain` | string | Security domain | `access` |
| `action.notable.param.severity` | string | Detection severity | `high` |
| `action.notable.param.owner` | string | Default notable owner | `unassigned` |
| `action.notable.param.status` | int | Initial status (1=new, 2=in progress, etc.) | `1` |
| `action.notable.param.next_steps` | string | Analyst investigation steps | `Check $src$ in asset inventory` |
| `action.notable.param.drilldown_name` | string | Drilldown button label | `View events for $src$` |
| `action.notable.param.drilldown_search` | string | Drilldown SPL query | `index=wineventlog src_ip="$src$"` |
| `action.notable.param.drilldown_earliest_offset` | string | Drilldown time start | `$info_min_time$` |
| `action.notable.param.drilldown_latest_offset` | string | Drilldown time end | `$info_max_time$` |
| `action.notable.param.mitre_attack_id` | JSON array string | MITRE ATT&CK technique IDs | `["T1110.003","T1078"]` |
| `action.notable.param.kill_chain_phases` | JSON array string | Kill chain phases | `["exploitation","installation"]` |
| `action.notable.param.annotations` | JSON object string | Custom key-value annotations | `{"cve":["CVE-2021-1234"]}` |

---

### 9.3 Risk Scoring Stanza Parameters

| Parameter | Type | Description | Example Value |
|---|---|---|---|
| `action.risk` | bool (0/1) | Enable risk event generation | `1` |
| `action.risk.param.risk_object` | string | Field containing the risk object | `src` |
| `action.risk.param.risk_object_type` | string | Risk object category | `system` |
| `action.risk.param.risk_score` | int | Risk score value | `40` |
| `action.risk.param.risk_message` | string | Human-readable risk message | `Brute force from $src$` |
| `action.risk.param.threat_object` | string | Field containing the threat indicator | `process` |
| `action.risk.param.threat_object_type` | string | Threat indicator category | `process` |

---

### 9.4 Throttle / Suppression Parameters

| Parameter | Type | Description | Example Value |
|---|---|---|---|
| `alert.suppress` | bool (0/1) | Enable throttling/suppression | `1` |
| `alert.suppress.fields` | string | Comma-separated suppress key fields | `src,user` |
| `alert.suppress.period` | string | Suppression duration with unit | `3600s` |
| `alert.suppress.group_name` | string | Optional: named suppression group | `brute_force_group` |

---

### 9.5 Scheduling Parameters

| Parameter | Type | Description | Example Value |
|---|---|---|---|
| `enableSched` | bool (0/1) | Enable scheduled execution | `1` |
| `cron_schedule` | string | Cron expression | `*/15 * * * *` |
| `dispatch.earliest_time` | string | Search window start | `-15m` |
| `dispatch.latest_time` | string | Search window end | `now` |
| `schedule_window` | string | Scheduling flexibility window | `auto` or `5` |
| `schedule_priority` | string | Scheduler priority | `default`, `higher`, `highest` |
| `realtime_schedule` | bool (0/1) | Use real-time scheduling | `0` (default; `1` for RT) |
| `max_concurrent` | int | Max concurrent instances | `1` (default) |
| `counttype` | string | Trigger condition type | `number of events` |
| `relation` | string | Comparison operator for trigger | `greater than` |
| `quantity` | int | Threshold for trigger | `0` |

**Note on `counttype`, `relation`, `quantity`:** These define the trigger condition for the alert action. For ES event-based detections that should fire on any results, use:
```ini
counttype = number of events
relation = greater than
quantity = 0
```

---

### 9.6 MITRE and Annotation Parameters

```ini
# MITRE ATT&CK IDs — stored as JSON array string
action.notable.param.mitre_attack_id = ["T1110.003","T1078.002"]

# Kill Chain phases — stored as JSON array string  
action.notable.param.kill_chain_phases = ["exploitation"]

# Annotations — stored as JSON object string
action.notable.param.annotations = {"cve":["CVE-2021-44228"],"confidence":"high","data_source":"Windows Security Events"}
```

---

### 9.7 Full Annotated Example Stanza

```ini
# ==============================================================================
# Detection: Windows - Password Spray via Authentication Failures - Rule
# Author: SOC Engineering Team
# Version: 1.0.0
# Last Modified: 2025-01-15
# MITRE ATT&CK: T1110.003 (Password Spraying)
# ==============================================================================

[Windows - Password Spray via Authentication Failures - Rule]

# --- Core Search ---
search = `datamodel("Authentication","Authentication")` \
| rename "Authentication.*" as "*" \
| search action="failure" \
| stats count as failure_count dc(user) as unique_users values(user) as user_list by src \
| where failure_count >= 20 AND unique_users >= 5 \
| lookup asset_lookup_by_str ip as src OUTPUT priority as src_priority, owner as src_owner \
| eval risk_score = case( \
    unique_users >= 20, 80, \
    unique_users >= 10, 60, \
    unique_users >= 5, 40, \
    true(), 20 \
  )

# --- Scheduling ---
enableSched = 1
cron_schedule = */5 * * * *
dispatch.earliest_time = -10m
dispatch.latest_time = now
schedule_window = auto
schedule_priority = default

# --- Trigger Condition ---
counttype = number of events
relation = greater than
quantity = 0

# --- Throttling ---
alert.suppress = 1
alert.suppress.fields = src
alert.suppress.period = 3600s

# --- Notable Event Action ---
action.notable = 1
action.notable.param.rule_title = Password Spray from $src$ — $failure_count$ failures across $unique_users$ accounts
action.notable.param.rule_description = Multiple authentication failures detected from source $src$ targeting $unique_users$ distinct user accounts ($failure_count$ total failures). This pattern is consistent with a password spray attack. Targeted users: $user_list$
action.notable.param.security_domain = access
action.notable.param.severity = high
action.notable.param.owner = unassigned
action.notable.param.status = 1
action.notable.param.next_steps = 1. Verify $src$ against asset inventory (known IP? VPN range? External?)\n2. Check if $src$ correlates with any known-good service account.\n3. Review all users in $user_list$ for successful logins following this burst.\n4. Check TI lookup for $src$ — is it a known attack infrastructure IP?\n5. Escalate if any targeted user shows subsequent successful login.
action.notable.param.drilldown_name = View Authentication Events for $src$
action.notable.param.drilldown_search = `datamodel("Authentication","Authentication")` | rename "Authentication.*" as "*" | search src="$src$" | table _time, action, user, src, dest, app
action.notable.param.drilldown_earliest_offset = $info_min_time$
action.notable.param.drilldown_latest_offset = $info_max_time$

# --- MITRE ATT&CK ---
action.notable.param.mitre_attack_id = ["T1110.003","T1110","T1078"]
action.notable.param.kill_chain_phases = ["exploitation"]

# --- Annotations ---
action.notable.param.annotations = {"confidence":"high","data_source":"Windows Security Events / Authentication Data Model","cis_controls":["CIS-16"],"author":"SOC Engineering","version":"1.0.0"}

# --- Risk Scoring Action ---
action.risk = 1
action.risk.param.risk_object = src
action.risk.param.risk_object_type = system
action.risk.param.risk_score = $risk_score$
action.risk.param.risk_message = Password spray attack from $src$ — $failure_count$ failures targeting $unique_users$ accounts. Asset owner: $src_owner$
action.risk.param.threat_object = src
action.risk.param.threat_object_type = ip_address
```

---

## 10. SPL Patterns for Event-Based Detections

### 10.1 Basic Threshold Detection

**Use case:** Fire when an event count crosses a threshold within the time window.

```spl
`datamodel("Authentication","Authentication")`
| rename "Authentication.*" as "*"
| search action="failure"
| stats count as failure_count by src, dest
| where failure_count > 10
| eval detection = "Excessive Authentication Failures"
| table _time, src, dest, failure_count, detection
```

---

### 10.2 Field Comparison / Allowlist Detection

**Use case:** Fire when a value is NOT in an approved list (allowlist exception detection).

```spl
`datamodel("Endpoint","Processes")`
| rename "Processes.*" as "*"
| search process_name="powershell.exe"
| lookup allowed_powershell_parents parent_process_name OUTPUT allowed
| where isnull(allowed) OR allowed!="true"
| eval risk_flag = if(match(command_line, "(?i)(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})"), "encoded_command", "plain_execution")
| table _time, host, user, process_name, parent_process_name, command_line, risk_flag
```

---

### 10.3 Sequence / Transaction Detection

**Use case:** Detect a sequence of events in a defined order within a time window (e.g., recon followed by exploitation).

```spl
index=wineventlog EventCode IN (4624, 4672, 4688)
| transaction host maxspan=10m keeporphans=false
| where eventcount >= 2
| eval sequence_types = mvjoin(mvdedup(EventCode), ",")
| where match(sequence_types, "4624") AND match(sequence_types, "4672")
| eval detection = "Logon followed by Privilege Escalation"
| table _time, host, user, sequence_types, eventcount, detection
```

---

### 10.4 Rare / Anomaly Detection with stats

**Use case:** Detect rare or first-seen behaviors using statistical rarity.

```spl
`datamodel("Network_Traffic","All_Traffic")`
| rename "All_Traffic.*" as "*"
| search direction="outbound"
| stats count as connection_count, dc(dest_port) as unique_ports, 
         values(dest_port) as port_list by src_ip
| where unique_ports > 20
| eval rarity_score = round((unique_ports / connection_count) * 100, 2)
| where rarity_score > 50
| table src_ip, connection_count, unique_ports, rarity_score, port_list
```

**Using `eventstats` for relative rarity:**
```spl
`datamodel("Authentication","Authentication")`
| rename "Authentication.*" as "*"
| search action="success"
| stats count by user, src_country
| eventstats avg(count) as avg_count stdev(count) as stdev_count by user
| eval z_score = (count - avg_count) / stdev_count
| where z_score > 3 AND src_country != "United States"
| table user, src_country, count, avg_count, z_score
```

---

### 10.5 Threat Intel Matching Detection

**Use case:** Match network events against TI IOC collections.

```spl
`datamodel("Network_Traffic","All_Traffic")`
| rename "All_Traffic.*" as "*"
| search direction="outbound" bytes_out > 0
| lookup ip_intel ip as dest_ip 
    OUTPUT description as ti_description, sev as ti_severity, source as ti_source
| where isnotnull(ti_description)
| eval alert_title = "Outbound connection to known malicious IP: " . dest_ip
| table _time, src_ip, dest_ip, dest_port, bytes_out, bytes_in, 
        ti_description, ti_severity, ti_source, alert_title
```

**Multi-feed TI matching:**
```spl
index=proxy uri_path=* 
| eval dest_domain = replace(uri_path, "^https?://([^/]+).*", "\1")
| lookup domain_intel domain as dest_domain 
    OUTPUT description as domain_intel_desc, sev as domain_sev
| lookup url_intel url as uri_path 
    OUTPUT description as url_intel_desc, sev as url_sev
| eval ti_match = coalesce(domain_intel_desc, url_intel_desc)
| eval ti_severity = coalesce(domain_sev, url_sev)
| where isnotnull(ti_match)
| table _time, src_ip, dest_domain, uri_path, ti_match, ti_severity, action, bytes
```

---

### 10.6 Asset / Identity Enriched Detection

**Use case:** Use asset and identity priority in detection thresholds and risk scoring.

```spl
`datamodel("Endpoint","Processes")`
| rename "Processes.*" as "*"
| search process_name IN ("net.exe","net1.exe") command_line="*localgroup*administrators*"
| lookup asset_lookup_by_str nt_host as dest OUTPUT priority as asset_priority, 
    category as asset_category, owner as asset_owner
| lookup identity_lookup_expanded identity as user OUTPUT priority as user_priority,
    bunit, watchlist
| eval combined_risk = case(
    asset_priority="critical" AND user_priority="critical", 100,
    asset_priority="critical" OR user_priority="critical", 80,
    asset_priority="high" OR user_priority="high", 60,
    watchlist="true", 70,
    true(), 40
  )
| where combined_risk >= 40
| table _time, dest, user, process_name, command_line, asset_priority, 
        user_priority, asset_category, bunit, watchlist, combined_risk
```

---

### 10.7 Multi-Index Detection with union / append

**Use case:** Detect behaviors that span multiple data sources or log types.

```spl
index=wineventlog EventCode=7045 ServiceFileName="*\\Temp\\*"
| eval detection_source="Windows Service Creation in Temp"
| fields _time, host, user, ServiceName, ServiceFileName, detection_source

| append [
    search index=wineventlog EventCode=4698 TaskName="*" 
        [search index=wineventlog EventCode=4698 
         | stats count by TaskName 
         | where count < 3 
         | fields TaskName]
    | eval detection_source="New Rare Scheduled Task"
    | fields _time, host, user, TaskName, detection_source
]

| stats values(detection_source) as detection_sources, 
        values(ServiceFileName) as service_files,
        values(TaskName) as task_names,
        count as event_count by host, user
| where event_count >= 2
| eval multi_stage_persistence = "yes"
```

---

### 10.8 Risk Notables Trigger Pattern

**Use case:** Query the Risk Index to generate notables when cumulative risk exceeds a threshold — this is a detection that operates ON the Risk Index.

```spl
index=risk 
| stats sum(risk_score) as total_risk_score, 
        dc(source) as detection_count,
        values(source) as triggering_detections,
        values(risk_message) as risk_messages,
        values(threat_object) as threat_objects
    by risk_object, risk_object_type
| where total_risk_score >= 100
| eval risk_level = case(
    total_risk_score >= 200, "critical",
    total_risk_score >= 150, "high",
    total_risk_score >= 100, "medium",
    true(), "low"
  )
| table risk_object, risk_object_type, total_risk_score, detection_count, 
        risk_level, triggering_detections, risk_messages, threat_objects
```

---

## 11. Other Detection Types — Reference

### 11.1 Correlation Search

**Definition:** The legacy detection mechanism in Splunk ES. A correlation search is structurally identical to an event-based detection but was created and managed directly via `savedsearches.conf` or via the older "Correlation Searches" UI (available in ES versions before 8.0's unified detection framework).

**Key differences from event-based detections:**
- No unified creation wizard; configured via `savedsearches.conf` or the Correlation Searches editor.
- Same underlying mechanism — saved search + notable/risk action.
- In ES 8.0, correlation searches are visible alongside event-based detections in Content Management.
- Existing correlation searches from ES 7.x are not automatically converted to event-based detections — they continue to function as-is.

**When to use:** Legacy content migration; complex SPL that the UI wizard can't represent; direct `conf`-file automation pipelines.

---

### 11.2 Risk-Based Alerting (RBA) Notable

**Definition:** A special detection (usually a correlation search) that queries the `risk` index and generates a high-fidelity notable event when a Risk Object's accumulated risk score exceeds a threshold. This is the "aggregation layer" on top of all risk-scoring event-based detections.

**Architecture:**
```
Individual Event-Based Detections (many, low-severity) 
    → Risk Index (accumulation)
        → RBA Notable Detection (one, high-fidelity)
            → Incident Review (analyst triage)
```

**Standard ES-provided RBA notable detection:**
```spl
index=risk 
| stats sum(risk_score) as total_risk dc(source) as source_count 
        values(risk_message) as messages values(threat_object) as threats
    by risk_object risk_object_type
| where total_risk >= 100
```

**Benefits:**
- Dramatically reduces alert volume by suppressing individual signals into entity-centric, multi-signal alerts.
- High-fidelity: a Risk Notable for a user with `total_risk=350` from 15 different detection sources is far more actionable than 15 individual low-confidence alerts.
- Investigation context: the Risk Notable bundles ALL contributing risk events and messages into a single notable event.

---

### 11.3 Anomaly Detection

**Definition:** Detections based on statistical deviation from a baseline, often powered by Splunk's Machine Learning Toolkit (MLTK) or ES's built-in anomaly commands.

**Key SPL commands:**

```spl
# Built-in anomaly detection
| anomalies field=bytes_out threshold=0.01

# MLTK density function anomaly detection
| fit DensityFunction bytes_out by src_ip threshold=0.005 into bytes_baseline

# Standard deviation baseline comparison
| eventstats avg(count) as baseline_avg stdev(count) as baseline_std by user
| eval deviation = abs(count - baseline_avg) / baseline_std
| where deviation > 3
```

**Use Cases:**
- User behavior analytics (UEBA): "This user logged in from 3 countries in 2 hours."
- Data exfiltration baseline: "This host uploaded 10x its 30-day average bytes today."
- Process anomaly: "First time this user executed certutil.exe in 90 days."

---

### 11.4 TI-Based Detections

**Definition:** Detections whose primary logic is matching events against threat intelligence feed data. In ES, the TI Framework handles feed ingestion, normalization, and lookup management automatically.

**Configuration path:**
```
ES → Security Intelligence → Threat Intelligence Management
```

**ES automatically runs TI-matching searches** against the following data models based on configured TI sources:
- `IP Intelligence` → matched against `Network_Traffic`, `Authentication`, `Web`
- `Domain Intelligence` → matched against `Network_Resolution`, `Web`
- `File Intelligence` → matched against `Endpoint.Filesystem`, `Endpoint.Processes`
- `URL Intelligence` → matched against `Web`
- `Certificate Intelligence` → matched against SSL/TLS traffic

**Custom TI-based event detection (for custom feeds):**
```spl
`datamodel("Network_Traffic","All_Traffic")`
| rename "All_Traffic.*" as "*"
| lookup custom_threat_feed ip as dest_ip 
    OUTPUT threat_category, confidence, analyst_notes
| where isnotnull(threat_category) AND confidence >= 70
| table _time, src_ip, dest_ip, dest_port, bytes, threat_category, confidence, analyst_notes
```

---

## 12. Detection Tuning and Lifecycle

### 12.1 Baselining and False Positive Reduction

Before deploying a detection in production, baseline its behavior:

```spl
# Step 1: Run detection SPL in historical search (last 30 days) without filtering
`datamodel("Authentication","Authentication")`
| rename "Authentication.*" as "*"
| search action="failure"
| stats count as failure_count dc(user) as unique_users by src
| where failure_count >= 20 AND unique_users >= 5
| stats count by src
| sort -count
| head 20
```

```spl
# Step 2: Identify top FP sources
| inputlookup your_detection_results.csv
| stats count by src
| lookup asset_lookup_by_str ip as src OUTPUT owner, category, bunit
| sort -count
```

**Common FP reduction techniques:**

| Technique | SPL Pattern | Use Case |
|---|---|---|
| Allowlist lookup | `| lookup fp_allowlist src OUTPUT is_allowed \| where isnull(is_allowed)` | Known-good IPs/hosts excluded |
| Category exclusion | `| where asset_category!="monitoring"` | Exclude monitoring/scanning systems |
| Time-based filtering | `| where hour(_time) >= 6 AND hour(_time) <= 22` | Business hours only |
| Threshold increase | `| where count > 50` (increase from 10) | Tune threshold based on baseline |
| Field combination | `| where action="failure" AND user!="svc_*"` | Exclude service account names |

---

### 12.2 Using `makeresults` for Testing

Test detection logic without real data:

```spl
| makeresults count=5
| streamstats count as row_num
| eval 
    src = case(row_num=1, "192.168.1.100", row_num=2, "10.0.0.50", 
               row_num=3, "192.168.1.100", row_num=4, "172.16.0.5", 
               row_num=5, "192.168.1.100"),
    user = case(row_num=1, "jsmith", row_num=2, "ajonas", 
                row_num=3, "bwilliams", row_num=4, "jsmith", 
                row_num=5, "cthomas"),
    action = "failure"
| stats count as failure_count dc(user) as unique_users by src
| where failure_count >= 3 AND unique_users >= 2
```

---

### 12.3 Suppression Management in ES

ES provides a **Suppression** management interface for creating named suppression rules that persist beyond the detection's built-in throttling:

**Path:** `Incident Review → Incident Review Settings → Suppressions`

A suppression rule can match against any field in a notable event and suppress new notables matching that pattern for a defined period. Unlike detection-level throttling, suppressions apply post-facto — they prevent notables matching the suppression criteria from appearing in Incident Review.

```spl
# View active suppressions via SPL
| rest splunk_server=local /servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches
| search title="Suppression - *"
| table title, search, disabled, updated
```

---

### 12.4 Version Control via REST API

Detections can be exported and version-controlled programmatically:

```bash
# Export a detection's configuration via REST API
curl -k -u admin:password \
  "https://splunk-search-head:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/Windows%20-%20Password%20Spray%20-%20Rule?output_mode=json" \
  -o detection_export.json

# Deploy a detection from savedsearches.conf via REST API
curl -k -u admin:password \
  -d @detection_payload.json \
  "https://splunk-search-head:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
```

**GitOps pattern:** Store all detections as `.conf` files in version control → CI/CD pipeline uses the Splunk REST API to deploy changes to search heads.

---

## 13. Permissions and Role-Based Access

| Capability Required | Splunk Role | Action |
|---|---|---|
| `ess_analyst` | ES Analyst | View notable events; update status/owner; run drilldowns |
| `ess_admin` | ES Admin | Create/edit/delete detections; configure TI sources; manage asset/identity |
| `can_write` | Any write-capable role | Required alongside ES roles to save searches |
| `schedule_search` | Required to enable scheduled execution | Scheduling detections |
| `schedule_priority_validation` | Required to set priority above `default` | Setting `higher` or `highest` schedule priority |
| `rest_apps_management` | Admin | Deploying detections via REST API |
| `edit_lookups` | Admin | Modifying asset/identity lookup tables |

**Creating detections from non-admin accounts:**
ES 8.0 allows ES Admin-level users who are not Splunk Admins to create and manage detections. The `ess_admin` role is sufficient for the detection wizard. However, deploying via `savedsearches.conf` direct file editing requires server access or Deployment Server privileges.

---

## 14. Glossary

| Term | Definition |
|---|---|
| **Adaptive Response Action (AR Action)** | A modular action triggered by a detection when it fires; includes notable creation, risk scoring, email, webhook, and integration-specific actions |
| **Correlation Search** | Legacy ES detection mechanism; functionally equivalent to event-based detection but predates the ES 8.0 unified wizard |
| **CIM (Common Information Model)** | Splunk's field naming and data normalization standard; required for cross-source detection portability |
| **Data Model** | A structured representation of CIM-normalized data with predefined fields and relationships; used with `tstats` and `datamodel()` macro |
| **Detection** | In ES 8.0, the unified term for any scheduled search producing security events; replaces "correlation search" in user-facing nomenclature |
| **Drilldown** | A secondary search launched from a notable event in Incident Review to provide raw event context for triage |
| **ES (Enterprise Security)** | Splunk Enterprise Security; the Splunk premium app providing SIEM functionality on top of the Splunk platform |
| **ESCU (Enterprise Security Content Update)** | Splunk's official threat detection content library; provides hundreds of pre-built event-based detections |
| **Identity Center** | ES feature for managing identity/user data used in notable event enrichment and urgency calculation |
| **Incident Review** | The ES analyst triage interface where notable events are queued, reviewed, and worked |
| **Kill Chain** | Lockheed Martin Cyber Kill Chain; 7-phase model of attacker progression used for detection classification |
| **MITRE ATT&CK** | A knowledge base of adversary tactics, techniques, and procedures (TTPs) used for detection mapping and coverage analysis |
| **Notable Event** | An ES alert artifact written to the `notable` index; represents a detected condition requiring analyst attention |
| **RBA (Risk-Based Alerting)** | ES framework for accumulating risk scores across multiple detection signals and generating high-fidelity alerts based on cumulative entity risk |
| **Risk Event** | An artifact written to the `risk` index by a risk-scoring detection; contributes to an entity's risk score without directly creating a notable |
| **Risk Index** | Splunk index (`risk`) storing risk events; the data source for RBA notable detections |
| **Risk Object** | The entity (host, user, IP) to which risk scores are attributed |
| **Risk Score** | A numeric value representing the risk contribution of a single detection firing; additive across detections over a time window |
| **Saved Search** | A stored SPL query in `savedsearches.conf`; the underlying mechanism for all ES detections and scheduled searches |
| **Schedule Window** | The allowable delay (in minutes) for a detection's scheduled execution, used to reduce scheduler contention |
| **Security Domain** | A high-level classification (`access`, `endpoint`, `network`, `threat`, `audit`, `identity`) for organizing detections and notable events |
| **Suppression** | Throttling mechanism that prevents duplicate notable events for the same condition within a defined time window |
| **Threat Intelligence (TI)** | Structured data about known threats (IPs, domains, file hashes) used to match against observed events |
| **Throttling** | See Suppression |
| **Urgency** | The final priority level assigned to a notable event; computed from detection severity × asset or identity priority |
| **`savedsearches.conf`** | Splunk configuration file storing all saved searches, including ES detections; the authoritative source of detection configuration |
| **`tstats`** | A high-performance SPL command for querying summary-indexed or accelerated data model data; preferred for high-volume detection environments |
