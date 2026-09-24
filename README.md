# Identity Risk Analyzer

ASP.NET Core MVC application for read-only Active Directory risk analysis.

**Isolated AD test lab:** [scripts/adlab/README.md](scripts/adlab/README.md) contains the P1-16 Windows Server scripts, setup order, verification, expected findings, and cleanup. **FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.**

## Active Directory configuration

The `ActiveDirectory` section in `src/IdentityRiskAnalyzer.Web/appsettings.json` contains non-secret connection settings:

| Setting | Description |
| --- | --- |
| `Server` | Active Directory LDAP server hostname |
| `Port` | LDAP server port |
| `UseSsl` | Enables LDAPS when `true` |
| `BaseDn` | Directory base distinguished name used by the connection test |
| `ConnectTimeoutSeconds` | Maximum LDAP operation timeout in seconds |
| `PageSize` | Maximum number of LDAP entries requested per result page (1–1000) |

Port 389 is typically used for LDAP. Port 636 is typically used for LDAPS. The server certificate must be trusted by the host running the application.

For a deployment with a trusted domain controller certificate, use LDAPS:

```json
{
  "ActiveDirectory": {
    "Server": "dc01.adlab.test",
    "Port": 636,
    "UseSsl": true,
    "BaseDn": "DC=adlab,DC=test"
  }
}
```

Use the DC DNS hostname covered by its certificate. `UseSsl=true` enables LDAPS immediately on the configured port (normally 636); it does not enable StartTLS. The application uses the operating system's certificate validation and does not accept untrusted or mismatched certificates, including in Development. Explicit credentials remain in User Secrets or protected deployment configuration. The isolated lab instructions for CA, DC enrollment, client trust, and verification are in [scripts/adlab/README.md](scripts/adlab/README.md).

Store explicit credentials with .NET User Secrets during development:

```bash
dotnet user-secrets set "ActiveDirectory:Username" "ADLAB\svc_ira_scanner" --project src/IdentityRiskAnalyzer.Web
dotnet user-secrets set "ActiveDirectory:Password" "password-here" --project src/IdentityRiskAnalyzer.Web
```

When explicit credentials are not configured, LDAP Negotiate uses the current process identity where supported. Never store production credentials in `appsettings.json`, README files, or source control. For production, provide secrets through the deployment environment's protected configuration system.

Open `/ActiveDirectory` to review the safe connection settings and submit the **Test Connection** form. The test performs an LDAP bind and a base-scope query for the configured Base DN; it does not enumerate users or groups.

## Reading Active Directory users

The `/ActiveDirectory/Users` diagnostic page reads users from the configured `BaseDn` using LDAP subtree search and server-side paging. It requests only the attributes used by this stage and returns user records in memory; it does not save a scan or enumerate groups. The page displays at most the first 100 users even when the LDAP collection contains more.

`lastLogonTimestamp` is a replicated value and is presented as **Last Known Activity**, not as an exact last logon time. The application does not request or read user passwords or password hashes.

## Reading Active Directory groups

The `/ActiveDirectory/Groups` diagnostic page reads groups below the configured `BaseDn` with an LDAP subtree search and the same server-side paging setting used for users. It collects each group's direct `member` distinguished names, along with the group's GUID, SID, group type, description, and manager. Large `member` values use Active Directory ranged retrieval; if an additional range cannot be read, collected members are retained and the group is marked incomplete. Nested membership is not calculated, and all collection is read-only and held in memory for the request.

## Nested group analysis

The group graph is built locally from the loaded users and groups. Direct edges come from each group's `member` DNs; the graph resolves those DNs against case-insensitive in-memory user and group indexes. A breadth-first traversal finds the shortest path to each group, counts depth in group edges, and guards against cycles and self-references. `primaryGroupID` is resolved by combining it with the user's domain SID and matching the resulting SID against loaded groups. Foreign security principals or other members absent from the loaded collections are ignored; cross-domain resolution is not performed. `/ActiveDirectory/Users/{objectGuid}/Groups` displays direct and nested paths. The traversal depth limit is configured by `GroupAnalysis:MaxGroupNestingDepth` and defaults to 64.

## Privileged group analysis

`PrivilegeAnalysis:PrivilegedGroups` in `appsettings.json` configures which groups grant administrative membership. The defaults include Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators, and DNSAdmins. Domain Admins, Enterprise Admins, and Schema Admins use their domain-relative RIDs (512, 519, and 518); built-in groups use their well-known SIDs. DNSAdmins uses a configured name because its domain-relative RID is variable. SID/RID matches continue to work if a group is renamed; case-insensitive configured-name matching is the fallback. Add a custom group by adding a definition with its `Name` and optionally a `Sid` or `Rid`, or set `Enabled` to `false` to disable a definition. The analyzer only classifies existing membership paths: it does not infer privilege from words such as “Admin”, perform LDAP lookups, create risk findings, or modify Active Directory. The users list and user group page show whether the user has direct or nested paths to configured privileged groups, including every matched role and its full shortest path.

## Kerberos Delegation Analysis

Delegation analysis uses the LDAP attributes already collected for users. `userAccountControl` identifies unconstrained delegation and the protocol-transition flag; `msDS-AllowedToDelegateTo` provides constrained-delegation targets; presence of `msDS-AllowedToActOnBehalfOfOtherIdentity` identifies an RBCD configuration. Protocol Transition is reported instead of a second Constrained result for the same target list. Independent mechanisms such as Unconstrained Delegation and RBCD remain separate results. `NOT_DELEGATED` by itself is informational protection and does not create a delegation result. The account page shows detected mechanisms, targets, and evidence. RBCD ACL contents are not parsed in this MVP, and the application does not change delegation settings.

## Service Account Detection

Service-account classification uses the LDAP records already collected plus one paged subtree search for managed service accounts. Any collected `servicePrincipalName` is a strong signal; `msDS-ManagedServiceAccount` and `msDS-GroupManagedServiceAccount` object classes are definitive signals. The ordinary user filter remains unchanged because MSA/gMSA objects are computer subclasses; the separate batch search collects them without an LDAP request per account. `/ActiveDirectory/Users` and the user details page include these records.

Optional account-name heuristics are controlled by `ServiceAccountAnalysis:EnableNameHeuristics` and `ServiceAccountAnalysis:NamePatterns` in `appsettings.json`; the defaults are `svc_*`, `service_*`, and `sa_*`. Patterns are case-insensitive globs using `*`, not regular expressions. A pattern-only match is shown as **Possible** with **Heuristic** confidence. SPN matches are **High** confidence; MSA/gMSA matches are **Definitive**. Multiple independent signal types are identified separately. Password expiry, privilege membership, and delegation do not influence this classification. Interactive logon policy is not evaluated because effective rights depend on GPO user-right assignments; the details page states this limitation. Classification is read-only and does not create risk findings or change Active Directory.

## Risk Rule Engine

The account details page runs the deterministic, read-only risk rules against the LDAP record and the existing privilege, delegation, service-account, and duplicate-SPN analysis results. Findings are previews only; P1-10 does not persist them or calculate an object or directory score. Each finding carries its stable rule ID, severity, points, evidence, and a fixed recommendation. Rule errors are logged independently and do not prevent the remaining rules from running.

Thresholds and rule severity/points are configured under `RiskSettings` in `src/IdentityRiskAnalyzer.Web/appsettings.json`. Age thresholds are inclusive. `CurrentUtc` is passed into the evaluation context, and current account lockout is determined from the `LOCKOUT` bit in `msDS-User-Account-Control-Computed`; historical `lockoutTime` alone is not treated as a current lock.

| RuleId | Name and condition | Default severity | Default points |
| --- | --- | --- | ---: |
| IRA-ACCOUNT-001 | Enabled account activity age reaches `InactiveUserDays` | Medium | 15 |
| IRA-ACCOUNT-002 | Account expiration is earlier than evaluation time | Low | 10 |
| IRA-ACCOUNT-003 | Computed UAC contains the current `LOCKOUT` flag | Low | 5 |
| IRA-PASSWORD-001 | UAC contains `DONT_EXPIRE_PASSWORD` | Medium | 15 |
| IRA-PASSWORD-002 | Password age reaches `OldPasswordDays` | Medium | 10 |
| IRA-SERVICE-001 | Classified service account also has `DONT_EXPIRE_PASSWORD` | High | 25 |
| IRA-PRIV-001 | Direct path to a configured privileged group | High | 30 |
| IRA-PRIV-002 | Nested path to a configured privileged group | High | 30 |
| IRA-PRIV-003 | At least two distinct privileged target groups | Medium | 20 |
| IRA-PRIV-004 | Enabled privileged account activity age reaches `InactivePrivilegedUserDays` | High | 30 |
| IRA-DELEGATION-001 | Unconstrained delegation result exists | Critical | 50 |
| IRA-DELEGATION-002 | Constrained delegation result exists | Medium | 20 |
| IRA-DELEGATION-003 | Protocol Transition result exists | High | 35 |
| IRA-DELEGATION-004 | Resource-Based Constrained Delegation is configured | High | 25 |
| IRA-AD-001 | SIDHistory values are present | Medium | 15 |
| IRA-SPN-001 | An SPN is assigned to multiple distinct objects | High | 25 |

Duplicate SPNs are compared case-insensitively across collected user and managed-service-account principals; repeated values on one object alone are not considered a duplicate. Points are configured weights for individual findings and are not summed in this stage. No rule changes Active Directory, and the findings preview uses Razor's normal HTML encoding for evidence.

## Risk Scoring

P1-11 adds an explainable project-specific MVP scoring model. For each object, findings are deduplicated by object, RuleId, category, and evidence/target; findings with the same RuleId but different targets remain separate.

```text
RawScore = sum(max(RiskPoints, 0) for each distinct finding)
Object Risk Score = clamp(RawScore, 0, 100)
```

The displayed object score uses the 0–100 capped value. RawScore is retained separately (saturated at `Int32.MaxValue` if needed) for diagnostics. Default Object Risk Level thresholds are configurable through `RiskSettings:MediumFrom`, `RiskSettings:HighFrom`, and `RiskSettings:CriticalFrom`:

| Score | Object Risk Level |
| ---: | --- |
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

Configuration validation requires `0 <= MediumFrom < HighFrom < CriticalFrom <= 100`. Object level is determined by the score thresholds, not inherited from the most severe finding. Finding severity remains a separate count/display value; no hidden multipliers are applied.

For a non-empty analyzed directory, the summary uses:

```text
AverageObjectRisk = average(Object Risk Score for all analyzed objects)
AD Security Score = round(100 - AverageObjectRisk, nearest integer, midpoint away from zero)
```

The result is clamped to 0–100. An empty object set returns `SecurityScore = null` and `AverageRiskScore = null`; absence of data is not treated as a perfect score. The summary also reports object-level and finding-level severity counts, category totals and affected-object counts, and a configurable top-N list ordered by risk score, critical finding count, finding count, then stable object name/GUID. AD Security Score does not replace the critical/high counters. A score of 0 means low detected risk under the currently implemented rules; an AD Security Score of 100 means the lowest average detected risk. These project-specific scores are not an industry or Microsoft standard.

## Scan Pipeline

`/Scans` starts a request-driven, read-only directory scan. Each scan creates a `Running` row before LDAP collection. The pipeline collects users, managed service accounts, and groups once each; builds group membership paths locally; classifies privileged and service accounts; analyzes delegation and duplicate SPNs; evaluates risk rules; calculates object and AD Security Scores; and saves a SQLite snapshot. `ObjectsScanned` counts unique principals that completed risk evaluation, including managed service accounts, not loaded groups. The final snapshot uses one short SQLite transaction after LDAP and analysis. The existing `InitialCreate` migration is applied automatically at startup; P1-12 makes no schema changes.

The terminal status is `Completed` when there are no recoverable errors, `CompletedWithErrors` when one principal or rule failed or a group's member list is incomplete, `Failed` for a fatal LDAP, analysis, or persistence failure, and `Cancelled` for request cancellation. The run's finish time is stored in UTC. `ErrorsCount` counts rule failures, isolated principal failures, and groups with incomplete direct member lists; individual LDAP entries skipped inside a collector currently appear in server warnings and cannot yet be counted in the run. A database outage can prevent the terminal status from being saved; inspect server logs in that case.

Every scan keeps separate object snapshots, all shortest group membership paths, delegation mechanisms, and the exact deduplicated findings used for scoring. `GroupMembership.PathJson` is a JSON array of display names from principal to target group. Previous scans are never overwritten. `/Scans/{id}` reads the persisted summary, severity counts, top accounts, and recent findings from SQLite without LDAP. Only one scan can run at a time per application instance; multiple application instances do not coordinate. Scans run within the HTTP request, so request cancellation or time limits apply. No AD records or settings are modified.

## Dashboard

`/` and `/Dashboard` display the latest `Completed` or `CompletedWithErrors` ScanRun using SQLite only. The page identifies the ScanRun ID and UTC timestamp. A later `Failed` attempt appears as a separate warning and never replaces the last usable security snapshot. If no usable scan exists, the page shows an empty state and a Start Scan action. Opening the dashboard does not contact Active Directory.

The prominent **AD Security Score** runs from 0 to 100, with 100 representing lower average detected risk. **Account Risk Score** runs in the opposite direction. A null security score appears as **No data**. Findings and accounts are counted separately by severity. Other counters include analysed, service, privileged, and stale accounts. **Stale Accounts** counts distinct object GUIDs with saved finding `IRA-ACCOUNT-001`; the dashboard does not recalculate inactivity rules. Top risky accounts follow risk score, critical finding count, total finding count, stable name, and GUID order. Categories come from saved findings and include distinct affected-account counts.

The history chart and accessible table show up to ten usable ScanRuns in creation order, oldest to newest, on a fixed 0–100 scale. Failed scans are excluded. The chart uses server-rendered HTML and CSS; no Chart.js or frontend build is required. The dashboard also lists high-risk privileged accounts, service accounts ordered by risk score, and the most important findings. Account links open historical account details for the displayed ScanRun.

## Historical Account Details

`/Scans/{scanId}/Objects/{objectGuid}` displays an account from one specific saved ScanRun. The same object GUID can have a different Risk Score, Risk Level, findings, memberships, and delegation in another scan. The page reads only SQLite; it does not contact LDAP or rerun rules or current scoring settings. It shows the saved status, activity, privilege and service-account flags, all saved findings with evidence and recommendations, every privileged path, delegation mechanisms and targets, and all group memberships in pages of 50. Invalid historical `PathJson` or `TargetsJson` produces a visible fallback and a server warning instead of a page failure.

The score breakdown sums nonnegative points from that object's saved findings. The final Account Risk Score and Risk Level remain the stored snapshot values, including when accumulated points exceed the 100-point cap. The historical snapshot currently stores `IsServiceAccount` but not service-account detection method, confidence, or all raw LDAP attributes; the page does not infer or fetch those missing details. Live AD diagnostic pages remain separate from historical scan results.

## CSV Export

Completed and CompletedWithErrors scans provide separate **Accounts CSV** and **Findings CSV** downloads from Scan Details. The endpoints are `GET /Scans/{scanId}/Export/Accounts` and `GET /Scans/{scanId}/Export/Findings`. Failed, Running, Cancelled, and missing scans return 404 rather than an apparent empty report. A completed scan with no accounts or findings produces a header-only file.

Both reports read the specified historical SQLite snapshot only. Export never contacts LDAP or reruns rules, analysis, or scoring. Accounts include saved account risk values and a grouped count of saved findings; Findings include the saved evidence, recommendation, risk points, and the matching snapshot's object risk score and level. No credentials or passwords are included.

The files use semicolon delimiters, UTF-8 with a BOM, and CRLF line endings. Text containing semicolons, quotes, or line breaks is quoted and escaped; multiline evidence is preserved. Potential spreadsheet formulas in text fields are prefixed with an apostrophe before CSV escaping. Numeric fields remain numeric. Booleans use lowercase `true` and `false`; unknown nullable booleans and missing dates are empty cells. Timestamps use ISO 8601 UTC with a `Z` suffix. CSV files are generated in memory and named with the numeric ScanRun ID.

## Optional Security Event Log Analysis

`SecurityEventLog:Enabled` is `false` by default. When enabled during a ScanRun, the Windows collector reads only Security events 4625 (failed logon), 4771 (Kerberos pre-authentication failure), 4776 (credential validation failure), and 4740 (account lockout) from `SecurityEventLog:Server`, or from `ActiveDirectory:Server` if the override is empty. Event 4740 is retained as context; the two current heuristics count failed-authentication events only. The collector reads an indexed time window (`LookbackMinutes`, default 60) and stops at `MaximumEvents` (default 10,000). It normalizes only event metadata and never reads password or hash data. Repeated record IDs are ignored.

The **Possible Password Spray** heuristic requires at least 10 failures involving at least 5 distinct usernames from one source IP or workstation within 10 minutes. **Possible Brute Force** requires at least 10 failures against one case-insensitive username within 10 minutes, regardless of source. All thresholds and windows are configurable. These are indicators for investigation, not proof of attack or compromise; distributed sources, duplicate event types and incomplete audit coverage can cause misses or false positives. No automatic account changes are made.

Mapped scan principals receive object findings `IRA-AUTH-001` (High, 30 points) and `IRA-AUTH-002` (High, 25 points). Unknown or ambiguous usernames receive no object finding; the collector does not make LDAP lookups for them. Authentication findings enter object scoring before the snapshot is saved, so saved findings and scores remain consistent. Enabling the feature when the Security log is unavailable, including on a non-Windows host, marks an otherwise successful scan `CompletedWithErrors` and increments `ErrorsCount`. Skipped malformed records and truncated event windows are also counted. With the feature disabled, the collector is not called.

The scanner may need membership in the DC's **Event Log Readers** group, the DC's remote Event Log access policy and firewall access. In the isolated `adlab.test` lab only, run `scripts/adlab/11-Configure-EventLogReader.ps1 -ConfirmOptionalEventLogAccess` in an elevated PowerShell session on DC01. This script checks the expected single-DC lab and scanner account, then adds the scanner to the group once. It does not grant Domain Admin rights. A fresh scanner logon token may be required. To test safely, use a small fixed set of lab accounts and a few controlled failed logons; do not run generic credential spraying tools. Real DC event collection and attack simulations were not performed in this development environment.

## Optional Exchange delegation inventory

`ExchangeDelegation:Enabled` is `false` by default. The read-only inventory contract and model distinguish **FullAccess**, **SendAs** and **SendOnBehalf** mailbox delegation from Kerberos delegation. No Exchange connection or mailbox permission reader is configured in this deployment; enabling the flag reports the integration as unavailable and records a recoverable scan error. It never produces fabricated mailbox permissions. A supported Exchange session, read-only collector, persistence and operational verification would be needed before this inventory can be used. No Exchange Risk Rule is assigned. Exchange integration was not tested against a real Exchange environment.
