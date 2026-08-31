# Production Security Audit — Full-Stack Commercial Platform

**A self-conducted security audit of a production system I architected and built.**

17 findings scored with CVSS v3.1, classified by CWE, mapped to MITRE ATT&CK, and remediated with verified fixes.

---

## Why This Repository Exists

Most security portfolios show findings against intentionally vulnerable practice targets — DVWA, Juice Shop, HackTheBox machines. Those demonstrate tool familiarity, but they don't demonstrate what happens when you have to find real flaws in real code, under real constraints, where the fix has to ship without breaking production.

This audit is different: I built the system, then audited my own work, then fixed what I found.

That combination — developer context plus adversarial perspective — surfaces a specific class of vulnerability that external scanners consistently miss. The most severe finding in this audit (a privilege escalation via role-composition logic) was invisible to automated tooling. It required reading the authorization code and understanding what the developer *intended* versus what the code *actually did*.

> **Note on scope:** This is a sanitized public summary. Infrastructure identifiers, account details, endpoint paths, and exploitation specifics for unremediated findings have been withheld. The methodology, scoring rationale, and remediation approach are presented in full.

---

## The System Under Audit

A production commercial platform serving an aviation spare parts trading company — replacing fragmented spreadsheet and email workflows with a unified quotation, catalog, and CRM system.

| Layer | Stack |
|---|---|
| **Backend** | FastAPI · PostgreSQL · 190+ API endpoints · 4 isolated schemas · 20 migrations |
| **Frontend** | Next.js 15 · Admin console with CRM · Public multilingual catalog |
| **Auth** | JWT · PBKDF2 password hashing · RBAC across 3 roles |
| **AI** | LLM-based document extraction across 5 languages (text, XLSX, DOCX, scanned PDF via vision) |
| **Infrastructure** | Docker Compose (staging + production) · Caddy reverse proxy with TLS · Object storage |
| **Monitoring** | Wazuh SIEM · Grafana · Loki · Prometheus · fail2ban |

The platform is live and serving real international customers.

---

## Audit Methodology

Static analysis conducted against a pinned commit, with a dedicated pre-audit baseline branch created so every remediation could be diffed and verified.

**1. Authorization surface review**
Every API route handler examined for missing authentication, missing authorization, and absent input validation. Route-by-route, not sampled.

**2. Authentication flow tracing**
End-to-end path traced: password hashing → JWT generation → cookie attributes → session validation → logout → token lifecycle. This is where the highest-severity findings surfaced.

**3. Injection vector analysis**
All SQL construction patterns reviewed for string interpolation. XML and document parsing paths examined for entity expansion and parser-level attacks.

**4. File handling and storage**
Upload validation, MIME type enforcement, size limits, and object-storage key construction reviewed for traversal and namespace pollution.

**5. Infrastructure and configuration**
Container configuration, network exposure, secrets handling, and reverse proxy security posture assessed.

**6. CSRF and origin validation**
Server-action origin checks and cross-site request protections reviewed for bypass conditions.

Each finding was scored with **CVSS v3.1 base metrics**, classified by **CWE**, and mapped to **MITRE ATT&CK** techniques — providing both technical severity and threat-actor context rather than severity alone.

---

## Findings Summary

**17 findings total** — 1 High, 10 Medium, 2 Low, 4 Informational.

| Severity | Count | Remediated |
|---|---|---|
| 🔴 High | 1 | 1 |
| 🟠 Medium | 10 | 7 |
| 🟡 Low | 2 | 1 |
| ⚪ Informational | 4 | 1 |
| **Total** | **17** | **10** |

Remaining findings are documented, prioritized, and scheduled. Two require architectural changes to the authentication model and were deliberately deferred rather than patched incrementally — reasoning explained in [Engineering Judgment](#engineering-judgment) below.

---

## Selected Findings

The following are remediated findings presented in full. Pending findings are omitted from public detail.

---

### AV-01 — Missing rate limiting on authentication endpoint
**CVSS v3.1: 7.4 (High)** · CWE-307: Improper Restriction of Excessive Authentication Attempts · MITRE ATT&CK: T1110 (Brute Force)

**Finding**
The login endpoint enforced no attempt throttling. An attacker could submit unlimited credential guesses at full request rate, with no lockout, no delay, and no signal to defenders.

**Impact**
Direct credential brute-force and password-spraying viability against all accounts. With no rate limit, the only barrier is password entropy — and in a system with a small, known user base, that's a thin defense.

**Remediation**
Implemented adaptive rate limiting as FastAPI middleware using a sliding-window counter keyed on client IP. After a threshold of consecutive failures, the endpoint returns HTTP 429 with a `Retry-After` header. The failure counter resets on successful authentication, so legitimate users who mistype aren't progressively penalized.

**Verification**
Consecutive failed authentication attempts confirmed to trigger 429 with correct `Retry-After` value at the expected threshold. Successful login confirmed to reset the counter. Legitimate authentication flow confirmed unaffected.

---

### AV-06 — Privilege escalation via role-composition logic flaw
**CVSS v3.1: 6.5 (Medium)** · CWE-863: Incorrect Authorization · MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)

**Finding**
A buyer-restriction check determined role status by counting assigned roles rather than checking for role presence. The logic evaluated whether a user had exactly one role in order to classify them as buyer-restricted.

Any user assigned two roles — one of which was the restricted buyer role — failed the count check and bypassed the restriction entirely, gaining access to functionality the role was explicitly designed to block.

**Why this matters**
This is the finding that justifies manual code review. No scanner flags it. No dependency audit catches it. There is no CVE. The code is syntactically correct, passes type checking, and reads as reasonable at a glance. It fails only because the author's mental model — *"a buyer is someone whose only role is buyer"* — diverged from the security requirement: *"a buyer is anyone holding the buyer role."*

Finding it required reading the authorization logic with an attacker's question in mind: *what input makes this check return the wrong answer?*

**Remediation**
Rewrote the check to test for role presence rather than role cardinality. Restriction now applies correctly regardless of how many additional roles a user holds.

**Verification**
Multi-role user with buyer role confirmed to be correctly restricted post-fix. Single-role users confirmed unaffected. No regression in legitimate multi-role access paths.

---

### AV-07 — CSRF origin validation permitted missing Origin header
**CVSS v3.1: 5.4 (Medium)** · CWE-352: Cross-Site Request Forgery · MITRE ATT&CK: T1189 (Drive-by Compromise)

**Finding**
Server-action origin validation treated a missing `Origin` header as acceptable rather than as a failure condition. The check validated the header's *value* when present, but did not require its *presence*.

**Impact**
Requests that omit the Origin header entirely — achievable through several client and proxy conditions — bypassed CSRF protection rather than being rejected by it.

**Remediation**
Hardened the origin assertion to treat a missing Origin as disallowed. Fail-closed rather than fail-open.

**Verification**
Server action invoked without Origin header confirmed rejected. Legitimate same-origin requests confirmed unaffected.

---

### AV-08 — Internal notes exposed in customer-facing response payloads
**CVSS v3.1: 5.3 (Medium)** · CWE-200: Exposure of Sensitive Information to an Unauthorized Actor · MITRE ATT&CK: T1213 (Data from Information Repositories)

**Finding**
Response serialization for buyer-owned resources included internal operational notes intended solely for staff visibility. The data was not rendered in the customer-facing UI, but was present in the API response body and therefore accessible to any authenticated customer inspecting network traffic.

**Impact**
Leakage of internal commercial commentary — pricing rationale, client assessments, operational notes — to the customers those notes concerned.

**Remediation**
Separated response models by audience. Buyer-facing serialization excludes internal fields at the schema layer rather than relying on frontend rendering to hide them.

**Verification**
Buyer-context API responses confirmed to omit internal fields entirely. Staff-context responses confirmed to retain full visibility.

---

### AV-02, AV-03, AV-04, AV-12 — Authentication hardening cluster
**CVSS v3.1: 3.7 – 5.3 (Low/Medium)** · CWE-203, CWE-693, CWE-614, CWE-525

Four related findings addressed together as an authentication-surface hardening pass:

| ID | Finding | CWE | Remediation |
|---|---|---|---|
| **AV-02** | Username enumeration via response timing differential | CWE-203 | Normalized authentication response timing regardless of account existence |
| **AV-03** | Absent security response headers | CWE-693 | Added `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` at reverse proxy layer |
| **AV-04** | Session cookie `Secure` flag applied conditionally | CWE-614 | `Secure` enforced unconditionally |
| **AV-12** | Missing `Cache-Control: no-store` on authentication responses | CWE-525 | Explicit no-store directive on all auth-flow responses |

---

### AV-09 — Backend authorization errors surfaced as server errors
**CVSS v3.1: 3.1 (Low)** · CWE-755: Improper Handling of Exceptional Conditions

**Finding**
Backend 403 responses were not handled at the frontend proxy layer, surfacing to users as generic 500 server errors rather than authorization failures.

**Impact**
Primarily operational rather than exploitable — but it obscured genuine authorization events in logs, degrading the signal available for detecting authorization probing.

**Remediation**
Explicit handling for backend authorization responses, propagating correct HTTP semantics to the client and preserving the authorization signal in logs.

---

## Engineering Judgment

Two findings — server-side session revocation and token lifecycle synchronization — remain open by deliberate decision rather than oversight.

Both require replacing the current stateless authentication model with either refresh-token rotation or opaque server-side sessions. Both are documented, scored, and scheduled.

The reasoning for deferral: patching these incrementally would mean touching the authentication model twice — once with a partial mitigation, then again with the correct architecture. For a system at its current scale and threat exposure, the residual risk over one sprint is acceptable, and shipping the correct design once is better engineering than shipping a stopgap and then rewriting it.

Documenting a known risk with a rationale and a timeline is not the same as missing it. Security work is a series of prioritization decisions under constraint — the audit's value is in making those decisions explicit rather than pretending every finding is equally urgent.

---

## Defensive Controls Implemented

Beyond the audit remediations, the platform's security posture includes:

**Layered file scanning** — Uploads pass through magic-byte signature verification, ClamAV scanning, and hash-based reputation checking. Defends against polyglot files and macro-bearing document attacks that MIME-type validation alone misses.

**Correct client IP resolution for rate limiting** — Rate limits key on the CDN-provided client IP header rather than the client-controllable forwarded-for chain. Using the spoofable header would have made the rate limit trivially bypassable by an attacker rotating a forged value.

**SSH attack surface elimination** — Public SSH exposure removed entirely in favor of mesh-VPN-only access. Prior to this change, host logs recorded **50,000+ blocked authentication attempts** — the exposure was actively exploited, not theoretical.

**Full monitoring stack** — Wazuh SIEM with Grafana, Loki, and Prometheus, deployed from scratch and routed through an encrypted proxy chain to satisfy network egress restrictions in the deployment region.

**Schema-level data isolation** — Four PostgreSQL schemas enforce data boundaries at the database layer rather than relying solely on application-level authorization.

---

## Ongoing Work

| Area | Status |
|---|---|
| Dynamic analysis (OWASP ZAP / Burp Suite) against staging | Scheduled |
| IDOR testing across cross-tenant resource access | Scheduled |
| Dependency vulnerability scanning (`pip-audit`, `npm audit`) with CVE triage | Scheduled |
| Container hardening — non-root execution, image CVE scanning | Scheduled |
| CI integration — secrets scanning, dependency alerts, image scanning in build pipeline | Planned |

---

## What This Demonstrates

| Capability | Evidence |
|---|---|
| **Vulnerability discovery** | 17 findings in production code, including a logic flaw no scanner detects |
| **Industry-standard scoring** | CVSS v3.1 base metrics, CWE classification, MITRE ATT&CK mapping |
| **Remediation engineering** | Fixes designed, shipped, and manually verified against a baseline branch |
| **Full-stack security context** | Findings span auth, authorization, serialization, parsing, storage, and infrastructure |
| **Defensive engineering** | SIEM deployment, layered file scanning, attack-surface reduction with measured results |
| **Risk communication** | Severity-prioritized reporting with explicit rationale for deferral decisions |

---

## Contact

**Bruno Paolo Huaman Vela**
Security Engineer — AppSec & DevSecOps

📧 bhvela2000@gmail.com
🔗 [LinkedIn](https://www.linkedin.com/in/bruno-huaman-vela-648b431a7/)
💻 [GitHub](https://github.com/brunoh6)

ISO/IEC 27001 Certified
