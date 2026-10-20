# SIH 2026 — AI Email Threat Detection, Geolocation & Forensic Intelligence

**Project plan and execution blueprint**

| Field | Value |
|---|---|
| Document | `PLAN.md` |
| Version | 1.0 (draft for approval) |
| Status | Awaiting approval before Phase 0 |
| Team | Solo developer |
| Constraints | CPU-only, free tools only, offline-capable demo |
| Working name | `sih-email-forensics` |

**Stack update (approved):** React 18 + Vite replaces Streamlit for the frontend. FastAPI remains
the API layer. Python 3.12 is the runtime. This document has been updated accordingly; Phase 0
and the Phase 1 vertical slice are implemented.

---

## 0. How to use this document

This is the single source of truth for **what we are building, why, in what order, and how we
know each step is done**.

- Sections 1–2 establish shared understanding of the problem and a precise product definition.
- Sections 3–5 are the technical design.
- Section 6 is the phase-by-phase execution plan with exit gates.
- Sections 7–12 cover testing, risks, compliance, and conventions.
- Section 13 tracks open questions; Section 14 is the progress checklist.

Rules:
1. No phase starts until the previous phase's **exit gate** is met.
2. Every phase produces a runnable artifact, not just code.
3. If time runs short, use the **cut order** in Section 6.8, never skip the demo path.
4. Anything not listed as in-scope is out of scope by default.

---

## 1. Understanding the problem statement

### 1.1 The problem in one paragraph

Email is still a primary attack channel. Attackers use spoofed domains, display-name
impersonation, lookalike domains, compromised accounts, AI-written social engineering, hidden
redirects, and relay chains to bypass spam filters. Existing defenses mostly **filter or block**
but do not produce **investigative intelligence**: who sent it, through which infrastructure,
from where, whether the account was compromised, and whether it belongs to a larger campaign.
Investigators are left with raw headers and no correlation. The ask is a platform that both
**detects** fraudulent email and **forensically explains its probable origin** in a way that is
defensible, privacy-aware, and usable by analysts, administrators, fraud teams, and law
enforcement support.

### 1.2 Who the users are and what they need

| User | Primary question | What the product must give them |
|---|---|---|
| SOC / security analyst | Is this malicious? Why? | Risk score, label, top reasons, IOCs, auth results |
| Institutional email admin | Is our domain being spoofed? | Sender authentication evidence, domain intelligence |
| Fraud / BEC response team | Is this a payment diversion attempt? | BEC indicators, reply-to mismatch, requested amount, campaign link |
| Investigator / law-enforcement support | Where did it probably come from? | Relay path, origin IP, geolocation, ASN/hosting, infrastructure graph, confidence level |
| Compliance / legal reviewer | Can this be used as evidence? | Hashes, timestamps, methodology, limitations, privacy controls |

### 1.3 What current tools do vs what we add

| Existing capability | Gap we address |
|---|---|
| Spam filters, blocklists, signatures | No explanation, no origin trace, no correlation |
| Header viewers | Raw data, no validation, no geolocation, no risk synthesis |
| Threat intel feeds | Isolated indicators, not tied to a specific email or campaign |
| Sandboxing | Focuses on attachments/URLs, not sender identity or routing |
| SIEM | Needs pre-built detections; no email-specific forensic workflow |

### 1.4 What "forensic intelligence" means concretely

The product is a chain of evidence. Each link must be explicit and reproducible:

```
Raw .eml (hashed, immutable)
   -> Parsed headers + body (evidence extraction)
   -> Auth validation: SPF / DKIM / DMARC (did the claimed sender really send it?)
   -> Relay reconstruction: Received chain (what path did it take?)
   -> Origin resolution: earliest trustworthy public IP (where did it enter?)
   -> Enrichment: geolocation, ASN/ISP, reputation, Tor/VPN/hosting, domain age/registrar
   -> Content analysis: NLP/LLM classification and social-engineering indicators
   -> Correlation: IOCs, graph links, campaign clustering, prior cases
   -> Scoring: weighted, confidence-aware verdict with top reasons
   -> Report: human-readable, machine-exportable, evidence-grade
```

Key principle: **detection is probabilistic; evidence is deterministic.** We never let the LLM
invent indicators. Every IOC in a report must come from parsed bytes or an enrichment response.

### 1.5 Requirement traceability matrix

| Problem-statement requirement | Our capability | Demo evidence |
|---|---|---|
| Ingest raw email, metadata, headers | `.eml`/`.msg` upload + parser | Upload 3 files, see parsed metadata |
| Validate sender authentication | SPF/DKIM/DMARC parsing + live DNS checks + alignment | Auth table with pass/fail and DNS proof |
| Extract indicators of compromise | Deterministic IOC extractor (IP, domain, URL, hash, CID) | IOC table, exportable JSON |
| Reconstruct relay paths | Received-chain parser with trust boundaries | Hop table + trace map |
| Analyze originating IP + geolocation | Origin resolver + offline GeoIP + ASN | World map with pins and path lines |
| Confidence-based fraud risk | Weighted scorer (0–100) + label + reasons | Risk badge and gauge |
| Domain intelligence | WHOIS/RDAP age, registrar, MX, SPF/DMARC, lookalike check | Domain panel in detail view |
| Identity correlation / attribution support | Graph + campaign clustering + threat-intel matches | Graph view and campaign grouping |
| Actionable alerts | Immediate per-file verdicts, high-risk banner | Results table sorted by risk |
| Visual trace maps | Leaflet map from Received chain | Map tab |
| Forensic reports | Jinja2 -> HTML -> PDF | Downloadable PDF |
| Searchable case management | SQLite-backed analyses/cases/campaigns | Campaign view |
| Privacy, legal, evidentiary standards | Hashing, offline mode, redaction, disclaimers, methodology | Report appendix + privacy section |

### 1.6 What we will NOT claim

- We will not claim to identify a **person**. We identify **probable infrastructure and location**.
- IP geolocation is approximate and can be deliberately misleading (VPN, Tor, relay, cloud).
- A DKIM pass does not prove good intent; a DKIM fail does not prove malice.
- Header chains can contain attacker-injected `Received` lines; origin confidence must reflect this.
- AI classification is advisory evidence, not a legal conclusion.

These limitations will appear in the UI and in every generated report. Stating them increases
credibility with judges and mirrors real forensic practice.

### 1.7 "Explain it back" checklist (viva readiness)

Before Phase 4, the developer should be able to explain, without notes:

1. What SPF checks, and why it breaks on forwarding.
2. What DKIM signs, and why it usually survives forwarding.
3. What DMARC alignment means, and the difference between `p=none` and `p=reject`.
4. How `Received` headers are ordered and which end is earliest.
5. Why the bottom-most public IP is not always the true origin.
6. Why `Return-Path`, `From`, and `Reply-To` can differ, and when that is malicious.
7. What ASN, ISP, hosting, VPN, and Tor signals mean for attribution confidence.
8. Why WHOIS/RDAP age is a weak but useful signal.
9. How a weighted score can be gamed, and why confidence is reported separately.
10. What chain-of-custody data (hash, timestamp, tool version) is needed for evidentiary use.

---

## 2. Product definition

### 2.1 Goals

1. Accept raw email files and produce a complete forensic analysis in seconds.
2. Detect phishing, BEC, spoofing, and impersonation with explainable signals.
3. Trace the relay path and estimate probable origin with explicit confidence.
4. Correlate related emails into campaigns.
5. Generate a professional forensic report suitable for institutional and legal review.
6. Run entirely on a laptop CPU, with free/offline fallbacks for every external dependency.

### 2.2 Non-goals (for this version)

- Live SMTP/IMAP mailbox monitoring.
- Automatic blocking/quarantine actions in a mail server.
- Attachment detonation sandboxing (static hashes/names only).
- Real-time enterprise-scale streaming (batch upload only).
- Training a custom LLM from scratch.
- Definitively identifying a human actor.

### 2.3 Product scope

**MVP (must ship):**
- Batch `.eml` upload (single `.msg` best-effort).
- 5 signals: auth, domain, IP reputation/geo, NLP, header anomalies.
- Weighted score + label + top-3 reasons.
- Origin resolution + geolocation map.
- IOC table.
- Graph view (email -> IP -> domain -> campaign).
- PDF forensic report.
- Campaign grouping.
- Offline/demo mode with cached enrichments.

**Stretch (only after MVP is green):**
- `.msg` full support with attachment extraction.
- URL screenshotting or sandbox integration.
- Threat-intel pulse correlation (OTX).
- Similarity search over historical emails.
- Analyst notes and case status workflow.
- Docker Compose one-command deployment.
- Webhook/Slack alerting.

**Explicitly out:**
- SMTP gateway integration.
- User mailbox OAuth.
- Multi-tenant RBAC.
- GPU inference.
- Real-time pcap/network analysis.

### 2.4 Demo script (the definition of success)

A 3-minute demo must show all of the following without a crash and without a paid API:

1. Upload 3 `.eml` files (legit, phishing, BEC).
2. Results table shows three different risk levels with reasons in under 5 seconds each.
3. Open the phishing email:
   - Risk badge and gauge.
   - Auth table with SPF/DKIM/DMARC and DNS evidence.
   - Trace map with at least 3 hops and geographic pins.
   - IOC table with reputation annotations.
4. Open the graph tab: email linked to IPs, domains, and a campaign.
5. Click "Generate PDF": a multi-section forensic report downloads and opens.
6. Campaign view groups the phishing and BEC samples if they share infrastructure; otherwise
   show two distinct campaigns with clear reasons.
7. Turn off Wi-Fi (or set `OFFLINE_MODE=true`) and repeat step 3 using cached enrichments.

---

## 3. Architecture

### 3.1 High-level pipeline

```
+------------------------------------------------------------------+
| React UI (Vite)                                                  |
| Upload -> Results -> Detail (map/graph/auth/IOC) -> Campaigns    |
|                          | PDF download                          |
+--------------------------+---------------------------------------+
                           | HTTP/JSON (FastAPI)
+--------------------------v---------------------------------------+
| Analysis service (pure Python, importable library)               |
|                                                                  |
|  ingest -> parse headers/body -> extract IOCs -> auth validate   |
|        -> resolve origin -> enrich IP/domain/URL                 |
|        -> LLM classify -> score -> graph -> cluster -> report    |
+------+----------------+----------------+----------------+--------+
       |                |                |                |
   Local GeoIP      DNS/RDAP         Free TI APIs     Ollama (local)
   (MMDB file)      (dnspython)      (cached HTTP)    or OpenAI API
```

### 3.2 Architectural decisions that differ from the pasted spec

These are deliberate corrections; approve or override them before Phase 0.

| # | Original | Change | Why |
|---|---|---|---|
| 1 | `email-parser==3.0.0` | Python stdlib `email` (+ `extract-msg` for `.msg`) | Stdlib is RFC-compliant, maintained, zero risk; the pinned package is dubious/unmaintained |
| 2 | `maxminddb-geolite2==2024.0` auto-download | `geoip2` + bundled MMDB; DB-IP Lite fallback | MaxMind now requires an account/license key; the auto-download package is stale |
| 3 | Redis required in Compose | `diskcache` by default; Redis optional | Removes infrastructure for a solo demo; disk cache survives restarts |
| 4 | Only Redis cache | Add SQLite for analyses/cases/campaigns | Campaign view needs persistence; SQLite is zero-infra |
| 5 | LLM produces IOCs | LLM classifies and explains only; IOCs are deterministic | Prevents hallucinated evidence |
| 6 | Auth "all fail = 25" | Granular per-mechanism scoring, forwarding-aware | Avoids false positives on legitimate forwards |
| 7 | Build backend fully, then frontend | Vertical slice by end of Phase 1 | Keeps a demo path alive from day one |
| 8 | `weasyprint` Python-only | Document macOS system deps (`pango`, `libffi`); HTML fallback | PDF must never block a demo |
| 9 | "Real-time" alerts | Immediate batch verdicts + in-app alert banner | Honest scope for file-upload ingestion |
| 10 | Datasets assumed present | Phase 0 acquisition + schema validation + license record | The repo currently contains no data |
| 11 | Streamlit frontend | React 18 + Vite, plain CSS, Fetch API | Requested stack; cleaner separation and a production build step |

### 3.3 Module contracts

Each module is a pure function or class with explicit input/output, independently testable.

| Module | Input | Output |
|---|---|---|
| `ingest.py` | uploaded bytes + filename | `RawEmail` (sha256, bytes, size, format) |
| `header_parser.py` | `RawEmail` | `ParsedEmail` (headers, body, attachments, received chain, auth results) |
| `ioc_extractor.py` | `ParsedEmail` | `IOCSet` (IPs, domains, URLs, emails, hashes, CIDs) |
| `auth.py` | `ParsedEmail` + DNS resolver | `AuthReport` (SPF, DKIM, DMARC, alignment, evidence) |
| `origin.py` | received chain + trust config | `OriginReport` (candidate IPs, chosen origin, confidence, method) |
| `enrichers/ip_enrich.py` | IP list | geo, ASN, ISP, reputation, VPN/Tor/hosting flags |
| `enrichers/domain_enrich.py` | domain list | WHOIS age, registrar, MX, SPF/DMARC records, lookalike score |
| `enrichers/url_enrich.py` | URL list | redirect chain, reputation, URLhaus/VT hits |
| `ml/llm_classifier.py` | subject + body + headers | label, confidence, reasoning, social-engineering cues |
| `scorer.py` | all reports | score 0–100, label, top-3 reasons, confidence, signal breakdown |
| `graph_builder.py` | analysis result | NetworkX graph serialized to JSON for the React graph view |
| `campaign_cluster.py` | analyses store | campaign assignments + keys matched |
| `report_gen.py` | analysis + template | HTML and PDF bytes |
| `store.py` | analysis/case records | SQLite CRUD, search |

### 3.4 Canonical analysis result (JSON contract)

All layers depend on one schema. Define it as a Pydantic model in `backend/app/schemas.py`.

```json
{
  "id": "uuid",
  "evidence": {
    "filename": "phish.eml",
    "sha256": "…",
    "size_bytes": 12345,
    "analyzed_at_utc": "2026-…Z",
    "tool_version": "0.1.0",
    "offline_mode": true
  },
  "email": {
    "message_id": "…",
    "date": "…",
    "from": {"display": "…", "address": "…", "domain": "…"},
    "reply_to": {"address": "…", "domain": "…"},
    "return_path": {"address": "…", "domain": "…"},
    "to": ["…"],
    "subject": "…",
    "body_text_excerpt": "…",
    "attachments": [{"filename": "…", "sha256": "…", "content_type": "…"}]
  },
  "auth": {
    "spf": {"result": "fail", "domain": "…", "client_ip": "…", "evidence": "…"},
    "dkim": [{"result": "pass", "domain": "…", "selector": "…"}],
    "dmarc": {"result": "fail", "policy": "none", "aligned": false},
    "alignment": {"spf_aligned": false, "dkim_aligned": true},
    "score": 18,
    "notes": ["…"]
  },
  "routing": {
    "hops": [{"index": 0, "from": "…", "by": "…", "ip": "…", "timestamp": "…", "delay_seconds": 3, "trusted": false}],
    "origin_ip": "…",
    "origin_confidence": 0.72,
    "origin_method": "first_external_hop_before_trusted_mx",
    "anomalies": ["private_ip_in_chain", "timestamp_regression"]
  },
  "enrichment": {
    "ip": {"…": {"country": "…", "city": "…", "asn": 123, "isp": "…", "hosting": true, "vpn": false, "tor": false, "abuse_score": 87, "sources": ["maxmind", "abuseipdb"]}},
    "domain": {"…": {"age_days": 4, "registrar": "…", "mx": ["…"], "spf": "…", "dmarc": "…", "lookalike_of": "microsoft.com", "distance": 1}},
    "url": {"…": {"final_url": "…", "status": 200, "urlhaus": true, "vt_malicious": 4}}
  },
  "nlp": {"label": "phishing", "confidence": 0.91, "reasoning": "…", "cues": ["urgency", "credential_request"]},
  "score": {
    "total": 86,
    "label": "malicious",
    "confidence": 0.88,
    "signals": {"auth": 18, "domain": 16, "ip": 20, "nlp": 18, "header": 14},
    "top_reasons": ["SPF and DMARC fail for sender domain", "Domain registered 4 days ago", "Origin IP is a Tor exit node"]
  },
  "iocs": [{"type": "ip", "value": "…", "verdict": "malicious", "sources": ["feodo"]}],
  "campaign_id": "camp-…",
  "limitations": ["Geolocation is approximate", "…"]
}
```

### 3.5 Origin IP resolution (the hardest correctness problem)

Naive "first public IP in the chain" is wrong because attackers inject fake `Received` headers.
The resolver must be evidence-driven and honest about uncertainty.

Algorithm:

1. Parse all `Received` headers with their position, `from`, `by`, timestamp, and any IP literal.
2. Build the chain in **bottom-up** order (last header = earliest hop).
3. Mark hops as trusted if `by` matches a configured trusted MX/internal CIDR.
4. Walk from the trusted boundary outward to the first external public IP. That is the candidate.
5. Discard RFC1918, loopback, link-local, CGNAT, multicast, malformed, and duplicate hops.
6. Cross-check with `Received-SPF` client IP and `Authentication-Results` when present.
7. If candidates conflict, or if the chain is truncated/malformed, return `origin_ip=null` with
   `origin_confidence < 0.3` and an explanation.
8. Never promote a hop to "origin" solely because it appears in a header added by an untrusted host.

Output includes `origin_method` so the report can show its work. The scorer awards fewer
"malicious infrastructure" points when origin confidence is low, and adds an uncertainty note
instead of guessing.

### 3.6 LLM usage policy

**Allowed:** classify intent; summarize social-engineering cues; produce short analyst-style
reasoning; suggest which signals co-occur.

**Forbidden:** invent IOCs, invent headers, claim a specific person, output legal conclusions.

Rules:
- Deterministic IOC extraction runs before and independently of the LLM.
- Truncate input (subject + first ~2,000 tokens of body + selected headers).
- Temperature 0, JSON-only output, validate with a schema, one retry on parse failure.
- Cache by SHA-256 of the prompt payload.
- Hard cap: 100 LLM calls/day; on cap or failure, fall back to TF-IDF/LightGBM or a
  rule-based cue classifier. The pipeline must never fail because the LLM is unavailable.
- Prompt injection in the email body is treated as **data**, not instructions. The system prompt
  explicitly says so, and the output schema is the only accepted response shape.

### 3.7 Frontend and backend split

- `backend/app/services/` is a plain importable library with no FastAPI dependency.
- FastAPI is the only transport layer; it owns validation, upload limits, and persistence.
- React (Vite) consumes the JSON API. During development, Vite proxies `/api` to
  `http://127.0.0.1:8000`; in production it can be served as static files or from a CDN.
- SQLite stores analyses and campaigns so the case queue and campaign view survive restarts.
- Reports are generated by the backend and streamed as downloads.
- Frontend state is intentionally small: case list, selected analysis, upload status. No global
  state library is needed at this stage.

---

## 4. Data and intelligence sources

### 4.1 Datasets

Public corpora were acquired on **2026-10-20** and placed under `data/raw/` (gitignored).
Sources, licenses, checksums, row counts, and header coverage are recorded in
`docs/DATA_SOURCES.md`; `scripts/fetch_datasets.sh` reproduces the downloads.

| Corpus | Local path | Intended use |
|---|---|---|
| Nazario Phishing Corpus (2025) | `data/raw/nazario/` | Raw phishing `.eml`; relay, auth, origin, IOC tests |
| Apache SpamAssassin Public Corpus | `data/raw/spamassassin/` | Ham/spam header baseline |
| MeAJOR 2.0 | `data/raw/meajor/` | 108,685 preprocessed labelled bodies |
| Nigerian Fraud | `data/raw/curated_phishing/` | Fraud and BEC-adjacent text |
| cw-l email-corpus | `data/raw/cw-l-email-corpus/` | Recent redacted body/HTML; no routing headers |
| r-dube BEC datasets | `data/raw/bec/` | BEC subject/body cues |
| rtr-rep synthetic samples | `data/raw/synthetic_bec_samples/` | Safe end-to-end `.eml` tests |
| zefang-liu phishing dataset | `data/raw/hf_zefang_liu/` | Labelled text baseline |

The original spec filenames `phishing_validation.csv`, `phishing_data_by_type.csv`, and
`africa_bec.csv` were not present and no public copies were found. `meajor.csv` is covered by
the MeAJOR 2.0 release. No public raw-header BEC corpus was found; BEC header tests currently
use controlled synthetic samples.

Phase 0 tasks:
1. Record the original source and license for each corpus in `docs/DATA_SOURCES.md`.
2. Validate schemas with `scripts/validate_data.py`; fail loudly on missing columns.
3. De-duplicate by normalized body hash.
4. Create a **grouped split** by sender domain to prevent leakage.
5. Produce a small, committed `data/fixtures/` sample (e.g., 50 rows, license permitting) so tests
   run without the full corpus.

If a dataset cannot be re-acquired or its license is unclear, do not ship it. The system must
still demo using the hand-written `.eml` fixtures and any clearly licensed subset.

### 4.2 External services, budgets, and fallbacks

| Function | Primary | Free limit | Cache TTL | Fallback |
|---|---|---|---|---|
| Geo/ASN | Local MMDB (MaxMind GeoLite2 or DB-IP Lite) | Unlimited | 30 days | None needed (bundled) |
| IP abuse | AbuseIPDB | 1,000/day | 7 days | Shodan InternetDB, local blocklist |
| IP intel | Shodan InternetDB | Unmetered | 7 days | Skip, mark unavailable |
| Tor/Feodo | Feodo Tracker JSON + Tor exit list | Unmetered | 24 hours | Bundled snapshot |
| Domain WHOIS | RDAP (via `ipwhois`/HTTP) | Unmetered | 30 days | `python-whois`, bundled cache |
| DNS | `dnspython` | Unmetered | 1 hour | Cached records |
| URL rep | URLhaus | Unmetered (auth) | 24 hours | VT if key present |
| URL/file rep | VirusTotal | 500/day | 7 days | URLhaus |
| LLM | Ollama `phi3:mini` | Free | by prompt hash | TF-IDF model, rules |

Budget guardrails:
- Per-email cap: 3 IP lookups, 2 domain lookups, 5 URL lookups.
- Batch cap: 20 files per upload.
- Global daily cap enforced in `utils/budget.py`; when exhausted, degrade to cache-only.
- Circuit breaker: 3 consecutive failures disables a source for the session and annotates the
  report with "source unavailable".
- All HTTP calls use timeouts (3–5 s), retries (max 1), and a descriptive User-Agent.

### 4.3 Cache layout

```
data/cache/
  ip/<sha256>.json
  domain/<sha256>.json
  url/<sha256>.json
  llm/<sha256>.json
  feeds/feodo.json
  feeds/tor_exits.txt
```

Every cache entry stores `fetched_at`, `source`, `payload`, and `ttl`. A `--refresh` flag bypasses
reads. The demo can ship a pre-warmed cache (`make warm-cache`) so judging works offline.

---

## 5. Detection design

### 5.1 Signal weights (total 100)

| Signal | Max | What earns points |
|---|---|---|
| Authentication | 25 | SPF/DKIM/DMARC failures, alignment mismatch, missing records |
| Domain anomaly | 20 | Very new domain, lookalike/homoglyph, freemail in business context, missing auth DNS, disposable |
| IP reputation | 20 | Abuse score, Tor/proxy/VPN, hosting/DC, Feodo/botnet, blocklists |
| NLP classification | 20 | Phishing/BEC confidence; spam gets partial credit; legitimate gets zero |
| Header anomaly | 15 | Excessive hops, missing/forged Received, private IPs, timestamp regression, Reply-To mismatch, Message-ID mismatch |

Score interpretation:
- `>= 70`: **Malicious**
- `40–69`: **Suspicious**
- `< 40`: **Likely legitimate**

Report score and confidence separately. A high score built on missing data is not high confidence.

### 5.2 Granular authentication scoring

Do not simply check "all three failed". Proposed points (capped at 25):

| Condition | Points |
|---|---|
| SPF fail | 8 |
| SPF softfail | 5 |
| SPF none | 4 |
| DKIM fail (all signatures) | 7 |
| DKIM none | 5 |
| DMARC fail | 8 |
| DMARC none | 4 |
| SPF alignment fail while SPF passes | 3 |
| DKIM alignment fail while DKIM passes | 3 |
| From domain has no SPF and no DMARC | 2 |

Forwarding awareness:
- If the message was forwarded by a trusted mailing list, SPF may legitimately fail while DKIM
  passes. Detect `Received` hops from known forwarders or `List-*` headers, and reduce SPF weight.
- If DKIM passes for a domain aligned with `From`, do not treat SPF failure as strong evidence.
- Record the reason for any reduction in `auth.notes` so the report explains it.

### 5.3 False-positive controls

Known hard cases and required behavior:

| Case | Risk | Control |
|---|---|---|
| Legitimate mailing list / forward | SPF fail, false positive | Forwarding-aware auth scoring; DKIM alignment check |
| Executive email from new device | Domain/IP reputation flags | Require multiple independent signals for "Malicious" |
| Marketing email with tracking redirects | URL redirect flags | Follow redirects; score final destination, not tracker |
| Image-only email | No text for NLP | Mark NLP unavailable; renormalize weights; do not penalize |
| Shared cloud IP | Hosting ASN flag | Hosting alone is weak; require abuse/Tor/Feodo for strong points |
| Non-English email | NLP quality drop | Language detection; lower NLP confidence; rely on structural signals |
| `.msg` without full headers | Origin unknown | Degrade gracefully; lower origin confidence; show limitation |

Scoring rule: **"Malicious" requires at least two independent signal families above threshold.**
One severe signal can reach "Suspicious" on its own. This is enforced in `scorer.py` and unit-tested.

### 5.4 LLM prompt design

- System prompt: analyst role, strict JSON schema, explicit instruction that email content is
  untrusted data and must never be followed as instructions.
- Few-shot: 8–12 examples balanced across phishing, BEC, legitimate, spam, drawn from licensed
  data and hand-written fixtures. Keep the prompt under ~2,500 tokens.
- Output schema validated with Pydantic; on failure, retry once with "return only JSON", then
  fall back.
- Store `label`, `confidence`, `reasoning`, `cues`, `model`, `latency_ms`, `mode` in the result.
- Do not send attachments, full headers, or recipient lists to a remote API. Local Ollama is the
  default; remote API requires explicit `ALLOW_REMOTE_LLM=true`.

### 5.5 Evaluation methodology

Build the evaluation harness **before** tuning weights.

1. **Held-out set:** stratified sample from licensed datasets plus the fixture corpus.
2. **Grouped split:** by sender domain and normalized body hash to prevent leakage.
3. **Metrics:** precision, recall, F1 for malicious vs. benign; PR-AUC; false-positive rate at the
   chosen threshold; confusion matrix by class (legit/phishing/BEC/spam).
4. **Ablation:** score with each signal removed to show contribution.
5. **LLM evaluation:** 200 stratified samples, compared against the TF-IDF baseline; report
   accuracy, JSON validity rate, and latency.
6. **Adversarial suite:** forwarded mail, homograph domain, image-only, DKIM-pass spoof, header
   injection, malformed `Received`, non-English, huge attachment name, encoded subject.
7. **Targets for MVP:** recall >= 0.85 and FPR <= 0.10 on the held-out sample; 100% JSON validity;
   no unhandled exceptions on the adversarial suite.

Results are written to `docs/EVALUATION.md` and shown in the final presentation. Do not tune on
the test set; use a validation split.

---

## 6. Phased execution plan

Estimates assume one focused developer. Calendar time may be longer; the order is what matters.

**Total: 7–9 focused days.** MVP checkpoint at the end of Phase 4. The demo path must be green
from Phase 1 onward.

### Phase 0 — Foundation and data (0.5–1 day)

Deliverables:
- Repo scaffold exactly as Section 10.
- Python 3.11 virtualenv, pinned dependencies, `.env.example`, `.gitignore`.
- `make doctor` checks: Python version, imports, Ollama reachable, GeoIP DB present, API keys
  optional, disk space, data files present.
- Data acquisition + `docs/DATA_SOURCES.md` + schema validation.
- GeoIP database acquired and documented (MaxMind if account available, else DB-IP Lite).
- Ollama installed, `phi3:mini` pulled, one successful classification call.
- 8 hand-written `.eml` fixtures with expected outcomes.
- `docs/SPEC.md` (this plan's technical summary) and `README.md` quickstart.

Exit gate:
- `make doctor` prints all green (API keys may be marked optional).
- `make test` runs and passes the scaffold tests.
- `python scripts/validate_data.py` reports expected row counts and columns.
- `.eml` fixtures parse with stdlib without exceptions.

### Phase 1 — Vertical slice: parse, extract, authenticate (1–1.5 days)

Deliverables:
- `ingest.py`, `header_parser.py`, `ioc_extractor.py`, `auth.py`, `origin.py`.
- `analyze.py` CLI: `python -m app.cli analyze fixtures/phish.eml --out out.json`.
- React upload page, case queue, and detail view (metadata, auth, relay path, IOCs).
- Unit tests for each module against the fixtures.

Exit gate:
- All fixtures produce correct metadata, hop order, and auth results.
- Origin resolver returns the expected IP or an explicit "undetermined" for the malformed fixture.
- IOC extractor finds the planted indicators in every fixture and nothing from the body signature.
- The React UI shows a parsed email end-to-end. **This is the first demoable artifact.**
- `make test` and `npm run build` pass.

### Phase 2 — Enrichment and caching (1–1.5 days)

Deliverables:
- `enrichers/ip_enrich.py`, `domain_enrich.py`, `url_enrich.py`.
- `utils/cache.py` (diskcache), `utils/budget.py`, `utils/http.py`.
- Offline mode: every enricher returns a structured "unavailable" state instead of raising.
- Pre-warmed cache for the demo fixtures.
- Tests with recorded fixtures (no live network in CI).

Exit gate:
- IP enrichment shows country/city/ASN/hosting/Tor for public IPs and skips private IPs.
- Domain enrichment shows age, registrar, MX, SPF, DMARC, and lookalike result.
- With the network disabled, the pipeline still completes and marks sources unavailable.
- Cache hit/miss and budget behavior are tested.

### Phase 3 — Scoring and evaluation harness (1 day) — complete

Deliverables:
- `scorer.py` with granular signal scoring, two-family rule, confidence calculation, top reasons.
- `evaluation/run_eval.py`, `evaluation/metrics.py`, report in `docs/EVALUATION.md`.
- Thresholds configurable in `core/config.py`.

Exit gate:
- Fixtures receive the expected labels (legit < 40, phishing/BEC >= 70 unless intentionally subtle).
- Held-out sample meets MVP targets or deviations are documented with a plan.
- Ablation table exists and is reproducible with one command.
- Every score has at least one human-readable reason; no score without evidence.

### Phase 4 — NLP/LLM classifier + fallback (1 day)

Deliverables:
- `ml/llm_classifier.py` with dual mode (Ollama default, OpenAI-compatible optional).
- Schema validation, retry, cache, daily cap, prompt-injection guard.
- `ml/traditional.py`: TF-IDF + LogisticRegression/LightGBM trained on licensed data; persisted to
  `models/`.
- Few-shot examples stored in `ml/few_shot.py` (licensed/curated only).
- Integration into the scorer at 20% weight.

Exit gate:
- Both modes return valid JSON on the fixture set.
- Killing Ollama mid-run triggers the fallback without crashing.
- LLM output cannot introduce IOCs into the final report (test asserts IOC set equality).
- 200-sample evaluation recorded with accuracy and latency.

**MVP checkpoint:** the full pipeline (parse -> enrich -> score -> report) works on 8 fixtures,
with LLM or fallback, and a minimal report. Freeze features and fix bugs before adding UI polish.

### Phase 5 — Graph, campaigns, persistence (0.5–1 day)

Deliverables:
- `graph_builder.py`: NetworkX -> typed node/edge JSON consumed by a React graph component.
- `campaign_cluster.py`: cluster on registrable sender domain, origin IP /24, and subject
  simhash (Hamming <= 6); require at least two matching keys for a new campaign.
- `store.py`: SQLite schema for analyses, campaigns, and cases; search by sender/domain/IP/label.
- Campaign view data endpoint.

Exit gate:
- Two related fixtures cluster together; the legitimate fixture stays separate.
- The graph renders offline and includes email, IP, domain, and campaign nodes.
- Restarting the app preserves analyses and campaign assignments.

### Phase 6 — Full React UI, trace map, PDF report (1.5 days)

Deliverables:
- FastAPI: `POST /analyze`, `GET /analysis/{id}`, `GET /report/{id}.pdf`, `GET /campaigns`,
  `GET /health`. OpenAPI docs at `/docs`.
- React: Upload, Results, Detail (summary, map, graph, auth, IOC, raw headers), Campaigns.
- `TraceMap.jsx`: Leaflet map with hop pins and path lines; graceful handling of unknown geo.
- `InfrastructureGraph.jsx`: interactive graph from the backend node/edge JSON.
- `report_gen.py` + Jinja2 template -> HTML -> WeasyPrint PDF, with HTML fallback.
- Report sections exactly as Section 7 of the spec (10 sections).

Exit gate:
- The full demo script in Section 2.4 runs end-to-end, offline, in under 5 minutes.
- PDF opens, includes all 10 sections, and contains the evidence hash and limitations.
- API endpoints return the documented schema; a curl example exists in `docs/API.md`.
- No unhandled exception on malformed input, empty file, or unsupported extension.

### Phase 7 — Hardening and demo prep (1 day)

Deliverables:
- Adversarial suite in `backend/tests/adversarial/` with expected behavior.
- `Dockerfile`s and `docker-compose.yml` (Redis optional, Ollama on host documented).
- `docs/DEPLOY.md`, `docs/ARCHITECTURE.md`, Mermaid diagram in `README.md`.
- 2-minute demo recording and a judge-facing one-pager.
- Final evaluation refresh and `docs/EVALUATION.md` update.
- Performance pass: cold start, per-email latency, memory ceiling.

Exit gate:
- `docker compose up` works on a clean machine (or the README documents the only manual step).
- Adversarial suite passes; no crashes.
- Offline demo succeeds three times in a row.
- Repository contains no secrets, no unlicensed data, and no generated artifacts.

### 6.8 Cut order (if time runs short)

Cut from the bottom, never the top:

1. Campaign similarity beyond domain/subject.
2. Graph interactivity (static image fallback).
3. PDF styling (plain but complete PDF).
4. OTX/VirusTotal/GreyNoise integrations.
5. `.msg` support (document `.eml` only).
6. Docker packaging.
7. Leaflet map (show the hop table only).

**Never cut:** parser, auth, origin, scorer, report, offline demo, evidence hashing.

---

## 7. Testing strategy

| Layer | What | Tooling |
|---|---|---|
| Unit | Parser, IOC extraction, auth scoring, origin resolver, scorer | `pytest` |
| Contract | Canonical JSON schema validates for every fixture | Pydantic |
| Integration | Fixture -> enrichment (mocked) -> score -> report | `pytest`, `responses`/`respx` |
| Offline | Network disabled; pipeline completes with "unavailable" markers | `pytest` + monkeypatch |
| Adversarial | Malformed, forwarded, homograph, injection, image-only, non-English | `pytest` |
| Evaluation | Dataset metrics, ablation, LLM comparison | `evaluation/run_eval.py` |
| UI smoke | Upload -> results -> detail -> PDF | Manual checklist + Playwright (stretch) |

Conventions:
- No live network calls in unit tests. Record real responses into `tests/fixtures/http/`.
- Golden JSON snapshots for stable fields; timestamps and UUIDs excluded.
- Every bug fix adds a regression test.
- CI (GitHub Actions, free) runs lint + tests on push; no secrets required.

Commands:
```
make test          # unit + integration
make eval          # evaluation harness
make adversarial   # adversarial suite
make lint          # ruff + black --check
make doctor        # environment check
```

---

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Datasets not re-acquirable or unlicensed | Medium | High | Fixtures-first; document sources; don't ship unclear data |
| Ollama too slow/OOM on laptop | Medium | High | `phi3:mini`, one request at a time, TF-IDF fallback, pre-warm |
| GeoIP download blocked by account requirement | High | Medium | DB-IP Lite fallback; bundle DB; document license |
| Free API rate limits during demo | Medium | High | Cache, budget caps, pre-warmed cache, offline mode |
| Origin IP wrong due to forged headers | High | High | Trust boundaries, confidence reporting, "undetermined" path |
| False positives on forwarded legitimate mail | High | High | Forwarding-aware auth, two-family rule, adversarial tests |
| WeasyPrint system deps fail | Medium | Medium | HTML report fallback; Dockerfile with deps |
| Scope creep | High | High | Locked MVP, cut order, checkpoint after Phase 4 |
| Time overrun | High | High | Phase gates, vertical slice, cut order |
| LLM hallucinated evidence | Medium | High | Deterministic IOCs, schema validation, output tests |
| Privacy leak via remote API | Medium | High | Local LLM default; remote requires explicit flag; redaction |
| Demo machine differs from dev machine | Medium | High | Docker or frozen venv; `make doctor`; offline rehearsal |

---

## 9. Privacy, legal, and evidentiary safeguards

Product behavior:
- **Evidence integrity:** SHA-256 of the original file, UTC analysis timestamp, tool version, and
  parser version are stored and printed in every report.
- **Immutability:** original bytes are never modified; derived data is stored separately.
- **Offline mode:** disables all external enrichment; suitable for sensitive mail.
- **Minimization:** only headers/body text needed for analysis are stored; attachments are hashed,
  not executed.
- **Redaction:** optional toggle to mask local-parts of addresses and body excerpts in exports.
- **Retention:** configurable `DATA_RETENTION_DAYS`; `make purge` deletes analyses and cache.
- **Access:** local-only by default; no telemetry; no third-party analytics.
- **Language:** reports state "probable origin", list confidence and limitations, and explicitly
  disclaim identification of a person. They are investigative aids, not legal findings.
- **Chain of custody:** report includes the exact command/tool version used so results are
  reproducible.

Before submission, confirm:
- [ ] Every dataset's license permits use and demo.
- [ ] No API keys or personal data are committed.
- [ ] The privacy section of the report matches actual behavior.
- [ ] Remote LLM is off by default.

---

## 10. Repository structure

```
sih-email-forensics/
├── PLAN.md                     # this document
├── README.md
├── Makefile
├── .env.example
├── .gitignore
├── docker-compose.yml
├── docs/
│   ├── SPEC.md
│   ├── API.md
│   ├── DEPLOY.md
│   ├── ARCHITECTURE.md
│   ├── DATA_SOURCES.md
│   └── EVALUATION.md
├── data/
│   ├── raw/                    # licensed datasets (gitignored)
│   ├── fixtures/               # committed .eml samples + tiny licensed samples
│   ├── cache/                  # enrichment cache (gitignored)
│   └── cases.db                # SQLite (gitignored)
├── models/                     # TF-IDF/LightGBM artifacts (gitignored)
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── schemas.py
│   │   ├── cli.py
│   │   ├── api/routes.py
│   │   ├── core/config.py
│   │   ├── core/logging.py
│   │   ├── services/           # ingest, parser, ioc, auth, origin, scorer, graph, cluster, report, store
│   │   ├── enrichers/          # ip, domain, url
│   │   ├── ml/                 # llm_classifier, traditional, few_shot
│   │   ├── templates/          # forensic_report.html
│   │   └── utils/              # cache, budget, http, helpers
│   ├── tests/
│   │   ├── fixtures/
│   │   ├── adversarial/
│   │   └── http/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx
│   │   ├── api.js
│   │   ├── styles.css
│   │   └── components/         # upload, case queue, detail, map, graph
│   └── Dockerfile
├── evaluation/
│   ├── run_eval.py
│   └── metrics.py
├── scripts/
│   ├── validate_data.py
│   ├── warm_cache.py
│   └── make_fixtures.py
└── reports/                    # generated PDFs (gitignored)
```

Conventions:
- Python 3.12, type hints on public functions, `ruff` for lint and format.
- No comments unless they explain non-obvious reasoning.
- Config through Pydantic settings; no hard-coded keys or paths.
- UTC everywhere internally; local time only for display.
- One canonical schema (`schemas.py`); no ad-hoc dicts across module boundaries.

---

## 11. Environment setup (macOS, CPU-only)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cd frontend && npm install && cd ..
brew install pango libffi          # WeasyPrint on macOS
ollama serve &                     # or the Ollama app
ollama pull phi3:mini
cp .env.example .env               # fill optional keys
make test
make build
```

GeoIP:
- Preferred: MaxMind GeoLite2 City + ASN (free account, license key).
- Fallback: DB-IP Lite City + ASN (free, attribution required).
- Store as `data/geoip/*.mmdb`; verify with a known IP in `make doctor`.

Dependency notes:
- Remove `email-parser`, `msg-extractor`, `maxminddb-geolite2` from the spec's list.
- Add `geoip2`, `extract-msg`, `pytest`, `respx`, `ruff`.
- `lightgbm` is optional; LogisticRegression is sufficient for the fallback baseline.
- Pin exact versions after a successful install; commit the lockfile.

---

## 12. Decision log and open questions

### 12.1 Decisions proposed in this plan

| ID | Decision | Default |
|---|---|---|
| D1 | Ingestion is file upload only | Locked |
| D2 | Local LLM is the default; remote is opt-in | Locked |
| D3 | Deterministic IOCs only | Locked |
| D4 | SQLite for persistence, diskcache for caching | Locked |
| D5 | React talks to FastAPI only; no direct service imports | Locked |
| D6 | Two-family rule for "Malicious" | Locked |
| D7 | DB-IP Lite fallback if no MaxMind account | Locked |
| D8 | 8 fixtures + adversarial suite | Locked |

### 12.2 Questions to confirm before Phase 0

1. **Deadline / available days** — is 7–9 focused days realistic, or should we plan a 4-day MVP?
2. **Judging connectivity** — will Wi-Fi be available? If not, offline-first becomes mandatory.
3. **API keys** — do you have (or can you register for) MaxMind, AbuseIPDB, URLhaus, VirusTotal?
4. **Dataset origin** — where did the four CSVs come from, and are their licenses acceptable?
5. **Skill focus** — do you want to maximize ML/NLP depth or forensic/UI polish? This shifts time
   between Phases 3–4 and 5–6.
6. **Presentation language** — should reports/UI be English only, or English + Hindi?

Defaults if unanswered: 7-day plan, offline-first, no keys, fixtures-first, balanced, English.

---

## 13. Phase progress tracker

- [x] Phase 0 — Foundation: professional structure, `.venv`, FastAPI, React/Vite, SQLite,
  fixtures, tests, dev scripts
- [ ] Phase 0b — Datasets, GeoIP database, Ollama model, `make doctor`
- [x] Phase 1 — Parse, IOC, auth, origin, batch API, React case queue + detail view
- [x] Phase 2 — Enrichment, cache, budget, offline mode
- [x] Phase 3 — Scorer, thresholds, evaluation harness
- [ ] Phase 4 — LLM classifier + TF-IDF fallback (**MVP checkpoint**)
- [ ] Phase 5 — Graph, campaign clustering, case management
- [ ] Phase 6 — Full React UI, Leaflet trace map, PDF report
- [ ] Phase 7 — Adversarial tests, Docker, docs, demo recording

---

## 14. Approval

This plan is intentionally explicit so implementation can proceed phase by phase without
re-litigating scope.

**To start Phase 0, reply `approved`.** If you want changes, name the section and the decision
(e.g., "Section 3.2 item 3: keep Redis").

Accepted risks if approved as-is: 7–9 day solo effort, local CPU LLM may be slow on long emails,
geolocation is approximate, and some datasets may need to be swapped if licenses are unclear.
