# Email Forensics Platform

AI-assisted email threat detection, origin tracing, and forensic analysis.

**Current status: Phase 3 complete** — deterministic parsing, authentication evidence, relay-path
reconstruction, IOC extraction, GeoIP/ASN enrichment, DNS/RDAP domain intelligence,
passive URL analysis, disk caching, daily budgets, offline mode, weighted risk scoring,
an evaluation harness, and a React analyst console.

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, Pydantic, SQLite |
| Frontend | React 18, Vite, plain CSS |
| Parsing | Python standard library `email` |
| Enrichment | DB-IP Lite MMDB, dnspython, RDAP, Shodan InternetDB, Tor exit list |
| Cache | diskcache with TTLs and daily request budget |
| Scoring | configurable rule-based families, two-family rule, confidence, reasons |
| Evaluation | reproducible fixtures + optional held-out corpus metrics and ablations |
| Tests | pytest, mocked DNS/HTTP, offline fixtures |

## Quick start

```bash
make setup
make geoip   # downloads ~130 MB of DB-IP Lite City/ASN data
make dev
```

- Frontend: http://127.0.0.1:5173
- API: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs

Or run the services in separate terminals:

```bash
make backend
make frontend
```

## Analyze an email

Use the upload panel, or call the API directly:

```bash
curl -F "files=@backend/tests/fixtures/phishing_credential.eml" \
  http://127.0.0.1:8000/api/analyses
```

Fixture files live in `backend/tests/fixtures/`:

| File | Scenario |
|---|---|
| `legit_business.eml` | Legitimate email, all auth passes |
| `phishing_credential.eml` | Credential phishing, SPF/DMARC fail |
| `bec_wire_transfer.eml` | BEC wire request, Reply-To mismatch, DKIM pass |
| `spoofed_display_name.eml` | Display-name spoof from freemail |
| `forwarded_mailing_list.eml` | Forwarded list mail, SPF fail but DKIM/DMARC pass |
| `malformed.eml` | Missing headers, origin undetermined |

## Risk scoring

Phase 3 scores five independent evidence families out of 100: authentication (25), domain (20),
IP reputation (20), content (20), and headers (15). A malicious verdict requires both the score
threshold (default 70) and at least two independent families above 5 points; one severe family
is capped at suspicious. The suspicious threshold is 40.

`POST /api/analyses` and `GET /api/analyses/{id}` include a `score` object with the total,
label, confidence, per-family points, evidence coverage, top human-readable reasons, and notes.
The React detail view shows the score breakdown and the case queue includes a risk column.

The calibration fixtures currently score:

| Fixture | Score | Expected |
|---|---:|---|
| `phishing_credential.eml` | 70 | malicious |
| `spoofed_display_name.eml` | 43 | suspicious |
| `bec_wire_transfer.eml` | 40 | suspicious (intentionally subtle until Phase 4 NLP) |
| `legit_business.eml` | 0 | likely legitimate |
| `forwarded_mailing_list.eml` | 0 | likely legitimate |
| `malformed.eml` | 8 | likely legitimate, low confidence |

Thresholds and family maxima are configurable with the `APP_SCORING_*`,
`APP_MALICIOUS_THRESHOLD`, `APP_SUSPICIOUS_THRESHOLD`, and `APP_*_SIGNAL_MAX` settings.

## Tests, lint, and evaluation

```bash
make test
make lint
make eval          # offline fixture calibration + metrics + ablation report
make eval-corpus   # add local held-out corpus samples
```

The evaluation writes `reports/evaluation.json` and regenerates
[`docs/EVALUATION.md`](docs/EVALUATION.md). Held-out corpus evaluation is offline by default;
use `PYTHONPATH=backend .venv/bin/python evaluation/run_eval.py --online` with a small
`--corpus-limit` if live enrichment is needed.

## Datasets

Public corpora are downloaded to `data/raw/` (gitignored), including Nazario phishing
mail, the Apache SpamAssassin corpus, MeAJOR 2.0, Nigerian Fraud, cw-l email-corpus,
BEC datasets, synthetic `.eml` samples, and a Hugging Face phishing dataset.

Provenance, licenses, counts, checksums, and header coverage are recorded in
[`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md). Rebuild the downloads and generate a
ready-to-upload sample set with:

```bash
make data
make sample-data
```

The generated 93 `.eml` files land in `data/fixtures/generated/` with a SHA-256 manifest.
Do not commit raw corpora or visit URLs from the samples.

## Enrichment

Enrichment is offline-first. Local GeoIP and cached results work without a network; external
lookups degrade to structured `offline`/`unavailable` source states and never abort analysis.

| Source | Data | Cache | Notes |
|---|---|---|---|
| DB-IP Lite City/ASN | country, city, approximate coordinates, ASN, organization | local MMDB | bundled download, no per-query network |
| DNS (`dnspython`) | A, MX, NS, TXT, SPF, `_dmarc` DMARC | 1 hour | no external API key |
| RDAP | registration/expiry dates, registrar, statuses | 30 days | via `rdap.org` |
| Shodan InternetDB | tags, open ports, CVEs | 7 days | public IPs only |
| Tor exit list | Tor exit membership | 24 hours feed | public IPs only |
| Lookalike engine | brand similarity and edit distance | local | heuristic, not proof |
| URL analysis | scheme, punycode, shorteners, risky TLDs, lookalikes | local | URLs are never fetched |

Per-email limits are 3 public IPs, 4 domains, and 5 URLs. A global daily cap
(`APP_DAILY_EXTERNAL_REQUEST_LIMIT`, default 500) protects free APIs. Private, loopback,
link-local, and reserved addresses are never sent to external services.

```bash
make warm-cache                    # pre-fetch demo fixture enrichment
APP_OFFLINE_MODE=true make backend # run using only local data and cache
```

Relevant settings are listed in `.env.example`. Set `APP_ENRICHMENT_ENABLED=false` to disable
the whole layer, or disable individual sources with `APP_RDAP_ENABLED`,
`APP_INTERNETDB_ENABLED`, and `APP_TOR_EXIT_LIST_ENABLED`.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Service status and enrichment readiness |
| POST | `/api/analyses` | Upload one or more `.eml` files |
| GET | `/api/analyses` | List analyzed emails |
| GET | `/api/analyses/{id}` | Full analysis detail |

## Project structure

```
backend/
  app/
    api/          HTTP routes
    core/         settings
    enrichers/    GeoIP, IP, domain, URL, orchestration
    services/     ingest, parser, auth, origin, IOC, analyzer, store
    utils/        IP, cache, budget, HTTP helpers
    main.py       FastAPI app factory
  tests/          unit + API tests, .eml fixtures
frontend/
  src/
    components/   upload, case queue, detail view
    api.js        API client
    App.jsx       application shell
evaluation/       reproducible scoring evaluation and ablation harness
data/             SQLite case store, corpora, GeoIP, cache (gitignored)
docs/             data sources, evaluation, design, and deployment notes
scripts/          dataset/GeoIP fetch, cache warming, development helpers
```

## Phase roadmap

1. **Phase 1 (complete):** parse `.eml`, auth evidence, relay chain, IOC extraction, case storage, React UI.
2. **Phase 2 (complete):** GeoIP/ASN, DNS/RDAP, lookalike and passive URL intelligence, caching, budgets, offline mode.
3. **Phase 3 (complete):** weighted risk scoring, thresholds, confidence, reasons, and evaluation harness.
4. **Phase 4 (current):** NLP/LLM classification with offline fallback.
5. **Phase 5:** graph correlation and campaign clustering.
6. **Phase 6:** trace map, forensic PDF reports, full case management.
7. **Phase 7:** adversarial testing, demo hardening, deployment.

## Evidence handling

- The original upload is hashed with SHA-256 and never modified.
- Analysis results record the hash, UTC analysis time, tool version, and offline-mode flag.
- Only public IPs and domain names are sent to external enrichment services.
- Private and reserved addresses are skipped; URLs are parsed passively and never fetched.
- Origin and geolocation are probabilistic and are reported with confidence.
