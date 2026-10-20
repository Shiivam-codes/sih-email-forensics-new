# Email Forensics Platform

AI-assisted email threat detection, origin tracing, and forensic analysis.

**Current status: Phase 1** — deterministic parsing, sender-authentication evidence,
relay-path reconstruction, probable-origin selection, IOC extraction, SQLite case storage,
FastAPI API, and a React analyst console.

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, Pydantic, SQLite |
| Frontend | React 18, Vite, plain CSS |
| Parsing | Python standard library `email` |
| Tests | pytest |

## Quick start

```bash
make setup
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

## Tests and lint

```bash
make test
make lint
```

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

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Service status |
| POST | `/api/analyses` | Upload one or more `.eml` files |
| GET | `/api/analyses` | List analyzed emails |
| GET | `/api/analyses/{id}` | Full analysis detail |

## Project structure

```
backend/
  app/
    api/          HTTP routes
    core/         settings
    services/     ingest, parser, auth, origin, IOC, analyzer, store
    utils/        IP helpers
    main.py       FastAPI app factory
  tests/          unit + API tests, .eml fixtures
frontend/
  src/
    components/   upload, case queue, detail view
    api.js        API client
    App.jsx       application shell
data/             SQLite case store and downloaded corpora (gitignored)
docs/             data sources, design, and deployment notes
scripts/          dataset fetch and development helpers
```

## Phase roadmap

1. **Phase 1 (current):** parse `.eml`, auth evidence, relay chain, IOC extraction, case storage, React UI.
2. **Phase 2:** geolocation, ASN/reputation enrichment, DNS and domain intelligence, caching.
3. **Phase 3:** weighted risk scoring, evaluation harness.
4. **Phase 4:** NLP/LLM classification with offline fallback.
5. **Phase 5:** graph correlation and campaign clustering.
6. **Phase 6:** trace map, forensic PDF reports, full case management.
7. **Phase 7:** adversarial testing, demo hardening, deployment.

## Evidence handling

- The original upload is hashed with SHA-256 and never modified.
- Analysis results record the hash, UTC analysis time, and tool version.
- Phase 1 performs no external network calls.
- Origin and geolocation are probabilistic and are reported with confidence.
