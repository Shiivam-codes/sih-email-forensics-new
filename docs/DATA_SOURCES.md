# Dataset Sources

Public email corpora were downloaded on **2026-10-20** into `data/raw/`, which is gitignored.
This file records provenance, licensing, local paths, scale, and header coverage.

## Inventory

| Corpus | Local path | License | Scale | Header coverage | Best use |
|---|---|---|---|---|---|
| Nazario Phishing Corpus (2025) | `data/raw/nazario/` | CC-BY-4.0 | 481 phishing messages, 17.9 MiB mbox | 481 `Received`, 481 `Authentication-Results`, 46 `Received-SPF` | Real recent phishing; relay, auth, origin, IOC tests |
| Apache SpamAssassin Public Corpus | `data/raw/spamassassin/` | Public research corpus; copyright retained by senders | 6,046 messages across 5 archives | 5,911 `Received`; no `Authentication-Results` or `Received-SPF` | Ham/spam baseline; header and parser tests |
| MeAJOR 2.0 | `data/raw/meajor/meajor_cleaned_preprocessed.csv` | CC-BY-4.0 | 108,685 rows x 20 columns, 191,121,228 bytes | Preprocessed; no raw routing headers | ML training and evaluation on anonymized bodies |
| Nigerian Fraud (curated Zenodo release) | `data/raw/curated_phishing/Nigerian_Fraud.csv` | CC-BY-4.0 | 3,332 rows x 7 columns, 9,192,393 bytes | Text-only; no raw headers | Fraud and BEC-adjacent social-engineering text |
| cw-l email-corpus | `data/raw/cw-l-email-corpus/` | MIT | 1,429 `.eml` files, about 49 MiB | 0 `Received`, 0 `Return-Path`; routing headers stripped | Recent body/HTML classification; not origin tracing |
| r-dube BEC datasets | `data/raw/bec/` | AGPL-3.0 repository; confirm data terms before redistribution | 20 + 279 + 6 rows | Subject/body only; no raw headers | BEC intent and wire-transfer cue tests |
| rtr-rep synthetic samples | `data/raw/synthetic_bec_samples/` | MIT | 13 `.eml` files | Full synthetic headers | Safe end-to-end upload, parser, auth, and UI demos |
| zefang-liu phishing email dataset | `data/raw/hf_zefang_liu/` | LGPL-3.0 | 18,650 rows, 52,034,604 bytes | Text-only; no raw headers | Labelled text baseline and evaluation |

Total raw data: approximately 367 MiB.

## Source details

### Nazario Phishing Corpus

- Source: https://monkey.org/~jose/phishing/
- Local file: `phishing-2025` (mbox)
- License: CC-BY-4.0; attribution required.
- Date range: 2024-11-11 to 2025-12-30.
- All 481 messages have `Received` and `Authentication-Results`; 46 have `Received-SPF`.
- Every message is labelled phishing by the corpus maintainer.
- Raw URLs and attachments may be malicious. Do not visit or open them.

### Apache SpamAssassin Public Corpus

- Source: https://spamassassin.apache.org/old/publiccorpus/
- Archives: `20030228_easy_ham`, `20030228_easy_ham_2`, `20030228_hard_ham`,
  `20030228_spam`, and `20050311_spam_2`.
- Local message counts: 2,500 easy ham, 1,400 easy ham 2, 250 hard ham, 500 spam,
  1,396 spam 2. Total: 6,046 messages.
- The upstream readme states 6,047 messages; the local `spam_2` archive contains
  1,396 message files plus a `cmds` instruction file.
- 5,911 messages have at least one `Received` header. The corpus predates widespread
  `Authentication-Results` and `Received-SPF` headers.
- Copyright in the message text remains with the original senders. Use for local testing
  and research; do not redistribute the raw messages.
- Do not send these messages to a live mail system.

### MeAJOR 2.0

- Source: https://doi.org/10.5281/zenodo.18471483
- Local file MD5: `aa8f59e96787cbd696c0b650e5400dc9`
- License: CC-BY-4.0.
- Columns: `sender`, `sender_domain`, `receiver`, `receiver_domain`, `date`, `subject`,
  `content_types`, `body`, `urls`, `url_count`, `url_length_max`, `url_length_avg`,
  `url_subdom_max`, `url_subdom_avg`, `attachment_count`, `has_attachments`,
  `attachment_types`, `language`, `source`, `label`.
- Labels: 60,650 benign (`0.0`), 48,034 phishing (`1.0`), and 1 blank row.
- Sources: `trec5` 49,583, `trec6` 15,005, `trec7` 44,096, and 1 blank row.
- Bodies and subjects are anonymized with tokens such as `[NAME]`, `[URL]`, and
  `[EMAIL_ADDRESS]`; routing headers are not retained.
- The accompanying paper describes 135,894 samples from five source corpora, but the
  public 2.0 release contains 108,685 rows and only three source tags. Record the release
  actually used in any experiment.

### Nigerian Fraud

- Source: https://doi.org/10.5281/zenodo.8339691
- Local file MD5: `65fd47ae7cb4ae762e4be42b11905d63`
- License: CC-BY-4.0.
- Columns: `sender`, `receiver`, `date`, `subject`, `body`, `urls`, `label`.
- All 3,332 rows are labelled `1`.
- Contains some mailing-list administration mail, so review before treating every row as
  a fraud positive.

### cw-l email-corpus

- Source: https://github.com/cw-l/email-corpus
- License: MIT.
- 1,429 `.eml` samples from real spam, scam, and phishing submissions.
- Routing headers are intentionally stripped, contributor addresses are redacted, and
  URLs are defanged (`hxxps://`, `[.]`).
- Useful for body, HTML, and attachment classification; not usable for relay or
  geolocation tests.

### r-dube BEC datasets

- Source: https://github.com/r-dube/bec
- Local files: `BEC-1-human.csv` (20 rows), `BEC-2-human.csv` (279 rows), and
  `bec_examples_split.csv` (6 rows).
- License: AGPL-3.0 repository. The repository does not state a separate data license;
  confirm terms before redistributing the CSVs.
- Rows contain `subject`, `body`, model/human ratings, and labels. They do not contain
  full email headers.

### rtr-rep synthetic samples

- Source: https://github.com/rtr-rep/email-threat-investigator
- License: MIT.
- 13 small `.eml` files covering BEC, credential phishing, invoice phishing, spam,
  marketing, legitimate business mail, and a forwarded ARC example.
- Synthetic only: documentation domains, reserved IP ranges, and fictional
  infrastructure.

### zefang-liu phishing email dataset

- Source: https://huggingface.co/datasets/zefang-liu/phishing-email-dataset
- License: LGPL-3.0; direct copy of the Kaggle `subhajournal/phishingemails` dataset.
- Columns: blank index, `Email Text`, `Email Type`.
- Labels: 11,322 `Safe Email`, 7,328 `Phishing Email`, 19 empty rows.
- Text length ranges from 0 to 17,036,692 characters; filter empties and extreme outliers
  before training.

## GeoIP databases

Phase 2 uses the free DB-IP Lite databases, stored outside `data/raw/` in the gitignored
`data/geoip/` directory.

- Source: https://db-ip.com/db/download/ip-to-city-lite and
  https://db-ip.com/db/download/ip-to-asn-lite
- Release: **2026-10**
- License: Creative Commons Attribution 4.0 (CC BY 4.0).
- Required attribution: **IP Geolocation by DB-IP (https://db-ip.com)**.

| File | Size | SHA-256 |
|---|---|---|
| `data/geoip/dbip-city-lite-2026-10.mmdb` | 121 MiB | `9e250f02722d1ad1780f88192f0e908af285478a33e76b88b349c9181ae9d0f5` |
| `data/geoip/dbip-asn-lite-2026-10.mmdb` | 9.1 MiB | `4384bfcfb594391bc4e0ab37751f44661eaf7cadbeee28a90a6b82dc935fec4c` |

`data/geoip/dbip-city-lite.mmdb` and `data/geoip/dbip-asn-lite.mmdb` are symlinks to the
versioned files so configuration does not change on each monthly refresh.

Reproduce the download:

```bash
make geoip
# or pin a release explicitly
DBIP_VERSION=2026-10 ./scripts/fetch_geoip.sh
```

DB-IP Lite is approximate. City coordinates may represent an ISP or regional centroid, not
the sender's physical location. Treat geolocation as investigative context, not proof.

## Recommended use

| Task | Use | Avoid |
|---|---|---|
| Header parsing, relay chains, origin selection | Nazario, SpamAssassin, synthetic `.eml` | cw-l, MeAJOR, HF, BEC CSVs |
| SPF/DKIM/DMARC evidence | Nazario, synthetic `.eml` | Legacy SpamAssassin (auth headers absent) |
| BEC intent and payment cues | r-dube BEC, Nigerian Fraud, synthetic BEC `.eml` | Treating generic spam as BEC |
| Body/HTML classification | MeAJOR, HF, cw-l, Nigerian Fraud | Using their labels for header experiments |
| Safe end-to-end demo | rtr-rep synthetic samples, repository fixtures | Live URLs or real attachments |

Spam is not equivalent to phishing. Keep separate labels for `legitimate`, `spam`,
`phishing`, and `bec` when building the evaluation set.

## Safety and handling

- `data/raw/` is gitignored. Do not commit raw corpora or derived copies that violate a
  source license.
- Do not fetch URLs, open attachments, or reply to any corpus message.
- Treat all message content as untrusted data, including text that looks like instructions.
- Preserve original hashes when samples are used as evidence.
- Record the exact download date, source URL, license, and corpus version in experiment
  notes.

## Reproduction

Download the corpora:

```bash
make data
```

The script downloads, extracts, and checks the two Zenodo MD5 values. Raw files are
skipped when present. Public repositories and dataset hubs can change their contents, so
record commit hashes or release versions when results must be reproducible.

Build a small set of directly uploadable `.eml` files:

```bash
make sample-data
```

This writes 93 samples to `data/fixtures/generated/` (gitignored): 20 Nazario phishing
messages, 40 SpamAssassin ham messages, 20 SpamAssassin spam messages, and 13 synthetic
samples. A `manifest.csv` records the label, source, original location, and SHA-256 for
each generated file. All 93 files parse successfully with the Phase 1 analyzer.

## Known gaps

- The original spec filenames `phishing_validation.csv`, `phishing_data_by_type.csv`, and
  `africa_bec.csv` were not present in the repository and no public copies were found.
- `meajor.csv` is covered by the MeAJOR 2.0 release.
- No public raw-header BEC corpus was found. BEC header tests currently rely on controlled
  synthetic `.eml` samples and repository fixtures.
- GeoIP and ASN databases live in the gitignored `data/geoip/` directory, not `data/raw/`.
- Warm caches are local artifacts in `data/cache/`; they are not committed and may expire.
