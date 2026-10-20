# Phase 3 Evaluation

Generated: `2026-10-20T17:12:39.045436+00:00`  
Mode: **offline**  
Scoring version: `phase3-rules-v1`  
Samples: **81**

> This is a rule-based baseline. Corpus spam/benign labels are broad proxies, not per-message forensic ground truth. Treat the numbers as calibration evidence.

## Headline metrics

Strict scoring counts only `malicious` as a positive. Flagged triage also counts `suspicious` as a positive, matching an analyst queue where suspicious mail is reviewed.

| Metric | Strict malicious | Flagged triage |
|---|---:|---:|
| Precision | 100.0% | 100.0% |
| Recall | 2.1% | 10.4% |
| F1 | 4.1% | 18.9% |
| False-positive rate | 0.0% | 0.0% |
| Accuracy | 42.0% | 46.9% |
| Average precision | 64.2% | 64.2% |

### Confusion matrices

| Strict | Predicted threat | Predicted benign |
|---|---:|---:|
| Actual threat | 1 | 47 |
| Actual benign | 0 | 33 |

| Flagged | Predicted threat | Predicted benign |
|---|---:|---:|
| Actual threat | 5 | 43 |
| Actual benign | 0 | 33 |

## Family ablation

Each row removes one signal family and re-applies the same thresholds and two-family rule. The table uses flagged-triage positives so the contribution of each family remains visible.

| Removed family | Precision | Recall | F1 | FPR | AP |
|---|---:|---:|---:|---:|---:|
| auth | 100.0% | 6.2% | 11.8% | 0.0% | 67.1% |
| domain | 100.0% | 4.2% | 8.0% | 0.0% | 66.2% |
| ip | 100.0% | 10.4% | 18.9% | 0.0% | 64.2% |
| content | 100.0% | 2.1% | 4.1% | 0.0% | 52.4% |
| header | 100.0% | 2.1% | 4.1% | 0.0% | 65.7% |

## Per-source

| Source | Count | Precision | Recall | FPR | AP |
|---|---:|---:|---:|---:|---:|
| fixture | 6 | 100.0% | 33.3% | 0.0% | 100.0% |
| nazario_2025 | 15 | 0.0% | 0.0% | 0.0% | 100.0% |
| spamassassin_easy_ham | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| spamassassin_hard_ham | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| spamassassin_spam | 15 | 0.0% | 0.0% | 0.0% | 100.0% |
| spamassassin_spam_2 | 15 | 0.0% | 0.0% | 0.0% | 100.0% |

## Fixture calibration

| Fixture | Expected | Score | Predicted | Confidence | Signals |
|---|---|---:|---|---:|---|
| `bec_wire_transfer.eml` | bec (threat) | 40 | suspicious | 45.0% | auth=0, domain=6, ip=0, content=20, header=14 |
| `forwarded_mailing_list.eml` | mailing_list (benign) | 0 | likely legitimate | 81.0% | auth=0, domain=0, ip=0, content=0, header=0 |
| `legit_business.eml` | legit (benign) | 0 | likely legitimate | 81.0% | auth=0, domain=0, ip=0, content=0, header=0 |
| `malformed.eml` | malformed (benign) | 8 | likely legitimate | 62.0% | auth=0, domain=0, ip=0, content=0, header=8 |
| `phishing_credential.eml` | phishing (threat) | 70 | malicious | 65.0% | auth=21, domain=14, ip=20, content=12, header=3 |
| `spoofed_display_name.eml` | spoof (threat) | 43 | suspicious | 48.0% | auth=0, domain=20, ip=0, content=11, header=12 |

## Interpretation

- `phishing_credential` combines authentication failure, a lookalike domain, a Tor origin, and credential/urgency language.
- `bec_wire_transfer` is intentionally subtle: it lands at the suspicious boundary until Phase 4 adds semantic BEC detection.
- `forwarded_mailing_list` verifies the SPF-forwarding discount: aligned DKIM prevents a false phishing verdict.
- `legit_business` verifies that cloud/hosting infrastructure alone does not raise the verdict.
- `malformed` is expected to remain low-confidence and benign; missing evidence must not manufacture a malicious score.

## Limitations

- Corpus evaluation is offline by default, so domain/IP signals are absent unless the local cache was warmed for those messages.
- SpamAssassin spam is broad unwanted mail, not hand-verified phishing; its labels are a proxy for threat triage, not forensic ground truth.
- The sampled Nazario mbox is historical phishing; its low recall reflects the limits of rule-based content detection and motivates Phase 4 NLP.
- Online corpus runs can be slow and consume the daily enrichment budget; use a small `--corpus-limit` with `--online`.

## Reproduction

```bash
make eval                       # fixtures only, offline
make eval-corpus                # add local held-out corpus samples
PYTHONPATH=backend .venv/bin/python evaluation/run_eval.py --online
```
