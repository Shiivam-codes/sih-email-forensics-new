import argparse
import json
import mailbox
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import Settings
from app.enrichers.service import EnrichmentService
from app.services.analyzer import analyze_email
from metrics import binary_metrics, format_percent

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "backend" / "tests" / "fixtures"
DATA = ROOT / "data" / "raw"
REPORTS = ROOT / "reports"
DOCS = ROOT / "docs" / "EVALUATION.md"

FIXTURE_LABELS = {
    "legit_business.eml": (0, "legit"),
    "forwarded_mailing_list.eml": (0, "mailing_list"),
    "phishing_credential.eml": (1, "phishing"),
    "spoofed_display_name.eml": (1, "spoof"),
    "bec_wire_transfer.eml": (1, "bec"),
    "malformed.eml": (0, "malformed"),
}


@dataclass
class Sample:
    source: str
    name: str
    data: bytes
    truth: int
    category: str


@dataclass
class Record:
    source: str
    name: str
    category: str
    truth: int
    total: int
    label: str
    confidence: float
    signals: dict[str, int]
    error: str | None = None


def main() -> None:
    args = _parse_args()
    settings = Settings(
        offline_mode=not args.online,
        cache_path=str(args.cache_path),
        daily_external_request_limit=settings_limit(args),
    )
    samples = _fixture_samples()
    if args.include_corpus:
        samples.extend(_corpus_samples(args.corpus_limit, args.seed))
    if not samples:
        raise SystemExit("No evaluation samples found")

    service = EnrichmentService(settings) if settings.enrichment_enabled else None
    try:
        records = _analyze_samples(samples, settings, service)
    finally:
        if service is not None:
            service.close()

    base = _metrics(records)
    flagged = _metrics(records, flag_suspicious=True)
    ablations = {} if args.no_ablation else _ablations(records, settings)
    per_source = {
        source: _metrics([record for record in records if record.source == source])
        for source in sorted({record.source for record in records})
    }
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "online" if args.online else "offline",
        "scoring_version": settings.scoring_version,
        "thresholds": {
            "malicious": settings.malicious_threshold,
            "suspicious": settings.suspicious_threshold,
            "family_min_points": settings.family_min_points,
        },
        "sample_count": len(records),
        "errors": [record.__dict__ for record in records if record.error],
        "metrics": base,
        "flagged_metrics": flagged,
        "per_source": per_source,
        "ablations": ablations,
        "records": [record.__dict__ for record in records],
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = REPORTS / f"evaluation-{timestamp}.json"
    json_path.write_text(json.dumps(payload, indent=2))
    (REPORTS / "evaluation.json").write_text(json.dumps(payload, indent=2))
    DOCS.write_text(_markdown(payload))
    print(f"Evaluation written to {json_path}")
    print(f"Summary written to {DOCS}")
    print(
        f"strict precision={base['precision']:.3f} recall={base['recall']:.3f} "
        f"f1={base['f1']:.3f} fpr={base['false_positive_rate']:.3f} "
        f"ap={base['average_precision']:.3f}\n"
        f"flagged precision={flagged['precision']:.3f} recall={flagged['recall']:.3f} "
        f"f1={flagged['f1']:.3f} fpr={flagged['false_positive_rate']:.3f}"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Phase 3 risk scoring")
    parser.add_argument("--online", action="store_true", help="Allow live enrichment queries")
    parser.add_argument(
        "--include-corpus",
        action="store_true",
        help="Add held-out samples from local Nazario/SpamAssassin corpora",
    )
    parser.add_argument(
        "--corpus-limit",
        type=int,
        default=15,
        help="Samples per corpus source (default: 15)",
    )
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--no-ablation", action="store_true")
    parser.add_argument(
        "--cache-path",
        type=Path,
        default=ROOT / "data" / "cache",
    )
    return parser.parse_args()


def settings_limit(args: argparse.Namespace) -> int:
    return 500 if args.online else 1


def _fixture_samples() -> list[Sample]:
    samples: list[Sample] = []
    for path in sorted(FIXTURES.glob("*.eml")):
        label = FIXTURE_LABELS.get(path.name)
        if label is None:
            continue
        truth, category = label
        samples.append(
            Sample(
                source="fixture",
                name=path.name,
                data=path.read_bytes(),
                truth=truth,
                category=category,
            )
        )
    return samples


def _corpus_samples(limit: int, seed: int) -> list[Sample]:
    rng = random.Random(seed)
    sources: list[tuple[str, Path, int, str, str]] = [
        ("nazario_2025", DATA / "nazario" / "phishing-2025", 1, "phishing", "mbox"),
        ("spamassassin_easy_ham", DATA / "spamassassin" / "easy_ham", 0, "ham", "dir"),
        ("spamassassin_hard_ham", DATA / "spamassassin" / "hard_ham", 0, "ham", "dir"),
        ("spamassassin_spam", DATA / "spamassassin" / "spam", 1, "spam", "dir"),
        ("spamassassin_spam_2", DATA / "spamassassin" / "spam_2", 1, "spam", "dir"),
    ]
    samples: list[Sample] = []
    for source, path, truth, category, kind in sources:
        if not path.exists():
            continue
        if kind == "mbox":
            samples.extend(_sample_mbox(source, path, truth, category, limit, rng))
        else:
            samples.extend(_sample_dir(source, path, truth, category, limit, rng))
    return samples


def _sample_mbox(
    source: str,
    path: Path,
    truth: int,
    category: str,
    limit: int,
    rng: random.Random,
) -> list[Sample]:
    box = mailbox.mbox(str(path), create=False)
    try:
        keys = list(box.keys())
        chosen = rng.sample(keys, min(limit, len(keys))) if keys else []
        return [
            Sample(
                source=source,
                name=f"{path.name}#{key}",
                data=box.get_message(key).as_bytes(),
                truth=truth,
                category=category,
            )
            for key in sorted(chosen)
        ]
    finally:
        box.close()


def _sample_dir(
    source: str,
    path: Path,
    truth: int,
    category: str,
    limit: int,
    rng: random.Random,
) -> list[Sample]:
    files = sorted(item for item in path.iterdir() if item.is_file())
    chosen = rng.sample(files, min(limit, len(files))) if files else []
    return [
        Sample(
            source=source,
            name=file.name,
            data=file.read_bytes(),
            truth=truth,
            category=category,
        )
        for file in sorted(chosen)
    ]


def _analyze_samples(
    samples: list[Sample],
    settings: Settings,
    service: EnrichmentService | None,
) -> list[Record]:
    records: list[Record] = []
    for sample in samples:
        try:
            result = analyze_email(
                sample.data,
                sample.name if sample.name.lower().endswith(".eml") else f"{sample.name}.eml",
                settings.max_upload_bytes,
                enricher=service,
                settings=settings,
            )
        except Exception as exc:
            records.append(
                Record(
                    source=sample.source,
                    name=sample.name,
                    category=sample.category,
                    truth=sample.truth,
                    total=0,
                    label="error",
                    confidence=0.0,
                    signals={},
                    error=str(exc),
                )
            )
            continue
        records.append(
            Record(
                source=sample.source,
                name=sample.name,
                category=sample.category,
                truth=sample.truth,
                total=result.score.total,
                label=result.score.label,
                confidence=result.score.confidence,
                signals=result.score.signals,
            )
        )
    return records


def _metrics(
    records: list[Record], flag_suspicious: bool = False
) -> dict[str, float | int]:
    valid = [record for record in records if record.error is None]
    truth = [record.truth for record in valid]
    positive = {"malicious", "suspicious"} if flag_suspicious else {"malicious"}
    predicted = [1 if record.label in positive else 0 for record in valid]
    scores = [record.total for record in valid]
    return binary_metrics(truth, predicted, scores)


def _ablations(records: list[Record], settings: Settings) -> dict[str, dict]:
    families = ["auth", "domain", "ip", "content", "header"]
    output: dict[str, dict] = {}
    for family in families:
        adjusted: list[Record] = []
        for record in records:
            signals = dict(record.signals)
            signals[family] = 0
            total = min(100, sum(signals.values()))
            label = _label_from_signals(total, signals, settings)
            adjusted.append(
                Record(
                    source=record.source,
                    name=record.name,
                    category=record.category,
                    truth=record.truth,
                    total=total,
                    label=label,
                    confidence=record.confidence,
                    signals=signals,
                    error=record.error,
                )
            )
        output[family] = _metrics(adjusted, flag_suspicious=True)
    return output


def _label_from_signals(total: int, signals: dict[str, int], settings: Settings) -> str:
    families = sum(1 for value in signals.values() if value >= settings.family_min_points)
    if total >= settings.malicious_threshold and families >= 2:
        return "malicious"
    if total >= settings.suspicious_threshold:
        return "suspicious"
    return "likely_legitimate"


def _markdown(payload: dict) -> str:
    metrics = payload["metrics"]
    flagged = payload["flagged_metrics"]
    lines = [
        "# Phase 3 Evaluation",
        "",
        f"Generated: `{payload['generated_at']}`  ",
        f"Mode: **{payload['mode']}**  ",
        f"Scoring version: `{payload['scoring_version']}`  ",
        f"Samples: **{payload['sample_count']}**",
        "",
        "> This is a rule-based baseline. Corpus spam/benign labels are broad proxies, not "
        "per-message forensic ground truth. Treat the numbers as calibration evidence.",
        "",
        "## Headline metrics",
        "",
        "Strict scoring counts only `malicious` as a positive. Flagged triage also counts "
        "`suspicious` as a positive, matching an analyst queue where suspicious mail is reviewed.",
        "",
        "| Metric | Strict malicious | Flagged triage |",
        "|---|---:|---:|",
        f"| Precision | {format_percent(metrics['precision'])} | {format_percent(flagged['precision'])} |",
        f"| Recall | {format_percent(metrics['recall'])} | {format_percent(flagged['recall'])} |",
        f"| F1 | {format_percent(metrics['f1'])} | {format_percent(flagged['f1'])} |",
        f"| False-positive rate | {format_percent(metrics['false_positive_rate'])} | {format_percent(flagged['false_positive_rate'])} |",
        f"| Accuracy | {format_percent(metrics['accuracy'])} | {format_percent(flagged['accuracy'])} |",
        f"| Average precision | {format_percent(metrics['average_precision'])} | {format_percent(flagged['average_precision'])} |",
        "",
        "### Confusion matrices",
        "",
        "| Strict | Predicted threat | Predicted benign |",
        "|---|---:|---:|",
        f"| Actual threat | {metrics['tp']} | {metrics['fn']} |",
        f"| Actual benign | {metrics['fp']} | {metrics['tn']} |",
        "",
        "| Flagged | Predicted threat | Predicted benign |",
        "|---|---:|---:|",
        f"| Actual threat | {flagged['tp']} | {flagged['fn']} |",
        f"| Actual benign | {flagged['fp']} | {flagged['tn']} |",
        "",
        "## Family ablation",
        "",
        "Each row removes one signal family and re-applies the same thresholds and two-family rule. "
        "The table uses flagged-triage positives so the contribution of each family remains visible.",
        "",
        "| Removed family | Precision | Recall | F1 | FPR | AP |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for family, values in payload["ablations"].items():
        lines.append(
            f"| {family} | {format_percent(values['precision'])} | "
            f"{format_percent(values['recall'])} | {format_percent(values['f1'])} | "
            f"{format_percent(values['false_positive_rate'])} | "
            f"{format_percent(values['average_precision'])} |"
        )
    lines.extend(
        [
            "",
            "## Per-source",
            "",
            "| Source | Count | Precision | Recall | FPR | AP |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for source, values in payload["per_source"].items():
        count = sum(
            1
            for record in payload["records"]
            if record["source"] == source and record["error"] is None
        )
        lines.append(
            f"| {source} | {count} | {format_percent(values['precision'])} | "
            f"{format_percent(values['recall'])} | "
            f"{format_percent(values['false_positive_rate'])} | "
            f"{format_percent(values['average_precision'])} |"
        )
    lines.extend(
        [
            "",
            "## Fixture calibration",
            "",
            "| Fixture | Expected | Score | Predicted | Confidence | Signals |",
            "|---|---|---:|---|---:|---|",
        ]
    )
    for record in payload["records"]:
        if record["source"] != "fixture":
            continue
        expected = "threat" if record["truth"] else "benign"
        signals = ", ".join(f"{key}={value}" for key, value in record["signals"].items())
        lines.append(
            f"| `{record['name']}` | {record['category']} ({expected}) | "
            f"{record['total']} | {record['label'].replace('_', ' ')} | "
            f"{format_percent(record['confidence'])} | {signals} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `phishing_credential` combines authentication failure, a lookalike domain, "
            "a Tor origin, and credential/urgency language.",
            "- `bec_wire_transfer` is intentionally subtle: it lands at the suspicious "
            "boundary until Phase 4 adds semantic BEC detection.",
            "- `forwarded_mailing_list` verifies the SPF-forwarding discount: aligned DKIM "
            "prevents a false phishing verdict.",
            "- `legit_business` verifies that cloud/hosting infrastructure alone does not "
            "raise the verdict.",
            "- `malformed` is expected to remain low-confidence and benign; missing evidence "
            "must not manufacture a malicious score.",
            "",
            "## Limitations",
            "",
            "- Corpus evaluation is offline by default, so domain/IP signals are absent unless "
            "the local cache was warmed for those messages.",
            "- SpamAssassin spam is broad unwanted mail, not hand-verified phishing; its labels "
            "are a proxy for threat triage, not forensic ground truth.",
            "- The sampled Nazario mbox is historical phishing; its low recall reflects the "
            "limits of rule-based content detection and motivates Phase 4 NLP.",
            "- Online corpus runs can be slow and consume the daily enrichment budget; use a "
            "small `--corpus-limit` with `--online`.",
            "",
            "## Reproduction",
            "",
            "```bash",
            "make eval                       # fixtures only, offline",
            "make eval-corpus                # add local held-out corpus samples",
            "PYTHONPATH=backend .venv/bin/python evaluation/run_eval.py --online",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
