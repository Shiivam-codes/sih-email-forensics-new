from __future__ import annotations

import argparse
import csv
import hashlib
import mailbox
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
DEFAULT_OUT = ROOT / "data" / "fixtures" / "generated"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_nazario(out: Path, limit: int) -> list[dict[str, str]]:
    source = RAW / "nazario" / "phishing-2025"
    if not source.exists():
        raise SystemExit(f"missing {source}; run scripts/fetch_datasets.sh first")

    target = out / "phishing"
    target.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    for index, message in enumerate(mailbox.mbox(source), start=1):
        if index > limit:
            break
        path = target / f"nazario_phishing_{index:04d}.eml"
        path.write_bytes(message.as_bytes())
        rows.append(
            {
                "path": str(path.relative_to(ROOT)),
                "label": "phishing",
                "source": "nazario",
                "original": f"phishing-2025 message {index}",
                "sha256": sha256(path),
            }
        )
    return rows


def write_spamassassin(out: Path, limit: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    groups = [("easy_ham", "ham"), ("hard_ham", "ham"), ("spam", "spam")]
    for corpus_dir, label in groups:
        source = RAW / "spamassassin" / corpus_dir
        if not source.exists():
            raise SystemExit(f"missing {source}; run scripts/fetch_datasets.sh first")
        target = out / label
        target.mkdir(parents=True, exist_ok=True)
        files = sorted(path for path in source.iterdir() if path.is_file() and path.name != "cmds")
        for index, path in enumerate(files[:limit], start=1):
            dest = target / f"spamassassin_{corpus_dir}_{index:04d}.eml"
            shutil.copyfile(path, dest)
            rows.append(
                {
                    "path": str(dest.relative_to(ROOT)),
                    "label": label,
                    "source": "spamassassin",
                    "original": str(path.relative_to(ROOT)),
                    "sha256": sha256(dest),
                }
            )
    return rows


def write_synthetic(out: Path) -> list[dict[str, str]]:
    source = RAW / "synthetic_bec_samples"
    if not source.exists():
        raise SystemExit(f"missing {source}; run scripts/fetch_datasets.sh first")
    target = out / "synthetic"
    target.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    for path in sorted(source.glob("*.eml")):
        dest = target / path.name
        shutil.copyfile(path, dest)
        rows.append(
            {
                "path": str(dest.relative_to(ROOT)),
                "label": "synthetic_mixed",
                "source": "rtr-rep",
                "original": str(path.relative_to(ROOT)),
                "sha256": sha256(dest),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a small, ready-to-upload .eml sample set")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=20, help="samples per source group")
    args = parser.parse_args()

    if args.limit < 1:
        raise SystemExit("--limit must be at least 1")

    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    rows = []
    rows.extend(write_nazario(out, args.limit))
    rows.extend(write_spamassassin(out, args.limit))
    rows.extend(write_synthetic(out))

    manifest = out / "manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "label", "source", "original", "sha256"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {len(rows)} .eml files to {out}")
    print(f"manifest: {manifest}")


if __name__ == "__main__":
    main()
