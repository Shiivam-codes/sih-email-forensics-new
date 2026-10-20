#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW="$ROOT/data/raw"
PYTHON="$ROOT/.venv/bin/python"

if [ ! -x "$PYTHON" ]; then
  PYTHON="python3"
fi

fetch() {
  local url="$1"
  local out="$2"

  mkdir -p "$(dirname "$out")"
  if [ -s "$out" ]; then
    printf 'skip %s\n' "$out"
    return
  fi

  printf 'fetch %s\n' "$url"
  curl -fSL --retry 3 --retry-delay 2 -o "$out" "$url"
}

md5_check() {
  local expected="$1"
  local file="$2"
  local actual

  actual="$("$PYTHON" -c 'import hashlib, sys; print(hashlib.md5(open(sys.argv[1], "rb").read()).hexdigest())' "$file")"
  if [ "$actual" != "$expected" ]; then
    printf 'md5 mismatch: %s\nexpected %s\ngot      %s\n' "$file" "$expected" "$actual" >&2
    exit 1
  fi
}

fetch "https://monkey.org/~jose/phishing/phishing-2025" "$RAW/nazario/phishing-2025"
fetch "https://monkey.org/~jose/phishing/README.txt" "$RAW/nazario/README.txt"
fetch "https://monkey.org/~jose/phishing/LICENSE.txt" "$RAW/nazario/LICENSE.txt"

archive_dir() {
  case "$1" in
    20030228_easy_ham.tar.bz2) printf 'easy_ham' ;;
    20030228_easy_ham_2.tar.bz2) printf 'easy_ham_2' ;;
    20030228_hard_ham.tar.bz2) printf 'hard_ham' ;;
    20030228_spam.tar.bz2) printf 'spam' ;;
    20050311_spam_2.tar.bz2) printf 'spam_2' ;;
  esac
}

fetch "https://spamassassin.apache.org/old/publiccorpus/readme.html" "$RAW/spamassassin/readme.html"
for archive in \
  20030228_easy_ham.tar.bz2 \
  20030228_easy_ham_2.tar.bz2 \
  20030228_hard_ham.tar.bz2 \
  20030228_spam.tar.bz2 \
  20050311_spam_2.tar.bz2; do
  fetch "https://spamassassin.apache.org/old/publiccorpus/$archive" "$RAW/spamassassin/$archive"
  dir="$(archive_dir "$archive")"
  if [ ! -d "$RAW/spamassassin/$dir" ]; then
    tar -xjf "$RAW/spamassassin/$archive" -C "$RAW/spamassassin"
  fi
done

if [ ! -d "$RAW/cw-l-email-corpus/email-corpus-main" ]; then
  fetch "https://github.com/cw-l/email-corpus/archive/refs/heads/main.zip" "$RAW/cw-l-email-corpus/email-corpus.zip"
  unzip -q -o "$RAW/cw-l-email-corpus/email-corpus.zip" -d "$RAW/cw-l-email-corpus"
  rm -f "$RAW/cw-l-email-corpus/email-corpus.zip"
fi

fetch "https://zenodo.org/api/records/18471483/files/meajor_cleaned_preprocessed.csv/content" "$RAW/meajor/meajor_cleaned_preprocessed.csv"
md5_check "aa8f59e96787cbd696c0b650e5400dc9" "$RAW/meajor/meajor_cleaned_preprocessed.csv"

fetch "https://zenodo.org/api/records/8339691/files/Nigerian_Fraud.csv/content" "$RAW/curated_phishing/Nigerian_Fraud.csv"
md5_check "65fd47ae7cb4ae762e4be42b11905d63" "$RAW/curated_phishing/Nigerian_Fraud.csv"

for file in README.md LICENSE BEC-1-human.csv BEC-2-human.csv bec_examples_split.csv; do
  fetch "https://raw.githubusercontent.com/r-dube/bec/main/$file" "$RAW/bec/$file"
done

for file in \
  bec-reply-only-scam.eml \
  benign-newsletter.eml \
  fake-microsoft-login.eml \
  legitimate-company-email.eml \
  suspicious-reply-to-bec.eml \
  synthetic-chronopost-cloud-storage-phish.eml \
  synthetic-forwarded-arc-legitimate.eml \
  synthetic-generated-sender-spam.eml \
  synthetic-invoice-attachment-phish.eml \
  synthetic-iptv-cloud-storage-spam.eml \
  synthetic-omnisend-splach-marketing.eml \
  synthetic-paypal-raw-ip-payment-phish.eml \
  synthetic-salesforce-marketing-email.eml; do
  fetch "https://raw.githubusercontent.com/rtr-rep/email-threat-investigator/main/samples/$file" "$RAW/synthetic_bec_samples/$file"
done
fetch "https://raw.githubusercontent.com/rtr-rep/email-threat-investigator/main/LICENSE" "$RAW/synthetic_bec_samples/LICENSE"

fetch "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv" "$RAW/hf_zefang_liu/Phishing_Email.csv"
fetch "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/raw/main/README.md" "$RAW/hf_zefang_liu/README.md"

printf 'datasets ready under %s\n' "$RAW"
