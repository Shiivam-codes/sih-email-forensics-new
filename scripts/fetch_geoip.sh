#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/data/geoip"
VERSION="${DBIP_VERSION:-2026-10}"

mkdir -p "$DEST"

for KIND in city asn; do
  ARCHIVE="dbip-${KIND}-lite-${VERSION}.mmdb.gz"
  DATABASE="dbip-${KIND}-lite-${VERSION}.mmdb"
  if [[ ! -s "$DEST/$DATABASE" ]]; then
    curl -fSL --retry 3 --connect-timeout 15 \
      -o "$DEST/$ARCHIVE" \
      "https://download.db-ip.com/free/$ARCHIVE"
    gunzip -f "$DEST/$ARCHIVE"
  fi
  if [[ ! -s "$DEST/$DATABASE" ]]; then
    echo "GeoIP download failed for $DATABASE" >&2
    exit 1
  fi
  ln -sf "$DATABASE" "$DEST/dbip-${KIND}-lite.mmdb"
done

echo "GeoIP databases ready in $DEST"
ls -lh "$DEST"/*.mmdb
