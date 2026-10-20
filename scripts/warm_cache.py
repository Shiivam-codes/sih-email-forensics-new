from pathlib import Path

from app.core.config import Settings
from app.enrichers.service import EnrichmentService
from app.services.analyzer import analyze_email

FIXTURES = Path("backend/tests/fixtures")


def main() -> None:
    settings = Settings()
    if settings.offline_mode:
        raise SystemExit("APP_OFFLINE_MODE is enabled; disable it to warm the cache")
    if not settings.enrichment_enabled:
        raise SystemExit("Enrichment is disabled; set APP_ENRICHMENT_ENABLED=true")

    service = EnrichmentService(settings)
    fixtures = sorted(FIXTURES.glob("*.eml"))
    if not fixtures:
        raise SystemExit(f"No fixtures found in {FIXTURES}")

    try:
        for path in fixtures:
            result = analyze_email(
                path.read_bytes(),
                path.name,
                settings.max_upload_bytes,
                enricher=service,
                settings=settings,
            )
            enrichment = result.enrichment
            print(
                f"{path.name}: {enrichment.status} "
                f"ips={len(enrichment.ip)} domains={len(enrichment.domain)} "
                f"urls={len(enrichment.url)} hits={enrichment.cache_hits} "
                f"misses={enrichment.cache_misses}"
            )
    finally:
        service.close()

    print(f"Cache warmed at {settings.cache_path}")


if __name__ == "__main__":
    main()
