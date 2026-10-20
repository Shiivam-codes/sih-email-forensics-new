import logging

from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.schemas import AnalysisResult, AnalysisSummary, BatchAnalysisResponse, BatchError
from app.services.analyzer import analyze_email
from app.services.ingest import IngestError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request) -> dict[str, object]:
    settings = request.app.state.settings
    store = request.app.state.store
    return {
        "status": "ok",
        "version": settings.version,
        "environment": settings.environment,
        "analyses": store.count(),
        "enrichment": request.app.state.enricher.health(),
        "scoring": {
            "enabled": settings.scoring_enabled,
            "version": settings.scoring_version,
            "malicious_threshold": settings.malicious_threshold,
            "suspicious_threshold": settings.suspicious_threshold,
        },
    }


@router.post("/analyses", response_model=BatchAnalysisResponse, status_code=201)
async def create_analysis(
    request: Request,
    files: list[UploadFile] = File(...),
) -> BatchAnalysisResponse:
    settings = request.app.state.settings
    store = request.app.state.store

    if not files:
        raise HTTPException(status_code=400, detail="At least one email file is required")
    if len(files) > settings.max_batch_files:
        raise HTTPException(
            status_code=400,
            detail=f"A maximum of {settings.max_batch_files} files is allowed per request",
        )

    results = []
    errors: list[BatchError] = []

    for upload in files:
        filename = upload.filename or "email.eml"
        try:
            data = await upload.read(settings.max_upload_bytes + 1)
            enricher = request.app.state.enricher if settings.enrichment_enabled else None
            result = analyze_email(
                data,
                filename,
                settings.max_upload_bytes,
                enricher=enricher,
                settings=settings,
            )
            store.save(result)
            results.append(result)
        except IngestError as exc:
            errors.append(BatchError(filename=filename, detail=str(exc)))
        except Exception as exc:
            logger.exception("Failed to analyze %s", filename)
            errors.append(BatchError(filename=filename, detail=f"Analysis failed: {exc}"))
        finally:
            await upload.close()

    if not results and errors:
        raise HTTPException(status_code=422, detail=[error.model_dump() for error in errors])

    return BatchAnalysisResponse(results=results, errors=errors)


@router.get("/analyses", response_model=list[AnalysisSummary])
def list_analyses(request: Request) -> list[AnalysisSummary]:
    return request.app.state.store.list()


@router.get("/analyses/{analysis_id}", response_model=AnalysisResult)
def get_analysis(request: Request, analysis_id: str) -> AnalysisResult:
    result = request.app.state.store.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result
