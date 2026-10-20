import sqlite3
from pathlib import Path

from app.schemas import AnalysisResult, AnalysisSummary


class AnalysisStore:
    def __init__(self, database_path: str) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    data TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_analyses_analyzed_at "
                "ON analyses (analyzed_at DESC)"
            )

    def save(self, result: AnalysisResult) -> None:
        payload = result.model_dump_json()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO analyses
                    (id, filename, sha256, analyzed_at, verdict, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.id,
                    result.evidence.filename,
                    result.evidence.sha256,
                    result.evidence.analyzed_at.isoformat(),
                    result.auth.verdict,
                    payload,
                ),
            )

    def get(self, analysis_id: str) -> AnalysisResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        if row is None:
            return None
        return AnalysisResult.model_validate_json(row["data"])

    def list(self) -> list[AnalysisSummary]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM analyses ORDER BY analyzed_at DESC"
            ).fetchall()
        summaries: list[AnalysisSummary] = []
        for row in rows:
            result = AnalysisResult.model_validate_json(row["data"])
            summaries.append(
                AnalysisSummary(
                    id=result.id,
                    filename=result.evidence.filename,
                    sha256=result.evidence.sha256,
                    analyzed_at=result.evidence.analyzed_at,
                    verdict=result.auth.verdict,
                    hop_count=len(result.routing.hops),
                    ioc_count=len(result.iocs),
                    subject=result.email.subject,
                    sender=result.email.sender.address,
                    origin_ip=result.routing.origin_ip,
                    score=result.score.total if result.score.available else None,
                    label=result.score.label if result.score.available else None,
                )
            )
        return summaries

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM analyses").fetchone()
        return int(row["total"]) if row else 0

    def delete_all(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM analyses")
