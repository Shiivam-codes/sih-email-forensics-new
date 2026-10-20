from app.schemas import SourceStatus

TERMINAL_STATUSES = {"offline", "disabled", "budget_exceeded"}


class SourceTracker:
    def __init__(self) -> None:
        self._items: dict[str, SourceStatus] = {}

    def mark(self, source: str, status: str, detail: str | None = None) -> None:
        current = self._items.get(source)
        if current is None:
            self._items[source] = SourceStatus(source=source, status=status, detail=detail)
            return
        if current.status in TERMINAL_STATUSES:
            return
        if status in TERMINAL_STATUSES:
            self._items[source] = SourceStatus(source=source, status=status, detail=detail)
            return
        if current.status == status:
            if detail:
                current.detail = detail
            return
        if {current.status, status} == {"ok", "unavailable"}:
            self._items[source] = SourceStatus(
                source=source,
                status="partial",
                detail=detail or current.detail,
            )
            return
        self._items[source] = SourceStatus(source=source, status=status, detail=detail)

    def as_dict(self) -> dict[str, SourceStatus]:
        return dict(self._items)
