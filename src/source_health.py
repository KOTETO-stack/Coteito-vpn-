from __future__ import annotations

from dataclasses import dataclass

from source_collector import (
    CollectedSource,
    SourceCollectorError,
    collect_source,
)
from models import Source


@dataclass(frozen=True)
class SourceHealth:
    """Результат проверки источника."""

    source: Source
    available: bool
    content_size: int
    error: str | None = None


def check_source(
    source: Source,
    timeout: int = 10,
) -> SourceHealth:
    """
    Проверяет доступность одного источника.

    Содержимое источника не записывается в результат проверки.
    """

    try:
        collected: CollectedSource = collect_source(
            source,
            timeout=timeout,
        )

    except SourceCollectorError as exc:
        return SourceHealth(
            source=source,
            available=False,
            content_size=0,
            error=str(exc),
        )

    return SourceHealth(
        source=source,
        available=True,
        content_size=len(collected.content.encode("utf-8")),
    )


def check_sources(
    sources: list[Source],
    timeout: int = 10,
) -> list[SourceHealth]:
    """Проверяет несколько источников."""

    results: list[SourceHealth] = []

    for source in sources:
        results.append(
            check_source(
                source,
                timeout=timeout,
            )
        )

    return results


def healthy_sources(
    health_results: list[SourceHealth],
) -> list[Source]:
    """Возвращает только доступные источники."""

    return [
        result.source
        for result in health_results
        if result.available
    ]