from __future__ import annotations

from models import Source


class SourceManagerError(Exception):
    """Ошибка управления источниками."""


def normalize_sources(
    sources: list[Source],
    max_sources: int = 100,
) -> list[Source]:
    """
    Нормализует список источников.

    - оставляет только включённые источники;
    - удаляет дубликаты;
    - ограничивает количество источников.
    """

    if max_sources <= 0:
        raise SourceManagerError(
            "max_sources должен быть больше нуля."
        )

    result: list[Source] = []
    seen: set[str] = set()

    for source in sources:
        if not source.enabled:
            continue

        url = source.url.strip()

        if not url:
            continue

        normalized_url = url.lower()

        if normalized_url in seen:
            continue

        seen.add(normalized_url)

        result.append(
            Source(
                url=url,
                name=source.name,
                enabled=True,
            )
        )

        if len(result) >= max_sources:
            break

    return result


def get_enabled_sources(
    sources: list[Source],
) -> list[Source]:
    """Возвращает только включённые источники."""

    return [
        source
        for source in sources
        if source.enabled and source.url.strip()
    ]