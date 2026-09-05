from __future__ import annotations

from urllib.parse import urlparse

from models import Source


class SourceLoaderError(Exception):
    """Ошибка загрузки списка источников."""


ALLOWED_SCHEMES = {"http", "https"}


def _validate_source_url(url: str) -> str:
    """Проверяет URL источника."""

    normalized = url.strip()

    if not normalized:
        raise SourceLoaderError(
            "URL источника не может быть пустым."
        )

    parsed = urlparse(normalized)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SourceLoaderError(
            f"Недопустимая схема источника: {parsed.scheme}"
        )

    if not parsed.hostname:
        raise SourceLoaderError(
            "URL источника не содержит hostname."
        )

    return normalized


def source_from_url(
    url: str,
    name: str | None = None,
) -> Source:
    """Создаёт Source из URL."""

    normalized_url = _validate_source_url(url)

    return Source(
        url=normalized_url,
        name=name.strip() if name else None,
        enabled=True,
    )


def load_sources_from_lines(
    lines: list[str],
) -> list[Source]:
    """
    Создаёт список источников из строк.

    Пустые строки и комментарии игнорируются.
    Некорректные URL пропускаются.
    """

    sources: list[Source] = []

    for line in lines:
        value = line.strip()

        if not value or value.startswith("#"):
            continue

        try:
            source = source_from_url(value)
        except SourceLoaderError:
            continue

        sources.append(source)

    return sources