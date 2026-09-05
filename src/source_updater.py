from __future__ import annotations

from pathlib import Path

from models import Source
from source_health import check_source


class SourceUpdaterError(Exception):
    """Ошибка обновления источников."""


def update_sources(
    sources: list[Source],
    timeout: int = 10,
) -> list[Source]:
    """
    Проверяет источники и возвращает только доступные.

    Содержимое источников здесь не изменяется.
    Проверяется только их техническая доступность.
    """

    healthy: list[Source] = []

    for source in sources:
        result = check_source(
            source,
            timeout=timeout,
        )

        if result.available:
            healthy.append(source)

    return healthy


def save_sources(
    sources: list[Source],
    path: str | Path,
) -> Path:
    """
    Сохраняет список рабочих источников.

    Один URL на строку.
    """

    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = [
        source.url
        for source in sources
        if source.enabled and source.url.strip()
    ]

    try:
        output_path.write_text(
            "\n".join(lines) + ("\n" if lines else ""),
            encoding="utf-8",
        )
    except OSError as exc:
        raise SourceUpdaterError(
            f"Не удалось сохранить источники: {exc}"
        ) from exc

    return output_path