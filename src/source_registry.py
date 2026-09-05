from __future__ import annotations

from pathlib import Path

from models import Source
from source_loader import load_sources_from_lines
from source_manager import normalize_sources


DEFAULT_SOURCES_PATH = Path("sources/sources.txt")


class SourceRegistryError(Exception):
    """Ошибка реестра источников."""


def load_source_registry(
    path: str | Path = DEFAULT_SOURCES_PATH,
    max_sources: int = 100,
) -> list[Source]:
    """
    Загружает источники из текстового файла.

    Формат файла:
        один URL на строку

    Пустые строки и строки, начинающиеся с #,
    игнорируются.
    """

    source_path = Path(path)

    if not source_path.is_file():
        raise SourceRegistryError(
            f"Файл источников не найден: {source_path}"
        )

    try:
        lines = source_path.read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError as exc:
        raise SourceRegistryError(
            f"Не удалось прочитать файл источников: {exc}"
        ) from exc

    sources = load_sources_from_lines(lines)

    return normalize_sources(
        sources,
        max_sources=max_sources,
    )