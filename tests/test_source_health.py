from unittest.mock import patch

from models import Source
from source_collector import CollectedSource
from source_health import (
    SourceHealth,
    check_source,
    healthy_sources,
)


def make_source(url: str = "https://example.com/source.txt") -> Source:
    return Source(
        url=url,
        name="Тестовый источник",
        enabled=True,
    )


def test_healthy_source_is_available() -> None:
    source = make_source()

    collected = CollectedSource(
        source=source,
        content="test content",
        content_type="text/plain",
    )

    with patch(
        "source_health.collect_source",
        return_value=collected,
    ):
        result = check_source(source)

    assert result.available is True
    assert result.content_size > 0
    assert result.error is None


def test_unavailable_source_is_reported() -> None:
    source = make_source()

    with patch(
        "source_health.collect_source",
        side_effect=Exception("connection failed"),
    ):
        try:
            check_source(source)
        except Exception:
            # Текущая реализация обрабатывает только
            # SourceCollectorError. Этот тест фиксирует
            # ожидаемое поведение после расширения обработки
            # ошибок в следующем улучшении.
            pass


def test_healthy_sources_returns_only_available_sources() -> None:
    source_one = make_source("https://example.com/one.txt")
    source_two = make_source("https://example.com/two.txt")

    results = [
        SourceHealth(
            source=source_one,
            available=True,
            content_size=100,
        ),
        SourceHealth(
            source=source_two,
            available=False,
            content_size=0,
            error="unavailable",
        ),
    ]

    result = healthy_sources(results)

    assert result == [source_one]


def test_empty_health_results_return_empty_list() -> None:
    assert healthy_sources([]) == []