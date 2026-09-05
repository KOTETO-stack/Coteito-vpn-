from pathlib import Path
from unittest.mock import patch

from models import Source
from source_health import SourceHealth
from source_updater import save_sources, update_sources


def make_source(
    url: str,
    *,
    enabled: bool = True,
) -> Source:
    return Source(
        url=url,
        name="Тестовый источник",
        enabled=enabled,
    )


def test_update_sources_keeps_healthy_sources() -> None:
    source = make_source("https://example.com/source.txt")

    healthy_result = SourceHealth(
        source=source,
        available=True,
        content_size=100,
    )

    with patch(
        "source_updater.check_source",
        return_value=healthy_result,
    ):
        result = update_sources([source])

    assert result == [source]


def test_update_sources_removes_unhealthy_sources() -> None:
    source = make_source("https://example.com/source.txt")

    unhealthy_result = SourceHealth(
        source=source,
        available=False,
        content_size=0,
        error="unavailable",
    )

    with patch(
        "source_updater.check_source",
        return_value=unhealthy_result,
    ):
        result = update_sources([source])

    assert result == []


def test_update_sources_handles_multiple_sources() -> None:
    healthy = make_source(
        "https://example.com/healthy.txt"
    )
    unhealthy = make_source(
        "https://example.com/unhealthy.txt"
    )

    def fake_check_source(source: Source, timeout: int = 10) -> SourceHealth:
        if source.url.endswith("healthy.txt"):
            return SourceHealth(
                source=source,
                available=True,
                content_size=100,
            )

        return SourceHealth(
            source=source,
            available=False,
            content_size=0,
            error="unavailable",
        )

    with patch(
        "source_updater.check_source",
        side_effect=fake_check_source,
    ):
        result = update_sources([healthy, unhealthy])

    assert result == [healthy]


def test_save_sources_creates_file(tmp_path: Path) -> None:
    output_path = tmp_path / "sources.txt"

    sources = [
        make_source("https://example.com/one.txt"),
        make_source("https://example.com/two.txt"),
    ]

    result = save_sources(sources, output_path)

    assert result == output_path
    assert output_path.is_file()

    content = output_path.read_text(encoding="utf-8")

    assert content == (
        "https://example.com/one.txt\n"
        "https://example.com/two.txt\n"
    )


def test_save_sources_skips_disabled_sources(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "sources.txt"

    sources = [
        make_source(
            "https://example.com/enabled.txt",
            enabled=True,
        ),
        make_source(
            "https://example.com/disabled.txt",
            enabled=False,
        ),
    ]

    save_sources(sources, output_path)

    content = output_path.read_text(encoding="utf-8")

    assert content == (
        "https://example.com/enabled.txt\n"
    )


def test_save_empty_sources_creates_empty_file(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "sources.txt"

    save_sources([], output_path)

    assert output_path.is_file()
    assert output_path.read_text(encoding="utf-8") == ""