from models import Source
from source_manager import (
    SourceManagerError,
    get_enabled_sources,
    normalize_sources,
)


def test_normalize_sources_removes_duplicates() -> None:
    sources = [
        Source(url="https://example.com/source.txt"),
        Source(url="https://example.com/source.txt"),
    ]

    result = normalize_sources(sources)

    assert len(result) == 1
    assert result[0].url == "https://example.com/source.txt"


def test_normalize_sources_skips_disabled_sources() -> None:
    sources = [
        Source(
            url="https://example.com/disabled.txt",
            enabled=False,
        ),
        Source(
            url="https://example.com/enabled.txt",
            enabled=True,
        ),
    ]

    result = normalize_sources(sources)

    assert len(result) == 1
    assert result[0].url == "https://example.com/enabled.txt"


def test_normalize_sources_skips_empty_urls() -> None:
    sources = [
        Source(url="   "),
        Source(url="https://example.com/valid.txt"),
    ]

    result = normalize_sources(sources)

    assert len(result) == 1
    assert result[0].url == "https://example.com/valid.txt"


def test_normalize_sources_respects_max_sources() -> None:
    sources = [
        Source(url="https://example.com/one.txt"),
        Source(url="https://example.com/two.txt"),
        Source(url="https://example.com/three.txt"),
    ]

    result = normalize_sources(sources, max_sources=2)

    assert len(result) == 2
    assert result[0].url == "https://example.com/one.txt"
    assert result[1].url == "https://example.com/two.txt"


def test_normalize_sources_rejects_invalid_limit() -> None:
    try:
        normalize_sources([], max_sources=0)
    except SourceManagerError:
        pass
    else:
        raise AssertionError(
            "Ожидалась ошибка при max_sources=0."
        )


def test_get_enabled_sources() -> None:
    sources = [
        Source(
            url="https://example.com/one.txt",
            enabled=True,
        ),
        Source(
            url="https://example.com/two.txt",
            enabled=False,
        ),
        Source(
            url="   ",
            enabled=True,
        ),
    ]

    result = get_enabled_sources(sources)

    assert len(result) == 1
    assert result[0].url == "https://example.com/one.txt"