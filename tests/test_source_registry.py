from pathlib import Path

from source_registry import SourceRegistryError, load_source_registry


def test_load_source_registry(tmp_path: Path) -> None:
    source_file = tmp_path / "sources.txt"
    source_file.write_text(
        """
# комментарий

https://example.com/one.txt
https://example.com/two.txt
""",
        encoding="utf-8",
    )

    sources = load_source_registry(
        path=source_file,
        max_sources=100,
    )

    assert len(sources) == 2
    assert sources[0].url == "https://example.com/one.txt"
    assert sources[1].url == "https://example.com/two.txt"


def test_load_source_registry_respects_limit(tmp_path: Path) -> None:
    source_file = tmp_path / "sources.txt"
    source_file.write_text(
        "\n".join(
            [
                "https://example.com/one.txt",
                "https://example.com/two.txt",
                "https://example.com/three.txt",
            ]
        ),
        encoding="utf-8",
    )

    sources = load_source_registry(
        path=source_file,
        max_sources=2,
    )

    assert len(sources) == 2


def test_load_source_registry_removes_duplicates(tmp_path: Path) -> None:
    source_file = tmp_path / "sources.txt"
    source_file.write_text(
        """
https://example.com/source.txt
https://example.com/source.txt
""",
        encoding="utf-8",
    )

    sources = load_source_registry(path=source_file)

    assert len(sources) == 1


def test_missing_registry_raises_error(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.txt"

    try:
        load_source_registry(path=missing_file)
    except SourceRegistryError:
        pass
    else:
        raise AssertionError(
            "Ожидалась ошибка для отсутствующего файла источников."
        )