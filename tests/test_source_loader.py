from source_loader import SourceLoaderError, load_sources_from_lines, source_from_url


def test_source_from_https_url() -> None:
    source = source_from_url(
        "https://example.com/config.txt",
        name="Тестовый источник",
    )

    assert source.url == "https://example.com/config.txt"
    assert source.name == "Тестовый источник"
    assert source.enabled is True


def test_source_from_http_url() -> None:
    source = source_from_url("http://example.com/config.txt")

    assert source.url == "http://example.com/config.txt"


def test_source_url_is_trimmed() -> None:
    source = source_from_url("  https://example.com/config.txt  ")

    assert source.url == "https://example.com/config.txt"


def test_invalid_scheme_is_rejected() -> None:
    try:
        source_from_url("ftp://example.com/config.txt")
    except SourceLoaderError:
        pass
    else:
        raise AssertionError("Ожидалась ошибка для FTP-источника.")


def test_empty_url_is_rejected() -> None:
    try:
        source_from_url("   ")
    except SourceLoaderError:
        pass
    else:
        raise AssertionError("Ожидалась ошибка для пустого URL.")


def test_url_without_hostname_is_rejected() -> None:
    try:
        source_from_url("https:///config.txt")
    except SourceLoaderError:
        pass
    else:
        raise AssertionError("Ожидалась ошибка для URL без hostname.")


def test_load_sources_from_lines_ignores_comments() -> None:
    lines = [
        "# комментарий",
        "",
        "https://example.com/one.txt",
        "https://example.com/two.txt",
    ]

    sources = load_sources_from_lines(lines)

    assert len(sources) == 2
    assert sources[0].url == "https://example.com/one.txt"
    assert sources[1].url == "https://example.com/two.txt"


def test_load_sources_from_lines_ignores_invalid_urls() -> None:
    lines = [
        "https://example.com/valid.txt",
        "ftp://example.com/invalid.txt",
        "not-a-url",
    ]

    sources = load_sources_from_lines(lines)

    assert len(sources) == 1
    assert sources[0].url == "https://example.com/valid.txt"