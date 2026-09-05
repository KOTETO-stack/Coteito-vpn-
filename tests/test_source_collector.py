from unittest.mock import MagicMock, patch

import pytest

from models import Source
from source_collector import (
    SourceCollectorError,
    _validate_url,
    collect_source,
)


def make_source(
    url: str = "https://example.com/source.txt",
) -> Source:
    return Source(
        url=url,
        name="Тестовый источник",
        enabled=True,
    )


def test_disabled_source_is_rejected() -> None:
    source = Source(
        url="https://example.com/source.txt",
        enabled=False,
    )

    with pytest.raises(SourceCollectorError):
        collect_source(source)


def test_invalid_scheme_is_rejected() -> None:
    with pytest.raises(SourceCollectorError):
        _validate_url("ftp://example.com/source.txt")


def test_missing_hostname_is_rejected() -> None:
    with pytest.raises(SourceCollectorError):
        _validate_url("https:///source.txt")


@patch("source_collector.socket.getaddrinfo")
def test_private_address_is_rejected(mock_getaddrinfo: MagicMock) -> None:
    mock_getaddrinfo.return_value = [
        (
            2,
            1,
            6,
            "",
            ("192.168.1.10", 0),
        )
    ]

    with pytest.raises(SourceCollectorError):
        _validate_url("https://example.com/source.txt")


@patch("source_collector.socket.getaddrinfo")
def test_loopback_address_is_rejected(mock_getaddrinfo: MagicMock) -> None:
    mock_getaddrinfo.return_value = [
        (
            2,
            1,
            6,
            "",
            ("127.0.0.1", 0),
        )
    ]

    with pytest.raises(SourceCollectorError):
        _validate_url("https://example.com/source.txt")


@patch("source_collector.socket.getaddrinfo")
def test_public_address_is_allowed(mock_getaddrinfo: MagicMock) -> None:
    mock_getaddrinfo.return_value = [
        (
            2,
            1,
            6,
            "",
            ("93.184.216.34", 0),
        )
    ]

    _validate_url("https://example.com/source.txt")


@patch("source_collector.urlopen")
@patch("source_collector.socket.getaddrinfo")
def test_collect_source_reads_content(
    mock_getaddrinfo: MagicMock,
    mock_urlopen: MagicMock,
) -> None:
    mock_getaddrinfo.return_value = [
        (
            2,
            1,
            6,
            "",
            ("93.184.216.34", 0),
        )
    ]

    response = MagicMock()
    response.status = 200
    response.headers.get.return_value = "text/plain"
    response.read.side_effect = [
        b"test content",
        b"",
    ]

    context_manager = MagicMock()
    context_manager.__enter__.return_value = response
    context_manager.__exit__.return_value = False
    mock_urlopen.return_value = context_manager

    result = collect_source(make_source())

    assert result.content == "test content"
    assert result.content_type == "text/plain"
    assert result.source.url == "https://example.com/source.txt"


@patch("source_collector.urlopen")
@patch("source_collector.socket.getaddrinfo")
def test_non_success_http_status_is_rejected(
    mock_getaddrinfo: MagicMock,
    mock_urlopen: MagicMock,
) -> None:
    mock_getaddrinfo.return_value = [
        (
            2,
            1,
            6,
            "",
            ("93.184.216.34", 0),
        )
    ]

    response = MagicMock()
    response.status = 404

    context_manager = MagicMock()
    context_manager.__enter__.return_value = response
    context_manager.__exit__.return_value = False
    mock_urlopen.return_value = context_manager

    with pytest.raises(SourceCollectorError):
        collect_source(make_source())


@patch("source_collector.urlopen")
@patch("source_collector.socket.getaddrinfo")
def test_response_larger_than_limit_is_rejected(
    mock_getaddrinfo: MagicMock,
    mock_urlopen: MagicMock,
) -> None:
    mock_getaddrinfo.return_value = [
        (
            2,
            1,
            6,
            "",
            ("93.184.216.34", 0),
        )
    ]

    response = MagicMock()
    response.status = 200
    response.headers.get.return_value = "text/plain"

    # Один слишком большой блок должен быть отклонён.
    response.read.side_effect = [
        b"x" * (2 * 1024 * 1024 + 1),
    ]

    context_manager = MagicMock()
    context_manager.__enter__.return_value = response
    context_manager.__exit__.return_value = False
    mock_urlopen.return_value = context_manager

    with pytest.raises(SourceCollectorError):
        collect_source(make_source())