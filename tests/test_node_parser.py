import base64

from models import Node, Source
from node_parser import (
    NodeParserError,
    ParsedSource,
    collect_parsed_nodes,
    parse_content,
    parse_healthy_source,
)
from source_health import SourceHealth


def make_source() -> Source:
    return Source(
        url="https://example.com/source.txt",
        name="Тестовый источник",
    )


def make_health(
    *,
    available: bool = True,
) -> SourceHealth:
    return SourceHealth(
        source=make_source(),
        available=available,
        content_size=100 if available else 0,
        error=None if available else "unavailable",
    )


def test_parse_healthy_source() -> None:
    health = make_health()

    content = (
        "trojan://test-password@example.com:443"
        "?sni=example.com#Germany-Berlin"
    )

    result = parse_healthy_source(
        health,
        content,
    )

    assert result.source_url == (
        "https://example.com/source.txt"
    )

    assert len(result.nodes) == 1

    node = result.nodes[0]

    assert node.protocol == "trojan"
    assert node.address == "example.com"
    assert node.port == 443

    assert node.credentials is not None
    assert node.credentials.password == "test-password"

    assert node.parameters["sni"] == "example.com"
    assert "password" not in node.parameters


def test_parse_hysteria2_credentials() -> None:
    health = make_health()

    content = (
        "hysteria2://hy2-password@example.com:443"
        "?sni=example.com#Germany-Berlin"
    )

    result = parse_healthy_source(
        health,
        content,
    )

    assert len(result.nodes) == 1

    node = result.nodes[0]

    assert node.protocol == "hysteria2"
    assert node.credentials is not None
    assert node.credentials.password == "hy2-password"


def test_parse_hy2_alias() -> None:
    health = make_health()

    content = (
        "hy2://hy2-password@example.com:443"
        "?sni=example.com"
    )

    result = parse_healthy_source(
        health,
        content,
    )

    assert len(result.nodes) == 1
    assert result.nodes[0].protocol == "hysteria2"


def test_parse_base64_source() -> None:
    uri = (
        "trojan://test-password@example.com:443"
        "?sni=example.com"
    )

    encoded = base64.b64encode(
        uri.encode("utf-8"),
    ).decode("ascii")

    nodes = parse_content(encoded)

    assert len(nodes) == 1
    assert nodes[0].protocol == "trojan"
    assert nodes[0].address == "example.com"
    assert nodes[0].port == 443

    assert nodes[0].credentials is not None
    assert nodes[0].credentials.password == "test-password"


def test_parse_url_encoded_password() -> None:
    content = (
        "trojan://test%2Dpassword@example.com:443"
        "?sni=example.com"
    )

    nodes = parse_content(content)

    assert len(nodes) == 1
    assert nodes[0].credentials is not None
    assert nodes[0].credentials.password == "test-password"


def test_missing_credentials_are_not_accepted_as_credentials() -> None:
    health = make_health()

    content = (
        "trojan://example.com:443"
        "?sni=example.com"
    )

    result = parse_healthy_source(
        health,
        content,
    )

    assert len(result.nodes) == 1
    assert result.nodes[0].credentials is None


def test_unknown_protocol_is_ignored() -> None:
    nodes = parse_content(
        "ss://example-config"
    )

    assert nodes == []


def test_invalid_port_is_ignored() -> None:
    nodes = parse_content(
        "trojan://password@example.com:99999"
    )

    assert nodes == []


def test_comments_and_empty_lines_are_ignored() -> None:
    content = """
# comment

trojan://password@example.com:443
"""

    nodes = parse_content(content)

    assert len(nodes) == 1


def test_unavailable_source_is_rejected() -> None:
    health = make_health(
        available=False,
    )

    try:
        parse_healthy_source(
            health,
            "trojan://password@example.com:443",
        )
    except NodeParserError:
        pass
    else:
        raise AssertionError(
            "Ожидалась ошибка для недоступного источника."
        )


def test_parse_empty_source() -> None:
    health = make_health()

    result = parse_healthy_source(
        health,
        "",
    )

    assert result.nodes == []


def test_collect_parsed_nodes() -> None:
    node_one = Node(
        protocol="trojan",
        address="one.example",
        port=443,
    )

    node_two = Node(
        protocol="hysteria2",
        address="two.example",
        port=443,
    )

    parsed_sources = [
        ParsedSource(
            source_url="https://example.com/one.txt",
            nodes=[node_one],
        ),
        ParsedSource(
            source_url="https://example.com/two.txt",
            nodes=[node_two],
        ),
    ]

    result = collect_parsed_nodes(
        parsed_sources,
    )

    assert result == [
        node_one,
        node_two,
    ]


def test_collect_parsed_nodes_with_empty_sources() -> None:
    result = collect_parsed_nodes([])

    assert result == []