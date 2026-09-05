from models import Node, Source
from node_parser import (
    NodeParserError,
    ParsedSource,
    collect_parsed_nodes,
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

    # Пароль не должен попадать в обычные параметры.
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


def test_unavailable_source_is_rejected() -> None:
    health = make_health(available=False)

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