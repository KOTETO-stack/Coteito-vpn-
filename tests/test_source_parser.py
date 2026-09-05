from source_parser import parse_source


def test_parse_trojan_uri() -> None:
    content = (
        "trojan://password@example.com:443"
        "?sni=example.com#Germany-Berlin"
    )

    nodes = parse_source(content)

    assert len(nodes) == 1

    node = nodes[0]

    assert node.protocol == "trojan"
    assert node.address == "example.com"
    assert node.port == 443
    assert node.name == "Germany-Berlin"
    assert node.parameters["sni"] == "example.com"


def test_parse_hysteria2_uri() -> None:
    content = (
        "hysteria2://password@example.com:443"
        "?sni=example.com#Germany-Berlin"
    )

    nodes = parse_source(content)

    assert len(nodes) == 1

    node = nodes[0]

    assert node.protocol == "hysteria2"
    assert node.address == "example.com"
    assert node.port == 443


def test_hy2_alias_is_normalized() -> None:
    content = "hy2://password@example.com:443"

    nodes = parse_source(content)

    assert len(nodes) == 1
    assert nodes[0].protocol == "hysteria2"


def test_unknown_protocol_is_ignored() -> None:
    content = "ss://example-config"

    nodes = parse_source(content)

    assert nodes == []


def test_invalid_port_is_ignored() -> None:
    content = "trojan://password@example.com:99999"

    nodes = parse_source(content)

    assert nodes == []


def test_comments_and_empty_lines_are_ignored() -> None:
    content = """
# comment

trojan://password@example.com:443
"""

    nodes = parse_source(content)

    assert len(nodes) == 1