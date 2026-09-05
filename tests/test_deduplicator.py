from deduplicator import deduplicate_nodes, node_key
from models import Node


def make_node(
    *,
    protocol: str = "trojan",
    address: str = "example.com",
    port: int = 443,
) -> Node:
    return Node(
        protocol=protocol,
        address=address,
        port=port,
    )


def test_duplicate_nodes_are_removed() -> None:
    first = make_node()
    second = make_node()

    result = deduplicate_nodes([first, second])

    assert result == [first]


def test_different_ports_are_not_duplicates() -> None:
    first = make_node(port=443)
    second = make_node(port=8443)

    result = deduplicate_nodes([first, second])

    assert result == [first, second]


def test_different_protocols_are_not_duplicates() -> None:
    first = make_node(protocol="trojan")
    second = make_node(protocol="hysteria2")

    result = deduplicate_nodes([first, second])

    assert result == [first, second]


def test_address_and_protocol_are_case_normalized() -> None:
    first = make_node(
        protocol="Trojan",
        address="Example.COM",
    )
    second = make_node(
        protocol="trojan",
        address="example.com",
    )

    result = deduplicate_nodes([first, second])

    assert result == [first]


def test_node_key_is_stable() -> None:
    node = make_node(
        protocol="Trojan",
        address="Example.COM",
        port=443,
    )

    assert node_key(node) == ("trojan", "example.com", 443)