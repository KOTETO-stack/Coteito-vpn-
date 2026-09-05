from filter import filter_nodes, sort_nodes
from models import Node


def make_valid_node(
    *,
    country: str = "Германия",
    city: str = "Берлин",
    latency_ms: float = 100.0,
) -> Node:
    return Node(
        protocol="trojan",
        address="example.com",
        port=443,
        country=country,
        city=city,
        flag="🇩🇪",
        latency_ms=latency_ms,
        reachable=True,
        tls_valid=True,
        dns_leak=False,
        validated=True,
    )


def test_valid_node_is_accepted() -> None:
    node = make_valid_node()

    result = filter_nodes([node])

    assert result == [node]


def test_unvalidated_node_is_rejected() -> None:
    node = make_valid_node()
    node.validated = False

    result = filter_nodes([node])

    assert result == []


def test_node_with_dns_leak_is_rejected() -> None:
    node = make_valid_node()
    node.dns_leak = True

    result = filter_nodes([node])

    assert result == []


def test_node_with_unknown_dns_status_is_rejected() -> None:
    node = make_valid_node()
    node.dns_leak = None

    result = filter_nodes([node])

    assert result == []


def test_high_latency_node_is_rejected() -> None:
    node = make_valid_node(
        latency_ms=600.0,
    )

    result = filter_nodes(
        [node],
        max_latency_ms=500.0,
    )

    assert result == []


def test_excluded_country_is_rejected() -> None:
    node = make_valid_node(
        country="Ukraine",
    )

    result = filter_nodes(
        [node],
        excluded_countries={"Ukraine"},
    )

    assert result == []


def test_nodes_are_sorted_by_latency() -> None:
    slow = make_valid_node(
        city="Мюнхен",
        latency_ms=300.0,
    )

    fast = make_valid_node(
        city="Берлин",
        latency_ms=80.0,
    )

    result = sort_nodes([slow, fast])

    assert result == [fast, slow]