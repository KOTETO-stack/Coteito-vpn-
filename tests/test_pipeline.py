from models import Node
from pipeline import process_nodes


def make_node(
    *,
    address: str,
    port: int = 443,
    country: str = "Germany",
    city: str = "Berlin",
    latency_ms: float = 100.0,
) -> Node:
    return Node(
        protocol="trojan",
        address=address,
        port=port,
        country=country,
        city=city,
        latency_ms=latency_ms,
        reachable=True,
        tls_valid=True,
        dns_leak=False,
        validated=True,
    )


def test_pipeline_removes_duplicates() -> None:
    first = make_node(address="example.com")
    second = make_node(address="example.com")

    result = process_nodes([first, second])

    assert len(result) == 1


def test_pipeline_removes_excluded_country() -> None:
    germany = make_node(
        address="germany.example",
        country="Germany",
    )
    excluded = make_node(
        address="excluded.example",
        country="Ukraine",
    )

    result = process_nodes(
        [germany, excluded],
        excluded_countries={"Ukraine"},
    )

    assert result == [germany]


def test_pipeline_removes_high_latency_nodes() -> None:
    fast = make_node(
        address="fast.example",
        latency_ms=100.0,
    )
    slow = make_node(
        address="slow.example",
        latency_ms=600.0,
    )

    result = process_nodes(
        [slow, fast],
        max_latency_ms=500.0,
    )

    assert result == [fast]


def test_pipeline_sorts_by_latency() -> None:
    slow = make_node(
        address="slow.example",
        city="Munich",
        latency_ms=300.0,
    )
    fast = make_node(
        address="fast.example",
        city="Berlin",
        latency_ms=50.0,
    )

    result = process_nodes([slow, fast])

    assert result == [fast, slow]


def test_pipeline_applies_russian_names() -> None:
    node = make_node(
        address="example.com",
        country="Germany",
        city="Berlin",
    )

    result = process_nodes([node])

    assert len(result) == 1
    assert result[0].name == "Германия Berlin 🇩🇪"
    assert result[0].flag == "🇩🇪"


def test_pipeline_rejects_unvalidated_node() -> None:
    node = make_node(address="example.com")
    node.validated = False

    result = process_nodes([node])

    assert result == []