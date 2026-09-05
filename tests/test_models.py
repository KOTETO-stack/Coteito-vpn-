from models import Node, Source, ValidationResult


def test_source_creation() -> None:
    source = Source(
        url="https://example.com/source.txt",
        name="Тестовый источник",
    )

    assert source.url == "https://example.com/source.txt"
    assert source.name == "Тестовый источник"
    assert source.enabled is True


def test_node_display_name() -> None:
    node = Node(
        protocol="trojan",
        address="example.com",
        port=443,
        country="Германия",
        city="Берлин",
        flag="🇩🇪",
    )

    assert node.display_name() == "Германия Берлин 🇩🇪"


def test_node_fallback_display_name() -> None:
    node = Node(
        protocol="trojan",
        address="example.com",
        port=443,
    )

    assert node.display_name() == "example.com:443"


def test_validation_result_failed_without_connection() -> None:
    result = ValidationResult(
        reachable=False,
        tls_valid=False,
        latency_ms=None,
        dns_leak=None,
        errors=["connection failed"],
    )

    assert result.passed is False


def test_validation_result_failed_with_dns_leak() -> None:
    result = ValidationResult(
        reachable=True,
        tls_valid=True,
        latency_ms=100.0,
        dns_leak=True,
        errors=[],
    )

    assert result.passed is False