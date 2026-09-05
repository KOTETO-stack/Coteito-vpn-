from models import Node
from node_validator import validate_nodes


def make_node(
    *,
    protocol: str = "unknown",
    address: str = "127.0.0.1",
    port: int = 443,
) -> Node:
    return Node(
        protocol=protocol,
        address=address,
        port=port,
    )


def test_validate_nodes_requires_a_list() -> None:
    try:
        validate_nodes("not-a-list")  # type: ignore[arg-type]
    except Exception as exc:
        assert type(exc).__name__ == "NodeValidatorError"
    else:
        raise AssertionError("Ожидалась ошибка для некорректного типа.")


def test_unsupported_protocol_is_not_validated() -> None:
    node = make_node(protocol="unknown")

    result = validate_nodes([node])

    assert len(result) == 1
    assert result[0].validated is False


def test_unsupported_protocol_has_no_valid_connection() -> None:
    node = make_node(protocol="unknown")

    result = validate_nodes([node])

    assert result[0].reachable is False
    assert result[0].tls_valid is False


def test_empty_node_list_is_supported() -> None:
    result = validate_nodes([])

    assert result == []