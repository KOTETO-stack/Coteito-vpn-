from __future__ import annotations

from models import Node
from validator import (
    ValidatorConfig,
    apply_validation_result,
    validate_node,
)


class NodeValidatorError(Exception):
    """Ошибка проверки VPN-узлов."""


def validate_nodes(
    nodes: list[Node],
    timeout_seconds: float = 10.0,
    max_latency_ms: float = 500.0,
    verify_tls: bool = True,
) -> list[Node]:
    """
    Проверяет список VPN-узлов.

    Результат проверки записывается непосредственно
    в объекты Node.
    """

    if not isinstance(nodes, list):
        raise NodeValidatorError(
            "nodes должен быть списком."
        )

    config = ValidatorConfig(
        timeout_seconds=timeout_seconds,
        max_latency_ms=max_latency_ms,
        verify_tls=verify_tls,
    )

    validated_nodes: list[Node] = []

    for node in nodes:
        try:
            result = validate_node(
                node,
                config=config,
            )
        except Exception as exc:
            node.validated = False
            continue

        apply_validation_result(
            node,
            result,
        )

        validated_nodes.append(node)

    return validated_nodes