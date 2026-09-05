from __future__ import annotations

from dns_checker import check_node_dns, apply_dns_result
from dns_policy import DNSPolicy
from models import Node


class DNSValidatorError(Exception):
    """Ошибка DNS-проверки узлов."""


def validate_node_dns(
    node: Node,
    policy: DNSPolicy | None = None,
) -> Node:
    """
    Выполняет DNS-проверку одного узла
    и записывает результат в Node.
    """

    policy = policy or DNSPolicy()

    result = check_node_dns(node)

    apply_dns_result(
        node,
        result,
    )

    if not policy.accepts(result):
        node.validated = False

    return node


def validate_nodes_dns(
    nodes: list[Node],
    policy: DNSPolicy | None = None,
) -> list[Node]:
    """
    Выполняет DNS-проверку всех узлов.

    Узлы не удаляются из списка:
    результат проверки сохраняется в каждом Node.
    """

    if not isinstance(nodes, list):
        raise DNSValidatorError(
            "nodes должен быть списком."
        )

    policy = policy or DNSPolicy()

    for node in nodes:
        validate_node_dns(
            node,
            policy=policy,
        )

    return nodes