from __future__ import annotations

from models import Node


def node_key(node: Node) -> tuple[str, str, int]:
    """
    Возвращает стабильный идентификатор узла.

    Протокол, адрес и порт используются для определения дублей.
    """

    return (
        node.protocol.lower().strip(),
        node.address.lower().strip(),
        node.port,
    )


def deduplicate_nodes(nodes: list[Node]) -> list[Node]:
    """
    Удаляет дубликаты, сохраняя порядок первого появления.
    """

    result: list[Node] = []
    seen: set[tuple[str, str, int]] = set()

    for node in nodes:
        key = node_key(node)

        if key in seen:
            continue

        seen.add(key)
        result.append(node)

    return result