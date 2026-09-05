from __future__ import annotations

from models import Node
from deduplicator import deduplicate_nodes
from filter import filter_nodes, sort_nodes
from naming import apply_node_names


class PipelineError(Exception):
    """Ошибка обработки VPN-узлов."""


def process_nodes(
    nodes: list[Node],
    excluded_countries: set[str] | None = None,
    max_latency_ms: float = 500.0,
) -> list[Node]:
    """
    Обрабатывает список узлов перед генерацией подписки.

    Порядок:
    1. Удаление дубликатов.
    2. Фильтрация.
    3. Сортировка.
    4. Формирование названий.
    """

    if not isinstance(nodes, list):
        raise PipelineError(
            "nodes должен быть списком."
        )

    unique_nodes = deduplicate_nodes(nodes)

    filtered_nodes = filter_nodes(
        unique_nodes,
        excluded_countries=excluded_countries,
        max_latency_ms=max_latency_ms,
    )

    sorted_nodes = sort_nodes(filtered_nodes)

    return apply_node_names(sorted_nodes)