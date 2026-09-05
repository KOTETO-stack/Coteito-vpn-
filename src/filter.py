from __future__ import annotations

from models import Node


DEFAULT_MAX_LATENCY_MS = 500.0


class FilterError(Exception):
    """Ошибка фильтрации VPN-узлов."""


def _normalize(value: str | None) -> str:
    """Нормализует строковое значение."""

    if value is None:
        return ""

    return value.strip().lower()


def is_excluded_country(
    node: Node,
    excluded_countries: set[str],
) -> bool:
    """Проверяет, находится ли страна в списке исключений."""

    country = _normalize(node.country)

    return country in {
        _normalize(country_name)
        for country_name in excluded_countries
    }


def is_validated_node(
    node: Node,
    max_latency_ms: float = DEFAULT_MAX_LATENCY_MS,
) -> bool:
    """
    Проверяет, соответствует ли узел базовым требованиям
    перед публикацией.
    """

    if not node.validated:
        return False

    if not node.reachable:
        return False

    if not node.tls_valid:
        return False

    if node.dns_leak is not False:
        return False

    if node.latency_ms is None:
        return False

    if node.latency_ms > max_latency_ms:
        return False

    return True


def filter_nodes(
    nodes: list[Node],
    excluded_countries: set[str] | None = None,
    max_latency_ms: float = DEFAULT_MAX_LATENCY_MS,
) -> list[Node]:
    """
    Возвращает только узлы, разрешённые для публикации.

    Порядок исходного списка сохраняется.
    """

    excluded_countries = excluded_countries or set()

    result: list[Node] = []

    for node in nodes:
        if is_excluded_country(
            node,
            excluded_countries,
        ):
            continue

        if not is_validated_node(
            node,
            max_latency_ms=max_latency_ms,
        ):
            continue

        result.append(node)

    return result


def sort_nodes(nodes: list[Node]) -> list[Node]:
    """
    Сортирует прошедшие фильтрацию узлы.

    Узлы с неизвестной задержкой отправляются в конец.
    """

    return sorted(
        nodes,
        key=lambda node: (
            node.latency_ms is None,
            node.latency_ms or float("inf"),
            _normalize(node.country),
            _normalize(node.city),
        ),
    )