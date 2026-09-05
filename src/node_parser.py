from __future__ import annotations

from dataclasses import dataclass

from models import Node
from source_parser import parse_source
from source_health import SourceHealth


class NodeParserError(Exception):
    """Ошибка обработки VPN-узлов."""


@dataclass(frozen=True)
class ParsedSource:
    """Результат разбора одного источника."""

    source_url: str
    nodes: list[Node]


def parse_healthy_source(
    health: SourceHealth,
    content: str,
) -> ParsedSource:
    """
    Разбирает содержимое проверенного источника.

    Источник должен предварительно пройти проверку доступности.
    """

    if not health.available:
        raise NodeParserError(
            f"Нельзя разбирать недоступный источник: "
            f"{health.source.url}"
        )

    try:
        nodes = parse_source(content)
    except Exception as exc:
        raise NodeParserError(
            f"Не удалось разобрать источник: "
            f"{health.source.url}"
        ) from exc

    return ParsedSource(
        source_url=health.source.url,
        nodes=nodes,
    )


def collect_parsed_nodes(
    parsed_sources: list[ParsedSource],
) -> list[Node]:
    """Объединяет узлы из нескольких источников."""

    nodes: list[Node] = []

    for parsed_source in parsed_sources:
        nodes.extend(parsed_source.nodes)

    return nodes