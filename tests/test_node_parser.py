from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

from credentials import CredentialsError, NodeCredentials
from models import Node
from source_health import SourceHealth


class NodeParserError(Exception):
    """Ошибка обработки VPN-узлов."""


@dataclass(frozen=True)
class ParsedSource:
    source_url: str
    nodes: list[Node]


def _credentials_from_uri(parsed) -> NodeCredentials | None:
    if parsed.username is None:
        return None

    password = unquote(parsed.password or "")

    if not password:
        return None

    try:
        return NodeCredentials(password=password)
    except CredentialsError:
        return None


def _parse_uri(uri: str) -> Node | None:
    parsed = urlparse(uri)

    if parsed.scheme.lower() not in {
        "trojan",
        "hysteria2",
        "hy2",
    }:
        return None

    if not parsed.hostname or parsed.port is None:
        return None

    query = parse_qs(
        parsed.query,
        keep_blank_values=False,
    )

    parameters: dict[str, str] = {}

    for key in (
        "sni",
        "security",
        "type",
        "host",
        "path",
    ):
        values = query.get(key)

        if values:
            value = unquote(values[0]).strip()

            if value:
                parameters[key] = value

    protocol = (
        "hysteria2"
        if parsed.scheme.lower() == "hy2"
        else parsed.scheme.lower()
    )

    name = (
        unquote(parsed.fragment).strip()
        if parsed.fragment
        else None
    )

    return Node(
        protocol=protocol,
        address=parsed.hostname,
        port=parsed.port,
        name=name,
        credentials=_credentials_from_uri(parsed),
        parameters=parameters,
    )


def parse_healthy_source(
    health: SourceHealth,
    content: str,
) -> ParsedSource:
    if not health.available:
        raise NodeParserError(
            f"Нельзя разбирать недоступный источник: "
            f"{health.source.url}"
        )

    if not isinstance(content, str):
        raise NodeParserError(
            "Содержимое источника должно быть строкой."
        )

    nodes: list[Node] = []

    for line in content.splitlines():
        candidate = line.strip()

        if not candidate or candidate.startswith("#"):
            continue

        try:
            node = _parse_uri(candidate)
        except ValueError:
            continue

        if node is not None:
            nodes.append(node)

    return ParsedSource(
        source_url=health.source.url,
        nodes=nodes,
    )


def collect_parsed_nodes(
    parsed_sources: list[ParsedSource],
) -> list[Node]:
    nodes: list[Node] = []

    for parsed_source in parsed_sources:
        nodes.extend(parsed_source.nodes)

    return nodes