from __future__ import annotations

import base64
import binascii
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


ALLOWED_PROTOCOLS = {
    "trojan",
    "hysteria2",
    "hy2",
}


def _decode_base64(value: str) -> str | None:
    value = "".join(value.strip().split())

    if not value:
        return None

    value += "=" * (-len(value) % 4)

    try:
        decoded = base64.b64decode(
            value,
            validate=True,
        )
    except (ValueError, binascii.Error):
        return None

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _credentials_from_uri(
    parsed,
) -> NodeCredentials | None:
    if parsed.username is None:
        return None

    password = unquote(
        parsed.password or "",
    )

    if not password:
        return None

    try:
        return NodeCredentials(
            password=password,
        )
    except CredentialsError:
        return None


def _parse_uri(uri: str) -> Node | None:
    parsed = urlparse(uri)

    protocol = parsed.scheme.lower()

    if protocol not in ALLOWED_PROTOCOLS:
        return None

    if not parsed.hostname:
        return None

    if parsed.port is None:
        return None

    if not 1 <= parsed.port <= 65535:
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

        if not values:
            continue

        value = unquote(
            values[0],
        ).strip()

        if value:
            parameters[key] = value

    normalized_protocol = (
        "hysteria2"
        if protocol == "hy2"
        else protocol
    )

    name = (
        unquote(
            parsed.fragment,
        ).strip()
        if parsed.fragment
        else None
    )

    return Node(
        protocol=normalized_protocol,
        address=parsed.hostname,
        port=parsed.port,
        name=name,
        credentials=_credentials_from_uri(
            parsed,
        ),
        parameters=parameters,
    )


def _candidate_lines(
    content: str,
) -> list[str]:
    lines: list[str] = []

    for line in content.splitlines():
        candidate = line.strip()

        if not candidate:
            continue

        if candidate.startswith("#"):
            continue

        lines.append(candidate)

    has_uri = any(
        line.lower().startswith(
            (
                "trojan://",
                "hysteria2://",
                "hy2://",
            )
        )
        for line in lines
    )

    if not has_uri:
        decoded = _decode_base64(
            content,
        )

        if decoded:
            for line in decoded.splitlines():
                candidate = line.strip()

                if candidate and not candidate.startswith("#"):
                    lines.append(candidate)

    return lines


def parse_content(
    content: str,
) -> list[Node]:
    if not isinstance(content, str):
        raise NodeParserError(
            "Содержимое источника должно быть строкой."
        )

    nodes: list[Node] = []

    for line in _candidate_lines(content):
        try:
            node = _parse_uri(line)
        except ValueError:
            continue

        if node is not None:
            nodes.append(node)

    return nodes


def parse_healthy_source(
    health: SourceHealth,
    content: str,
) -> ParsedSource:
    if not health.available:
        raise NodeParserError(
            "Нельзя разбирать недоступный источник: "
            f"{health.source.url}"
        )

    return ParsedSource(
        source_url=health.source.url,
        nodes=parse_content(content),
    )


def collect_parsed_nodes(
    parsed_sources: list[ParsedSource],
) -> list[Node]:
    nodes: list[Node] = []

    for parsed_source in parsed_sources:
        nodes.extend(
            parsed_source.nodes,
        )

    return nodes