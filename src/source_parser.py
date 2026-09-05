from __future__ import annotations

import base64
import binascii
from urllib.parse import parse_qs, unquote, urlparse

from models import Node


ALLOWED_PROTOCOLS = {"trojan", "hysteria2", "hy2"}


class SourceParserError(Exception):
    """Ошибка разбора источника."""


def _decode_base64(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None

    value = "".join(value.split())
    value += "=" * (-len(value) % 4)

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_uri(uri: str) -> Node | None:
    uri = uri.strip()
    if not uri:
        return None

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

    for key in ("sni", "security", "type", "host", "path"):
        values = query.get(key)

        if not values:
            continue

        value = unquote(values[0]).strip()

        if value:
            parameters[key] = value

    name = (
        unquote(parsed.fragment).strip()
        if parsed.fragment
        else None
    )

    normalized_protocol = (
        "hysteria2"
        if protocol == "hy2"
        else protocol
    )

    return Node(
        protocol=normalized_protocol,
        address=parsed.hostname,
        port=parsed.port,
        name=name,
        parameters=parameters,
    )


def _candidate_lines(content: str) -> list[str]:
    lines: list[str] = []

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        lines.append(line)

    if not any(
        line.lower().startswith(
            (
                "trojan://",
                "hysteria2://",
                "hy2://",
            )
        )
        for line in lines
    ):
        decoded = _decode_base64(content)

        if decoded:
            for line in decoded.splitlines():
                line = line.strip()

                if line:
                    lines.append(line)

    return lines


def parse_source(content: str) -> list[Node]:
    if not isinstance(content, str):
        raise SourceParserError(
            "Содержимое источника должно быть строкой."
        )

    nodes: list[Node] = []

    for line in _candidate_lines(content):
        candidate = line.strip()

        try:
            node = _parse_uri(candidate)
        except ValueError:
            continue

        if node is not None:
            nodes.append(node)

    return nodes


def parse_sources(contents: list[str]) -> list[Node]:
    result: list[Node] = []

    for content in contents:
        try:
            result.extend(parse_source(content))
        except SourceParserError:
            continue

    return result