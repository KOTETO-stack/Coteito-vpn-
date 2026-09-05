from __future__ import annotations

import base64
from urllib.parse import parse_qs, unquote, urlparse

from models import Node


ALLOWED_PROTOCOLS = {"trojan", "hysteria2", "hy2"}


class SourceParserError(Exception):
    """Ошибка разбора источника."""


def _decode_base64(value: str) -> str | None:
    """Пытается декодировать Base64-текст."""

    value = value.strip()

    if not value:
        return None

    # Убираем возможные пробелы и переносы строк.
    value = "".join(value.split())

    # Добавляем padding.
    value += "=" * (-len(value) % 4)

    try:
        decoded = base64.b64decode(
            value,
            validate=True,
        )
    except (ValueError, base64.binascii.Error):
        return None

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_uri(uri: str) -> Node | None:
    """Преобразует одну URI-конфигурацию в Node."""

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

    for key, values in query.items():
        if not values:
            continue

        # Сохраняем только первое значение.
        parameters[key] = unquote(values[0])

    # Не сохраняем секреты в дополнительные поля.
    # Они могут понадобиться генератору конфигурации позже,
    # но не должны попадать в диагностические логи.
    name = unquote(parsed.fragment) if parsed.fragment else None

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
    """
    Возвращает возможные строки конфигураций.

    Поддерживает обычный текст и Base64-содержащие источники.
    """

    lines: list[str] = []

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        lines.append(line)

    # Если в источнике не обнаружено URI,
    # пробуем рассматривать весь текст как Base64.
    if not any(
        line.lower().startswith(
            ("trojan://", "hysteria2://", "hy2://")
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
    """Разбирает содержимое одного источника."""

    if not isinstance(content, str):
        raise SourceParserError(
            "Содержимое источника должно быть строкой."
        )

    nodes: list[Node] = []

    for line in _candidate_lines(content):
        # Некоторые источники могут содержать пробелы
        # вокруг URI.
        candidate = line.strip()

        try:
            node = _parse_uri(candidate)
        except ValueError:
            # Некорректный порт или URL не должен
            # останавливать обработку всего источника.
            continue

        if node is not None:
            nodes.append(node)

    return nodes


def parse_sources(contents: list[str]) -> list[Node]:
    """Разбирает несколько источников."""

    result: list[Node] = []

    for content in contents:
        try:
            result.extend(parse_source(content))
        except SourceParserError:
            continue

    return result