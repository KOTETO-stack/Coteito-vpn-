from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from models import Source


DEFAULT_TIMEOUT = 10
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MiB

USER_AGENT = "Karing-Subscription-Builder/1.0"


class SourceCollectorError(Exception):
    """Ошибка получения содержимого источника."""


@dataclass(frozen=True)
class CollectedSource:
    """Результат загрузки одного источника."""

    source: Source
    content: str
    content_type: str | None = None


def _validate_url(url: str) -> None:
    """Проверяет URL перед сетевым запросом."""

    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise SourceCollectorError(
            f"Недопустимая схема URL: {parsed.scheme}"
        )

    if not parsed.hostname:
        raise SourceCollectorError("URL не содержит hostname.")

    hostname = parsed.hostname

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise SourceCollectorError(
            f"Не удалось разрешить hostname: {hostname}"
        ) from exc

    checked_addresses: set[str] = set()

    for address_info in addresses:
        address = address_info[4][0]

        if address in checked_addresses:
            continue

        checked_addresses.add(address)

        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise SourceCollectorError(
                f"Некорректный IP-адрес: {address}"
            ) from exc

        # Не разрешаем обращаться к локальным,
        # loopback, link-local, multicast и reserved адресам.
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise SourceCollectorError(
                f"Источник разрешается в недопустимый адрес: {address}"
            )


def _read_limited(response) -> bytes:
    """
    Читает ответ с ограничением размера.

    Это защищает сборщик от чрезмерно больших ответов.
    """

    data = bytearray()

    while True:
        chunk = response.read(64 * 1024)

        if not chunk:
            break

        data.extend(chunk)

        if len(data) > MAX_RESPONSE_SIZE:
            raise SourceCollectorError(
                f"Ответ источника превышает "
                f"{MAX_RESPONSE_SIZE} байт."
            )

    return bytes(data)


def collect_source(
    source: Source,
    timeout: int = DEFAULT_TIMEOUT,
) -> CollectedSource:
    """Загружает один публичный источник."""

    if not source.enabled:
        raise SourceCollectorError(
            f"Источник отключён: {source.url}"
        )

    _validate_url(source.url)

    request = Request(
        source.url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain,text/*;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )

    try:
        with urlopen(
            request,
            timeout=timeout,
        ) as response:

            status = getattr(response, "status", 200)

            if status < 200 or status >= 300:
                raise SourceCollectorError(
                    f"Источник вернул HTTP {status}: {source.url}"
                )

            content_type = response.headers.get("Content-Type")

            raw = _read_limited(response)

    except HTTPError as exc:
        raise SourceCollectorError(
            f"HTTP ошибка {exc.code}: {source.url}"
        ) from exc

    except URLError as exc:
        raise SourceCollectorError(
            f"Ошибка подключения к источнику {source.url}: {exc.reason}"
        ) from exc

    except TimeoutError as exc:
        raise SourceCollectorError(
            f"Тайм-аут источника: {source.url}"
        ) from exc

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            raise SourceCollectorError(
                f"Не удалось декодировать ответ: {source.url}"
            ) from exc

    return CollectedSource(
        source=source,
        content=content,
        content_type=content_type,
    )


def collect_sources(
    sources: list[Source],
    timeout: int = DEFAULT_TIMEOUT,
) -> list[CollectedSource]:
    """
    Загружает несколько источников.

    Ошибка одного источника не останавливает сбор остальных.
    """

    results: list[CollectedSource] = []

    for source in sources:
        try:
            result = collect_source(
                source,
                timeout=timeout,
            )
        except SourceCollectorError:
            continue

        results.append(result)

    return results