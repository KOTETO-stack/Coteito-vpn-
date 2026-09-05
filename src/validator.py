from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

from models import Node, ValidationResult


DEFAULT_TIMEOUT = 10.0


class ValidatorError(Exception):
    """Ошибка проверки VPN-узла."""


@dataclass(frozen=True)
class ValidatorConfig:
    """Параметры технической проверки."""

    timeout_seconds: float = DEFAULT_TIMEOUT
    max_latency_ms: float = 500.0
    verify_tls: bool = True


def _tcp_check(node: Node, timeout: float) -> float:
    """
    Проверяет TCP-доступность адреса и измеряет задержку.

    Возвращает время подключения в миллисекундах.
    """

    started = time.perf_counter()

    with socket.create_connection(
        (node.address, node.port),
        timeout=timeout,
    ):
        pass

    elapsed = (time.perf_counter() - started) * 1000

    return elapsed


def _tls_check(
    node: Node,
    timeout: float,
    verify_certificate: bool,
) -> bool:
    """
    Проверяет TLS только для TCP/TLS-соединения.

    Важно: успешный TLS handshake не означает,
    что Trojan или Hysteria2 успешно авторизовался.
    """

    if node.protocol == "hysteria2":
        # Hysteria2 работает поверх QUIC/UDP, поэтому
        # обычная TCP/TLS-проверка здесь неприменима.
        return False

    if node.protocol != "trojan":
        return False

    if verify_certificate:
        context = ssl.create_default_context()
        server_hostname = node.address
    else:
        context = ssl._create_unverified_context()
        server_hostname = node.address

    raw_socket = socket.create_connection(
        (node.address, node.port),
        timeout=timeout,
    )

    try:
        with context.wrap_socket(
            raw_socket,
            server_hostname=server_hostname,
        ):
            return True
    finally:
        try:
            raw_socket.close()
        except OSError:
            pass


def validate_node(
    node: Node,
    config: ValidatorConfig | None = None,
) -> ValidationResult:
    """
    Выполняет безопасную базовую проверку узла.

    Результат intentionally консервативный:
    сетевой доступ сам по себе не считается доказательством
    работоспособности VPN-протокола.
    """

    config = config or ValidatorConfig()

    errors: list[str] = []
    latency_ms: float | None = None
    reachable = False
    tls_valid = False

    try:
        latency_ms = _tcp_check(
            node,
            config.timeout_seconds,
        )
        reachable = True

    except (OSError, TimeoutError) as exc:
        errors.append(
            f"TCP-проверка не пройдена: {type(exc).__name__}"
        )

    if reachable and latency_ms is not None:
        if latency_ms > config.max_latency_ms:
            errors.append(
                f"Задержка выше допустимой: "
                f"{latency_ms:.1f} мс"
            )

    if reachable and node.protocol == "trojan":
        try:
            tls_valid = _tls_check(
                node,
                config.timeout_seconds,
                config.verify_tls,
            )

        except (OSError, ssl.SSLError, TimeoutError) as exc:
            errors.append(
                f"TLS-проверка не пройдена: "
                f"{type(exc).__name__}"
            )

    elif node.protocol == "hysteria2":
        errors.append(
            "Для Hysteria2 требуется отдельный QUIC/UDP "
            "протокольный валидатор."
        )

    else:
        errors.append(
            f"Неподдерживаемый протокол: {node.protocol}"
        )

    # DNS leak здесь намеренно НЕ объявляется отсутствующим.
    # Для этого потребуется отдельная проверка маршрутизации
    # через реально установленный VPN-туннель.
    dns_leak = None

    # Пока полноценный протокольный handshake не реализован,
    # узел не считается готовым к публикации.
    validated = False

    return ValidationResult(
        reachable=reachable,
        tls_valid=tls_valid,
        latency_ms=latency_ms,
        dns_leak=dns_leak,
        errors=errors,
    )


def apply_validation_result(
    node: Node,
    result: ValidationResult,
) -> Node:
    """
    Записывает результат проверки в модель Node.
    """

    node.reachable = result.reachable
    node.tls_valid = result.tls_valid
    node.latency_ms = result.latency_ms
    node.dns_leak = result.dns_leak
    node.validated = result.passed

    return node