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
    """Параметры базовой технической проверки."""

    timeout_seconds: float = DEFAULT_TIMEOUT
    max_latency_ms: float = 500.0
    verify_tls: bool = True

    def validate(self) -> None:
        """Проверяет параметры валидатора."""

        if self.timeout_seconds <= 0:
            raise ValidatorError(
                "timeout_seconds должен быть больше нуля."
            )

        if self.max_latency_ms <= 0:
            raise ValidatorError(
                "max_latency_ms должен быть больше нуля."
            )


def _tcp_check(node: Node, timeout: float) -> float:
    """
    Проверяет TCP-доступность адреса.

    Возвращает время установления TCP-соединения
    в миллисекундах.
    """

    started = time.perf_counter()

    with socket.create_connection(
        (node.address, node.port),
        timeout=timeout,
    ):
        pass

    return (time.perf_counter() - started) * 1000


def _trojan_tls_check(
    node: Node,
    timeout: float,
    verify_certificate: bool,
) -> bool:
    """
    Проверяет TLS-соединение Trojan.

    Это только проверка TLS handshake.
    Она НЕ доказывает успешную авторизацию Trojan.
    """

    if node.protocol != "trojan":
        return False

    if verify_certificate:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()

    raw_socket = socket.create_connection(
        (node.address, node.port),
        timeout=timeout,
    )

    try:
        with context.wrap_socket(
            raw_socket,
            server_hostname=node.address,
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
    Выполняет базовую техническую проверку узла.

    Важно:
    - TCP-доступность не равна работоспособности VPN;
    - TLS handshake не равен успешной авторизации Trojan;
    - Hysteria2 требует отдельной проверки QUIC/UDP;
    - DNS leak пока считается НЕПРОВЕРЕННЫМ.
    """

    config = config or ValidatorConfig()
    config.validate()

    errors: list[str] = []

    latency_ms: float | None = None
    reachable = False
    tls_valid = False

    if node.protocol not in {"trojan", "hysteria2"}:
        errors.append(
            f"Неподдерживаемый протокол: {node.protocol}"
        )

        return ValidationResult(
            reachable=False,
            tls_valid=False,
            latency_ms=None,
            dns_leak=None,
            errors=errors,
        )

    try:
        latency_ms = _tcp_check(
            node,
            config.timeout_seconds,
        )
        reachable = True

    except (OSError, TimeoutError) as exc:
        errors.append(
            "TCP-проверка не пройдена: "
            f"{type(exc).__name__}"
        )

    if (
        reachable
        and latency_ms is not None
        and latency_ms > config.max_latency_ms
    ):
        errors.append(
            "Задержка выше допустимой: "
            f"{latency_ms:.1f} мс"
        )

    if reachable and node.protocol == "trojan":
        try:
            tls_valid = _trojan_tls_check(
                node,
                config.timeout_seconds,
                config.verify_tls,
            )

        except (
            OSError,
            ssl.SSLError,
            TimeoutError,
        ) as exc:
            errors.append(
                "TLS-проверка не пройдена: "
                f"{type(exc).__name__}"
            )

    elif node.protocol == "hysteria2":
        errors.append(
            "Hysteria2 пока не прошёл "
            "протокольную проверку QUIC/UDP."
        )

    # None означает:
    # «DNS leak ещё не проверялся».
    dns_leak: bool | None = None

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
    """Записывает результат проверки в Node."""

    node.reachable = result.reachable
    node.tls_valid = result.tls_valid
    node.latency_ms = result.latency_ms
    node.dns_leak = result.dns_leak

    # Узел считается полностью проверенным
    # только если прошёл все обязательные проверки.
    node.validated = result.passed

    return node