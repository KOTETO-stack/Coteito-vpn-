from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from models import Node


class DNSCheckStatus(str, Enum):
    """Состояние DNS-проверки."""

    NO_LEAK = "no_leak"
    LEAK_DETECTED = "leak_detected"
    NOT_CHECKED = "not_checked"
    ERROR = "error"


@dataclass(frozen=True)
class DNSCheckResult:
    """Результат DNS-проверки."""

    status: DNSCheckStatus
    resolver_addresses: tuple[str, ...] = ()
    error: str | None = None

    @property
    def passed(self) -> bool:
        """True только при подтверждённом отсутствии утечки."""

        return self.status == DNSCheckStatus.NO_LEAK


def create_not_checked_result() -> DNSCheckResult:
    """Создаёт результат для ещё не выполненной проверки."""

    return DNSCheckResult(
        status=DNSCheckStatus.NOT_CHECKED,
    )


def apply_dns_result(
    node: Node,
    result: DNSCheckResult,
) -> Node:
    """
    Записывает результат DNS-проверки в Node.

    None означает, что проверка не была подтверждена.
    """

    if result.status == DNSCheckStatus.NO_LEAK:
        node.dns_leak = False

    elif result.status == DNSCheckStatus.LEAK_DETECTED:
        node.dns_leak = True

    else:
        node.dns_leak = None

    return node


def check_node_dns(
    node: Node,
) -> DNSCheckResult:
    """
    Заглушка протокола DNS-проверки.

    Реальная проверка должна выполняться после создания
    тестового VPN-туннеля и проверки DNS-маршрута.

    Простого DNS-запроса с машины сборщика недостаточно:
    он не доказывает, через какой DNS будет идти трафик
    пользователя в Karing.
    """

    if not node.reachable:
        return DNSCheckResult(
            status=DNSCheckStatus.ERROR,
            error="Узел недоступен.",
        )

    return create_not_checked_result()