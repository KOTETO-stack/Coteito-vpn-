from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from models import Node


class DNSCheckStatus(str, Enum):
    NO_LEAK = "no_leak"
    LEAK_DETECTED = "leak_detected"
    NOT_CHECKED = "not_checked"
    ERROR = "error"


@dataclass(frozen=True)
class DNSCheckResult:
    status: DNSCheckStatus
    resolver_addresses: tuple[str, ...] = ()
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == DNSCheckStatus.NO_LEAK


def create_not_checked_result() -> DNSCheckResult:
    return DNSCheckResult(
        status=DNSCheckStatus.NOT_CHECKED,
    )


def apply_dns_result(
    node: Node,
    result: DNSCheckResult,
) -> Node:
    if result.status == DNSCheckStatus.NO_LEAK:
        node.dns_leak = False

    elif result.status == DNSCheckStatus.LEAK_DETECTED:
        node.dns_leak = True

    else:
        node.dns_leak = None

    return node


def check_node_dns(node: Node) -> DNSCheckResult:
    """
    Возвращает статус DNS-проверки узла.

    Важно:
    настоящий DNS leak test должен выполняться через
    уже установленный VPN-туннель. Обычный DNS-запрос
    с машины сборщика такой проверкой не является.
    """

    if not node.reachable:
        return DNSCheckResult(
            status=DNSCheckStatus.ERROR,
            error="Узел недоступен.",
        )

    return create_not_checked_result()