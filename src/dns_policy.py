from __future__ import annotations

from dataclasses import dataclass

from dns_checker import DNSCheckResult, DNSCheckStatus


class DNSPolicyError(Exception):
    """Ошибка политики DNS-проверки."""


@dataclass(frozen=True)
class DNSPolicy:
    """Правила допуска результата DNS-проверки."""

    require_completed_check: bool = True
    reject_leaks: bool = True

    def accepts(self, result: DNSCheckResult) -> bool:
        """Определяет, допускается ли результат."""

        if result.status == DNSCheckStatus.NO_LEAK:
            return True

        if result.status == DNSCheckStatus.LEAK_DETECTED:
            return not self.reject_leaks

        if result.status in {
            DNSCheckStatus.NOT_CHECKED,
            DNSCheckStatus.ERROR,
        }:
            return not self.require_completed_check

        return False