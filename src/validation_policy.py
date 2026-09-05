from __future__ import annotations

from dataclasses import dataclass

from models import ValidationResult


class ValidationPolicyError(Exception):
    """Ошибка политики проверки."""


@dataclass(frozen=True)
class ValidationPolicy:
    """Правила допуска VPN-узла к публикации."""

    max_latency_ms: float = 500.0
    require_reachable: bool = True
    require_tls: bool = True
    require_dns_check: bool = True
    reject_dns_leak: bool = True

    def validate(self) -> None:
        """Проверяет корректность самой политики."""

        if self.max_latency_ms <= 0:
            raise ValidationPolicyError(
                "max_latency_ms должен быть больше нуля."
            )

    def accepts(self, result: ValidationResult) -> bool:
        """Определяет, допускается ли результат к публикации."""

        if self.require_reachable and not result.reachable:
            return False

        if (
            result.latency_ms is None
            or result.latency_ms > self.max_latency_ms
        ):
            return False

        if self.require_tls and not result.tls_valid:
            return False

        if self.require_dns_check:
            if result.dns_leak is None:
                return False

            if self.reject_dns_leak and result.dns_leak:
                return False

        if result.errors:
            return False

        return True