from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from credentials import NodeCredentials


@dataclass(frozen=True)
class Source:
    """Публичный источник конфигураций."""

    url: str
    name: Optional[str] = None
    enabled: bool = True


@dataclass
class Node:
    """Нормализованная VPN-конфигурация."""

    protocol: str
    address: str
    port: int

    name: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    flag: Optional[str] = None

    latency_ms: Optional[float] = None
    reachable: bool = False
    tls_valid: bool = False
    dns_leak: Optional[bool] = None
    validated: bool = False

    credentials: Optional[NodeCredentials] = None

    parameters: dict[str, str] = field(default_factory=dict)

    def display_name(self) -> str:
        """Возвращает локализованное имя узла."""

        parts = [
            self.country,
            self.city,
            self.flag,
        ]

        return " ".join(
            part.strip()
            for part in parts
            if part and part.strip()
        ) or self.name or f"{self.address}:{self.port}"


@dataclass
class ValidationResult:
    """Результат проверки одного VPN-узла."""

    reachable: bool
    tls_valid: bool
    latency_ms: Optional[float]
    dns_leak: Optional[bool]
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """
        Узел считается прошедшим проверку только при
        подтверждённом отсутствии DNS-утечки.
        """

        return (
            self.reachable
            and self.tls_valid
            and self.latency_ms is not None
            and self.dns_leak is False
            and not self.errors
        )