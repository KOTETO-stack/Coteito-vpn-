from __future__ import annotations

from dataclasses import dataclass


class CredentialsError(Exception):
    """Ошибка обработки учётных данных VPN-узла."""


@dataclass(frozen=True, repr=False)
class NodeCredentials:
    """
    Секретные данные VPN-узла.

    repr=False предотвращает случайный вывод пароля
    при отладке, логировании или отображении объекта.
    """

    password: str

    def __post_init__(self) -> None:
        if not isinstance(self.password, str):
            raise CredentialsError(
                "Пароль должен быть строкой."
            )

        if not self.password:
            raise CredentialsError(
                "Пароль не может быть пустым."
            )

    def __repr__(self) -> str:
        return "NodeCredentials(password='***')"

    def masked(self) -> str:
        """Безопасное представление для диагностических сообщений."""
        return "***"