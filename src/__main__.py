from __future__ import annotations

from .config_loader import ConfigError, load_config


def main() -> int:
    """Точка входа приложения."""

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}")
        return 1

    print("Karing VPN Subscription Builder")
    print("Конфигурация успешно загружена.")
    print(
        "Разрешённые протоколы:",
        ", ".join(config["protocols"]["allowed"]),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())