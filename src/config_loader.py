from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path("config/config.yaml")

ALLOWED_PROTOCOLS = {"hysteria2", "trojan"}
ALLOWED_SCHEMES = {"http", "https"}


class ConfigError(Exception):
    """Ошибка конфигурации проекта."""


def _require_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} должен быть объектом YAML.")
    return value


def _require_bool(section: dict[str, Any], key: str) -> bool:
    value = section.get(key)

    if not isinstance(value, bool):
        raise ConfigError(f"Параметр {key} должен иметь значение true/false.")

    return value


def _require_positive_number(
    section: dict[str, Any],
    key: str,
) -> int | float:
    value = section.get(key)

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"Параметр {key} должен быть числом.")

    if value <= 0:
        raise ConfigError(f"Параметр {key} должен быть больше нуля.")

    return value


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    """
    Проверяет основные параметры конфигурации.

    Функция не изменяет исходный объект.
    """

    project = _require_mapping(config.get("project"), "project")
    protocols = _require_mapping(config.get("protocols"), "protocols")
    sources = _require_mapping(config.get("sources"), "sources")
    nodes = _require_mapping(config.get("nodes"), "nodes")
    healthcheck = _require_mapping(config.get("healthcheck"), "healthcheck")
    privacy = _require_mapping(config.get("privacy"), "privacy")
    safety = _require_mapping(config.get("safety"), "safety")

    if project.get("client") != "karing":
        raise ConfigError("project.client должен быть равен 'karing'.")

    allowed_protocols = protocols.get("allowed")

    if not isinstance(allowed_protocols, list):
        raise ConfigError("protocols.allowed должен быть списком.")

    normalized_protocols = {
        str(protocol).strip().lower()
        for protocol in allowed_protocols
    }

    unknown_protocols = normalized_protocols - ALLOWED_PROTOCOLS

    if unknown_protocols:
        raise ConfigError(
            "Обнаружены неподдерживаемые протоколы: "
            + ", ".join(sorted(unknown_protocols))
        )

    if not normalized_protocols:
        raise ConfigError("Не задан ни один разрешённый протокол.")

    allowed_schemes = sources.get("allowed_schemes")

    if not isinstance(allowed_schemes, list):
        raise ConfigError("sources.allowed_schemes должен быть списком.")

    normalized_schemes = {
        str(scheme).strip().lower()
        for scheme in allowed_schemes
    }

    unknown_schemes = normalized_schemes - ALLOWED_SCHEMES

    if unknown_schemes:
        raise ConfigError(
            "Обнаружены неподдерживаемые схемы источников: "
            + ", ".join(sorted(unknown_schemes))
        )

    _require_positive_number(sources, "max_sources")
    _require_positive_number(nodes, "max_latency_ms")
    _require_positive_number(nodes, "validation_attempts")
    _require_positive_number(nodes, "min_success_ratio")
    _require_positive_number(healthcheck, "timeout_seconds")

    success_ratio = nodes["min_success_ratio"]

    if not 0 < success_ratio <= 1:
        raise ConfigError("nodes.min_success_ratio должен быть между 0 и 1.")

    if nodes["max_latency_ms"] > 5000:
        raise ConfigError(
            "nodes.max_latency_ms слишком велик: "
            "проверьте значение перед запуском."
        )

    if not _require_bool(sources, "enabled"):
        raise ConfigError("Сбор источников должен быть включён.")

    if _require_bool(sources, "allow_messaging_sources"):
        raise ConfigError(
            "Источники из мессенджеров отключены политикой проекта."
        )

    _require_bool(healthcheck, "enabled")

    tls = _require_mapping(
        healthcheck.get("tls"),
        "healthcheck.tls",
    )

    if not _require_bool(tls, "verify_certificate"):
        raise ConfigError(
            "Проверка TLS-сертификата должна оставаться включённой."
        )

    for key in (
        "send_personal_data",
        "send_cookies",
        "send_authentication_tokens",
        "collect_user_traffic",
        "store_user_traffic",
    ):
        if privacy.get(key) is not False:
            raise ConfigError(
                f"privacy.{key} должен быть false."
            )

    if safety.get("never_publish_unvalidated_nodes") is not True:
        raise ConfigError(
            "Публикация непроверенных узлов запрещена."
        )

    if safety.get("never_publish_malformed_nodes") is not True:
        raise ConfigError(
            "Публикация некорректных конфигураций запрещена."
        )

    return config


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """
    Загружает YAML-файл и выполняет его базовую проверку.

    Используется SafeLoader, поэтому YAML не может создавать
    произвольные Python-объекты.
    """

    config_path = Path(path)

    if not config_path.is_file():
        raise ConfigError(
            f"Файл конфигурации не найден: {config_path}"
        )

    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(
            f"Не удалось прочитать конфигурацию: {exc}"
        ) from exc

    try:
        config = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Некорректный YAML: {exc}"
        ) from exc

    if not isinstance(config, dict):
        raise ConfigError(
            "Корень конфигурации должен быть YAML-объектом."
        )

    return validate_config(config)


if __name__ == "__main__":
    try:
        configuration = load_config()
        print("Конфигурация успешно проверена.")
        print(
            "Разрешённые протоколы:",
            ", ".join(configuration["protocols"]["allowed"]),
        )
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}")
        raise SystemExit(1)