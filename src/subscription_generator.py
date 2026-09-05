from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import Node


class SubscriptionGeneratorError(Exception):
    """Ошибка генерации подписки."""


SUPPORTED_FORMATS = {"sing-box", "clash"}


def _validate_node(node: Node) -> None:
    """Проверяет минимальные требования перед публикацией."""

    if not node.validated:
        raise SubscriptionGeneratorError(
            f"Попытка опубликовать непроверенный узел: "
            f"{node.address}:{node.port}"
        )

    if not node.reachable:
        raise SubscriptionGeneratorError(
            f"Узел недоступен: {node.address}:{node.port}"
        )

    if node.latency_ms is None:
        raise SubscriptionGeneratorError(
            f"У узла отсутствует результат проверки задержки: "
            f"{node.address}:{node.port}"
        )

    if node.dns_leak is not False:
        raise SubscriptionGeneratorError(
            f"У узла отсутствует подтверждение DNS-проверки: "
            f"{node.address}:{node.port}"
        )

    if node.protocol not in {"trojan", "hysteria2"}:
        raise SubscriptionGeneratorError(
            f"Неподдерживаемый протокол: {node.protocol}"
        )


def _validated_nodes(nodes: list[Node]) -> list[Node]:
    """Возвращает только узлы, разрешённые к публикации."""

    result: list[Node] = []

    for node in nodes:
        try:
            _validate_node(node)
        except SubscriptionGeneratorError:
            continue

        result.append(node)

    return result


def _trojan_singbox(node: Node) -> dict[str, Any]:
    """Формирует Trojan-outbound для sing-box."""

    return {
        "type": "trojan",
        "tag": node.display_name(),
        "server": node.address,
        "server_port": node.port,
        "password": node.parameters.get("password", ""),
        "tls": {
            "enabled": True,
            "server_name": node.parameters.get(
                "sni",
                node.address,
            ),
        },
    }


def _hysteria2_singbox(node: Node) -> dict[str, Any]:
    """Формирует Hysteria2-outbound для sing-box."""

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "tag": node.display_name(),
        "server": node.address,
        "server_port": node.port,
        "password": node.parameters.get("password", ""),
    }

    sni = node.parameters.get("sni")

    if sni:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni,
        }

    return outbound


def generate_singbox(nodes: list[Node]) -> dict[str, Any]:
    """Создаёт sing-box конфигурацию."""

    outbounds: list[dict[str, Any]] = []

    for node in _validated_nodes(nodes):
        if node.protocol == "trojan":
            outbounds.append(_trojan_singbox(node))

        elif node.protocol == "hysteria2":
            outbounds.append(_hysteria2_singbox(node))

    if not outbounds:
        raise SubscriptionGeneratorError(
            "Нет проверенных узлов для генерации sing-box подписки."
        )

    return {
        "log": {
            "level": "warn",
        },
        "outbounds": outbounds,
    }


def _trojan_clash(node: Node) -> dict[str, Any]:
    """Формирует Trojan-прокси для Clash.Meta."""

    return {
        "name": node.display_name(),
        "type": "trojan",
        "server": node.address,
        "port": node.port,
        "password": node.parameters.get("password", ""),
        "sni": node.parameters.get(
            "sni",
            node.address,
        ),
        "udp": True,
    }


def _hysteria2_clash(node: Node) -> dict[str, Any]:
    """Формирует Hysteria2-прокси для Clash.Meta."""

    proxy: dict[str, Any] = {
        "name": node.display_name(),
        "type": "hysteria2",
        "server": node.address,
        "port": node.port,
        "password": node.parameters.get("password", ""),
        "udp": True,
    }

    sni = node.parameters.get("sni")

    if sni:
        proxy["sni"] = sni

    return proxy


def generate_clash(nodes: list[Node]) -> dict[str, Any]:
    """Создаёт Clash.Meta конфигурацию."""

    proxies: list[dict[str, Any]] = []

    for node in _validated_nodes(nodes):
        if node.protocol == "trojan":
            proxies.append(_trojan_clash(node))

        elif node.protocol == "hysteria2":
            proxies.append(_hysteria2_clash(node))

    if not proxies:
        raise SubscriptionGeneratorError(
            "Нет проверенных узлов для генерации Clash подписки."
        )

    proxy_names = [
        proxy["name"]
        for proxy in proxies
    ]

    return {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
            }
        ],
        "rules": [
            "MATCH,AUTO",
        ],
    }


def generate_subscription(
    nodes: list[Node],
    output_format: str,
) -> dict[str, Any]:
    """
    Формирует подписку указанного формата.

    Допускаются только:
    - sing-box
    - Clash.Meta
    """

    normalized_format = output_format.strip().lower()

    if normalized_format not in SUPPORTED_FORMATS:
        raise SubscriptionGeneratorError(
            f"Неподдерживаемый формат: {output_format}"
        )

    if normalized_format == "sing-box":
        return generate_singbox(nodes)

    return generate_clash(nodes)


def write_subscription(
    nodes: list[Node],
    output_path: str | Path,
    output_format: str,
) -> Path:
    """Генерирует и записывает подписку на диск."""

    path = Path(output_path)

    subscription = generate_subscription(
        nodes,
        output_format,
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        path.write_text(
            json.dumps(
                subscription,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        raise SubscriptionGeneratorError(
            f"Не удалось записать подписку: {path}"
        ) from exc

    return path