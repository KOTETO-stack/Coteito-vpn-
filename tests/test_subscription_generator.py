from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import Node


class SubscriptionGeneratorError(Exception):
    """Ошибка генерации подписки."""


SUPPORTED_FORMATS = {"sing-box", "clash"}
SUPPORTED_PROTOCOLS = {"trojan", "hysteria2"}


def _validate_node(node: Node) -> None:
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
            "У узла отсутствует результат проверки задержки: "
            f"{node.address}:{node.port}"
        )

    if node.dns_leak is not False:
        raise SubscriptionGeneratorError(
            "У узла отсутствует подтверждение отсутствия DNS-утечки: "
            f"{node.address}:{node.port}"
        )

    if node.protocol not in SUPPORTED_PROTOCOLS:
        raise SubscriptionGeneratorError(
            f"Неподдерживаемый протокол: {node.protocol}"
        )

    if node.credentials is None:
        raise SubscriptionGeneratorError(
            f"У узла отсутствуют credentials: "
            f"{node.address}:{node.port}"
        )


def _validated_nodes(nodes: list[Node]) -> list[Node]:
    result: list[Node] = []

    for node in nodes:
        try:
            _validate_node(node)
        except SubscriptionGeneratorError:
            continue

        result.append(node)

    return result


def _trojan_singbox(node: Node) -> dict[str, Any]:
    if node.credentials is None:
        raise SubscriptionGeneratorError(
            "Для Trojan отсутствуют credentials."
        )

    outbound: dict[str, Any] = {
        "type": "trojan",
        "tag": node.display_name(),
        "server": node.address,
        "server_port": node.port,
        "password": node.credentials.password,
        "tls": {
            "enabled": True,
            "server_name": node.parameters.get(
                "sni",
                node.address,
            ),
        },
    }

    return outbound


def _hysteria2_singbox(node: Node) -> dict[str, Any]:
    if node.credentials is None:
        raise SubscriptionGeneratorError(
            "Для Hysteria2 отсутствуют credentials."
        )

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "tag": node.display_name(),
        "server": node.address,
        "server_port": node.port,
        "password": node.credentials.password,
    }

    sni = node.parameters.get("sni")

    if sni:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni,
        }

    return outbound


def generate_singbox(
    nodes: list[Node],
) -> dict[str, Any]:
    outbounds: list[dict[str, Any]] = []

    for node in _validated_nodes(nodes):
        if node.protocol == "trojan":
            outbounds.append(
                _trojan_singbox(node)
            )
        elif node.protocol == "hysteria2":
            outbounds.append(
                _hysteria2_singbox(node)
            )

    if not outbounds:
        raise SubscriptionGeneratorError(
            "Нет проверенных узлов для генерации "
            "sing-box подписки."
        )

    return {
        "log": {
            "level": "warn",
        },
        "outbounds": outbounds,
    }


def _trojan_clash(node: Node) -> dict[str, Any]:
    if node.credentials is None:
        raise SubscriptionGeneratorError(
            "Для Trojan отсутствуют credentials."
        )

    return {
        "name": node.display_name(),
        "type": "trojan",
        "server": node.address,
        "port": node.port,
        "password": node.credentials.password,
        "sni": node.parameters.get(
            "sni",
            node.address,
        ),
        "udp": True,
    }


def _hysteria2_clash(node: Node) -> dict[str, Any]:
    if node.credentials is None:
        raise SubscriptionGeneratorError(
            "Для Hysteria2 отсутствуют credentials."
        )

    proxy: dict[str, Any] = {
        "name": node.display_name(),
        "type": "hysteria2",
        "server": node.address,
        "port": node.port,
        "password": node.credentials.password,
        "udp": True,
    }

    sni = node.parameters.get("sni")

    if sni:
        proxy["sni"] = sni

    return proxy


def generate_clash(
    nodes: list[Node],
) -> dict[str, Any]:
    proxies: list[dict[str, Any]] = []

    for node in _validated_nodes(nodes):
        if node.protocol == "trojan":
            proxies.append(
                _trojan_clash(node)
            )
        elif node.protocol == "hysteria2":
            proxies.append(
                _hysteria2_clash(node)
            )

    if not proxies:
        raise SubscriptionGeneratorError(
            "Нет проверенных узлов для генерации "
            "Clash подписки."
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
                "url": (
                    "https://www.gstatic.com/"
                    "generate_204"
                ),
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