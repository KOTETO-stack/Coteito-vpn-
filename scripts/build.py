#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сборка финального sing-box конфига.
Берёт шаблон, вставляет сервера из подписки, генерирует готовый JSON.
"""

import json
import os
import sys

TEMPLATE_PATH = "config/sing-box-template.json"
SERVERS_PATH = "output/servers_debug.json"
OUTPUT_PATH = "output/sing-box.json"
SUBSCRIPTION_PATH = "output/subscription.txt"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def server_to_outbound(s):
    """Преобразует сервер из fetch.py в sing-box outbound."""
    t = s.get("type", "").lower()
    tag = s.get("ps", f"{t}-{s.get('add','')}")

    if t == "trojan":
        return {
            "type": "trojan",
            "tag": tag,
            "server": s.get("add", ""),
            "server_port": s.get("port", 443),
            "password": s.get("password", ""),
            "tls": {
                "enabled": True,
                "server_name": s.get("sni", s.get("add", "")),
                "insecure": s.get("skip-cert-verify", False),
                "utls": {
                    "enabled": True,
                    "fingerprint": s.get("fp", "chrome")
                }
            } if s.get("security") != "none" else {"enabled": False},
            "transport": build_transport(s)
        }

    elif t in ("hysteria2", "hy2"):
        obfs = {}
        if s.get("obfs"):
            obfs = {
                "type": s.get("obfs", ""),
                "password": s.get("obfs-password", "")
            }
        return {
            "type": "hysteria2",
            "tag": tag,
            "server": s.get("add", ""),
            "server_port": s.get("port", 443),
            "password": s.get("password", ""),
            "tls": {
                "enabled": True,
                "server_name": s.get("sni", s.get("add", "")),
                "insecure": s.get("insecure", False)
            },
            "obfs": obfs if obfs.get("type") else None
        }

    elif t == "vless":
        # Xray Reality
        tls = {"enabled": False}
        if s.get("security") == "reality":
            tls = {
                "enabled": True,
                "server_name": s.get("sni", ""),
                "utls": {
                    "enabled": True,
                    "fingerprint": s.get("fp", "chrome")
                },
                "reality": {
                    "enabled": True,
                    "public_key": s.get("pbk", ""),
                    "short_id": s.get("sid", "")
                }
            }
        elif s.get("security") == "tls":
            tls = {
                "enabled": True,
                "server_name": s.get("sni", s.get("add", "")),
                "utls": {
                    "enabled": True,
                    "fingerprint": s.get("fp", "chrome")
                }
            }

        return {
            "type": "vless",
            "tag": tag,
            "server": s.get("add", ""),
            "server_port": s.get("port", 443),
            "uuid": s.get("id", ""),
            "flow": s.get("flow", ""),
            "tls": tls,
            "transport": build_transport(s),
            "packet_encoding": "xudp"
        }

    return None


def build_transport(s):
    """Собирает transport для VLESS/Trojan."""
    net = s.get("net", "tcp")
    if net == "tcp":
        return None
    transport = {"type": net}
    if net in ("ws", "httpupgrade"):
        transport["path"] = s.get("path", "/")
        if s.get("host"):
            transport["headers"] = {"Host": s.get("host")}
    elif net == "grpc":
        transport["service_name"] = s.get("path", "")
    elif net == "http":
        transport["path"] = s.get("path", "/")
        transport["method"] = "GET"
        if s.get("host"):
            transport["headers"] = {"Host": s.get("host")}
    return transport


def insert_servers(template, servers):
    """Вставляет сервера в шаблон sing-box."""
    config = json.loads(json.dumps(template))  # deep copy

    # Генерируем outbounds для каждого сервера
    server_outbounds = []
    for s in servers:
        ob = server_to_outbound(s)
        if ob:
            server_outbounds.append(ob)

    # Находим auto-select и вставляем туда
    for i, ob in enumerate(config["outbounds"]):
        if ob.get("tag") == "auto-select":
            # outbounds = все сервера + warp + tor
            ob["outbounds"] = [s["tag"] for s in server_outbounds] + ["warp-out", "tor-out"]
            break

    # Вставляем серверные outbounds перед warp-out
    warp_idx = None
    for i, ob in enumerate(config["outbounds"]):
        if ob.get("tag") == "warp-out":
            warp_idx = i
            break

    if warp_idx is not None:
        for s in server_outbounds:
            config["outbounds"].insert(warp_idx, s)
            warp_idx += 1

    # messengers selector — тоже сервера + warp
    for ob in config["outbounds"]:
        if ob.get("tag") == "messengers":
            ob["outbounds"] = [s["tag"] for s in server_outbounds] + ["warp-out"]

    return config


def build_singbox_config():
    """Основная функция сборки."""
    print("=" * 60)
    print("СБОРКА SING-BOX КОНФИГА")
    print("=" * 60)

    if not os.path.exists(SERVERS_PATH):
        print(f"ОШИБКА: Не найден {SERVERS_PATH}")
        print("Сначала запустите: python scripts/fetch.py")
        sys.exit(1)

    template = load_json(TEMPLATE_PATH)
    servers = load_json(SERVERS_PATH)

    print(f"Загружено серверов: {len(servers)}")
    print(f"Шаблон: {TEMPLATE_PATH}")

    config = insert_servers(template, servers)

    save_json(config, OUTPUT_PATH)
    print(f"Конфиг сохранён: {OUTPUT_PATH}")

    # Также сохраняем human-readable список
    with open("output/server_list.txt", "w", encoding="utf-8") as f:
        for s in servers:
            ping = s.get("ping_ms", "?")
            f.write(f"{s.get('ps','Unknown')} — {s.get('add','')}:{s.get('port','')} ({ping}ms)\n")

    print(f"Список серверов: output/server_list.txt")
    print("=" * 60)
    return config


if __name__ == "__main__":
    build_singbox_config()
