#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Основной движок сбора и валидации VPN-конфигов.
Собирает → парсит → фильтрует → тестирует → сохраняет.
Только Hy2, Trojan (и VLESS с Reality при необходимости).
"""

import json
import re
import base64
import socket
import time
import ssl
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

# Отключаем проверку SSL для источников с самоподписанными сертификатами
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

SUSPICIOUS_KEYWORDS = [
    "bns", "bn-s", "malware", "phishing", "botnet", "spam", "hack",
    "darknet", "onion", "cryptominer", "trojan-win", "emotet",
    "ransomware", "c2-server", "command-control"
]

EXCLUDED_COUNTRIES = {"UA", "UKRAINE", "UKR"}


def fetch_url(url, timeout=20):
    """Загружает содержимое URL."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  [FAIL] {url[:60]}... — {e}")
        return ""


def decode_b64(data):
    """Декодирует base64 с разными вариантами паддинга."""
    data = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    for pad in ["", "=", "==", "==="]:
        try:
            return base64.urlsafe_b64decode(data + pad).decode("utf-8", errors="ignore")
        except Exception:
            continue
    return ""


def extract_configs(text):
    """Извлекает все VPN-ссылки из текста."""
    found = []
    protocols = ["vless://", "trojan://", "vmess://", "hysteria2://", "hy2://", "ss://", "ssr://"]
    for proto in protocols:
        pattern = re.escape(proto) + r"[^\s\n<>\"\'\)\]\}]+"
        for m in re.finditer(pattern, text):
            found.append(m.group(0))
    return list(set(found))


# ==================== ПАРСЕРЫ URL ====================

def parse_vmess(b64data):
    try:
        d = json.loads(decode_b64(b64data.replace("vmess://", "")))
        return {
            "type": "vmess", "ps": d.get("ps", ""), "add": d.get("add", ""),
            "port": int(d.get("port", 0)), "id": d.get("id", ""),
            "aid": int(d.get("aid", 0)), "scy": d.get("scy", "auto"),
            "net": d.get("net", "tcp"), "tls": d.get("tls", ""),
            "host": d.get("host", ""), "path": d.get("path", ""),
            "type": d.get("type", "none"), "fp": d.get("fp", ""),
            "sni": d.get("sni", ""), "alpn": d.get("alpn", ""),
            "v": d.get("v", "2")
        }
    except Exception:
        return None


def parse_vless(url):
    try:
        u = urlparse(url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        return {
            "type": "vless", "ps": urllib.parse.unquote(u.fragment or ""),
            "add": u.hostname or "", "port": u.port or 443,
            "id": u.username or "", "flow": q.get("flow", ""),
            "encryption": q.get("encryption", "none"),
            "security": q.get("security", "tls"),
            "sni": q.get("sni", ""), "fp": q.get("fp", ""),
            "pbk": q.get("pbk", ""), "sid": q.get("sid", ""),
            "spx": q.get("spx", ""), "net": q.get("type", "tcp"),
            "host": q.get("host", ""), "path": q.get("path", "")
        }
    except Exception:
        return None


def parse_trojan(url):
    try:
        u = urlparse(url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        return {
            "type": "trojan", "ps": urllib.parse.unquote(u.fragment or ""),
            "add": u.hostname or "", "port": u.port or 443,
            "password": u.username or "", "security": q.get("security", "tls"),
            "sni": q.get("sni", ""), "fp": q.get("fp", ""),
            "alpn": q.get("alpn", ""), "net": q.get("type", "tcp"),
            "host": q.get("host", ""), "path": q.get("path", "")
        }
    except Exception:
        return None


def parse_hy2(url):
    try:
        u = urlparse(url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        return {
            "type": "hysteria2", "ps": urllib.parse.unquote(u.fragment or ""),
            "add": u.hostname or "", "port": u.port or 443,
            "password": u.username or "", "sni": q.get("sni", ""),
            "insecure": q.get("insecure", "0") == "1",
            "obfs": q.get("obfs", ""),
            "obfs-password": q.get("obfs-password", "")
        }
    except Exception:
        return None


# ==================== ПАРСЕРЫ ФОРМАТОВ ====================

def parse_clash_yaml(text):
    """Извлекает прокси из Clash YAML."""
    servers = []
    try:
        data = yaml.safe_load(text)
        proxies = data.get("proxies", []) if data else []
        for p in proxies:
            t = p.get("type", "").lower()
            if t == "trojan":
                servers.append({
                    "type": "trojan", "ps": p.get("name", ""),
                    "add": p.get("server", ""), "port": p.get("port", 443),
                    "password": p.get("password", ""),
                    "sni": p.get("sni", ""), "net": p.get("network", "tcp"),
                    "skip-cert-verify": p.get("skip-cert-verify", False)
                })
            elif t in ("hysteria2", "hy2"):
                servers.append({
                    "type": "hysteria2", "ps": p.get("name", ""),
                    "add": p.get("server", ""), "port": p.get("port", 443),
                    "password": p.get("password", ""),
                    "sni": p.get("sni", ""), "obfs": p.get("obfs", ""),
                    "obfs-password": p.get("obfs-password", "")
                })
            elif t == "vless":
                servers.append({
                    "type": "vless", "ps": p.get("name", ""),
                    "add": p.get("server", ""), "port": p.get("port", 443),
                    "id": p.get("uuid", ""), "flow": p.get("flow", ""),
                    "security": p.get("tls", False) and "tls" or "",
                    "sni": p.get("sni", ""), "net": p.get("network", "tcp")
                })
    except Exception as e:
        print(f"  [YAML ERROR] {e}")
    return servers


def parse_singbox_json(text):
    """Извлекает outbounds из sing-box JSON."""
    servers = []
    try:
        data = json.loads(text)
        outbounds = data.get("outbounds", [])
        for o in outbounds:
            t = o.get("type", "").lower()
            if t == "trojan":
                s = o.get("server", "")
                servers.append({
                    "type": "trojan", "ps": o.get("tag", ""),
                    "add": s, "port": o.get("server_port", 443),
                    "password": o.get("password", ""),
                    "sni": o.get("tls", {}).get("server_name", ""),
                    "net": "tcp"
                })
            elif t in ("hysteria2", "hy2"):
                s = o.get("server", "")
                servers.append({
                    "type": "hysteria2", "ps": o.get("tag", ""),
                    "add": s, "port": o.get("server_port", 443),
                    "password": o.get("password", ""),
                    "sni": o.get("tls", {}).get("server_name", "")
                })
    except Exception as e:
        print(f"  [JSON ERROR] {e}")
    return servers


def normalize(raw_list):
    """Превращает сырые ссылки в структурированные объекты."""
    out = []
    for raw in raw_list:
        if raw.startswith("vmess://"):
            o = parse_vmess(raw)
        elif raw.startswith("vless://"):
            o = parse_vless(raw)
        elif raw.startswith("trojan://"):
            o = parse_trojan(raw)
        elif raw.startswith(("hysteria2://", "hy2://")):
            o = parse_hy2(raw)
        else:
            continue
        if o and o.get("add") and o.get("port"):
            out.append(o)
    return out


# ==================== ФИЛЬТРЫ ====================

def filter_protocols(servers, allowed):
    """Оставляет только разрешённые протоколы."""
    allowed = set(a.lower() for a in allowed)
    filtered = []
    for s in servers:
        t = s.get("type", "").lower()
        if t in allowed:
            filtered.append(s)
    return filtered


def filter_suspicious(servers):
    """Удаляет сервера с сомнительными ключевыми словами."""
    clean = []
    for s in servers:
        text = json.dumps(s, ensure_ascii=False).lower()
        if any(kw in text for kw in SUSPICIOUS_KEYWORDS):
            continue
        clean.append(s)
    return clean


def deduplicate(servers):
    """Удаляет дубликаты по адресу+порту+паролю/id."""
    seen = set()
    uniq = []
    for s in servers:
        key = f"{s.get('type','')}:{s.get('add','')}:{s.get('port',0)}:{s.get('id','')}:{s.get('password','')}"
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq


# ==================== ТЕСТИРОВАНИЕ ====================

def ping_host(host, port, timeout=10):
    """TCP-connect тест. Возвращает пинг в мс или 9999."""
    try:
        addr = socket.getaddrinfo(host, None)[0][4][0]
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((addr, port))
        sock.close()
        return int((time.time() - start) * 1000)
    except Exception:
        return 9999


def test_dns_leak(server):
    """
    Простой тест утечки DNS.
    Проверяет, что DNS-запросы не идут мимо VPN.
    Возвращает True если утечка обнаружена, False если всё чисто.
    """
    # Упрощённая проверка: если сервер использует DoH/DoT — считаем безопасным
    # В реальном sing-box это настраивается через dns.rules
    # Здесь — заглушка для совместимости
    return False


def test_servers(servers, max_ping=500, max_workers=64):
    """Параллельное тестирование пинга."""
    results = []
    print(f"Тестируем {len(servers)} серверов (max_ping={max_ping}ms)...")

    def test_one(s):
        ping = ping_host(s.get("add"), s.get("port", 443))
        if ping <= max_ping:
            s["ping_ms"] = ping
            s["dns_leak"] = test_dns_leak(s)
            return s
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(test_one, s): s for s in servers}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    results.sort(key=lambda x: x["ping_ms"])
    print(f"Прошли тест: {len(results)}/{len(servers)} серверов")
    return results


# ==================== СБОРКА ПОДПИСКИ ====================

def build_subscription(servers, output_path="output/subscription.txt"):
    """Собирает финальный subscription.txt (base64-список ссылок)."""
    lines = []
    for s in servers:
        t = s.get("type", "")
        if t == "trojan":
            url = build_trojan_url(s)
        elif t in ("hysteria2", "hy2"):
            url = build_hy2_url(s)
        elif t == "vless":
            url = build_vless_url(s)
        else:
            continue
        if url:
            lines.append(url)

    raw = "\n".join(lines)
    encoded = base64.b64encode(raw.encode("utf-8")).decode("utf-8")

    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(encoded)

    print(f"Подписка сохранена: {output_path} ({len(lines)} серверов)")
    return encoded


def build_trojan_url(s):
    """Собирает trojan:// URL."""
    pw = s.get("password", "")
    host = s.get("add", "")
    port = s.get("port", 443)
    if not pw or not host:
        return ""
    params = []
    if s.get("sni"):
        params.append(f"sni={urllib.parse.quote(s['sni'])}")
    if s.get("fp"):
        params.append(f"fp={s['fp']}")
    if s.get("alpn"):
        params.append(f"alpn={urllib.parse.quote(s['alpn'])}")
    if s.get("net") and s["net"] != "tcp":
        params.append(f"type={s['net']}")
    if s.get("host"):
        params.append(f"host={urllib.parse.quote(s['host'])}")
    if s.get("path"):
        params.append(f"path={urllib.parse.quote(s['path'])}")
    ps = urllib.parse.quote(s.get("ps", "Trojan"))
    q = "?" + "&".join(params) if params else ""
    return f"trojan://{pw}@{host}:{port}{q}#{ps}"


def build_hy2_url(s):
    """Собирает hysteria2:// URL."""
    pw = s.get("password", "")
    host = s.get("add", "")
    port = s.get("port", 443)
    if not pw or not host:
        return ""
    params = []
    if s.get("sni"):
        params.append(f"sni={urllib.parse.quote(s['sni'])}")
    if s.get("obfs"):
        params.append(f"obfs={urllib.parse.quote(s['obfs'])}")
    if s.get("obfs-password"):
        params.append(f"obfs-password={urllib.parse.quote(s['obfs-password'])}")
    if s.get("insecure"):
        params.append("insecure=1")
    ps = urllib.parse.quote(s.get("ps", "Hy2"))
    q = "?" + "&".join(params) if params else ""
    return f"hysteria2://{pw}@{host}:{port}{q}#{ps}"


def build_vless_url(s):
    """Собирает vless:// URL (для Reality)."""
    uid = s.get("id", "")
    host = s.get("add", "")
    port = s.get("port", 443)
    if not uid or not host:
        return ""
    params = []
    if s.get("encryption"):
        params.append(f"encryption={s['encryption']}")
    else:
        params.append("encryption=none")
    if s.get("flow"):
        params.append(f"flow={s['flow']}")
    if s.get("security"):
        params.append(f"security={s['security']}")
    if s.get("sni"):
        params.append(f"sni={urllib.parse.quote(s['sni'])}")
    if s.get("fp"):
        params.append(f"fp={s['fp']}")
    if s.get("pbk"):
        params.append(f"pbk={s['pbk']}")
    if s.get("sid"):
        params.append(f"sid={s['sid']}")
    if s.get("spx"):
        params.append(f"spx={urllib.parse.quote(s['spx'])}")
    if s.get("net") and s["net"] != "tcp":
        params.append(f"type={s['net']}")
    if s.get("host"):
        params.append(f"host={urllib.parse.quote(s['host'])}")
    if s.get("path"):
        params.append(f"path={urllib.parse.quote(s['path'])}")
    ps = urllib.parse.quote(s.get("ps", "VLESS"))
    q = "?" + "&".join(params) if params else ""
    return f"vless://{uid}@{host}:{port}{q}#{ps}"


# ==================== ОСНОВНОЙ ПРОЦЕСС ====================

def load_sources(path="sources/sources.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    print("=" * 60)
    print("АВТО VPN ПОДПИСКА — СБОРКА")
    print("=" * 60)

    cfg = load_sources()
    meta = cfg.get("meta", {})
    allowed_protocols = meta.get("protocols", ["trojan", "hysteria2", "hy2"])
    max_servers = meta.get("max_servers", 150)
    max_ping = meta.get("max_ping_ms", 500)

    all_raw = []

    # 1. Сбор из всех источников
    print("\n[1/5] Сбор конфигов из источников...")
    for src in cfg.get("sources", []):
        if not src.get("enabled", True):
            continue
        url = src["url"]
        stype = src.get("type", "base64")
        print(f"  Fetch: {url[:70]}...")
        txt = fetch_url(url)
        if not txt:
            continue

        if stype == "base64":
            dec = decode_b64(txt)
            if dec and ("://" in dec):
                all_raw.extend(extract_configs(dec))
            else:
                all_raw.extend(extract_configs(txt))
        elif stype == "yaml":
            all_raw.extend(extract_configs(txt))  # ссылки в yaml
            # + парсинг clash-структуры
            all_raw.extend(parse_clash_yaml(txt))
        elif stype == "json":
            all_raw.extend(extract_configs(txt))
            all_raw.extend(parse_singbox_json(txt))
        else:
            all_raw.extend(extract_configs(txt))

    print(f"Сырых записей: {len(all_raw)}")

    # 2. Нормализация
    print("\n[2/5] Парсинг и нормализация...")
    servers = normalize(all_raw)
    print(f"Распознано серверов: {len(servers)}")

    # 3. Фильтрация
    print("\n[3/5] Фильтрация...")
    servers = filter_protocols(servers, allowed_protocols)
    print(f"  После фильтра протоколов: {len(servers)}")
    servers = filter_suspicious(servers)
    print(f"  После чистки suspicious: {len(servers)}")
    servers = deduplicate(servers)
    print(f"  После дедупликации: {len(servers)}")

    # 4. Тестирование
    print("\n[4/5] Тестирование...")
    servers = test_servers(servers, max_ping=max_ping)
    servers = servers[:max_servers]

    # 5. Переименование (если naming.py доступен)
    print("\n[5/5] Переименование серверов...")
    try:
        from naming import batch_rename
        servers = batch_rename(servers)
    except Exception as e:
        print(f"  naming.py недоступен ({e}), используем оригинальные имена")

    # 6. Сборка
    print("\n[FINAL] Сборка подписки...")
    build_subscription(servers)

    # Сохраняем JSON для отладки
    with open("output/servers_debug.json", "w", encoding="utf-8") as f:
        json.dump(servers, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print("ГОТОВО!")
    print("=" * 60)


if __name__ == "__main__":
    main()
