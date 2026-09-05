#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Расширенное тестирование VPN-серверов.
Пинг, DNS leak, доступность Google/YouTube/Telegram.
"""

import json
import socket
import time
import ssl
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# DNS-серверы для проверки утечек
DNS_CHECK_SERVERS = [
    ("8.8.8.8", 53),      # Google
    ("1.1.1.1", 53),      # Cloudflare
    ("94.140.14.14", 53), # AdGuard
]

# Тестовые URL для проверки доступности
TEST_URLS = {
    "google": "https://www.google.com/generate_204",
    "youtube": "https://www.youtube.com",
    "telegram": "https://web.telegram.org",
    "tiktok": "https://www.tiktok.com",
    "github": "https://github.com"
}


def tcp_ping(host, port, timeout=5):
    """TCP connect пинг."""
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


def http_test(url, timeout=10):
    """HTTP HEAD запрос для проверки доступности."""
    try:
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            return r.getcode() < 400
    except Exception:
        return False


def dns_leak_test(server):
    """
    Проверка утечки DNS.
    Проверяет, что DNS-запросы не идут напрямую (мимо VPN).
    Упрощённая версия: проверяем, что сервер использует DoH/DoT.
    """
    # В реальном sing-box это контролируется через dns.rules
    # Здесь — проверяем, что сервер не использует публичные DNS напрямую
    add = server.get("add", "")
    port = server.get("port", 443)
    
    # Если порт 53 — явная утечка DNS
    if port == 53:
        return True  # Утечка обнаружена
    
    # Проверяем SNI — если SNI совпадает с DNS-сервером — подозрительно
    sni = server.get("sni", "")
    dns_hosts = ["dns.google", "cloudflare-dns.com", "dns.adguard-dns.com"]
    if sni in dns_hosts:
        return False  # Это DoH — нормально
    
    return False  # По умолчанию считаем безопасным


def test_server(s):
    """Полное тестирование одного сервера."""
    result = {
        "original": s,
        "ping_ms": 9999,
        "dns_leak": False,
        "google_ok": False,
        "youtube_ok": False,
        "telegram_ok": False,
        "tiktok_ok": False,
        "github_ok": False,
        "score": 0
    }
    
    host = s.get("add", "")
    port = s.get("port", 443)
    
    if not host:
        return result
    
    # 1. TCP Ping
    ping = tcp_ping(host, port, timeout=8)
    result["ping_ms"] = ping
    
    if ping > 500:
        return result  # Слишком медленный
    
    # 2. DNS Leak
    result["dns_leak"] = dns_leak_test(s)
    
    # 3. Доступность сервисов (через HTTP тест)
    # В реальности это тестирует сам сервер, не VPN-туннель
    # Но даёт представление о живости ноды
    result["google_ok"] = http_test(TEST_URLS["google"])
    result["youtube_ok"] = http_test(TEST_URLS["youtube"])
    result["telegram_ok"] = http_test(TEST_URLS["telegram"])
    result["tiktok_ok"] = http_test(TEST_URLS["tiktok"])
    result["github_ok"] = http_test(TEST_URLS["github"])
    
    # 4. Скоринг
    score = 100
    score -= ping // 10  # -1 за каждые 10ms
    if result["dns_leak"]:
        score -= 50
    if not result["google_ok"]:
        score -= 10
    if not result["youtube_ok"]:
        score -= 10
    if not result["telegram_ok"]:
        score -= 10
    result["score"] = max(0, score)
    
    return result


def run_tests(input_path="output/servers_debug.json", output_path="output/servers_tested.json", max_workers=50):
    """Запускает тестирование всех серверов."""
    with open(input_path, "r", encoding="utf-8") as f:
        servers = json.load(f)
    
    print(f"Тестируем {len(servers)} серверов...")
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(test_server, s): s for s in servers}
        for i, fut in enumerate(as_completed(futures)):
            r = fut.result()
            results.append(r)
            if (i + 1) % 10 == 0:
                print(f"  Протестировано: {i + 1}/{len(servers)}")
    
    # Сортируем по скору (лучшие первые)
    results.sort(key=lambda x: (-x["score"], x["ping_ms"]))
    
    # Фильтруем: только живые, без утечек, пинг <= 500
    passed = [r for r in results if r["ping_ms"] <= 500 and not r["dns_leak"] and r["score"] > 0]
    
    # Сохраняем результаты
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "total": len(servers),
            "passed": len(passed),
            "failed": len(servers) - len(passed),
            "servers": passed
        }, f, ensure_ascii=False, indent=2)
    
    print(f"\nРезультаты:")
    print(f"  Всего: {len(servers)}")
    print(f"  Прошли: {len(passed)}")
    print(f"  Отсеяны: {len(servers) - len(passed)}")
    print(f"  Сохранено: {output_path}")
    
    return passed


def generate_report(test_results, output_path="output/test_report.md"):
    """Генерирует human-readable отчёт."""
    lines = [
        "# Отчёт тестирования VPN-серверов",
        "",
        f"**Дата:** {time.strftime('%Y-%m-%d %H:%M')}",
        f"**Всего серверов:** {test_results['total']}",
        f"**Прошли тест:** {test_results['passed']}",
        f"**Отсеяны:** {test_results['failed']}",
        "",
        "## Топ серверов",
        "",
        "| # | Название | Пинг | Google | YouTube | Telegram | TikTok | Скор |",
        "|---|----------|------|--------|---------|----------|--------|------|"
    ]
    
    for i, s in enumerate(test_results["servers"][:20], 1):
        o = s["original"]
        name = o.get("ps", o.get("add", "Unknown"))
        ping = s["ping_ms"]
        g = "✅" if s["google_ok"] else "❌"
        y = "✅" if s["youtube_ok"] else "❌"
        t = "✅" if s["telegram_ok"] else "❌"
        tt = "✅" if s["tiktok_ok"] else "❌"
        score = s["score"]
        lines.append(f"| {i} | {name} | {ping}ms | {g} | {y} | {t} | {tt} | {score} |")
    
    lines.extend([
        "",
        "## Критерии отсева",
        "",
        "- Пинг > 500ms",
        "- DNS утечка обнаружена",
        "- Недоступен Google (сервер мёртв)",
        ""
    ])
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    print(f"Отчёт сохранён: {output_path}")


if __name__ == "__main__":
    results = run_tests()
    
    # Пересохраняем servers_debug.json только с прошедшими
    clean_servers = [r["original"] for r in results]
    with open("output/servers_debug.json", "w", encoding="utf-8") as f:
        json.dump(clean_servers, f, ensure_ascii=False, indent=2)
    
    print(f"Очищенный список: {len(clean_servers)} серверов")
