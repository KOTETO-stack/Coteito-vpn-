#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генерация названий серверов: [Страна] [Город] [Флаг]
Определяет геолокацию по IP, переводит на русский, ставит emoji флага.
Кэширует результаты в geo_cache.json
"""

import json
import os
import time
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse

CACHE_FILE = "geo_cache.json"
API_DELAY = 1.5  # секунды между запросами (лимит ip-api: 45/мин)

# Русские названия стран (fallback если API не доступен)
COUNTRY_NAMES_RU = {
    "US": "США", "GB": "Великобритания", "DE": "Германия", "FR": "Франция",
    "NL": "Нидерланды", "JP": "Япония", "SG": "Сингапур", "KR": "Южная Корея",
    "HK": "Гонконг", "TW": "Тайвань", "CA": "Канада", "AU": "Австралия",
    "IN": "Индия", "TR": "Турция", "AE": "ОАЭ", "BR": "Бразилия", "PL": "Польша",
    "FI": "Финляндия", "SE": "Швеция", "NO": "Норвегия", "DK": "Дания",
    "CH": "Швейцария", "IT": "Италия", "ES": "Испания", "PT": "Португалия",
    "BE": "Бельгия", "AT": "Австрия", "CZ": "Чехия", "HU": "Венгрия",
    "RO": "Румыния", "BG": "Болгария", "GR": "Греция", "IL": "Израиль",
    "RU": "Россия", "CN": "Китай", "TH": "Таиланд", "VN": "Вьетнам",
    "MY": "Малайзия", "ID": "Индонезия", "PH": "Филиппины", "MX": "Мексика",
    "AR": "Аргентина", "CL": "Чили", "ZA": "ЮАР", "EG": "Египет",
    "SA": "Саудовская Аравия", "QA": "Катар", "KW": "Кувейт", "OM": "Оман",
    "KZ": "Казахстан", "UZ": "Узбекистан", "AZ": "Азербайджан", "AM": "Армения",
    "GE": "Грузия", "MD": "Молдова", "BY": "Беларусь", "LT": "Литва",
    "LV": "Латвия", "EE": "Эстония", "SK": "Словакия", "SI": "Словения",
    "HR": "Хорватия", "RS": "Сербия", "BA": "Босния и Герцеговина",
    "ME": "Черногория", "MK": "Северная Македония", "AL": "Албания",
    "IE": "Ирландия", "IS": "Исландия", "LU": "Люксембург", "MT": "Мальта",
    "CY": "Кипр", "NZ": "Новая Зеландия", "PK": "Пакистан", "BD": "Бангладеш",
    "LK": "Шри-Ланка", "NP": "Непал", "KH": "Камбоджа", "LA": "Лаос",
    "MM": "Мьянма", "MN": "Монголия", "KG": "Кыргызстан", "TJ": "Таджикистан",
    "TM": "Туркменистан", "IR": "Иран", "IQ": "Ирак", "SY": "Сирия",
    "JO": "Иордания", "LB": "Ливан", "YE": "Йемен", "BH": "Бахрейн",
    "NG": "Нигерия", "KE": "Кения", "GH": "Гана", "TZ": "Танзания",
    "UG": "Уганда", "ZM": "Замбия", "ZW": "Зимбабве", "BW": "Ботсвана",
    "NA": "Намибия", "MZ": "Мозамбик", "MG": "Мадагаскар", "MU": "Маврикий",
    "SN": "Сенегал", "CI": "Кот-д'Ивуар", "CM": "Камерун", "AO": "Ангола",
    "DZ": "Алжир", "MA": "Марокко", "TN": "Тунис", "LY": "Ливия",
    "SD": "Судан", "ET": "Эфиопия", "UG": "Уганда", "RW": "Руанда",
    "BI": "Бурунди", "MW": "Малави", "ML": "Мали", "BF": "Буркина-Фасо",
    "NE": "Нигер", "TD": "Чад", "CF": "ЦАР", "GA": "Габон", "GQ": "Экваториальная Гвинея",
    "CG": "Конго", "CD": "ДР Конго", "UG": "Уганда"
}

# Города на русском (fallback)
CITY_NAMES_RU = {
    "Mountain View": "Маунтин-Вью", "Ashburn": "Ашберн", "New York": "Нью-Йорк",
    "Los Angeles": "Лос-Анджелес", "Miami": "Майами", "Dallas": "Даллас",
    "Chicago": "Чикаго", "Seattle": "Сиэтл", "San Francisco": "Сан-Франциско",
    "London": "Лондон", "Manchester": "Манчестер", "Frankfurt": "Франкфурт",
    "Berlin": "Берлин", "Munich": "Мюнхен", "Hamburg": "Гамбург",
    "Paris": "Париж", "Marseille": "Марсель", "Lyon": "Лион",
    "Amsterdam": "Амстердам", "Rotterdam": "Роттердам", "Tokyo": "Токио",
    "Osaka": "Осака", "Singapore": "Сингапур", "Seoul": "Сеул",
    "Busan": "Пусан", "Hong Kong": "Гонконг", "Taipei": "Тайбэй",
    "Toronto": "Торонто", "Vancouver": "Ванкувер", "Montreal": "Монреаль",
    "Sydney": "Сидней", "Melbourne": "Мельбурн", "Mumbai": "Мумбаи",
    "Delhi": "Дели", "Bangalore": "Бангалор", "Istanbul": "Стамбул",
    "Ankara": "Анкара", "Dubai": "Дубай", "Abu Dhabi": "Абу-Даби",
    "Sao Paulo": "Сан-Паулу", "Rio de Janeiro": "Рио-де-Жанейро",
    "Warsaw": "Варшава", "Krakow": "Краков", "Helsinki": "Хельсинки",
    "Stockholm": "Стокгольм", "Oslo": "Осло", "Copenhagen": "Копенгаген",
    "Zurich": "Цюрих", "Geneva": "Женева", "Rome": "Рим", "Milan": "Милан",
    "Madrid": "Мадрид", "Barcelona": "Барселона", "Lisbon": "Лиссабон",
    "Brussels": "Брюссель", "Vienna": "Вена", "Prague": "Прага",
    "Budapest": "Будапешт", "Bucharest": "Бухарест", "Sofia": "София",
    "Athens": "Афины", "Tel Aviv": "Тель-Авив", "Jerusalem": "Иерусалим",
    "Moscow": "Москва", "Saint Petersburg": "Санкт-Петербург",
    "Beijing": "Пекин", "Shanghai": "Шанхай", "Shenzhen": "Шэньчжэнь",
    "Guangzhou": "Гуанчжоу", "Bangkok": "Бангкок", "Hanoi": "Ханой",
    "Ho Chi Minh City": "Хошимин", "Kuala Lumpur": "Куала-Лумпур",
    "Jakarta": "Джакарта", "Manila": "Манила", "Mexico City": "Мехико",
    "Buenos Aires": "Буэнос-Айрес", "Santiago": "Сантьяго",
    "Cape Town": "Кейптаун", "Johannesburg": "Йоханнесбург",
    "Cairo": "Каир", "Alexandria": "Александрия", "Riyadh": "Эр-Рияд",
    "Doha": "Доха", "Kuwait City": "Эль-Кувейт", "Muscat": "Маскат",
    "Almaty": "Алматы", "Astana": "Астана", "Tashkent": "Ташкент",
    "Baku": "Баку", "Yerevan": "Ереван", "Tbilisi": "Тбилиси",
    "Chisinau": "Кишинёв", "Minsk": "Минск", "Vilnius": "Вильнюс",
    "Riga": "Рига", "Tallinn": "Таллин", "Bratislava": "Братислава",
    "Ljubljana": "Любляна", "Zagreb": "Загреб", "Belgrade": "Белград",
    "Sarajevo": "Сараево", "Podgorica": "Подгорица", "Skopje": "Скопье",
    "Tirana": "Тирана", "Dublin": "Дублин", "Reykjavik": "Рейкьявик",
    "Luxembourg": "Люксембург", "Valletta": "Валлетта", "Nicosia": "Никосия",
    "Wellington": "Веллингтон", "Auckland": "Окленд", "Karachi": "Карачи",
    "Lahore": "Лахор", "Dhaka": "Дакка", "Colombo": "Коломбо",
    "Kathmandu": "Катманду", "Phnom Penh": "Пномпень", "Vientiane": "Вьентьян",
    "Yangon": "Янгон", "Ulaanbaatar": "Улан-Батор", "Bishkek": "Бишкек",
    "Dushanbe": "Душанбе", "Ashgabat": "Ашхабад", "Tehran": "Тегеран",
    "Baghdad": "Багдад", "Damascus": "Дамаск", "Amman": "Амман",
    "Beirut": "Бейрут", "Sanaa": "Сана", "Manama": "Манама",
    "Lagos": "Лагос", "Nairobi": "Найроби", "Accra": "Аккра",
    "Dar es Salaam": "Дар-эс-Салам", "Kampala": "Кампала",
    "Lusaka": "Лусака", "Harare": "Хараре", "Gaborone": "Габороне",
    "Windhoek": "Виндхук", "Maputo": "Мапуту", "Antananarivo": "Антананариву",
    "Port Louis": "Порт-Луи", "Dakar": "Дакар", "Abidjan": "Абиджан",
    "Yaounde": "Яунде", "Luanda": "Луанда", "Algiers": "Алжир",
    "Casablanca": "Касабланка", "Tunis": "Тунис", "Tripoli": "Триполи",
    "Khartoum": "Хартум", "Addis Ababa": "Аддис-Абеба", "Kigali": "Кигали",
    "Bujumbura": "Бужумбура", "Lilongwe": "Лилонгве", "Bamako": "Бамако",
    "Ouagadougou": "Уагадугу", "Niamey": "Ниамей", "N'Djamena": "Нджамена",
    "Bangui": "Банги", "Libreville": "Либревиль", "Malabo": "Малабо",
    "Brazzaville": "Браззавиль", "Kinshasa": "Киншаса"
}

EXCLUDED_COUNTRIES = {"UA", "UKRAINE", "UKR"}


def flag_emoji(country_code):
    """Преобразует ISO код страны в emoji флаг."""
    if not country_code or len(country_code) != 2:
        return ""
    code = country_code.upper()
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def resolve_host(hostname):
    """Получает IP по hostname."""
    try:
        return socket.getaddrinfo(hostname, None)[0][4][0]
    except Exception:
        return None


def fetch_geo(ip):
    """Запрашивает геолокацию через ip-api.com (бесплатно, на русском)."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,query&lang=ru"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "city": data.get("city", ""),
                    "ip": data.get("query", ip)
                }
    except Exception:
        pass
    return None


def get_geo(hostname):
    """
    Определяет геолокацию сервера.
    Возвращает (country_ru, city_ru, country_code, flag_emoji).
    Использует кэш и API с задержкой.
    """
    cache = load_cache()
    
    # Пробуем по hostname
    if hostname in cache:
        c = cache[hostname]
        return c["country"], c["city"], c["code"], c["flag"]
    
    ip = resolve_host(hostname)
    if not ip:
        return "Неизвестно", "Неизвестно", "", ""
    
    # Пробуем по IP
    if ip in cache:
        c = cache[ip]
        # Сохраняем и под hostname
        cache[hostname] = c
        save_cache(cache)
        return c["country"], c["city"], c["code"], c["flag"]
    
    # Запрос к API
    geo = fetch_geo(ip)
    time.sleep(API_DELAY)  # соблюдаем лимит
    
    if geo:
        cc = geo.get("country_code", "").upper()
        if cc in EXCLUDED_COUNTRIES:
            return None, None, None, None  # Исключаем UA
        
        country = geo.get("country", COUNTRY_NAMES_RU.get(cc, cc))
        city = geo.get("city", CITY_NAMES_RU.get(geo.get("city", ""), geo.get("city", "Неизвестно")))
        flag = flag_emoji(cc)
        
        entry = {
            "country": country,
            "city": city,
            "code": cc,
            "flag": flag,
            "ip": ip
        }
        cache[ip] = entry
        cache[hostname] = entry
        save_cache(cache)
        return country, city, cc, flag
    
    # Fallback: whois
    country, city, cc = whois_lookup(ip)
    if cc in EXCLUDED_COUNTRIES:
        return None, None, None, None
    
    flag = flag_emoji(cc)
    entry = {
        "country": country or COUNTRY_NAMES_RU.get(cc, "Неизвестно"),
        "city": city or "Неизвестно",
        "code": cc,
        "flag": flag,
        "ip": ip
    }
    cache[ip] = entry
    cache[hostname] = entry
    save_cache(cache)
    return entry["country"], entry["city"], cc, flag


def whois_lookup(ip):
    """Fallback: получает страну через whois."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.send(f"{ip}\n".encode())
        response = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            response += d
        s.close()
        text = response.decode("utf-8", errors="ignore")
        
        country = ""
        cc = ""
        for line in text.splitlines():
            if line.lower().startswith("country:"):
                cc = line.split(":")[1].strip().upper()
                country = COUNTRY_NAMES_RU.get(cc, cc)
                break
        return country, "", cc
    except Exception:
        return "", "", ""


def generate_name(hostname, existing_names=None):
    """
    Генерирует название сервера: [Страна] [Город] [Флаг]
    Возвращает строку или None если страна в чёрном списке.
    """
    if existing_names is None:
        existing_names = set()
    
    result = get_geo(hostname)
    if result[0] is None:  # Исключённая страна
        return None
    
    country, city, cc, flag = result
    
    # Очистка названия
    country = country.strip()
    city = city.strip()
    
    if not country:
        country = "Неизвестно"
    if not city:
        city = "Неизвестно"
    
    base = f"{country} {city} {flag}".strip()
    
    # Уникальность: если такое уже есть, добавляем номер
    if base in existing_names:
        i = 2
        while f"{base} #{i}" in existing_names:
            i += 1
        base = f"{base} #{i}"
    
    existing_names.add(base)
    return base


def batch_rename(servers):
    """
    Принимает список серверов (dict с ключом 'add'),
    возвращает список с добавленным/обновлённым ключом 'ps'.
    """
    existing = set()
    renamed = []
    excluded = 0
    
    for s in servers:
        hostname = s.get("add", "")
        if not hostname:
            continue
        
        name = generate_name(hostname, existing)
        if name is None:
            excluded += 1
            continue  # Пропускаем UA и недоступные
        
        s["ps"] = name
        renamed.append(s)
    
    print(f"Переименовано: {len(renamed)}, исключено (UA/недоступно): {excluded}")
    return renamed


if __name__ == "__main__":
    # Тест
    test_servers = [
        {"add": "8.8.8.8"},
        {"add": "1.1.1.1"},
        {"add": "google.com"}
    ]
    result = batch_rename(test_servers)
    for r in result:
        print(r["ps"])
