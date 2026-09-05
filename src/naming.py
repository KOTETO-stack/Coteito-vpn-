from __future__ import annotations

from models import Node


COUNTRY_FLAGS: dict[str, str] = {
    "germany": "🇩🇪",
    "de": "🇩🇪",
    "france": "🇫🇷",
    "fr": "🇫🇷",
    "netherlands": "🇳🇱",
    "nl": "🇳🇱",
    "finland": "🇫🇮",
    "fi": "🇫🇮",
    "sweden": "🇸🇪",
    "se": "🇸🇪",
    "norway": "🇳🇴",
    "no": "🇳🇴",
    "denmark": "🇩🇰",
    "dk": "🇩🇰",
    "poland": "🇵🇱",
    "pl": "🇵🇱",
    "united kingdom": "🇬🇧",
    "uk": "🇬🇧",
    "great britain": "🇬🇧",
    "france": "🇫🇷",
    "italy": "🇮🇹",
    "it": "🇮🇹",
    "spain": "🇪🇸",
    "es": "🇪🇸",
    "portugal": "🇵🇹",
    "pt": "🇵🇹",
    "switzerland": "🇨🇭",
    "ch": "🇨🇭",
    "austria": "🇦🇹",
    "at": "🇦🇹",
    "belgium": "🇧🇪",
    "be": "🇧🇪",
    "czech republic": "🇨🇿",
    "czechia": "🇨🇿",
    "cz": "🇨🇿",
    "estonia": "🇪🇪",
    "ee": "🇪🇪",
    "latvia": "🇱🇻",
    "lv": "🇱🇻",
    "lithuania": "🇱🇹",
    "lt": "🇱🇹",
    "romania": "🇷🇴",
    "ro": "🇷🇴",
    "bulgaria": "🇧🇬",
    "bg": "🇧🇬",
    "canada": "🇨🇦",
    "ca": "🇨🇦",
    "united states": "🇺🇸",
    "usa": "🇺🇸",
    "us": "🇺🇸",
    "japan": "🇯🇵",
    "jp": "🇯🇵",
    "singapore": "🇸🇬",
    "sg": "🇸🇬",
    "south korea": "🇰🇷",
    "korea": "🇰🇷",
    "kr": "🇰🇷",
    "australia": "🇦🇺",
    "au": "🇦🇺",
}


COUNTRY_RU: dict[str, str] = {
    "germany": "Германия",
    "de": "Германия",
    "france": "Франция",
    "fr": "Франция",
    "netherlands": "Нидерланды",
    "nl": "Нидерланды",
    "finland": "Финляндия",
    "fi": "Финляндия",
    "sweden": "Швеция",
    "se": "Швеция",
    "norway": "Норвегия",
    "no": "Норвегия",
    "denmark": "Дания",
    "dk": "Дания",
    "poland": "Польша",
    "pl": "Польша",
    "united kingdom": "Великобритания",
    "uk": "Великобритания",
    "great britain": "Великобритания",
    "italy": "Италия",
    "it": "Италия",
    "spain": "Испания",
    "es": "Испания",
    "portugal": "Португалия",
    "pt": "Португалия",
    "switzerland": "Швейцария",
    "ch": "Швейцария",
    "austria": "Австрия",
    "at": "Австрия",
    "belgium": "Бельгия",
    "be": "Бельгия",
    "czech republic": "Чехия",
    "czechia": "Чехия",
    "cz": "Чехия",
    "estonia": "Эстония",
    "ee": "Эстония",
    "latvia": "Латвия",
    "lv": "Латвия",
    "lithuania": "Литва",
    "lt": "Литва",
    "romania": "Румыния",
    "ro": "Румыния",
    "bulgaria": "Болгария",
    "bg": "Болгария",
    "canada": "Канада",
    "ca": "Канада",
    "united states": "США",
    "usa": "США",
    "us": "США",
    "japan": "Япония",
    "jp": "Япония",
    "singapore": "Сингапур",
    "sg": "Сингапур",
    "south korea": "Южная Корея",
    "korea": "Южная Корея",
    "kr": "Южная Корея",
    "australia": "Австралия",
    "au": "Австралия",
}


def _normalize(value: str | None) -> str:
    if not value:
        return ""

    return " ".join(value.strip().lower().split())


def country_name_ru(country: str | None) -> str:
    """Возвращает русское название страны."""

    normalized = _normalize(country)

    if not normalized:
        return "Неизвестная страна"

    return COUNTRY_RU.get(
        normalized,
        country.strip() if country else "Неизвестная страна",
    )


def country_flag(country: str | None) -> str:
    """Возвращает флаг страны."""

    normalized = _normalize(country)

    return COUNTRY_FLAGS.get(normalized, "🌐")


def build_node_name(node: Node) -> str:
    """
    Формирует отображаемое имя:

    Германия Берлин 🇩🇪
    """

    country = country_name_ru(node.country)
    city = (node.city or "").strip()
    flag = country_flag(node.country)

    if city:
        return f"{country} {city} {flag}"

    return f"{country} {flag}"


def apply_node_names(nodes: list[Node]) -> list[Node]:
    """Назначает имена всем узлам."""

    for node in nodes:
        node.flag = country_flag(node.country)
        node.name = build_node_name(node)

    return nodes