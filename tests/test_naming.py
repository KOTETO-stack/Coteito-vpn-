from models import Node
from naming import (
    apply_node_names,
    build_node_name,
    country_flag,
    country_name_ru,
)


def make_node(
    *,
    country: str | None = "Germany",
    city: str | None = "Berlin",
) -> Node:
    return Node(
        protocol="trojan",
        address="example.com",
        port=443,
        country=country,
        city=city,
    )


def test_country_name_is_translated_to_russian() -> None:
    assert country_name_ru("Germany") == "Германия"
    assert country_name_ru("DE") == "Германия"


def test_country_flag_is_detected() -> None:
    assert country_flag("Germany") == "🇩🇪"
    assert country_flag("DE") == "🇩🇪"


def test_unknown_country_gets_fallback_name() -> None:
    assert country_name_ru(None) == "Неизвестная страна"


def test_unknown_country_gets_fallback_flag() -> None:
    assert country_flag("Unknown Country") == "🌐"


def test_build_node_name() -> None:
    node = make_node()

    assert build_node_name(node) == "Германия Berlin 🇩🇪"


def test_build_node_name_without_city() -> None:
    node = make_node(city=None)

    assert build_node_name(node) == "Германия 🇩🇪"


def test_apply_node_names_updates_name_and_flag() -> None:
    node = make_node()

    result = apply_node_names([node])

    assert result == [node]
    assert node.name == "Германия Berlin 🇩🇪"
    assert node.flag == "🇩🇪"