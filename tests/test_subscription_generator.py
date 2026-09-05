import json
from pathlib import Path

import pytest

from models import Node
from subscription_generator import (
    SubscriptionGeneratorError,
    generate_clash,
    generate_singbox,
    generate_subscription,
    write_subscription,
)


def make_node(
    *,
    protocol: str = "trojan",
    address: str = "example.com",
    port: int = 443,
    name: str = "Германия Берлин 🇩🇪",
) -> Node:
    return Node(
        protocol=protocol,
        address=address,
        port=port,
        country="Германия",
        city="Берлин",
        flag="🇩🇪",
        name=name,
        latency_ms=100.0,
        reachable=True,
        tls_valid=True,
        dns_leak=False,
        validated=True,
        parameters={
            "password": "test-password",
            "sni": "example.com",
        },
    )


def test_generate_singbox_contains_trojan_node() -> None:
    node = make_node()

    result = generate_singbox([node])

    assert "outbounds" in result
    assert len(result["outbounds"]) == 1
    assert result["outbounds"][0]["type"] == "trojan"
    assert result["outbounds"][0]["server"] == "example.com"
    assert result["outbounds"][0]["server_port"] == 443


def test_generate_singbox_contains_hysteria2_node() -> None:
    node = make_node(protocol="hysteria2")

    result = generate_singbox([node])

    assert len(result["outbounds"]) == 1
    assert result["outbounds"][0]["type"] == "hysteria2"


def test_generate_clash_contains_trojan_node() -> None:
    node = make_node()

    result = generate_clash([node])

    assert "proxies" in result
    assert len(result["proxies"]) == 1
    assert result["proxies"][0]["type"] == "trojan"
    assert result["proxies"][0]["server"] == "example.com"


def test_generate_clash_contains_hysteria2_node() -> None:
    node = make_node(protocol="hysteria2")

    result = generate_clash([node])

    assert len(result["proxies"]) == 1
    assert result["proxies"][0]["type"] == "hysteria2"


def test_unvalidated_node_is_not_published() -> None:
    node = make_node()
    node.validated = False

    with pytest.raises(SubscriptionGeneratorError):
        generate_singbox([node])


def test_unknown_dns_status_is_not_published() -> None:
    node = make_node()
    node.dns_leak = None

    with pytest.raises(SubscriptionGeneratorError):
        generate_singbox([node])


def test_unsupported_format_is_rejected() -> None:
    node = make_node()

    with pytest.raises(SubscriptionGeneratorError):
        generate_subscription([node], "unknown")


def test_empty_node_list_is_rejected() -> None:
    with pytest.raises(SubscriptionGeneratorError):
        generate_singbox([])


def test_write_subscription_creates_json_file(tmp_path: Path) -> None:
    node = make_node()
    output_path = tmp_path / "subscription.json"

    result = write_subscription(
        [node],
        output_path,
        "sing-box",
    )

    assert result == output_path
    assert output_path.is_file()

    data = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert "outbounds" in data
    assert len(data["outbounds"]) == 1


def test_generated_node_uses_display_name() -> None:
    node = make_node(
        name=None,
    )

    result = generate_clash([node])

    assert result["proxies"][0]["name"] == "Германия Берлин 🇩🇪"