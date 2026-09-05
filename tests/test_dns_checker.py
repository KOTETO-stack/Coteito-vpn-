from dns_checker import (
    DNSCheckResult,
    DNSCheckStatus,
    apply_dns_result,
    create_not_checked_result,
)
from models import Node


def make_node() -> Node:
    return Node(
        protocol="trojan",
        address="example.com",
        port=443,
        reachable=True,
    )


def test_not_checked_result() -> None:
    result = create_not_checked_result()

    assert result.status == DNSCheckStatus.NOT_CHECKED
    assert result.passed is False


def test_no_leak_result_passes() -> None:
    result = DNSCheckResult(
        status=DNSCheckStatus.NO_LEAK,
        resolver_addresses=("1.1.1.1",),
    )

    assert result.passed is True


def test_leak_result_does_not_pass() -> None:
    result = DNSCheckResult(
        status=DNSCheckStatus.LEAK_DETECTED,
        resolver_addresses=("192.0.2.1",),
    )

    assert result.passed is False


def test_error_result_does_not_pass() -> None:
    result = DNSCheckResult(
        status=DNSCheckStatus.ERROR,
        error="DNS test failed",
    )

    assert result.passed is False


def test_apply_no_leak_result_to_node() -> None:
    node = make_node()

    result = DNSCheckResult(
        status=DNSCheckStatus.NO_LEAK,
        resolver_addresses=("1.1.1.1",),
    )

    apply_dns_result(node, result)

    assert node.dns_leak is False


def test_apply_leak_result_to_node() -> None:
    node = make_node()

    result = DNSCheckResult(
        status=DNSCheckStatus.LEAK_DETECTED,
        resolver_addresses=("192.0.2.1",),
    )

    apply_dns_result(node, result)

    assert node.dns_leak is True


def test_apply_not_checked_result_to_node() -> None:
    node = make_node()

    result = DNSCheckResult(
        status=DNSCheckStatus.NOT_CHECKED,
    )

    apply_dns_result(node, result)

    assert node.dns_leak is None