from dns_checker import DNSCheckResult, DNSCheckStatus
from dns_policy import DNSPolicy


def test_no_leak_is_accepted() -> None:
    policy = DNSPolicy()

    result = DNSCheckResult(
        status=DNSCheckStatus.NO_LEAK,
        resolver_addresses=("1.1.1.1",),
    )

    assert policy.accepts(result) is True


def test_detected_leak_is_rejected() -> None:
    policy = DNSPolicy()

    result = DNSCheckResult(
        status=DNSCheckStatus.LEAK_DETECTED,
        resolver_addresses=("192.0.2.1",),
    )

    assert policy.accepts(result) is False


def test_not_checked_is_rejected_by_default() -> None:
    policy = DNSPolicy()

    result = DNSCheckResult(
        status=DNSCheckStatus.NOT_CHECKED,
    )

    assert policy.accepts(result) is False


def test_error_is_rejected_by_default() -> None:
    policy = DNSPolicy()

    result = DNSCheckResult(
        status=DNSCheckStatus.ERROR,
        error="DNS check failed",
    )

    assert policy.accepts(result) is False


def test_leak_can_be_allowed_when_policy_disables_rejection() -> None:
    policy = DNSPolicy(
        reject_leaks=False,
    )

    result = DNSCheckResult(
        status=DNSCheckStatus.LEAK_DETECTED,
    )

    assert policy.accepts(result) is True


def test_not_checked_can_be_allowed_when_check_is_optional() -> None:
    policy = DNSPolicy(
        require_completed_check=False,
    )

    result = DNSCheckResult(
        status=DNSCheckStatus.NOT_CHECKED,
    )

    assert policy.accepts(result) is True