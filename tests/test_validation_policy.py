from models import ValidationResult
from validation_policy import ValidationPolicy


def make_result(
    *,
    reachable: bool = True,
    tls_valid: bool = True,
    latency_ms: float | None = 100.0,
    dns_leak: bool | None = False,
    errors: list[str] | None = None,
) -> ValidationResult:
    return ValidationResult(
        reachable=reachable,
        tls_valid=tls_valid,
        latency_ms=latency_ms,
        dns_leak=dns_leak,
        errors=errors or [],
    )


def test_valid_result_is_accepted() -> None:
    policy = ValidationPolicy()

    assert policy.accepts(make_result()) is True


def test_unreachable_result_is_rejected() -> None:
    policy = ValidationPolicy()

    result = make_result(reachable=False)

    assert policy.accepts(result) is False


def test_invalid_tls_is_rejected() -> None:
    policy = ValidationPolicy()

    result = make_result(tls_valid=False)

    assert policy.accepts(result) is False


def test_missing_latency_is_rejected() -> None:
    policy = ValidationPolicy()

    result = make_result(latency_ms=None)

    assert policy.accepts(result) is False


def test_high_latency_is_rejected() -> None:
    policy = ValidationPolicy(max_latency_ms=500.0)

    result = make_result(latency_ms=501.0)

    assert policy.accepts(result) is False


def test_dns_leak_is_rejected() -> None:
    policy = ValidationPolicy()

    result = make_result(dns_leak=True)

    assert policy.accepts(result) is False


def test_unknown_dns_status_is_rejected() -> None:
    policy = ValidationPolicy()

    result = make_result(dns_leak=None)

    assert policy.accepts(result) is False


def test_validation_errors_are_rejected() -> None:
    policy = ValidationPolicy()

    result = make_result(
        errors=["TLS handshake failed"],
    )

    assert policy.accepts(result) is False


def test_exact_latency_limit_is_accepted() -> None:
    policy = ValidationPolicy(max_latency_ms=500.0)

    result = make_result(latency_ms=500.0)

    assert policy.accepts(result) is True