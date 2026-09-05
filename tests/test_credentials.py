import pytest

from credentials import CredentialsError, NodeCredentials


def test_credentials_accept_valid_password() -> None:
    credentials = NodeCredentials(
        password="test-password",
    )

    assert credentials.password == "test-password"


def test_credentials_reject_empty_password() -> None:
    with pytest.raises(CredentialsError):
        NodeCredentials(password="")


def test_credentials_reject_non_string_password() -> None:
    with pytest.raises(CredentialsError):
        NodeCredentials(password=123)  # type: ignore[arg-type]


def test_credentials_repr_does_not_expose_password() -> None:
    credentials = NodeCredentials(
        password="super-secret-password",
    )

    representation = repr(credentials)

    assert "super-secret-password" not in representation
    assert "***" in representation


def test_credentials_masked_value_is_safe() -> None:
    credentials = NodeCredentials(
        password="super-secret-password",
    )

    assert credentials.masked() == "***"


def test_credentials_are_immutable() -> None:
    credentials = NodeCredentials(
        password="test-password",
    )

    with pytest.raises(AttributeError):
        credentials.password = "another-password"  # type: ignore[misc]