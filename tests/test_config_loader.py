from pathlib import Path

import pytest
import yaml

from config_loader import ConfigError, load_config, validate_config


def make_config() -> dict:
    return {
        "project": {
            "name": "Test",
            "language": "ru",
            "platform": "ios",
            "client": "karing",
        },
        "protocols": {
            "allowed": [
                "hysteria2",
                "trojan",
            ],
            "reject_unknown": True,
        },
        "sources": {
            "enabled": True,
            "allowed_schemes": [
                "http",
                "https",
            ],
            "allow_messaging_sources": False,
            "max_sources": 100,
        },
        "nodes": {
            "min_count_target": 100,
            "preferred_count": 150,
            "max_latency_ms": 500,
            "validation_attempts": 3,
            "min_success_ratio": 0.66,
            "remove_duplicates": True,
        },
        "healthcheck": {
            "enabled": True,
            "timeout_seconds": 10,
            "tls": {
                "enabled": True,
                "verify_certificate": True,
            },
        },
        "privacy": {
            "send_personal_data": False,
            "send_cookies": False,
            "send_authentication_tokens": False,
            "collect_user_traffic": False,
            "store_user_traffic": False,
            "technical_logs_only": True,
        },
        "safety": {
            "never_publish_unvalidated_nodes": True,
            "never_publish_malformed_nodes": True,
            "never_publish_unknown_protocols": True,
        },
    }


def test_valid_config_is_accepted() -> None:
    config = make_config()

    result = validate_config(config)

    assert result == config


def test_wrong_client_is_rejected() -> None:
    config = make_config()
    config["project"]["client"] = "other"

    with pytest.raises(ConfigError):
        validate_config(config)


def test_unknown_protocol_is_rejected() -> None:
    config = make_config()
    config["protocols"]["allowed"] = [
        "trojan",
        "unknown",
    ]

    with pytest.raises(ConfigError):
        validate_config(config)


def test_empty_protocol_list_is_rejected() -> None:
    config = make_config()
    config["protocols"]["allowed"] = []

    with pytest.raises(ConfigError):
        validate_config(config)


def test_unknown_source_scheme_is_rejected() -> None:
    config = make_config()
    config["sources"]["allowed_schemes"] = [
        "ftp",
    ]

    with pytest.raises(ConfigError):
        validate_config(config)


def test_messaging_sources_are_rejected() -> None:
    config = make_config()
    config["sources"]["allow_messaging_sources"] = True

    with pytest.raises(ConfigError):
        validate_config(config)


def test_invalid_success_ratio_is_rejected() -> None:
    config = make_config()
    config["nodes"]["min_success_ratio"] = 1.5

    with pytest.raises(ConfigError):
        validate_config(config)


def test_zero_success_ratio_is_rejected() -> None:
    config = make_config()
    config["nodes"]["min_success_ratio"] = 0

    with pytest.raises(ConfigError):
        validate_config(config)


def test_excessive_latency_limit_is_rejected() -> None:
    config = make_config()
    config["nodes"]["max_latency_ms"] = 10000

    with pytest.raises(ConfigError):
        validate_config(config)


def test_tls_certificate_verification_is_required() -> None:
    config = make_config()
    config["healthcheck"]["tls"]["verify_certificate"] = False

    with pytest.raises(ConfigError):
        validate_config(config)


def test_personal_data_must_remain_disabled() -> None:
    config = make_config()
    config["privacy"]["send_personal_data"] = True

    with pytest.raises(ConfigError):
        validate_config(config)


def test_user_traffic_collection_must_remain_disabled() -> None:
    config = make_config()
    config["privacy"]["collect_user_traffic"] = True

    with pytest.raises(ConfigError):
        validate_config(config)


def test_unvalidated_nodes_must_never_be_published() -> None:
    config = make_config()
    config["safety"]["never_publish_unvalidated_nodes"] = False

    with pytest.raises(ConfigError):
        validate_config(config)


def test_malformed_nodes_must_never_be_published() -> None:
    config = make_config()
    config["safety"]["never_publish_malformed_nodes"] = False

    with pytest.raises(ConfigError):
        validate_config(config)


def test_load_config_reads_yaml_file(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config = make_config()

    config_path.write_text(
        yaml.safe_dump(
            config,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )

    loaded = load_config(config_path)

    assert loaded["project"]["client"] == "karing"
    assert loaded["protocols"]["allowed"] == [
        "hysteria2",
        "trojan",
    ]


def test_missing_config_file_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "missing.yaml"

    with pytest.raises(ConfigError):
        load_config(config_path)