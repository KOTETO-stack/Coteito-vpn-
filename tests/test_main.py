from unittest.mock import patch

import __main__


def test_main_returns_zero_when_config_is_valid() -> None:
    fake_config = {
        "protocols": {
            "allowed": [
                "hysteria2",
                "trojan",
            ],
        },
    }

    with patch(
        "__main__.load_config",
        return_value=fake_config,
    ):
        result = __main__.main()

    assert result == 0


def test_main_returns_one_when_config_is_invalid() -> None:
    with patch(
        "__main__.load_config",
        side_effect=__main__.ConfigError(
            "invalid config"
        ),
    ):
        result = __main__.main()

    assert result == 1