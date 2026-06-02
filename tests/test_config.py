from pathlib import Path

from cybertrend.config import Settings


def test_settings_accept_comma_separated_recipient_lists(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "ALERT_RECIPIENTS=first@example.com,second@example.com",
                "DIGEST_RECIPIENTS=digest@example.com",
            ]
        )
    )

    settings = Settings(_env_file=env_file)

    assert settings.alert_recipients == ["first@example.com", "second@example.com"]
    assert settings.digest_recipients == ["digest@example.com"]


def test_performance_settings_have_safe_defaults():
    settings = Settings()

    assert settings.smtp_timeout_seconds == 30
    assert settings.max_items_per_source == 25
    assert settings.max_nvd_items == 50


def test_performance_settings_can_be_overridden_from_env_file(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SMTP_TIMEOUT_SECONDS=12",
                "MAX_ITEMS_PER_SOURCE=10",
                "MAX_NVD_ITEMS=20",
            ]
        )
    )

    settings = Settings(_env_file=env_file)

    assert settings.smtp_timeout_seconds == 12
    assert settings.max_items_per_source == 10
    assert settings.max_nvd_items == 20
