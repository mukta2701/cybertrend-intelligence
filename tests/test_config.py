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
