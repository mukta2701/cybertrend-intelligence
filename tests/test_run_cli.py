import os
import subprocess
import sys
from pathlib import Path


def test_run_cli_imports_package_from_source_checkout_for_commands():
    root = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "PYTHONPATH": "",
        "DATABASE_URL": "sqlite://",
        "LLM_PROVIDER": "disabled",
        "LLM_API_KEY": "",
        "SMTP_USER": "",
        "SMTP_PASSWORD": "",
        "SOURCE_QUEUE_URL": "",
        "ALERT_QUEUE_URL": "",
    }

    result = subprocess.run(
        [sys.executable, "run.py", "unknown"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Unknown command" in result.stdout
    assert "ModuleNotFoundError" not in result.stderr
