from __future__ import annotations

import json
import os
from typing import Annotated, Dict, List, Optional

import boto3
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "local"
    aws_region: str = "eu-west-2"
    database_url: str = "postgresql+psycopg://cybertrend:cybertrend@localhost:5432/cybertrend"
    api_key: str = "local-dev"

    reddit_client_id: Optional[str] = None
    reddit_client_secret: Optional[str] = None
    reddit_user_agent: str = "cybertrend-intelligence/0.1"
    nvd_api_key: Optional[str] = None
    tenable_access_key: Optional[str] = None
    tenable_secret_key: Optional[str] = None
    llm_provider: str = "disabled"
    llm_api_key: Optional[str] = None
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""

    ses_from_email: str = "security-alerts@example.com"
    ses_configuration_set: Optional[str] = None
    alert_recipients: Annotated[List[str], NoDecode] = Field(default_factory=list)
    digest_recipients: Annotated[List[str], NoDecode] = Field(default_factory=list)

    @field_validator("alert_recipients", "digest_recipients", mode="before")
    @classmethod
    def parse_csv(cls, value):
        if value is None or value == "":
            return []
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


SECRET_ENV_KEYS = {
    "API_KEY",
    "REDDIT_CLIENT_ID",
    "REDDIT_CLIENT_SECRET",
    "NVD_API_KEY",
    "TENABLE_ACCESS_KEY",
    "TENABLE_SECRET_KEY",
    "LLM_API_KEY",
    "SES_FROM_EMAIL",
    "SES_CONFIGURATION_SET",
    "ALERT_RECIPIENTS",
    "DIGEST_RECIPIENTS",
}


def _load_secret_json(secret_arn: str, region_name: str) -> Dict[str, str]:
    client = boto3.client("secretsmanager", region_name=region_name)
    response = client.get_secret_value(SecretId=secret_arn)
    raw = response.get("SecretString") or "{}"
    data = json.loads(raw)
    return {str(key): str(value) for key, value in data.items() if value is not None}


def _database_url_from_secret(secret: Dict[str, str]) -> Optional[str]:
    host = secret.get("host")
    username = secret.get("username")
    password = secret.get("password")
    dbname = secret.get("dbname") or secret.get("database") or "cybertrend"
    port = secret.get("port", "5432")
    if not host or not username or password is None:
        return None
    return f"postgresql+psycopg://{username}:{password}@{host}:{port}/{dbname}"


def _prime_env_from_secrets() -> None:
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "eu-west-2"
    app_secret_arn = os.getenv("APP_SECRET_ARN")
    db_secret_arn = os.getenv("DB_SECRET_ARN")
    if app_secret_arn:
        for key, value in _load_secret_json(app_secret_arn, region).items():
            if key in SECRET_ENV_KEYS:
                os.environ.setdefault(key, value)
    if db_secret_arn:
        database_url = _database_url_from_secret(_load_secret_json(db_secret_arn, region))
        if database_url:
            os.environ.setdefault("DATABASE_URL", database_url)


def get_settings() -> Settings:
    _prime_env_from_secrets()
    return Settings()
