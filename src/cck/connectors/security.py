"""Security and Credential Sanitization for CCK Connectors and Execution Adapters.

Enforces zero-leakage of credentials, bearer tokens, and secrets in logs,
exceptions, and journal payloads.
"""

import re
from typing import Any

SECRET_KEYS = {
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "private_key",
    "client_secret",
    "access_token",
    "refresh_token",
    "credentials",
}

BEARER_PATTERN = re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE)
GENERIC_KEY_PATTERN = re.compile(r"(key|secret|token)=[\w\-\.]+", re.IGNORECASE)


def scrub_secrets(data: Any) -> Any:
    """Recursively scrub credentials and secret values from strings, dicts, and lists."""
    if isinstance(data, str):
        s = BEARER_PATTERN.sub("Bearer [REDACTED_SECRET]", data)
        return GENERIC_KEY_PATTERN.sub(r"\1=[REDACTED_SECRET]", s)

    if isinstance(data, dict):
        clean_dict = {}
        for k, v in data.items():
            if str(k).lower() in SECRET_KEYS and not isinstance(v, (dict, list, tuple)):
                clean_dict[k] = "[REDACTED_SECRET]"
            else:
                clean_dict[k] = scrub_secrets(v)
        return clean_dict

    if isinstance(data, list):
        return [scrub_secrets(item) for item in data]

    if isinstance(data, tuple):
        return tuple(scrub_secrets(item) for item in data)

    return data
