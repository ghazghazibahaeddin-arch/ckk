"""Enterprise Key Management and Secret Management for CCK (Layer 7 & Cloud Service).

Implements cryptographically secure API Key generation, SHA-256 storage hashing,
key rotation, and constant-time verification.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from cck.core.exceptions import PolicyViolationError


class APIKeyRecord(BaseModel):
    """Metadata record of an enterprise API key (secrets never stored in plaintext)."""

    key_id: str = Field(..., description="Public identifier of the key, e.g. 'key_live_abc123'")
    name: str = Field(..., description="Human-readable label for the key")
    tenant_id: str = Field(..., description="Associated tenant organization")
    key_hash: str = Field(..., description="SHA-256 hash of the full secret token")
    is_active: bool = Field(default=True, description="Whether the key is valid for authentication")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revoked_at: datetime | None = Field(default=None)

    model_config = ConfigDict(extra="forbid")


class KeyManager:
    """Manages enterprise tenant API keys, hashing, rotation, and revocation."""

    def __init__(self) -> None:
        # key_id -> APIKeyRecord
        self._keys: dict[str, APIKeyRecord] = {}

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Compute SHA-256 hash of raw token."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def generate_key(self, tenant_id: str, name: str = "Production Key") -> tuple[str, APIKeyRecord]:
        """Generate a new secure API key.

        Returns:
            tuple[str, APIKeyRecord]: (raw_secret_token, key_record)
            Note: The raw secret token is returned ONCE to the user and never stored in plaintext.
        """
        token_random = secrets.token_urlsafe(32)
        key_id = f"cck_{secrets.token_hex(6)}"
        full_token = f"{key_id}_{token_random}"
        token_hash = self._hash_token(full_token)

        record = APIKeyRecord(
            key_id=key_id,
            name=name,
            tenant_id=tenant_id,
            key_hash=token_hash,
            is_active=True,
        )
        self._keys[key_id] = record
        return full_token, record

    def verify_token(self, full_token: str) -> tuple[bool, str | None]:
        """Verify full token against stored hashes using constant-time comparison.

        Returns:
            tuple[bool, str | None]: (is_valid, tenant_id)
        """
        if "_" not in full_token:
            return False, None
        key_id = full_token.split("_")[0] + "_" + full_token.split("_")[1]
        record = self._keys.get(key_id)
        if not record or not record.is_active:
            return False, None

        input_hash = self._hash_token(full_token)
        if hmac.compare_digest(input_hash, record.key_hash):
            return True, record.tenant_id
        return False, None

    def rotate_key(self, old_key_id: str, name: str = "Rotated Key") -> tuple[str, APIKeyRecord]:
        """Rotate an active key: generates a new key and immediately revokes the old one."""
        old_record = self._keys.get(old_key_id)
        if not old_record:
            raise PolicyViolationError(f"API Key '{old_key_id}' not found for rotation.")

        # Revoke old key
        self.revoke_key(old_key_id)

        # Generate replacement key for same tenant
        return self.generate_key(tenant_id=old_record.tenant_id, name=name)

    def revoke_key(self, key_id: str) -> APIKeyRecord:
        """Revoke an API key immediately."""
        record = self._keys.get(key_id)
        if not record:
            raise PolicyViolationError(f"API Key '{key_id}' not found.")

        updated = record.model_copy(
            update={
                "is_active": False,
                "revoked_at": datetime.now(timezone.utc),
            }
        )
        self._keys[key_id] = updated
        return updated
