"""Resource Reservations and Concurrency Control for CCK Control Plane (Layer 3).

Manages logical resource reservations with time-to-live (TTL), lease renewal,
authorized release, expiration, and crash recovery.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.core.exceptions import ReservationConflictError, ReservationError
from cck.core.types import ReservationStatus


class ReservationRecord(BaseModel):
    """Authoritative record of a logical resource reservation lease."""

    reservation_id: str = Field(
        default_factory=lambda: f"resv_{uuid4().hex}",
        description="Unique reservation ID",
    )
    resource_key: str = Field(..., description="Target resource identifier being reserved")
    holder_id: str = Field(..., description="Agent or session holding the reservation")
    status: ReservationStatus = Field(
        default=ReservationStatus.ACTIVE,
        description="Reservation state (ACTIVE, RELEASED, EXPIRED, REVOKED)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC acquisition timestamp",
    )
    expires_at: datetime = Field(..., description="UTC absolute expiration timestamp")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Contextual reservation metadata")

    model_config = ConfigDict(extra="forbid")

    def is_expired(self, current_time: datetime | None = None) -> bool:
        """Check if lease has expired."""
        now = current_time or datetime.now(timezone.utc)
        return now >= self.expires_at


class ReservationManager:
    """Manages lease acquisition, renewal, release, and concurrency conflicts."""

    def __init__(self) -> None:
        # resource_key -> active ReservationRecord
        self._reservations: dict[str, ReservationRecord] = {}

    def acquire_reservation(
        self,
        resource_key: str,
        holder_id: str,
        ttl_seconds: float = 60.0,
        metadata: dict[str, Any] | None = None,
        current_time: datetime | None = None,
    ) -> ReservationRecord:
        """Attempt to acquire an exclusive lock/reservation on a resource.

        Raises:
            ReservationConflictError: If resource is already reserved by another active holder.
        """
        now = current_time or datetime.now(timezone.utc)

        # Check existing reservation
        existing = self._reservations.get(resource_key)
        if (
            existing is not None
            and existing.status == ReservationStatus.ACTIVE
            and not existing.is_expired(now)
            and existing.holder_id != holder_id
        ):
            raise ReservationConflictError(
                f"Resource '{resource_key}' is already actively reserved by holder '{existing.holder_id}' "
                f"(expires at {existing.expires_at.isoformat()}). Concurrency conflict!"
            )

        expires_at = now + timedelta(seconds=ttl_seconds)
        record = ReservationRecord(
            resource_key=resource_key,
            holder_id=holder_id,
            status=ReservationStatus.ACTIVE,
            created_at=now,
            expires_at=expires_at,
            metadata=metadata or {},
        )
        self._reservations[resource_key] = record
        return record

    def renew_reservation(
        self,
        resource_key: str,
        holder_id: str,
        extension_seconds: float = 60.0,
        current_time: datetime | None = None,
    ) -> ReservationRecord:
        """Renew an active reservation lease.

        Enforces that only the authorized holder can renew.
        """
        now = current_time or datetime.now(timezone.utc)
        record = self._reservations.get(resource_key)

        if record is None or record.status != ReservationStatus.ACTIVE:
            raise ReservationError(f"No active reservation found for resource '{resource_key}'.")

        if record.holder_id != holder_id:
            raise ReservationError(
                f"Unauthorized: Holder '{holder_id}' cannot renew reservation held by '{record.holder_id}'."
            )

        if record.is_expired(now):
            raise ReservationError(f"Cannot renew expired reservation for resource '{resource_key}'.")

        new_expiry = max(record.expires_at, now) + timedelta(seconds=extension_seconds)
        updated = record.model_copy(update={"expires_at": new_expiry})
        self._reservations[resource_key] = updated
        return updated

    def release_reservation(
        self,
        resource_key: str,
        holder_id: str,
    ) -> ReservationRecord:
        """Explicitly release a reservation lease.

        Enforces that only the authorized holder can release.
        """
        record = self._reservations.get(resource_key)
        if record is None:
            raise ReservationError(f"Reservation for resource '{resource_key}' does not exist.")

        if record.holder_id != holder_id:
            raise ReservationError(
                f"Unauthorized: Holder '{holder_id}' cannot release reservation held by '{record.holder_id}'."
            )

        released = record.model_copy(update={"status": ReservationStatus.RELEASED})
        self._reservations[resource_key] = released
        return released

    def check_and_reap_expired(self, current_time: datetime | None = None) -> list[str]:
        """Sweep and mark expired reservations. Returns list of expired resource keys."""
        now = current_time or datetime.now(timezone.utc)
        expired_keys = []
        for key, rec in self._reservations.items():
            if rec.status == ReservationStatus.ACTIVE and rec.is_expired(now):
                expired_recs = rec.model_copy(update={"status": ReservationStatus.EXPIRED})
                self._reservations[key] = expired_recs
                expired_keys.append(key)
        return expired_keys
