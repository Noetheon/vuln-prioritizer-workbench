"""ATT&CK STIX snapshot catalog models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import field_validator, model_validator
from sqlalchemy import JSON, Column, DateTime, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.models.attack_common import (
    require_non_empty,
)
from app.models.attack_common import (
    validate_tactic_id as _validate_tactic_id,
)
from app.models.attack_common import (
    validate_technique_id as _validate_technique_id,
)
from app.models.base import get_datetime_utc


class AttackStixSnapshotBase(SQLModel):
    """Shared versioned ATT&CK STIX snapshot catalog fields."""

    attack_version: str = Field(min_length=1, max_length=40)
    domain: str = Field(min_length=1, max_length=80)
    stix_spec_version: str | None = Field(default=None, max_length=40)
    bundle_sha256: str = Field(min_length=64, max_length=64)
    source_path: str | None = Field(default=None, max_length=1000)
    object_counts_json: dict[str, int] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    source_metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )

    @field_validator("attack_version", "domain", "bundle_sha256")
    @classmethod
    def validate_required_snapshot_text(cls, value: str, info: Any) -> str:
        """Validate the required snapshot text field."""
        return require_non_empty(value, str(info.field_name))


class AttackStixSnapshot(AttackStixSnapshotBase, table=True):
    """Persisted versioned ATT&CK STIX bundle import."""

    __tablename__ = "attack_stix_snapshot"
    __table_args__ = (
        UniqueConstraint("bundle_sha256", name="uq_attack_stix_snapshot_bundle_sha256"),
        Index("ix_attack_stix_snapshot_domain_version", "domain", "attack_version"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    provider_snapshot_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="provider_snapshot.id",
        index=True,
        ondelete="SET NULL",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixSnapshotPublic(AttackStixSnapshotBase):
    """Public ATT&CK STIX snapshot response shape."""

    id: uuid.UUID
    provider_snapshot_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AttackStixTacticBase(SQLModel):
    """Shared tactic row for one imported ATT&CK STIX snapshot."""

    stix_id: str = Field(min_length=1, max_length=120)
    tactic_id: str = Field(min_length=6, max_length=16)
    name: str = Field(min_length=1, max_length=200)
    short_name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False

    @field_validator("tactic_id")
    @classmethod
    def validate_tactic_id(cls, value: str) -> str:
        """Validate the tactic id field."""
        return _validate_tactic_id(value)

    @field_validator("name", "stix_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        """Validate the required text field."""
        return require_non_empty(value, str(info.field_name))


class AttackStixTactic(AttackStixTacticBase, table=True):
    """Persisted tactic catalog row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_tactic"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "tactic_id",
            name="uq_attack_stix_tactic_snapshot_tactic",
        ),
        Index("ix_attack_stix_tactic_tactic_id", "tactic_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixTechniqueBase(SQLModel):
    """Shared technique row for one imported ATT&CK STIX snapshot."""

    stix_id: str = Field(min_length=1, max_length=120)
    technique_id: str = Field(min_length=5, max_length=16)
    name: str = Field(min_length=1, max_length=300)
    tactic_ids_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    tactic_short_names_json: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False
    is_subtechnique: bool = False

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        """Validate the technique id field."""
        return _validate_technique_id(value)

    @field_validator("name", "stix_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        """Validate the required text field."""
        return require_non_empty(value, str(info.field_name))

    @model_validator(mode="after")
    def validate_snapshot_tactic_ids(self) -> AttackStixTechniqueBase:
        """Validate the snapshot tactic ids field."""
        for tactic_id in self.tactic_ids_json:
            _validate_tactic_id(tactic_id)
        return self


class AttackStixTechnique(AttackStixTechniqueBase, table=True):
    """Persisted technique catalog row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_technique"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "technique_id",
            name="uq_attack_stix_technique_snapshot_technique",
        ),
        Index("ix_attack_stix_technique_technique_id", "technique_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixMitigationBase(SQLModel):
    """Shared mitigation row for one imported ATT&CK STIX snapshot."""

    stix_id: str = Field(min_length=1, max_length=120)
    mitigation_id: str = Field(min_length=5, max_length=16)
    name: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    url: str | None = Field(default=None, max_length=500)
    revoked: bool = False
    deprecated: bool = False

    @field_validator("name", "stix_id", "mitigation_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        """Validate the required text field."""
        return require_non_empty(value, str(info.field_name))


class AttackStixMitigation(AttackStixMitigationBase, table=True):
    """Persisted mitigation catalog row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_mitigation"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "mitigation_id",
            name="uq_attack_stix_mitigation_snapshot_mitigation",
        ),
        Index("ix_attack_stix_mitigation_mitigation_id", "mitigation_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AttackStixTechniqueMitigationBase(SQLModel):
    """Shared relationship row linking a STIX mitigation to a technique."""

    relationship_id: str = Field(min_length=1, max_length=120)
    technique_id: str = Field(min_length=5, max_length=16)
    mitigation_id: str = Field(min_length=5, max_length=16)
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str) -> str:
        """Validate the technique id field."""
        return _validate_technique_id(value)

    @field_validator("relationship_id", "mitigation_id")
    @classmethod
    def validate_required_text(cls, value: str, info: Any) -> str:
        """Validate the required text field."""
        return require_non_empty(value, str(info.field_name))


class AttackStixTechniqueMitigation(AttackStixTechniqueMitigationBase, table=True):
    """Persisted mitigation relationship row for one imported STIX snapshot."""

    __tablename__ = "attack_stix_technique_mitigation"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "technique_id",
            "mitigation_id",
            "relationship_id",
            name="uq_attack_stix_technique_mitigation_snapshot_relationship",
        ),
        Index(
            "ix_attack_stix_technique_mitigation_technique",
            "snapshot_id",
            "technique_id",
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    snapshot_id: uuid.UUID = Field(
        foreign_key="attack_stix_snapshot.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
