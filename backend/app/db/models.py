"""
Modele SQLAlchemy 2.0 mapujące tabele z docs/schema.sql.
"""

from datetime import datetime, time
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    Time,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CIDR, ENUM, INET, JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# PostgreSQL ENUM types (zdefiniowane w docs/schema.sql, create_type=False)
scan_run_status_enum = ENUM(
    "queued", "running", "paused_window", "completed", "failed", "cancelled",
    name="scan_run_status",
    create_type=False,
)
scan_chunk_status_enum = ENUM(
    "pending", "in_progress", "completed", "requeued_window", "failed",
    name="scan_chunk_status",
    create_type=False,
)
host_status_enum = ENUM(
    "online", "unstable", "offline", "archived",
    name="host_status",
    create_type=False,
)
finding_severity_enum = ENUM(
    "info", "low", "medium", "high", "critical",
    name="finding_severity",
    create_type=False,
)
change_event_type_enum = ENUM(
    "host_new",
    "host_offline",
    "host_recovered",
    "service_new",
    "service_closed",
    "service_changed",
    "tls_changed",
    "tech_changed",
    "signature_matched",
    name="change_event_type",
    create_type=False,
)
override_entity_type_enum = ENUM(
    "host", "service",
    name="override_entity_type",
    create_type=False,
)
signature_match_type_enum = ENUM(
    "header", "cookie", "favicon_hash", "html_fragment", "path_probe", "footer_version",
    name="signature_match_type",
    create_type=False,
)
target_type_enum = ENUM(
    "ip", "cidr", "domain",
    name="target_type",
    create_type=False,
)
user_role_enum = ENUM(
    "admin", "add_delete_modify", "modify_read", "read_only",
    name="user_role",
    create_type=False,
)


class RbacRole(Base):
    __tablename__ = "rbac_roles"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    permissions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(user_role_enum, nullable=False, default="read_only")
    custom_role_name: Mapped[str | None] = mapped_column(String(64), ForeignKey("rbac_roles.name", ondelete="SET NULL"))
    scope_restricted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allowed_scope: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TargetGroup(Base):
    __tablename__ = "target_groups"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    environment: Mapped[str] = mapped_column(String(32), default="prod", nullable=False)
    group_type: Mapped[str] = mapped_column(String(16), default="static", nullable=False)
    filter_rules: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    targets: Mapped[list["Target"]] = relationship("Target", back_populates="group", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("group_id", "raw_value"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    group_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("target_groups.id"), nullable=False)
    raw_value: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(target_type_enum, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    group: Mapped[TargetGroup] = relationship("TargetGroup", back_populates="targets")


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    nmap_flags: Mapped[str] = mapped_column(Text, nullable=False)
    ports: Mapped[str] = mapped_column(Text, nullable=False)
    rate_limit_pps: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    max_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    chunk_cidr_prefix: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    http_fingerprint_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    signatures_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    target_group_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("target_groups.id"), nullable=False)
    profile_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_profiles.id"), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False, default="0 22 * * *")
    window_start_utc: Mapped[time] = mapped_column(Time, nullable=False)
    window_end_utc: Mapped[time] = mapped_column(Time, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="Europe/Warsaw")
    missed_scans_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    target_group: Mapped[TargetGroup | None] = relationship("TargetGroup")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    schedule_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_schedules.id"))
    target_group_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("target_groups.id"), nullable=False)
    profile_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_profiles.id"), nullable=False)
    status: Mapped[str] = mapped_column(scan_run_status_enum, nullable=False, default="queued")
    scanned_ports: Mapped[str | None] = mapped_column(Text)
    window_deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_chunks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_chunks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    schedule: Mapped[ScanSchedule | None] = relationship("ScanSchedule")
    chunks: Mapped[list["ScanChunk"]] = relationship("ScanChunk", back_populates="scan_run")


class ScanChunk(Base):
    __tablename__ = "scan_chunks"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    target_cidr: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(scan_chunk_status_enum, nullable=False, default="pending")
    worker_id: Mapped[str | None] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan_run: Mapped[ScanRun] = relationship("ScanRun", back_populates="chunks")


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    ip_address: Mapped[IPv4Address | IPv6Address | str] = mapped_column(INET, unique=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(host_status_enum, nullable=False, default="online")
    missed_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_scan_run_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_runs.id"))

    services: Mapped[list["Service"]] = relationship("Service", back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    host_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    service_name: Mapped[str | None] = mapped_column(String(64))
    product: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(128))
    banner: Mapped[str | None] = mapped_column(Text)
    missed_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    host: Mapped[Host] = relationship("Host", back_populates="services")
    http_fingerprints: Mapped[list["HTTPFingerprint"]] = relationship(
        "HTTPFingerprint", back_populates="service", cascade="all, delete-orphan"
    )
    signature_matches: Mapped[list["SignatureMatch"]] = relationship(
        "SignatureMatch", back_populates="service", cascade="all, delete-orphan"
    )


class HTTPFingerprint(Base):
    __tablename__ = "http_fingerprints"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    service_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("services.id"), nullable=False)
    scan_run_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_runs.id"))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(8), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[int | None] = mapped_column(Integer)
    probe_error: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text)
    redirect_chain: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    headers_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    cookies_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    favicon_mmh3_hash: Mapped[str | None] = mapped_column(String(64))
    tls_subject: Mapped[str | None] = mapped_column(Text)
    tls_issuer: Mapped[str | None] = mapped_column(Text)
    tls_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tls_san: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    technologies: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    tech_confidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_admin_panel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_staging_env: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    service: Mapped[Service] = relationship("Service", back_populates="http_fingerprints")


class CustomSignature(Base):
    __tablename__ = "custom_signatures"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(finding_severity_enum, nullable=False, default="info")
    match_type: Mapped[str] = mapped_column(signature_match_type_enum, nullable=False)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    probe_path: Mapped[str | None] = mapped_column(Text)
    expected_status: Mapped[int | None] = mapped_column(Integer)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class SignatureMatch(Base):
    __tablename__ = "signature_matches"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    service_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("services.id"), nullable=False)
    signature_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("custom_signatures.id"), nullable=False)
    matched_evidence: Mapped[str | None] = mapped_column(Text)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    service: Mapped[Service] = relationship("Service", back_populates="signature_matches")
    signature: Mapped[CustomSignature] = relationship("CustomSignature")


class ChangeEvent(Base):
    __tablename__ = "change_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    host_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    service_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("services.id"))
    change_type: Mapped[str] = mapped_column(change_event_type_enum, nullable=False)
    severity: Mapped[str] = mapped_column(finding_severity_enum, nullable=False, default="info")
    previous_value: Mapped[dict | None] = mapped_column(JSONB)
    current_value: Mapped[dict | None] = mapped_column(JSONB)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    host: Mapped[Host] = relationship("Host")
    service: Mapped[Service | None] = relationship("Service")


class AssetOverride(Base):
    __tablename__ = "asset_overrides"
    __table_args__ = (UniqueConstraint("entity_type", "entity_id"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    entity_type: Mapped[str] = mapped_column(override_entity_type_enum, nullable=False)
    entity_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    custom_label: Mapped[str | None] = mapped_column(String(128))
    owner_unit: Mapped[str | None] = mapped_column(String(128))
    criticality: Mapped[str | None] = mapped_column(finding_severity_enum)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_ignored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="defectdojo")
    base_url: Mapped[str] = mapped_column(Text, nullable=False)
    api_token_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    product_type_name: Mapped[str] = mapped_column(String(255), nullable=False, default="AGH Attack Surface")
    engagement_name: Mapped[str] = mapped_column(String(255), nullable=False, default="Janus ASI — Attack Surface")
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DefectDojoExport(Base):
    __tablename__ = "defectdojo_exports"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    integration_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False)
    change_event_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("change_events.id"))
    host_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("hosts.id"))
    service_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("services.id"))
    product_name: Mapped[str | None] = mapped_column(String(255))
    defectdojo_product_id: Mapped[int | None] = mapped_column(Integer)
    defectdojo_finding_id: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="exported")
    error_message: Mapped[str | None] = mapped_column(Text)
    exported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
