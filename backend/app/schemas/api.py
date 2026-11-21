"""
Schematy odpowiedzi i żądań dla endpointów odczytu (/hosts, /changes) oraz nadpisań (/overrides).
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, Field, field_validator


def _coerce_ip_to_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (IPv4Address, IPv6Address)):
        return str(value)
    if isinstance(value, (IPv4Interface, IPv6Interface)):
        return str(value.ip)
    return str(value).split("/")[0]


class OverrideOut(BaseModel):
    id: UUID
    entity_type: Literal["host", "service"]
    entity_id: UUID
    custom_label: str | None = None
    owner_unit: str | None = None
    criticality: Literal["info", "low", "medium", "high", "critical"] | None = None
    tags: list[str] = Field(default_factory=list)
    is_false_positive: bool = False
    is_ignored: bool = False
    notes: str | None = None
    updated_at: datetime


class OverridePatchRequest(BaseModel):
    entity_type: Literal["host", "service"]
    entity_id: UUID
    custom_label: str | None = None
    owner_unit: str | None = None
    criticality: Literal["info", "low", "medium", "high", "critical"] | None = None
    tags: list[str] | None = None
    is_false_positive: bool | None = None
    is_ignored: bool | None = None
    notes: str | None = None


class HTTPFingerprintOut(BaseModel):
    id: UUID
    url: str
    scheme: str
    status_code: int | None = None
    response_time_ms: int | None = None
    probe_error: str | None = None
    title: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[str] = Field(default_factory=list)
    favicon_mmh3_hash: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_not_after: datetime | None = None
    tls_san: list[str] = Field(default_factory=list)
    tls_is_self_signed: bool = False
    technologies: list[str] = Field(default_factory=list)
    tech_confidence: dict[str, str] = Field(default_factory=dict)
    is_admin_panel: bool = False
    is_staging_env: bool = False
    captured_at: datetime


class SignatureMatchOut(BaseModel):
    id: UUID
    signature_id: UUID
    signature_name: str
    severity: str
    matched_evidence: str | None = None
    matched_at: datetime


class ServiceOut(BaseModel):
    id: UUID
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    missed_scans: int
    first_seen_at: datetime
    last_seen_at: datetime
    latest_http_fingerprint: HTTPFingerprintOut | None = None
    signature_matches: list[SignatureMatchOut] = Field(default_factory=list)
    override: OverrideOut | None = None


class HostSummaryOut(BaseModel):
    id: UUID
    ip_address: str
    hostname: str | None = None
    status: str
    missed_scans: int
    open_services_count: int
    is_admin_panel: bool = False
    is_staging_env: bool = False
    technologies: list[str] = Field(default_factory=list)
    signature_matches_count: int = 0
    highest_severity: str = "info"
    priority_score: int = 0
    first_seen_at: datetime
    last_seen_at: datetime
    override: OverrideOut | None = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def serialize_ip(cls, v: Any) -> str:
        return _coerce_ip_to_str(v) or ""


class HostDetailOut(BaseModel):
    id: UUID
    ip_address: str
    hostname: str | None = None
    status: str
    missed_scans: int
    first_seen_at: datetime
    last_seen_at: datetime
    last_scan_run_id: UUID | None = None
    override: OverrideOut | None = None
    services: list[ServiceOut] = Field(default_factory=list)

    @field_validator("ip_address", mode="before")
    @classmethod
    def serialize_ip(cls, v: Any) -> str:
        return _coerce_ip_to_str(v) or ""


class ChangeEventOut(BaseModel):
    id: UUID
    scan_run_id: UUID
    host_id: UUID
    host_ip: str | None = None
    service_id: UUID | None = None
    service_port: int | None = None
    service_protocol: str | None = None
    change_type: str
    severity: str
    previous_value: dict[str, Any] | None = None
    current_value: dict[str, Any] | None = None
    acknowledged: bool
    detected_at: datetime

    @field_validator("host_ip", mode="before")
    @classmethod
    def serialize_host_ip(cls, v: Any) -> str | None:
        return _coerce_ip_to_str(v)
