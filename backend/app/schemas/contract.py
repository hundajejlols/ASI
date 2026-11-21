"""
Wspólny kontrakt danych (Pydantic v2) zgodny z shared/contracts/*.schema.json
oraz scanner/internal/contract/types.go.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, Field


# --- Zadanie (Backend -> Redis -> Scanner) ---

class ScanProfilePayload(BaseModel):
    nmap_flags: str = "-sT -sV --version-light -T3"
    ports: str = "80,443,8080,8443,22"
    rate_limit_pps: int = Field(default=300, ge=1)
    http_fingerprint_enabled: bool = True
    signatures_enabled: bool = True


class SignatureRulePayload(BaseModel):
    id: UUID
    name: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    match_type: Literal[
        "header",
        "cookie",
        "favicon_hash",
        "html_fragment",
        "path_probe",
        "footer_version",
    ]
    pattern: str
    probe_path: str | None = None
    expected_status: int | None = None


class ScanJobChunk(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_run_id: UUID
    chunk_id: UUID
    target_cidr: str
    window_deadline_utc: datetime
    profile: ScanProfilePayload
    signatures: list[SignatureRulePayload] = Field(default_factory=list)


# --- Wynik (Scanner -> Backend) ---

class TLSInfo(BaseModel):
    subject: str
    issuer: str
    not_after: datetime
    san: list[str] = Field(default_factory=list)
    is_self_signed: bool = False


class HTTPFingerprintResult(BaseModel):
    url: str
    scheme: Literal["http", "https"]
    status_code: int
    response_time_ms: int | None = None
    probe_error: str | None = None
    title: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[str] = Field(default_factory=list)
    favicon_mmh3_hash: str | None = None
    tls: TLSInfo | None = None
    technologies: list[str] = Field(default_factory=list)
    tech_confidence: dict[str, str] = Field(default_factory=dict)
    is_admin_panel: bool = False
    is_staging_env: bool = False


class SignatureMatchResult(BaseModel):
    signature_id: UUID
    signature_name: str
    evidence: str


class ServiceResult(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: Literal["open", "filtered", "closed"] = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    http: HTTPFingerprintResult | None = None
    signature_matches: list[SignatureMatchResult] = Field(default_factory=list)


class HostResult(BaseModel):
    ip: str
    hostname: str | None = None
    is_up: bool
    services: list[ServiceResult] = Field(default_factory=list)


class ScanChunkResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_run_id: UUID
    chunk_id: UUID
    worker_id: str
    status: Literal["completed", "requeued_window", "failed"]
    error_message: str | None = None
    started_at: datetime
    finished_at: datetime
    hosts: list[HostResult] = Field(default_factory=list)
