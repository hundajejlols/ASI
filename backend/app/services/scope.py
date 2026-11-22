"""
Serwis kontroli widoczności i zakresu zasobów per konto użytkownika (Asset Scope / ABAC):
  - pozwala przypisać kontu dowolną kombinację:
      * grup (statycznych target_groups oraz dynamicznych Smart Groups),
      * pojedynczych adresów IP (IPv4/IPv6),
      * podsieci CIDR (np. 172.28.0.0/28),
      * zakresów IP start-koniec (np. 172.28.0.10-172.28.0.20),
      * konkretnych odkrytych hostów (host_ids).
  - dostarcza wspólne filtry SQL (sql_host_filter) oraz strażniki dostępu (assert_host_allowed,
    assert_ip_allowed, assert_targets_allowed) używane we wszystkich endpointach API.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import ColumnElement, cast, false, func, or_, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from app.core.security import Principal
from app.db.models import Host, Target, TargetGroup

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_ip_range(raw: str) -> tuple[IPAddress, IPAddress, str]:
    """Parsuje i waliduje zakres IP w formacie 'start-end' (np. '172.28.0.10-172.28.0.20')."""
    text_val = str(raw or "").strip()
    if "-" not in text_val:
        raise ValueError(f"Zakres IP musi mieć format 'start-koniec' (np. 172.28.0.10-172.28.0.20): {raw!r}")
    parts = [p.strip() for p in text_val.split("-", 1)]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Nieprawidłowy zakres IP: {raw!r}")
    start_ip = ipaddress.ip_address(parts[0])
    end_ip = ipaddress.ip_address(parts[1])
    if start_ip.version != end_ip.version:
        raise ValueError(f"Zakres IP musi mieć spójną wersję IPv4/IPv6: {raw!r}")
    if int(start_ip) > int(end_ip):
        raise ValueError(f"Początek zakresu IP nie może być większy od końca: {raw!r}")
    return start_ip, end_ip, f"{start_ip}-{end_ip}"


class UserScopeConfig(BaseModel):
    ips: list[str] = Field(default_factory=list, description="Dozwolone pojedyncze adresy IP (IPv4/IPv6)")
    cidrs: list[str] = Field(default_factory=list, description="Dozwolone podsieci CIDR (np. 172.28.0.0/28)")
    ip_ranges: list[str] = Field(default_factory=list, description="Dozwolone zakresy IP 'start-koniec'")
    group_ids: list[UUID] = Field(default_factory=list, description="Przypisane grupy (Static / Smart Groups)")
    host_ids: list[UUID] = Field(default_factory=list, description="Konkretne przypisane hosty (UUID)")

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in v:
            s = str(item or "").strip()
            if not s:
                continue
            try:
                norm = str(ipaddress.ip_address(s))
            except ValueError as exc:
                raise ValueError(f"Nieprawidłowy adres IP w zakresie konta: {s!r}") from exc
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        return out

    @field_validator("cidrs")
    @classmethod
    def validate_cidrs(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in v:
            s = str(item or "").strip()
            if not s:
                continue
            try:
                norm = str(ipaddress.ip_network(s, strict=False))
            except ValueError as exc:
                raise ValueError(f"Nieprawidłowa podsieć CIDR w zakresie konta: {s!r}") from exc
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        return out

    @field_validator("ip_ranges")
    @classmethod
    def validate_ip_ranges(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in v:
            s = str(item or "").strip()
            if not s:
                continue
            _, _, norm = parse_ip_range(s)
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        return out

    @field_validator("group_ids", "host_ids")
    @classmethod
    def dedup_uuids(cls, v: list[UUID]) -> list[UUID]:
        out: list[UUID] = []
        seen: set[UUID] = set()
        for u in v:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out


def parse_user_scope(raw: UserScopeConfig | dict[str, Any] | None) -> UserScopeConfig:
    if isinstance(raw, UserScopeConfig):
        return raw
    return UserScopeConfig.model_validate(raw or {})


def serialize_user_scope(cfg: UserScopeConfig) -> dict[str, Any]:
    return cfg.model_dump(mode="json")


@dataclass(frozen=True)
class ResolvedScope:
    restricted: bool
    allowed_networks: tuple[IPNetwork, ...] = ()
    allowed_host_ids: frozenset[UUID] = frozenset()
    allowed_group_ids: frozenset[UUID] = frozenset()
    allowed_domains: frozenset[str] = frozenset()

    @property
    def is_empty(self) -> bool:
        return self.restricted and not self.allowed_networks and not self.allowed_host_ids

    def sql_host_filter(self) -> ColumnElement[bool] | None:
        """
        Zwraca warunek SQLAlchemy na tabeli Host, albo None gdy konto ma pełny dostęp.
        Gdy zakres jest ograniczony i pusty, zwraca SQL `FALSE` (fail-closed).
        """
        if not self.restricted:
            return None
        clauses: list[ColumnElement[bool]] = []
        if self.allowed_host_ids:
            clauses.append(Host.id.in_(self.allowed_host_ids))
        for net in self.allowed_networks:
            clauses.append(Host.ip_address.op("<<=")(cast(str(net), CIDR)))
        if not clauses:
            return false()
        if len(clauses) == 1:
            return clauses[0]
        return or_(*clauses)

    def is_network_covered(self, target_net: IPNetwork) -> bool:
        """Sprawdza, czy KAŻDY adres IP w target_net mieści się w sumie dozwolonych sieci."""
        if not self.restricted:
            return True
        if not self.allowed_networks:
            return False
        remaining: list[IPNetwork] = [target_net]
        for allowed in self.allowed_networks:
            if allowed.version != target_net.version:
                continue
            next_remaining: list[IPNetwork] = []
            for piece in remaining:
                if piece.subnet_of(allowed):
                    continue
                if allowed.subnet_of(piece):
                    next_remaining.extend(piece.address_exclude(allowed))
                else:
                    next_remaining.append(piece)
            remaining = next_remaining
            if not remaining:
                return True
        return not remaining

    def is_ip_allowed(self, ip_str: str) -> bool:
        if not self.restricted:
            return True
        try:
            ip_obj = ipaddress.ip_address(str(ip_str).split("/")[0].strip())
        except ValueError:
            return False
        for net in self.allowed_networks:
            if net.version == ip_obj.version and ip_obj in net:
                return True
        return False

    def is_host_allowed(self, host: Host) -> bool:
        if not self.restricted:
            return True
        if host.id in self.allowed_host_ids:
            return True
        return self.is_ip_allowed(str(host.ip_address))

    def is_target_allowed(self, raw_value: str, target_type: str) -> bool:
        if not self.restricted:
            return True
        if target_type == "ip":
            return self.is_ip_allowed(raw_value)
        if target_type == "cidr":
            try:
                net = ipaddress.ip_network(raw_value.strip(), strict=False)
            except ValueError:
                return False
            return self.is_network_covered(net)
        if target_type == "domain":
            return raw_value.strip().lower() in self.allowed_domains
        return False

    def assert_host_allowed(self, host: Host) -> None:
        if not self.is_host_allowed(host):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Brak dostępu do hosta spoza przypisanego zakresu konta.",
            )

    def assert_ip_allowed(self, ip_str: str) -> None:
        if not self.is_ip_allowed(ip_str):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Adres IP '{ip_str}' znajduje się poza przypisanym zakresem konta.",
            )

    def assert_targets_allowed(self, typed_targets: list[tuple[str, str]]) -> None:
        if not self.restricted:
            return
        disallowed = [val for val, ttype in typed_targets if not self.is_target_allowed(val, ttype)]
        if disallowed:
            preview = ", ".join(disallowed[:3])
            extra = f" (+{len(disallowed) - 3} więcej)" if len(disallowed) > 3 else ""
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cele poza przypisanym zakresem konta: {preview}{extra}.",
            )


def _collapse_mixed_networks(nets: list[IPNetwork]) -> tuple[IPNetwork, ...]:
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
    collapsed: list[IPNetwork] = []
    if v4:
        collapsed.extend(ipaddress.collapse_addresses(v4))
    if v6:
        collapsed.extend(ipaddress.collapse_addresses(v6))
    return tuple(collapsed)


def resolve_scope_config(
    db: Session,
    *,
    scope_restricted: bool,
    raw_scope: UserScopeConfig | dict[str, Any] | None,
) -> ResolvedScope:
    """Rozwiązuje konfigurację zakresu użytkownika na zwinięte sieci IP/CIDR + zbiór host_ids."""
    if not scope_restricted:
        return ResolvedScope(restricted=False)

    try:
        cfg = parse_user_scope(raw_scope)
    except Exception:
        # Fail-closed przy uszkodzonej konfiguracji zakresu w DB
        return ResolvedScope(restricted=True)

    nets: list[IPNetwork] = []
    host_ids: set[UUID] = set(cfg.host_ids)
    group_ids: frozenset[UUID] = frozenset(cfg.group_ids)
    domains: set[str] = set()

    for ip_str in cfg.ips:
        ip_obj = ipaddress.ip_address(ip_str)
        nets.append(ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False))

    for cidr_str in cfg.cidrs:
        nets.append(ipaddress.ip_network(cidr_str, strict=False))

    for range_str in cfg.ip_ranges:
        start_ip, end_ip, _ = parse_ip_range(range_str)
        nets.extend(ipaddress.summarize_address_range(start_ip, end_ip))

    # Dołącz adresy IP jawnie przypisanych hostów (aby is_ip_allowed / skan celowany działały spójnie)
    if cfg.host_ids:
        explicit_ips = db.execute(
            select(Host.ip_address).where(Host.id.in_(cfg.host_ids))
        ).scalars().all()
        for ip_val in explicit_ips:
            try:
                ip_obj = ipaddress.ip_address(str(ip_val).split("/")[0])
                nets.append(ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False))
            except ValueError:
                pass

    # Rozwiąż przypisane grupy (statyczne i dynamiczne Smart Groups)
    if cfg.group_ids:
        from app.services.groups import resolve_hosts_by_rules

        groups = db.execute(
            select(TargetGroup).where(TargetGroup.id.in_(cfg.group_ids))
        ).scalars().all()
        static_group_ids: list[UUID] = []
        for grp in groups:
            if grp.group_type == "dynamic":
                resolved = resolve_hosts_by_rules(db, grp.filter_rules, limit=10000)
                for hid_str in resolved.get("host_ids", []):
                    try:
                        host_ids.add(UUID(hid_str))
                    except ValueError:
                        pass
                for ip_str in resolved.get("ips", []):
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        nets.append(ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False))
                    except ValueError:
                        pass
            else:
                static_group_ids.append(grp.id)

        if static_group_ids:
            targets = db.execute(
                select(Target).where(
                    Target.group_id.in_(static_group_ids),
                    Target.is_active.is_(True),
                )
            ).scalars().all()
            for t in targets:
                if t.type == "ip":
                    try:
                        ip_obj = ipaddress.ip_address(t.raw_value.strip())
                        nets.append(ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False))
                    except ValueError:
                        pass
                elif t.type == "cidr":
                    try:
                        nets.append(ipaddress.ip_network(t.raw_value.strip(), strict=False))
                    except ValueError:
                        pass
                elif t.type == "domain":
                    domains.add(t.raw_value.strip().lower())

    return ResolvedScope(
        restricted=True,
        allowed_networks=_collapse_mixed_networks(nets),
        allowed_host_ids=frozenset(host_ids),
        allowed_group_ids=group_ids,
        allowed_domains=frozenset(domains),
    )


def resolve_principal_scope(db: Session, principal: Principal) -> ResolvedScope:
    return resolve_scope_config(
        db,
        scope_restricted=principal.scope_restricted,
        raw_scope=principal.allowed_scope,
    )


def summarize_user_scope(
    db: Session,
    *,
    scope_restricted: bool,
    raw_scope: UserScopeConfig | dict[str, Any] | None,
) -> dict[str, Any]:
    """Zwraca czytelne podsumowanie zakresu konta wraz z liczbą pasujących hostów w DB."""
    try:
        cfg = parse_user_scope(raw_scope)
    except Exception:
        cfg = UserScopeConfig()

    if not scope_restricted:
        total_hosts = int(db.execute(select(func.count(Host.id))).scalar_one())
        return {
            "restricted": False,
            "matched_hosts_count": total_hosts,
            "sample_ips": [],
            "ips_count": 0,
            "cidrs_count": 0,
            "ip_ranges_count": 0,
            "group_ids_count": 0,
            "host_ids_count": 0,
            "group_names": [],
        }

    resolved = resolve_scope_config(db, scope_restricted=True, raw_scope=cfg)
    flt = resolved.sql_host_filter()
    matched_count = int(db.execute(select(func.count(Host.id)).where(flt)).scalar_one()) if flt is not None else 0
    sample_rows = (
        db.execute(select(Host.ip_address).where(flt).order_by(Host.ip_address).limit(12)).scalars().all()
        if flt is not None and matched_count > 0
        else []
    )
    group_names: list[str] = []
    if cfg.group_ids:
        group_names = list(
            db.execute(
                select(TargetGroup.name).where(TargetGroup.id.in_(cfg.group_ids)).order_by(TargetGroup.name)
            ).scalars().all()
        )

    return {
        "restricted": True,
        "matched_hosts_count": matched_count,
        "sample_ips": [str(ip).split("/")[0] for ip in sample_rows],
        "ips_count": len(cfg.ips),
        "cidrs_count": len(cfg.cidrs),
        "ip_ranges_count": len(cfg.ip_ranges),
        "group_ids_count": len(cfg.group_ids),
        "host_ids_count": len(cfg.host_ids),
        "group_names": group_names,
    }
