"""
Serwis automatycznych grup zasobów (Auto-Groups & Smart Groups):
  - dynamiczne rozwiązywanie hostów na podstawie reguł (technologie/CMS, porty, usługi, produkty,
    sygnatury pasywne, favicon MMH3, flagi admin/staging, status, owner_unit, tagi, zakres CIDR),
  - automatyczne odkrywanie gotowych grup na żywo (zero-config) z aktualnego stanu bazy,
  - przygotowanie listy IP i dopasowanych portów dla celowanego skanowania oraz harmonogramów.
"""

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session, selectinload

from app.db.models import AssetOverride, CustomSignature, Host, Service, SignatureMatch
from app.services.queries import fetch_latest_http_fingerprints

HostStatusLiteral = Literal["online", "unstable", "offline", "archived"]
AutoGroupCategory = Literal["technology", "port", "classification", "signature", "override"]


class GroupFilterRules(BaseModel):
    match_mode: Literal["all", "any"] = "all"
    technologies: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    service_names: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    signature_ids: list[UUID] = Field(default_factory=list)
    favicon_hashes: list[str] = Field(default_factory=list)
    is_admin_panel: bool | None = None
    is_staging_env: bool | None = None
    statuses: list[HostStatusLiteral] = Field(default_factory=lambda: ["online", "unstable"])
    owner_units: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    cidr_scope: str | None = None
    exclude_ignored: bool = True

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: list[int]) -> list[int]:
        cleaned: list[int] = []
        for p in v:
            pi = int(p)
            if not (1 <= pi <= 65535):
                raise ValueError(f"Numer portu poza zakresem 1-65535: {pi}")
            if pi not in cleaned:
                cleaned.append(pi)
        return sorted(cleaned)

    @field_validator("technologies", "service_names", "products", "favicon_hashes", "owner_units", "tags")
    @classmethod
    def clean_str_lists(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in v:
            s = str(item or "").strip()
            if s and s.lower() not in seen:
                seen.add(s.lower())
                out.append(s)
        return out

    @field_validator("cidr_scope")
    @classmethod
    def validate_cidr_scope(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        net = ipaddress.ip_network(str(v).strip(), strict=False)
        return str(net)


def parse_filter_rules(raw: GroupFilterRules | dict[str, Any] | None) -> GroupFilterRules:
    if isinstance(raw, GroupFilterRules):
        return raw
    return GroupFilterRules.model_validate(raw or {})


def serialize_filter_rules(rules: GroupFilterRules) -> dict[str, Any]:
    return rules.model_dump(mode="json")


def _load_candidate_hosts(
    db: Session,
    statuses: list[str] | None,
    cidr_scope: str | None,
    scope: Any = None,
) -> tuple[list[Host], dict[UUID, Any], dict[UUID, AssetOverride]]:
    stmt = (
        select(Host)
        .options(
            selectinload(Host.services)
            .selectinload(Service.signature_matches)
            .selectinload(SignatureMatch.signature)
        )
        .order_by(Host.ip_address)
    )
    if statuses:
        stmt = stmt.where(Host.status.in_(statuses))
    else:
        stmt = stmt.where(Host.status != "archived")

    if cidr_scope:
        stmt = stmt.where(Host.ip_address.op("<<=")(cast(cidr_scope, CIDR)))

    if scope is not None:
        scope_flt = scope.sql_host_filter()
        if scope_flt is not None:
            stmt = stmt.where(scope_flt)

    hosts = db.execute(stmt).scalars().all()
    if not hosts:
        return [], {}, {}

    host_ids = [h.id for h in hosts]
    open_svc_ids = [s.id for h in hosts for s in h.services if s.state == "open"]
    latest_fp_map = fetch_latest_http_fingerprints(db, open_svc_ids)

    ov_rows = db.execute(
        select(AssetOverride).where(
            AssetOverride.entity_type == "host",
            AssetOverride.entity_id.in_(host_ids),
        )
    ).scalars().all()
    ov_map = {ov.entity_id: ov for ov in ov_rows}
    return hosts, latest_fp_map, ov_map


def resolve_hosts_by_rules(
    db: Session,
    raw_rules: GroupFilterRules | dict[str, Any] | None,
    *,
    limit: int = 2000,
    scope: Any = None,
) -> dict[str, Any]:
    """
    Rozwiązuje dynamiczną listę hostów spełniających reguły `filter_rules`
    wraz ze zbiorem dopasowanych portów dla szybkiego skanu celowanego.
    """
    rules = parse_filter_rules(raw_rules)
    hosts, latest_fp_map, ov_map = _load_candidate_hosts(db, rules.statuses, rules.cidr_scope, scope=scope)

    tech_needles = [t.lower() for t in rules.technologies]
    port_set = set(rules.ports)
    svc_name_set = {s.lower() for s in rules.service_names}
    product_needles = [p.lower() for p in rules.products]
    sig_id_set = set(rules.signature_ids)
    fav_set = set(rules.favicon_hashes)
    unit_set = {u.lower() for u in rules.owner_units}
    tag_set = {t.lower() for t in rules.tags}

    matched_hosts_out: list[dict[str, Any]] = []
    global_matched_ports: set[int] = set()

    for h in hosts:
        ov = ov_map.get(h.id)
        if rules.exclude_ignored and ov and ov.is_ignored:
            continue

        open_services = [s for s in h.services if s.state == "open"] if h.status not in ("offline", "archived") else []
        open_ports = sorted({s.port for s in open_services})

        host_techs: set[str] = set()
        host_is_admin = False
        host_is_staging = False
        host_sig_ids: set[UUID] = set()
        host_favicons: set[str] = set()

        # Śledzenie portów, które spełniły poszczególne warunki usługowe
        ports_by_tech: set[int] = set()
        ports_by_port: set[int] = set()
        ports_by_svc_name: set[int] = set()
        ports_by_product: set[int] = set()
        ports_by_sig: set[int] = set()
        ports_by_fav: set[int] = set()
        ports_by_admin: set[int] = set()
        ports_by_staging: set[int] = set()

        for svc in open_services:
            fp = latest_fp_map.get(svc.id)
            svc_prod_banner = f"{svc.product or ''} {svc.banner or ''}".lower()

            if svc.port in port_set:
                ports_by_port.add(svc.port)
            if svc_name_set and (svc.service_name or "").strip().lower() in svc_name_set:
                ports_by_svc_name.add(svc.port)
            if product_needles and any(pn in svc_prod_banner for pn in product_needles):
                ports_by_product.add(svc.port)

            svc_techs_lower: list[str] = []
            if fp:
                for t in fp.technologies or []:
                    if t:
                        ts = str(t)
                        host_techs.add(ts)
                        svc_techs_lower.append(ts.lower())
                if fp.is_admin_panel:
                    host_is_admin = True
                    ports_by_admin.add(svc.port)
                if fp.is_staging_env:
                    host_is_staging = True
                    ports_by_staging.add(svc.port)
                if fp.favicon_mmh3_hash:
                    host_favicons.add(str(fp.favicon_mmh3_hash))
                    if str(fp.favicon_mmh3_hash) in fav_set:
                        ports_by_fav.add(svc.port)

            if tech_needles:
                if any(
                    any(tn in st for st in svc_techs_lower) or tn in svc_prod_banner
                    for tn in tech_needles
                ):
                    ports_by_tech.add(svc.port)

            for m in svc.signature_matches:
                if m.signature and m.signature.is_enabled:
                    host_sig_ids.add(m.signature_id)
                    if m.signature_id in sig_id_set:
                        ports_by_sig.add(svc.port)

        predicates: list[bool] = []
        matched_service_ports: set[int] = set()

        if tech_needles:
            ok = bool(ports_by_tech)
            predicates.append(ok)
            if ok:
                matched_service_ports.update(ports_by_tech)
        if port_set:
            ok = bool(ports_by_port)
            predicates.append(ok)
            if ok:
                matched_service_ports.update(ports_by_port)
        if svc_name_set:
            ok = bool(ports_by_svc_name)
            predicates.append(ok)
            if ok:
                matched_service_ports.update(ports_by_svc_name)
        if product_needles:
            ok = bool(ports_by_product)
            predicates.append(ok)
            if ok:
                matched_service_ports.update(ports_by_product)
        if sig_id_set:
            ok = bool(ports_by_sig)
            predicates.append(ok)
            if ok:
                matched_service_ports.update(ports_by_sig)
        if fav_set:
            ok = bool(ports_by_fav)
            predicates.append(ok)
            if ok:
                matched_service_ports.update(ports_by_fav)
        if rules.is_admin_panel is not None:
            ok = host_is_admin == rules.is_admin_panel
            predicates.append(ok)
            if ok and rules.is_admin_panel:
                matched_service_ports.update(ports_by_admin)
        if rules.is_staging_env is not None:
            ok = host_is_staging == rules.is_staging_env
            predicates.append(ok)
            if ok and rules.is_staging_env:
                matched_service_ports.update(ports_by_staging)
        if unit_set:
            ov_unit = (ov.owner_unit or "").strip().lower() if ov else ""
            predicates.append(ov_unit in unit_set)
        if tag_set:
            ov_tags = {str(t).strip().lower() for t in (ov.tags or [])} if ov else set()
            predicates.append(bool(ov_tags & tag_set))

        if predicates:
            matched = all(predicates) if rules.match_mode == "all" else any(predicates)
        else:
            matched = True

        if not matched:
            continue

        eff_ports = sorted(matched_service_ports) if matched_service_ports else open_ports
        global_matched_ports.update(eff_ports)

        ip_str = str(h.ip_address).split("/")[0]
        matched_hosts_out.append(
            {
                "id": str(h.id),
                "ip_address": ip_str,
                "hostname": h.hostname,
                "status": h.status,
                "missed_scans": h.missed_scans,
                "open_ports": open_ports,
                "matched_ports": eff_ports,
                "technologies": sorted(host_techs),
                "is_admin_panel": host_is_admin,
                "is_staging_env": host_is_staging,
                "custom_label": ov.custom_label if ov else None,
                "owner_unit": ov.owner_unit if ov else None,
                "tags": list(ov.tags or []) if ov else [],
            }
        )

    sorted_global_ports = sorted(global_matched_ports)
    suggested_ports_spec = (
        ",".join(str(p) for p in sorted_global_ports[:100])
        if sorted_global_ports
        else None
    )

    return {
        "total_hosts": len(matched_hosts_out),
        "host_ids": [h["id"] for h in matched_hosts_out],
        "ips": [h["ip_address"] for h in matched_hosts_out],
        "matched_ports": sorted_global_ports,
        "suggested_ports_spec": suggested_ports_spec,
        "hosts": matched_hosts_out[:limit],
        "truncated": len(matched_hosts_out) > limit,
    }


def discover_auto_groups(db: Session, *, scope: Any = None) -> dict[str, Any]:
    """
    Wylicza na żywo gotowe grupy automatyczne (zero-config) na podstawie aktualnych zasobów w DB:
      - Technologie / CMS (np. WordPress, PHP, nginx, LegacyCMS...)
      - Otwarte porty (np. Port 80, Port 443, Port 8080...)
      - Klasyfikacja (Panele administracyjne, Staging/Dev, Niestabilne, Offline)
      - Dopasowane sygnatury pasywne
      - Jednostki organizacyjne (owner_unit) i tagi z asset_overrides
    Zwraca też słownik `facets` do podpowiedzi w kreatorze Smart Groups.
    """
    hosts, latest_fp_map, ov_map = _load_candidate_hosts(db, None, None, scope=scope)

    tech_hosts: dict[str, dict[str, Any]] = {}
    port_hosts: dict[int, dict[str, Any]] = {}
    sig_hosts: dict[UUID, dict[str, Any]] = {}
    unit_hosts: dict[str, dict[str, Any]] = {}
    tag_hosts: dict[str, dict[str, Any]] = {}

    admin_bucket = {"hosts": {}, "ports": set()}
    staging_bucket = {"hosts": {}, "ports": set()}
    unstable_bucket = {"hosts": {}, "ports": set()}
    offline_bucket = {"hosts": {}, "ports": set()}

    facet_service_names: set[str] = set()
    facet_products: set[str] = set()
    facet_favicons: dict[str, int] = defaultdict(int)

    for h in hosts:
        ov = ov_map.get(h.id)
        if ov and ov.is_ignored:
            continue

        ip_str = str(h.ip_address).split("/")[0]
        hid = str(h.id)
        host_entry = {"id": hid, "ip": ip_str, "hostname": h.hostname}

        if h.status == "offline":
            offline_bucket["hosts"][hid] = host_entry
            continue
        if h.status == "unstable":
            unstable_bucket["hosts"][hid] = host_entry

        open_services = [s for s in h.services if s.state == "open"]
        for s in open_services:
            if h.status == "unstable":
                unstable_bucket["ports"].add(s.port)

        if ov:
            if ov.owner_unit and ov.owner_unit.strip():
                u_val = ov.owner_unit.strip()
                b = unit_hosts.setdefault(u_val, {"hosts": {}, "ports": set()})
                b["hosts"][hid] = host_entry
                for s in open_services:
                    b["ports"].add(s.port)
            for t in ov.tags or []:
                ts = str(t).strip()
                if ts:
                    b = tag_hosts.setdefault(ts, {"hosts": {}, "ports": set()})
                    b["hosts"][hid] = host_entry
                    for s in open_services:
                        b["ports"].add(s.port)

        for svc in open_services:
            if svc.service_name:
                facet_service_names.add(svc.service_name.strip())
            if svc.product:
                facet_products.add(svc.product.strip())

            pb = port_hosts.setdefault(
                svc.port,
                {"hosts": {}, "ports": {svc.port}, "protocols": set(), "service_names": set()},
            )
            pb["hosts"][hid] = host_entry
            pb["protocols"].add(svc.protocol)
            if svc.service_name:
                pb["service_names"].add(svc.service_name)

            fp = latest_fp_map.get(svc.id)
            if fp:
                if fp.favicon_mmh3_hash:
                    facet_favicons[str(fp.favicon_mmh3_hash)] += 1
                if fp.is_admin_panel:
                    admin_bucket["hosts"][hid] = host_entry
                    admin_bucket["ports"].add(svc.port)
                if fp.is_staging_env:
                    staging_bucket["hosts"][hid] = host_entry
                    staging_bucket["ports"].add(svc.port)
                for tech in fp.technologies or []:
                    ts = str(tech).strip()
                    if not ts:
                        continue
                    tb = tech_hosts.setdefault(ts, {"hosts": {}, "ports": set()})
                    tb["hosts"][hid] = host_entry
                    tb["ports"].add(svc.port)

            for m in svc.signature_matches:
                if m.signature and m.signature.is_enabled:
                    sb = sig_hosts.setdefault(
                        m.signature_id,
                        {
                            "name": m.signature.name,
                            "severity": m.signature.severity,
                            "hosts": {},
                            "ports": set(),
                        },
                    )
                    sb["hosts"][hid] = host_entry
                    sb["ports"].add(svc.port)

    groups: list[dict[str, Any]] = []

    def _pack_group(
        *,
        key: str,
        category: AutoGroupCategory,
        label: str,
        description: str,
        hosts_map: dict[str, dict[str, Any]],
        ports_set: set[int],
        filter_rules: GroupFilterRules,
    ) -> None:
        if not hosts_map:
            return
        entries = sorted(hosts_map.values(), key=lambda x: x["ip"])
        sorted_ports = sorted(ports_set)
        groups.append(
            {
                "key": key,
                "category": category,
                "label": label,
                "description": description,
                "host_count": len(entries),
                "host_ids": [e["id"] for e in entries],
                "sample_ips": [e["ip"] for e in entries[:8]],
                "matched_ports": sorted_ports,
                "suggested_ports_spec": ",".join(str(p) for p in sorted_ports[:100]) if sorted_ports else None,
                "filter_rules": serialize_filter_rules(filter_rules),
            }
        )

    # 1. Technologie / CMS
    for tech, data in sorted(tech_hosts.items(), key=lambda kv: (-len(kv[1]["hosts"]), kv[0].lower())):
        _pack_group(
            key=f"tech:{tech.lower()}",
            category="technology",
            label=tech,
            description=f"Wszystkie aktywne hosty z wykrytą technologią / CMS '{tech}'",
            hosts_map=data["hosts"],
            ports_set=data["ports"],
            filter_rules=GroupFilterRules(technologies=[tech]),
        )

    # 2. Otwarte porty
    for port_num, data in sorted(port_hosts.items(), key=lambda kv: (-len(kv[1]["hosts"]), kv[0])):
        svc_hint = ", ".join(sorted(data["service_names"])[:3])
        proto_hint = "/".join(sorted(data["protocols"]))
        _pack_group(
            key=f"port:{port_num}",
            category="port",
            label=f"Port {port_num}/{proto_hint}" + (f" ({svc_hint})" if svc_hint else ""),
            description=f"Wszystkie aktywne hosty z otwartym portem {port_num}",
            hosts_map=data["hosts"],
            ports_set={port_num},
            filter_rules=GroupFilterRules(ports=[port_num]),
        )

    # 3. Kategorie ryzyka / statusy
    _pack_group(
        key="class:admin_panel",
        category="classification",
        label="Panele administracyjne",
        description="Hosty z wykrytym panelem administracyjnym lub ekranem logowania",
        hosts_map=admin_bucket["hosts"],
        ports_set=admin_bucket["ports"],
        filter_rules=GroupFilterRules(is_admin_panel=True),
    )
    _pack_group(
        key="class:staging_env",
        category="classification",
        label="Środowiska Staging / Dev",
        description="Hosty sklasyfikowane jako środowiska testowe, UAT lub staging",
        hosts_map=staging_bucket["hosts"],
        ports_set=staging_bucket["ports"],
        filter_rules=GroupFilterRules(is_staging_env=True),
    )
    _pack_group(
        key="class:unstable",
        category="classification",
        label="Hosty niestabilne (unstable)",
        description="Hosty z 1 <= missed_scans < próg — kandydaci do celowanego re-probe",
        hosts_map=unstable_bucket["hosts"],
        ports_set=unstable_bucket["ports"],
        filter_rules=GroupFilterRules(statuses=["unstable"]),
    )
    _pack_group(
        key="class:offline",
        category="classification",
        label="Hosty offline",
        description="Hosty oznaczone jako offline — do okresowego sprawdzenia powrotu do sieci",
        hosts_map=offline_bucket["hosts"],
        ports_set=set(),
        filter_rules=GroupFilterRules(statuses=["offline"]),
    )

    # 4. Dopasowane sygnatury pasywne
    for sig_id, data in sorted(sig_hosts.items(), key=lambda kv: (-len(kv[1]["hosts"]), kv[1]["name"].lower())):
        _pack_group(
            key=f"sig:{sig_id}",
            category="signature",
            label=f"Sygnatura: {data['name']}",
            description=f"Hosty z aktywnym trafieniem sygnatury pasywnej ({data['severity'].upper()})",
            hosts_map=data["hosts"],
            ports_set=data["ports"],
            filter_rules=GroupFilterRules(signature_ids=[sig_id]),
        )

    # 5. Jednostki właściciela (owner_unit) i tagi z asset_overrides
    for unit_name, data in sorted(unit_hosts.items(), key=lambda kv: (-len(kv[1]["hosts"]), kv[0].lower())):
        _pack_group(
            key=f"unit:{unit_name.lower()}",
            category="override",
            label=f"Jednostka: {unit_name}",
            description=f"Hosty przypisane do jednostki / wydziału '{unit_name}' w asset_overrides",
            hosts_map=data["hosts"],
            ports_set=data["ports"],
            filter_rules=GroupFilterRules(owner_units=[unit_name]),
        )
    for tag_name, data in sorted(tag_hosts.items(), key=lambda kv: (-len(kv[1]["hosts"]), kv[0].lower())):
        _pack_group(
            key=f"tag:{tag_name.lower()}",
            category="override",
            label=f"Tag: #{tag_name}",
            description=f"Hosty oznaczone tagiem '{tag_name}' w asset_overrides",
            hosts_map=data["hosts"],
            ports_set=data["ports"],
            filter_rules=GroupFilterRules(tags=[tag_name]),
        )

    all_enabled_sigs = db.execute(
        select(CustomSignature).where(CustomSignature.is_enabled.is_(True)).order_by(CustomSignature.name)
    ).scalars().all()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_auto_groups": len(groups),
        "facets": {
            "technologies": sorted(tech_hosts.keys(), key=lambda s: (-len(tech_hosts[s]["hosts"]), s.lower())),
            "ports": sorted(port_hosts.keys()),
            "service_names": sorted(facet_service_names, key=str.lower),
            "products": sorted(facet_products, key=str.lower),
            "owner_units": sorted(unit_hosts.keys(), key=str.lower),
            "tags": sorted(tag_hosts.keys(), key=str.lower),
            "favicons": [k for k, _ in sorted(facet_favicons.items(), key=lambda kv: (-kv[1], kv[0]))[:20]],
            "signatures": [
                {"id": str(s.id), "name": s.name, "severity": s.severity}
                for s in all_enabled_sigs
            ],
        },
        "groups": groups,
    }
