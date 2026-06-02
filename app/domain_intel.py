from datetime import UTC, datetime
from typing import Any

import requests
import tldextract

from app.config import RDAP_TIMEOUT


REQUEST_TIMEOUT = RDAP_TIMEOUT
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def registered_domain(domain: str) -> str:
    extracted = _extractor(domain or "")
    value = extracted.registered_domain or domain
    return value.lower().strip(".")


def lookup_domain_intel(domain: str) -> dict[str, Any]:
    target = registered_domain(domain)
    if not target or "." not in target:
        return {
            "source": "RDAP",
            "status": "not_applicable",
            "detail": "Domain age lookup requires a registrable domain.",
            "domain": domain,
        }

    result: dict[str, Any] = {
        "source": "RDAP",
        "status": "unavailable",
        "detail": "RDAP lookup not completed.",
        "domain": target,
        "created_at": None,
        "expires_at": None,
        "updated_at": None,
        "age_days": None,
        "registrar": None,
        "nameservers": [],
        "new_domain": False,
    }

    try:
        response = requests.get(f"https://rdap.org/domain/{target}", timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            result.update({"status": "not_found", "detail": "RDAP did not find this domain."})
            return result
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        result["detail"] = f"RDAP lookup unavailable: {exc.__class__.__name__}."
        return result
    except ValueError:
        result["detail"] = "RDAP returned an unreadable response."
        return result

    events = payload.get("events") or []
    created_at = _event_date(events, {"registration", "registered"})
    expires_at = _event_date(events, {"expiration", "expiry"})
    updated_at = _event_date(events, {"last changed", "last update", "last update of rdap database"})
    age_days = _age_days(created_at)
    registrar = _registrar(payload.get("entities") or [])
    nameservers = sorted(
        {
            str(item.get("ldhName") or item.get("unicodeName") or "").lower()
            for item in payload.get("nameservers") or []
            if item.get("ldhName") or item.get("unicodeName")
        }
    )

    result.update(
        {
            "status": "ok",
            "detail": "RDAP domain registration data was found.",
            "created_at": created_at,
            "expires_at": expires_at,
            "updated_at": updated_at,
            "age_days": age_days,
            "registrar": registrar,
            "nameservers": nameservers,
            "new_domain": age_days is not None and age_days <= 30,
        }
    )
    return result


def _event_date(events: list[dict[str, Any]], names: set[str]) -> str | None:
    for event in events:
        action = str(event.get("eventAction") or "").lower()
        if action in names:
            return event.get("eventDate")
    return None


def _age_days(created_at: str | None) -> int | None:
    if not created_at:
        return None
    try:
        normalized = created_at.replace("Z", "+00:00")
        created = datetime.fromisoformat(normalized)
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - created).days)
    except ValueError:
        return None


def _registrar(entities: list[dict[str, Any]]) -> str | None:
    for entity in entities:
        roles = {str(role).lower() for role in entity.get("roles") or []}
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray") or []
        if len(vcard) < 2:
            continue
        for field in vcard[1]:
            if field and field[0] == "fn" and len(field) >= 4:
                return field[3]
    return None
