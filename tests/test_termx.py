#!/usr/bin/env python3
"""Integrační test Terminologického serveru (TermX, FHIR R4 v1.0.5).

Spouští se proti živému T2 prostředí (gateway + public mirror) a volitelně
proti PROD, pokud jsou v ``.env`` nastavené ``SEZ_PROD_*`` proměnné.

Pokrývá:
  - ``metadata`` (CapabilityStatement) na obou cestách
  - ``ValueSet/$expand`` pro každý ciselník v
    ``tests/test_dokumentace.py:DOCUMENTED_CISELNIKY``
  - ``ValueSet/$validate-code`` PASS i FAIL
  - ``CodeSystem/$lookup``
  - ``ConceptMap/$translate`` (smoke)
  - drift detector: porovnání obsahu ValueSet mezi gateway a public mirrorem

Spuštění:
    python tests/test_termx.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Umožni spuštění bez nutnosti instalace balíčku
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sez_api import SEZAuth, SEZClient, Terminologie  # noqa: E402
from sez_api import config as cfg  # noqa: E402

# Sdílíme katalog dokumentovaných číselníků s ostatními testy
try:
    from tests.test_dokumentace import DOCUMENTED_CISELNIKY  # type: ignore
except Exception:
    DOCUMENTED_CISELNIKY = {
        "stav-zasilky": ["0"],
        "medical-document-type": ["11506-3", "67781-5", "34748-4", "74207-2"],
        "document-category": ["11503-0", "26436-6", "18682-5", "107904-5", "57133-1"],
        "typ-adresata": ["PZS", "PAT"],
        "v3-Confidentiality": ["N", "M"],
        "languages": ["cs", "cs-CZ"],
    }

# Bázová URL pro kanonické ValueSet/CodeSystem URL.
# Pozor: terminologický server publikuje canonical URL pod
# https://ncez.mzcr.cz/terminology/..., NIKOLI pod termit.ncez.mzcr.cz/fhir.
NCEZ_VS_BASE = os.environ.get(
    "TERMX_VS_BASE", "https://ncez.mzcr.cz/terminology/ValueSet"
)
NCEZ_CS_BASE = os.environ.get(
    "TERMX_CS_BASE", "https://ncez.mzcr.cz/terminology/CodeSystem"
)


results: list[tuple[str, str, str]] = []
warnings: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    results.append((name, status, detail))
    icon = "✓" if ok else "✗"
    print(f"  {icon} {name}" + (f"  ({detail})" if detail else ""))
    return ok


def warn(msg: str) -> None:
    warnings.append(msg)
    print(f"  ⚠ {msg}")


def _expansion_codes(data) -> set[str]:
    if not isinstance(data, dict):
        return set()
    contains = (data.get("expansion") or {}).get("contains") or []
    return {c.get("code") for c in contains
            if isinstance(c, dict) and c.get("code") is not None}


def _validate_result_bool(data) -> bool | None:
    """Vrátí ``valueBoolean`` parametru ``result`` z FHIR Parameters."""
    if not isinstance(data, dict):
        return None
    for p in data.get("parameter") or []:
        if isinstance(p, dict) and p.get("name") == "result":
            return bool(p.get("valueBoolean"))
    return None


def _lookup_display(data) -> str | None:
    if not isinstance(data, dict):
        return None
    for p in data.get("parameter") or []:
        if isinstance(p, dict) and p.get("name") == "display":
            return p.get("valueString")
    return None


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None


def run_suite(label: str, term: Terminologie) -> None:
    print(f"\n[{label}] base_url={term.base_url}")

    # 1. metadata (CapabilityStatement)
    try:
        r = term.metadata()
        sc = r.status_code
        data = _safe_json(r) or {}
        ok = sc == 200 and data.get("resourceType") == "CapabilityStatement"
        check(f"{label} metadata → 200 + CapabilityStatement",
              ok, f"status={sc} type={data.get('resourceType')}")
        version = data.get("version") or data.get("fhirVersion") or ""
        if version:
            check(f"{label} metadata version reportováno", True, version)
    except Exception as e:
        check(f"{label} metadata", False, str(e))

    # 2. ValueSet/$expand pro každý dokumentovaný ciselník
    expand_summary: dict[str, set[str]] = {}
    for vs_id, expected_codes in DOCUMENTED_CISELNIKY.items():
        url = f"{NCEZ_VS_BASE}/{vs_id}"
        try:
            r = term.valueset_expand(url=url)
            sc = r.status_code
            if sc != 200:
                check(f"{label} {vs_id} $expand → 200",
                      False, f"status={sc}")
                continue
            data = r.json()
            codes = _expansion_codes(data)
            expand_summary[vs_id] = codes
            check(f"{label} {vs_id} $expand → 200",
                  True, f"{len(codes)} kódů")
            missing = [c for c in expected_codes if c not in codes]
            if missing:
                check(f"{label} {vs_id} obsahuje dokumentované kódy",
                      False, f"chybí: {missing}")
            else:
                check(f"{label} {vs_id} obsahuje všechny dokumentované kódy",
                      True, f"{len(expected_codes)}/{len(expected_codes)}")
            extra = sorted(codes - set(expected_codes))
            if extra and len(extra) <= 12:
                warn(f"{label} {vs_id} obsahuje nezdokumentované kódy: {extra}")
            elif extra:
                warn(f"{label} {vs_id} obsahuje {len(extra)} nezdokumentovaných kódů "
                     f"(prvních 5: {extra[:5]})")
        except Exception as e:
            check(f"{label} {vs_id} $expand", False, str(e))

    # 3. ValueSet/$validate-code – PASS na známém kódu
    pass_url = f"{NCEZ_VS_BASE}/medical-document-type"
    pass_code = "11506-3"
    try:
        r = term.valueset_validate_code(url=pass_url, code=pass_code)
        sc = r.status_code
        data = _safe_json(r)
        result = _validate_result_bool(data)
        check(f"{label} $validate-code PASS ({pass_code})",
              sc == 200 and result is True,
              f"status={sc} result={result}")
    except Exception as e:
        check(f"{label} $validate-code PASS", False, str(e))

    # 4. ValueSet/$validate-code – FAIL na smyšleném kódu
    fail_code = "XYZ-NEEXISTUJE-9999"
    try:
        r = term.valueset_validate_code(url=pass_url, code=fail_code)
        sc = r.status_code
        data = _safe_json(r)
        result = _validate_result_bool(data)
        check(f"{label} $validate-code FAIL ({fail_code})",
              sc == 200 and result is False,
              f"status={sc} result={result}")
    except Exception as e:
        check(f"{label} $validate-code FAIL", False, str(e))

    # 5. CodeSystem/$lookup
    cs_url = f"{NCEZ_CS_BASE}/medical-document-type"
    try:
        r = term.codesystem_lookup(system=cs_url, code=pass_code)
        sc = r.status_code
        data = _safe_json(r)
        display = _lookup_display(data)
        check(f"{label} CodeSystem/$lookup ({pass_code})",
              sc == 200 and bool(display),
              f"status={sc} display={display!r}")
    except Exception as e:
        check(f"{label} CodeSystem/$lookup", False, str(e))

    # 6. ConceptMap/$translate – smoke (akceptujeme i 404 dle dat)
    try:
        r = term.conceptmap_translate(
            code=pass_code, system=cs_url,
        )
        sc = r.status_code
        check(f"{label} ConceptMap/$translate (smoke)",
              sc in (200, 404, 422),
              f"status={sc}")
    except Exception as e:
        check(f"{label} ConceptMap/$translate", False, str(e))

    return expand_summary


def run_drift_detector(gateway_codes: dict[str, set[str]],
                       public_codes: dict[str, set[str]]) -> None:
    print("\n[DRIFT] Porovnání gateway vs. public mirror")
    common = set(gateway_codes) & set(public_codes)
    if not common:
        warn("Žádný společný ValueSet pro porovnání")
        return
    for vs_id in sorted(common):
        gw, pb = gateway_codes[vs_id], public_codes[vs_id]
        only_gw = gw - pb
        only_pb = pb - gw
        if not only_gw and not only_pb:
            check(f"DRIFT {vs_id} – stejná množina kódů",
                  True, f"{len(gw)} kódů")
        else:
            detail = ""
            if only_gw:
                detail += f"gateway+: {sorted(only_gw)[:5]} "
            if only_pb:
                detail += f"public+: {sorted(only_pb)[:5]}"
            warn(f"DRIFT {vs_id} – odlišnost: {detail.strip()}")
            check(f"DRIFT {vs_id} – stejná množina kódů",
                  False, detail.strip())


def build_term(client_id: str, p12_path: str, p12_password: str,
                cert_uid: str, env_label: str) -> tuple[Terminologie, Terminologie] | None:
    try:
        auth = SEZAuth(
            client_id=client_id, p12_path=p12_path,
            p12_password=p12_password, cert_uid=cert_uid or None,
        )
        client = SEZClient(auth)
        return Terminologie(client, public=False), Terminologie(client, public=True)
    except Exception as e:
        check(f"{env_label}: vytvoření klienta", False, str(e))
        return None


def main() -> int:
    cfg.validate()

    print("=" * 78)
    print("TermX – Terminologický server (FHIR v1.0.5)")
    print("=" * 78)

    # T2 (default z .env)
    pair = build_term(cfg.CLIENT_ID, cfg.P12_PATH, cfg.P12_PASSWORD,
                       cfg.CERT_UID, "T2")
    gateway_summary: dict[str, set[str]] = {}
    public_summary: dict[str, set[str]] = {}
    if pair:
        gw, pub = pair
        gateway_summary = run_suite("T2 Gateway", gw) or {}
        public_summary = run_suite("T2 Public", pub) or {}
        run_drift_detector(gateway_summary, public_summary)
    else:
        print("  ⚠ T2 nelze inicializovat – přeskočeno")

    # PROD (jen pokud je nastavené v .env)
    prod_id = getattr(cfg, "PROD_CLIENT_ID", "") or ""
    prod_p12 = getattr(cfg, "PROD_P12_PATH", "") or ""
    prod_pwd = getattr(cfg, "PROD_P12_PASSWORD", "") or ""
    if prod_id and prod_p12 and prod_pwd:
        print("\n--- PROD ---")
        # Přepnout SEZConfig na PROD
        from sez_api.client import SEZConfig
        SEZConfig.switch_environment("PROD")
        pair_prod = build_term(prod_id, prod_p12, prod_pwd,
                                getattr(cfg, "PROD_CERT_UID", ""),
                                "PROD")
        if pair_prod:
            gw_p, _pub_p = pair_prod
            run_suite("PROD Gateway", gw_p)
            print("  (PROD public mirror nepoužíván – PROD nemá veřejný TermX)")
        # vrátit zpět na T2 pro úklid
        SEZConfig.switch_environment("T2")
    else:
        print("\n--- PROD přeskočeno (chybí SEZ_PROD_* v .env) ---")

    # Souhrn
    print("\n" + "=" * 78)
    print("SHRNUTÍ")
    print("=" * 78)
    passed = sum(1 for _, s, _ in results if s == "PASS")
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    total = len(results)
    print(f"\n  Celkem testů: {total}")
    print(f"  Prošlo:       {passed}")
    print(f"  Selhalo:      {failed}")

    if failed:
        print("\n  SELHANÉ TESTY:")
        for name, status, detail in results:
            if status == "FAIL":
                print(f"    ✗ {name}  –  {detail}")

    if warnings:
        print(f"\n  VAROVÁNÍ ({len(warnings)}):")
        for w in warnings[:20]:
            print(f"    ⚠ {w}")

    print("\n" + ("=" * 78))
    print(f"VÝSLEDEK: {'PASS' if failed == 0 else 'FAIL'} ({passed}/{total})")
    print("=" * 78)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
