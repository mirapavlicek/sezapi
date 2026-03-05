#!/usr/bin/env python3
"""
Ověření dokumentace SEZ_API_Dokumentace.md proti reálným API response.
Testuje všechny služby a porovnává formát odpovědí s dokumentací.
"""

import json
import sys
import os
import hashlib
import base64
from datetime import datetime, timedelta, timezone

from sez_client import (
    SEZAuth, SEZClient, KRP, DocasneUloziste, SZZ, ELP, EZadanky, Notifikace
)

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

DOCUMENTED_CISELNIKY = {
    "stav-zasilky": ["0"],
    "medical-document-type": ["11506-3", "67781-5", "34748-4", "74207-2"],
    "document-category": ["11503-0", "26436-6", "18682-5", "107904-5", "57133-1"],
    "typ-adresata": ["PZS", "PAT"],
    "v3-Confidentiality": ["N", "M"],
    "format-code": [
        "urn:ihe:iti:xds:2017:mimeTypeSufficient",
        "urn:ihe:iti:xds-sd:pdf:2008",
        "urn:ihe:rad:PDF",
        "urn:cz-mzcr:ns:dasta:ds4:ds_dasta",
    ],
    "media-type": ["application/pdf", "application/fhir+json", "text/plain", "image/gif"],
    "languages": ["cs", "cs-CZ"],
    "event-code": ["US", "DX", "ES", "OP", "OPT", "IVOCT"],
    "odbornosti-snomed-ct": ["24251000087109"],
}

results = []
warnings = []


def check(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    results.append((name, status, detail))
    icon = "✓" if ok else "✗"
    print(f"  {icon} {name}" + (f"  ({detail})" if detail else ""))
    return ok


def check_ciselnik(obj, expected_ciselnik_kod):
    if not isinstance(obj, dict):
        return False
    if obj.get("ciselnikKod") != expected_ciselnik_kod:
        return False
    if "kod" not in obj or "verze" not in obj:
        return False
    return True


def check_zasilka_structure(z):
    ok = True
    required = ["id", "nazev", "typ", "klasifikace", "datumOd", "datumDo",
                 "autor", "zdravotnickyPracovnik", "poskytovatel", "pacient",
                 "ispzs", "adresat", "adresatTyp", "dostupnost"]
    for field in required:
        if field not in z:
            warnings.append(f"Zásilka chybí pole: {field}")
            ok = False

    if "stav" in z and z["stav"]:
        ok = check_ciselnik(z["stav"], "stav-zasilky") and ok
    if "typ" in z and z["typ"]:
        ok = check_ciselnik(z["typ"], "medical-document-type") and ok
    if "klasifikace" in z and z["klasifikace"]:
        kod = z["klasifikace"].get("ciselnikKod", "")
        if kod not in ("document-category", "search-document-types"):
            warnings.append(f"Zásilka klasifikace neočekávaný ciselnikKod: {kod}")
    if "adresatTyp" in z and z["adresatTyp"]:
        ok = check_ciselnik(z["adresatTyp"], "typ-adresata") and ok

    if "dokument" in z and isinstance(z["dokument"], list):
        for d in z["dokument"]:
            doc_required = ["nazev", "jazyk", "typ", "klasifikace", "pacient",
                            "dostupnost", "duvernost", "hash", "velikost"]
            for field in doc_required:
                if field not in d:
                    warnings.append(f"Dokument chybí pole: {field}")
                    ok = False
            if "jazyk" in d and d["jazyk"]:
                ok = check_ciselnik(d["jazyk"], "languages") and ok
            if "duvernost" in d and d["duvernost"]:
                ok = check_ciselnik(d["duvernost"], "v3-Confidentiality") and ok
            if "format" in d and d["format"]:
                ok = check_ciselnik(d["format"], "format-code") and ok
            if "mime" in d and d["mime"]:
                ok = check_ciselnik(d["mime"], "media-type") and ok
    return ok


auth = SEZAuth(
    client_id=CLIENT_ID,
    p12_path=P12_PATH,
    p12_password=P12_PASSWORD,
    cert_uid=CERT_UID,
)
client = SEZClient(auth)

print("=" * 70)
print("OVĚŘENÍ DOKUMENTACE – test všech služeb SEZ API")
print("=" * 70)

# === 1. Notifikace ===
print("\n[1] Notifikace")
notif = Notifikace(client)

r = notif.ping()
check("Notifikace ping → 200", r.status_code == 200, f"status={r.status_code}")

r = notif.katalog_kanalu()
check("Notifikace katalog kanálů → 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    d = r.json()
    check("Response má pageNumber/totalCount/page", 
          all(k in d for k in ["pageNumber", "totalCount", "page"]),
          f"klíče: {list(d.keys())[:5]}")

r = notif.katalog_sablon()
check("Notifikace katalog šablon → 200", r.status_code == 200, f"status={r.status_code}")

r = notif.katalog_zdroju()
check("Notifikace katalog zdrojů → 200", r.status_code == 200, f"status={r.status_code}")

# === 2. KRP ===
print("\n[2] KRP – Kmenový registr pacientů")
krp = KRP(client)

r = krp.hledat_rid("7653800856")
check("KRP hledat RID → 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    d = r.json()
    check("Response má odpovedInfo/odpovedData",
          "odpovedInfo" in d, f"klíče: {list(d.keys())}")
    if "odpovedInfo" in d:
        info = d["odpovedInfo"]
        check("odpovedInfo.stav je OK",
              info.get("stav") == "OK", f"stav={info.get('stav')}")
        check("odpovedInfo má zadostId/odpovedId",
              "zadostId" in info and "odpovedId" in info)

r = krp.hledat_rid("2667873559")
check("KRP hledat RID 2667873559 (MRAKOMOROVÁ) → 200", r.status_code == 200)

# === 3. SZZ ===
print("\n[3] SZZ – Sdílený zdravotní záznam")
szz = SZZ(client)

r = szz.alergie("7706120004")
check("SZZ alergie → 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    d = r.json()
    check("SZZ alergie → array response", isinstance(d, list), f"type={type(d).__name__}")

r = szz.lecive_pripravky("7706120004")
check("SZZ léčivé přípravky → 200", r.status_code == 200, f"status={r.status_code}")

r = szz.nezadouci_prihody("7706120004")
check("SZZ nežádoucí příhody → 200", r.status_code == 200, f"status={r.status_code}")

r = szz.krevni_skupina("7706120004")
check("SZZ krevní skupina → 200 nebo 404 (pacient nemusí mít záznam)", 
      r.status_code in (200, 404), f"status={r.status_code}")
if r.status_code == 404:
    d = r.json()
    check("SZZ 404 → RFC 7807 formát (type/title/status/detail)",
          all(k in d for k in ["type", "title", "status", "detail"]),
          f"klíče: {list(d.keys())}")

# === 4. ELP ===
print("\n[4] ELP – Elektronické posudky")
elp = ELP(client)

r = elp.vyhledej_posudky({"strankovani": {"page": 0, "size": 2}})
check("ELP vyhledání posudků → 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    d = r.json()
    check("Response má pageNumber/totalCount/page",
          all(k in d for k in ["pageNumber", "totalCount", "page"]),
          f"totalCount={d.get('totalCount')}")
    if d.get("page") and len(d["page"]) > 0:
        p = d["page"][0]
        check("Posudek má id/pacient",
              "id" in p and "pacient" in p,
              f"klíče: {list(p.keys())[:6]}")
        pid = p["id"]
        r2 = elp.detail_posudku(pid)
        check(f"ELP detail posudku {pid[:12]}... → 200", r2.status_code == 200)

# === 5. eŽádanky ===
print("\n[5] eŽádanky")
ez = EZadanky(client)

r = ez.dej_token()
check("eŽádanky DejToken → 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    d = r.json()
    check("Response má access_token", "access_token" in d)

# === 6. Dočasné úložiště ===
print("\n[6] Dočasné úložiště")
du = DocasneUloziste(client)

r = du.vyhledej_zasilku("2026-01-01T00:00:00+01:00", "2026-02-20T23:59:59+01:00", size=5)
du_ok = r.status_code == 200
check("DÚ VyhledejZasilku → 200", du_ok, 
      f"status={r.status_code}" + (" (DÚ T2 DOWN)" if not du_ok else ""))

if du_ok:
    d = r.json()
    check("Response má pole 'zasilka'", "zasilka" in d if isinstance(d, dict) else isinstance(d, list))

    items = d.get("zasilka", d) if isinstance(d, dict) else d
    if isinstance(items, list) and len(items) > 0:
        check(f"Nalezeno {len(items)} zásilek", True)

        z = items[0]
        struct_ok = check_zasilka_structure(z)
        check("Struktura zásilky odpovídá dokumentaci", struct_ok,
              "; ".join(warnings[-3:]) if not struct_ok else "")

        found_ciselniky = {}
        def collect_cis(obj):
            if isinstance(obj, dict):
                if "ciselnikKod" in obj:
                    ck = obj["ciselnikKod"]
                    if ck not in found_ciselniky:
                        found_ciselniky[ck] = set()
                    found_ciselniky[ck].add(obj.get("kod", ""))
                for v in obj.values():
                    collect_cis(v)
            elif isinstance(obj, list):
                for item in obj:
                    collect_cis(item)

        for item in items:
            collect_cis(item)

        for ck, codes in found_ciselniky.items():
            documented = DOCUMENTED_CISELNIKY.get(ck, None)
            if documented is None:
                check(f"Číselník '{ck}' v dokumentaci", False, "CHYBÍ v dokumentaci!")
            else:
                undocumented = codes - set(documented)
                if undocumented:
                    check(f"Číselník '{ck}' – nezdokumentované kódy", False,
                          f"chybí: {undocumented}")
                else:
                    check(f"Číselník '{ck}' – všechny kódy zdokumentovány", True,
                          f"{len(codes)} kódů OK")

    # Test UlozZasilku
    print("\n  [6b] UlozZasilku test")
    now = datetime.now(timezone.utc)
    test_content = "Testovací dokument pro ověření dokumentace API."
    content_bytes = test_content.encode("utf-8")
    content_b64 = base64.b64encode(content_bytes).decode("ascii")
    content_hash = hashlib.sha256(content_bytes).hexdigest()

    zasilka = {
        "nazev": "Test dokumentace - Krajska zdravotni",
        "popis": "Automatický test ověření dokumentace",
        "typ": {"ciselnikKod": "medical-document-type", "kod": "11506-3", "verze": "1.0.0"},
        "klasifikace": {"ciselnikKod": "document-category", "kod": "11503-0", "verze": "1.0.0"},
        "datumOd": now.isoformat(),
        "datumDo": (now + timedelta(days=30)).isoformat(),
        "autor": "102129137",
        "zdravotnickyPracovnik": "102129137",
        "poskytovatel": "25488627",
        "pacient": "2667873559",
        "ispzs": "NIS Krajska zdravotni",
        "adresat": "25488627",
        "adresatTyp": {"ciselnikKod": "typ-adresata", "kod": "PZS", "verze": "1.0.0"},
        "dostupnost": True,
        "dokument": [{
            "nazev": "Testovaci zprava",
            "popis": "Test",
            "jazyk": {"ciselnikKod": "languages", "kod": "cs", "verze": "5.0.0"},
            "typ": {"ciselnikKod": "medical-document-type", "kod": "67781-5", "verze": "1.0.0"},
            "klasifikace": {"ciselnikKod": "document-category", "kod": "11503-0", "verze": "1.0.0"},
            "autor": "102129137",
            "poskytovatel": "25488627",
            "pacient": "2667873559",
            "dostupnost": True,
            "duvernost": {"ciselnikKod": "v3-Confidentiality", "kod": "N", "verze": "2.0.0"},
            "format": {"ciselnikKod": "format-code", "kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient", "verze": "1.0.0"},
            "mime": {"ciselnikKod": "media-type", "kod": "text/plain", "verze": "1.0.0"},
            "hash": content_hash,
            "velikost": len(content_bytes),
            "soubor": {"soubor": content_b64},
        }],
    }

    r = du.uloz_zasilku(zasilka)
    check("DÚ UlozZasilku", r.status_code < 300 or r.status_code == 400,
          f"status={r.status_code}")
    if r.status_code < 300:
        rd = r.json()
        new_id = rd.get("id")
        check("UlozZasilku vrátilo id", new_id is not None, f"id={new_id}")
        check("UlozZasilku vrátilo verzeRadku", "verzeRadku" in rd)
        if new_id:
            r2 = du.dej_zasilku(new_id)
            check("DejZasilku na novou zásilku",
                  r2.status_code in (200, 400),
                  f"status={r2.status_code}" + 
                  (" (400=chybí ZP oprávnění – očekávané)" if r2.status_code == 400 else ""))
    elif r.status_code == 400:
        try:
            err = r.json()
            check("UlozZasilku 400 – chybový formát odpovídá dokumentaci",
                  "errors" in err or "Errors" in err,
                  json.dumps(err, ensure_ascii=False)[:200])
        except Exception:
            pass

else:
    print("  ⚠ DÚ T2 nedostupné – přeskočeno")

# === Shrnutí ===
print("\n" + "=" * 70)
print("SHRNUTÍ")
print("=" * 70)

passed = sum(1 for _, s, _ in results if s == "PASS")
failed = sum(1 for _, s, _ in results if s == "FAIL")
total = len(results)

print(f"\n  Celkem testů: {total}")
print(f"  Prošlo:       {passed}")
print(f"  Selhalo:      {failed}")

if failed > 0:
    print(f"\n  SELHANÉ TESTY:")
    for name, status, detail in results:
        if status == "FAIL":
            print(f"    ✗ {name}  –  {detail}")

if warnings:
    print(f"\n  VAROVÁNÍ ({len(warnings)}):")
    for w in warnings[:10]:
        print(f"    ⚠ {w}")

print(f"\n{'='*70}")
print(f"VÝSLEDEK: {'PASS' if failed == 0 else 'FAIL'} ({passed}/{total})")
print(f"{'='*70}")
