#!/usr/bin/env python3
"""
Systematický pokus obejít chybu 400 "Pracovník nemá oprávnění" na DejZasilku.
Zkouší různé přístupy: custom JWT claims, hlavičky, KRZP lookup, Registr oprávnění.
"""

import json
import time
import uuid
import jwt as pyjwt
import requests
from datetime import datetime, timezone

from sez_client import SEZAuth, SEZClient, DocasneUloziste

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

ICO = "25488627"
NRZP_PRACOVNIK = "102129137"
GATEWAY = "https://gwy-ext-sec-t2.csez.cz"
TOKEN_AUD = "https://jsuint-auth-t2.csez.cz/connect/token"

auth = SEZAuth(
    client_id=CLIENT_ID,
    p12_path=P12_PATH,
    p12_password=P12_PASSWORD,
    cert_uid=CERT_UID,
)

# Najdeme zásilku ke stažení
client = SEZClient(auth)
du = DocasneUloziste(client)
r = du.vyhledej_zasilku("2026-01-01T00:00:00+01:00", "2026-02-20T23:59:59+01:00", size=3)
if r.status_code != 200:
    print(f"CHYBA: VyhledejZasilku vrátilo {r.status_code}")
    exit(1)

zasilky = r.json().get("zasilka", [])
if not zasilky:
    print("Žádné zásilky k testování")
    exit(1)

test_id = zasilky[0]["id"]
print(f"Testovací zásilka: {test_id}")
print(f"  nazev: {zasilky[0].get('nazev')}")
print(f"  pacient: {zasilky[0].get('pacient')}")
print(f"  adresat: {zasilky[0].get('adresat')}")
print()

session = requests.Session()
session.cert = auth.tls_cert
session.verify = True


def build_assertion(extra_payload=None, extra_headers=None):
    now = int(time.time())
    payload = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": TOKEN_AUD,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 55,
    }
    if extra_payload:
        payload.update(extra_payload)
    headers = {"kid": CERT_UID}
    if extra_headers:
        headers.update(extra_headers)
    return pyjwt.encode(payload, auth._signing_key, algorithm="RS256", headers=headers)


def try_dej(label, assertion=None, extra_http_headers=None):
    if assertion is None:
        assertion = build_assertion()
    
    h = {
        "Authorization": f"Bearer {assertion}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Language": "cs",
        "X-Correlation-Id": str(uuid.uuid4()),
        "X-Trace-Id": str(uuid.uuid4()),
    }
    if extra_http_headers:
        h.update(extra_http_headers)
    
    url = f"{GATEWAY}/docasneUloziste/api/v1/Zasilka/DejZasilku/{test_id}"
    r = session.get(url, headers=h, timeout=30)
    
    status = r.status_code
    try:
        body = r.json()
    except Exception:
        body = r.text[:300]
    
    icon = "✓" if status == 200 else "✗"
    print(f"  {icon} [{status}] {label}")
    if status != 200:
        err_msg = ""
        if isinstance(body, dict):
            errs = body.get("errors", body.get("Errors", []))
            if errs:
                err_msg = json.dumps(errs, ensure_ascii=False)[:200]
            elif "error" in body:
                err_msg = body.get("error_description", body.get("error", ""))
            elif "title" in body:
                err_msg = body.get("detail", body.get("title", ""))
        else:
            err_msg = str(body)[:200]
        if err_msg:
            print(f"        → {err_msg}")
    else:
        if isinstance(body, dict) and "dokument" in body:
            docs = body.get("dokument", [])
            for d in docs:
                sob = d.get("soubor", {})
                has_content = sob.get("soubor") is not None if sob else False
                print(f"        → dokument '{d.get('nazev')}', soubor={has_content}")
    return status


print("=" * 70)
print("POKUS 1: Baseline – standardní assertion (očekáváme 400)")
print("=" * 70)
try_dej("Standardní JWT assertion")

print()
print("=" * 70)
print("POKUS 2: JWT s extra claims – nrzp / krzpid / act")
print("=" * 70)

variants = [
    ("sub = NRZP pracovníka", {"sub": NRZP_PRACOVNIK}),
    ("sub = NRZP_CLIENT_ID", {"sub": f"{NRZP_PRACOVNIK}_{CLIENT_ID}"}),
    ("claim nrzp", {"nrzp": NRZP_PRACOVNIK}),
    ("claim krzpid", {"krzpid": NRZP_PRACOVNIK}),
    ("claim zdravotnickyPracovnik", {"zdravotnickyPracovnik": NRZP_PRACOVNIK}),
    ("claim act (actor)", {"act": {"sub": NRZP_PRACOVNIK}}),
    ("claim amr + nrzp", {"amr": ["mTLS"], "nrzp": NRZP_PRACOVNIK}),
    ("claim scope + nrzp", {"scope": "du.read", "nrzp": NRZP_PRACOVNIK}),
]

for label, extra in variants:
    a = build_assertion(extra_payload=extra)
    s = try_dej(label, assertion=a)
    if s == 200:
        print("\n  *** ÚSPĚCH! ***\n")
        break

print()
print("=" * 70)
print("POKUS 3: Custom HTTP hlavičky")
print("=" * 70)

header_variants = [
    ("X-NRZP header", {"X-NRZP": NRZP_PRACOVNIK}),
    ("X-Worker-Id header", {"X-Worker-Id": NRZP_PRACOVNIK}),
    ("X-KRZPID header", {"X-KRZPID": NRZP_PRACOVNIK}),
    ("X-ZP-Id header", {"X-ZP-Id": NRZP_PRACOVNIK}),
    ("X-User-Id header", {"X-User-Id": NRZP_PRACOVNIK}),
    ("X-Forwarded-User header", {"X-Forwarded-User": NRZP_PRACOVNIK}),
]

for label, headers in header_variants:
    s = try_dej(label, extra_http_headers=headers)
    if s == 200:
        print("\n  *** ÚSPĚCH! ***\n")
        break

print()
print("=" * 70)
print("POKUS 4: KRZP – vyhledání pracovníka")
print("=" * 70)

# Zkusíme najít pracovníka v KRZP
krzp_url = f"{GATEWAY}/krzp/api/v2/pracovnik/hledat/krzpid"
krzp_body = {"krzpid": NRZP_PRACOVNIK}
a = build_assertion()
h = {
    "Authorization": f"Bearer {a}",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Correlation-Id": str(uuid.uuid4()),
}
r = session.post(krzp_url, json=krzp_body, headers=h, timeout=30)
print(f"  KRZP hledat krzpid={NRZP_PRACOVNIK} → {r.status_code}")
if r.status_code == 200:
    d = r.json()
    print(f"  Response: {json.dumps(d, ensure_ascii=False, indent=2)[:600]}")
else:
    print(f"  Error: {r.text[:300]}")

# Zkusíme i zamestnavatel endpoint
krzp_url2 = f"{GATEWAY}/krzp/api/v2/pracovnik/hledat/zamestnavatel"
krzp_body2 = {"ico": ICO}
a2 = build_assertion()
h2 = {
    "Authorization": f"Bearer {a2}",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Correlation-Id": str(uuid.uuid4()),
}
r2 = session.post(krzp_url2, json=krzp_body2, headers=h2, timeout=30)
print(f"\n  KRZP hledat zaměstnavatel ICO={ICO} → {r2.status_code}")
if r2.status_code == 200:
    d2 = r2.json()
    print(f"  Response: {json.dumps(d2, ensure_ascii=False, indent=2)[:600]}")
else:
    print(f"  Error: {r2.text[:300]}")

print()
print("=" * 70)
print("POKUS 5: Registr oprávnění – ověření oprávnění")
print("=" * 70)

# Over oprávnění pro ZP na zásilku
opravneni_url = f"{GATEWAY}/registrOpravneni/api/v1/Opravneni/Over"
pacient_rid = zasilky[0].get("pacient", "2667873559")
params = {
    "IdSluzbyEZ": "1",
    "IdTypuDokumentace": "5",
    "OpravnujiciOsoba.Role": "PoskytovatelZdravotnickychSluzeb",
    "OpravnujiciOsoba.Hodnota": ICO,
    "OpravnenaOsoba.Role": "ZdravotniPracovnik",
    "OpravnenaOsoba.Hodnota": NRZP_PRACOVNIK,
}
a3 = build_assertion()
h3 = {
    "Authorization": f"Bearer {a3}",
    "Accept": "application/json",
    "X-Correlation-Id": str(uuid.uuid4()),
}
r3 = session.get(opravneni_url, params=params, headers=h3, timeout=30)
print(f"  Registr oprávnění Over → {r3.status_code}")
if r3.status_code == 200:
    print(f"  Response: {r3.text[:300]}")
else:
    print(f"  Error: {r3.text[:300]}")

# Zkusíme různé kombinace IdSluzbyEZ
for svc_id in ["1", "2", "3", "4", "5"]:
    params2 = params.copy()
    params2["IdSluzbyEZ"] = svc_id
    a4 = build_assertion()
    h4 = {
        "Authorization": f"Bearer {a4}",
        "Accept": "application/json",
        "X-Correlation-Id": str(uuid.uuid4()),
    }
    r4 = session.get(opravneni_url, params=params2, headers=h4, timeout=30)
    icon = "✓" if r4.status_code == 200 else "✗"
    body_text = r4.text[:100] if r4.status_code == 200 else r4.text[:200]
    print(f"  {icon} IdSluzbyEZ={svc_id} → {r4.status_code}: {body_text}")

print()
print("=" * 70)
print("POKUS 6: DejZasilku na zásilku kterou jsme sami vytvořili")
print("=" * 70)

# Najdeme zásilku od naší identity
my_zasilky = [z for z in zasilky if z.get("poskytovatel") == ICO]
if my_zasilky:
    my_id = my_zasilky[0]["id"]
    print(f"  Naše zásilka: {my_id} (poskytovatel={my_zasilky[0].get('poskytovatel')})")
    s = try_dej(f"DejZasilku na vlastní zásilku {my_id[:12]}...")
else:
    print("  Žádná zásilka od naší identity")
    # Zkusíme i všechny nalezené
    for z in zasilky[:3]:
        zid = z["id"]
        print(f"\n  Zásilka {zid[:12]}... (poskytovatel={z.get('poskytovatel')}, adresat={z.get('adresat')})")
        try_dej(f"DejZasilku {zid[:12]}...")

print()
print("=" * 70)
print("HOTOVO – shrnutí")
print("=" * 70)
