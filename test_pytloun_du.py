#!/usr/bin/env python3
"""
Test DejZasilku s pytloun.p12 pro mTLS + krajska_zdravotni.pfx pro JWT signing.
"""

import json
import os
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.x509.oid import NameOID
from sez_client import SEZAuth, SEZClient, DocasneUloziste, Notifikace

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"

SIGNING_P12 = "/Users/mira/Downloads/krajska_zdravotni.pfx"
SIGNING_PWD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

TLS_P12 = "/Users/mira/Downloads/pytloun.p12"
TLS_PWD = "apofis"


def cert_info(cert, label):
    subj = cert.subject
    cn = subj.get_attributes_for_oid(NameOID.COMMON_NAME)
    org = subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    org_id = subj.get_attributes_for_oid(NameOID.ORGANIZATION_IDENTIFIER)
    serial_num = subj.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    print(f"[{label}]")
    print(f"  CN:     {cn[0].value if cn else '?'}")
    print(f"  O:      {org[0].value if org else '?'}")
    print(f"  OrgID:  {org_id[0].value if org_id else '?'}")
    print(f"  Serial: {serial_num[0].value if serial_num else '?'}")
    print(f"  Valid:  {cert.not_valid_before_utc} – {cert.not_valid_after_utc}")


print("=" * 70)
print("pytloun.p12 (mTLS) + krajska_zdravotni.pfx (JWT) → DejZasilku")
print("=" * 70)

auth = SEZAuth(
    client_id=CLIENT_ID,
    p12_path=SIGNING_P12,
    p12_password=SIGNING_PWD,
    cert_uid=CERT_UID,
    tls_p12_path=TLS_P12,
    tls_p12_password=TLS_PWD,
)

print()
cert_info(auth._signing_cert, "JWT signing (krajska_zdravotni)")
print()
cert_info(auth._tls_cert, "mTLS (pytloun)")

client = SEZClient(auth)

print(f"\n{'='*70}")
print("Testy:")
print(f"{'='*70}")

print("\n[1] Notifikace ping...")
r = Notifikace(client).ping()
print(f"  Status: {r.status_code}  {r.text[:200]}")

du = DocasneUloziste(client)

print("\n[2] VyhledejZasilku...")
r = du.vyhledej_zasilku("2026-02-01T00:00:00+01:00", "2026-02-20T23:59:59+01:00", size=3)
print(f"  Status: {r.status_code}")
try:
    data = r.json()
    if isinstance(data, dict) and "zasilka" in data:
        items = data["zasilka"]
    elif isinstance(data, list):
        items = data
    else:
        items = []
    print(f"  Zásilek: {len(items)}")
    for it in items[:3]:
        print(f"    - {it.get('id')} | {it.get('nazev')} | adresat={it.get('adresat')}")
except Exception:
    print(f"  Body: {r.text[:400]}")
    items = []

zasilky_to_try = []
for it in items:
    if it.get("adresat") == "25488627":
        zasilky_to_try.append((it["id"], it.get("nazev", "?")))
if not zasilky_to_try and items:
    zasilky_to_try.append((items[0]["id"], items[0].get("nazev", "?")))

for zid, nazev in zasilky_to_try[:3]:
    print(f"\n[3] DejZasilku: {zid} ({nazev})")
    r2 = du.dej_zasilku(zid)
    print(f"  Status: {r2.status_code}")
    try:
        d2 = r2.json()
        preview = json.dumps(d2, ensure_ascii=False, indent=2)
        print(f"  Body: {preview[:800]}")
        if r2.status_code < 300:
            os.makedirs("stazene_zasilky", exist_ok=True)
            fname = f"stazene_zasilky/zasilka_{zid}.json"
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(d2, f, ensure_ascii=False, indent=2)
            print(f"  >>> ULOŽENO: {fname}")
    except Exception:
        print(f"  Body: {r2.text[:600]}")

print(f"\n{'='*70}")
print("HOTOVO")
