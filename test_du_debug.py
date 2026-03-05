#!/usr/bin/env python3
"""Debug: ověření mTLS certifikátu + pokus o DÚ."""

import json
import os
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.x509.oid import NameOID
from sez_client import SEZAuth, SEZClient, DocasneUloziste, Notifikace

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

print("=" * 70)
print("DEBUG: ověření certifikátu pro mTLS a JWT signing")
print("=" * 70)

auth = SEZAuth(
    client_id=CLIENT_ID,
    p12_path=P12_PATH,
    p12_password=P12_PASSWORD,
    cert_uid=CERT_UID,
)

print(f"\n[Cert] P12 soubor:  {P12_PATH}")
print(f"[Cert] UID (kid):   {CERT_UID}")

signing_cert = auth._signing_cert
tls_cert = auth._tls_cert

def cert_info(cert, label):
    subj = cert.subject
    cn = subj.get_attributes_for_oid(NameOID.COMMON_NAME)
    org = subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    serial = cert.serial_number
    print(f"\n[{label}]")
    print(f"  CN:     {cn[0].value if cn else '?'}")
    print(f"  O:      {org[0].value if org else '?'}")
    print(f"  Serial: {serial}")
    print(f"  Valid:  {cert.not_valid_before_utc} - {cert.not_valid_after_utc}")
    print(f"  Same object as signing: {cert is signing_cert}")

cert_info(signing_cert, "JWT signing cert")
cert_info(tls_cert, "mTLS cert")

print(f"\n[mTLS PEM] Cert: {auth._tls_cert_path}")
print(f"[mTLS PEM] Key:  {auth._tls_key_path}")
print(f"[Session]  cert: {auth.tls_cert}")

same = (signing_cert is tls_cert)
print(f"\n>>> Signing cert == TLS cert (same object): {same}")
if same:
    print(">>> OK: JEDEN certifikát (krajska_zdravotni) pro mTLS i JWT")
else:
    print(">>> VAROVÁNÍ: různé certifikáty!")

client = SEZClient(auth)

print(f"\n{'='*70}")
print("Test volání:")
print(f"{'='*70}")

print("\n[1] Notifikace ping...")
r = Notifikace(client).ping()
print(f"  Status: {r.status_code} – {r.text[:100]}")

print("\n[2] DÚ VyhledejZasilku...")
du = DocasneUloziste(client)
r = du.vyhledej_zasilku("2026-02-01T00:00:00+01:00", "2026-02-19T23:59:59+01:00", size=2)
print(f"  Status: {r.status_code}")
try:
    d = r.json()
    print(f"  Body:   {json.dumps(d, ensure_ascii=False)[:400]}")
except Exception:
    print(f"  Body:   {r.text[:400]}")

if r.status_code < 300:
    items = d if isinstance(d, list) else d.get("zasilky", d.get("items", []))
    if items and isinstance(items, list) and len(items) > 0:
        zid = items[0].get("id", items[0].get("zasilkaId"))
        print(f"\n[3] DÚ DejZasilku ID={zid}...")
        r2 = du.dej_zasilku(zid)
        print(f"  Status: {r2.status_code}")
        try:
            print(f"  Body:   {json.dumps(r2.json(), ensure_ascii=False)[:600]}")
        except Exception:
            print(f"  Body:   {r2.text[:600]}")
        if r2.status_code < 300:
            fname = f"stazene_zasilky/zasilka_{zid}.json"
            os.makedirs("stazene_zasilky", exist_ok=True)
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(r2.json(), f, ensure_ascii=False, indent=2)
            print(f"  >>> ULOŽENO: {fname}")
else:
    print("\n[3] DejZasilku přeskočeno – VyhledejZasilku selhalo")

print(f"\n{'='*70}")
print("HOTOVO")
