#!/usr/bin/env python3
"""Rychlá kontrola: funguje autentizace? VyhledejZasilku vs DejZasilku."""

import logging
import json

from sez_client import SEZAuth, SEZClient, DocasneUloziste, Notifikace

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

auth = SEZAuth(
    client_id=CLIENT_ID,
    p12_path=P12_PATH,
    p12_password=P12_PASSWORD,
    cert_uid=CERT_UID,
)
client = SEZClient(auth)

print("=== 1. Notifikace PING ===")
resp = Notifikace(client).ping()
print(f"  Status: {resp.status_code}")
print(f"  Body:   {resp.text[:300]}")

print("\n=== 2. VyhledejZasilku ===")
du = DocasneUloziste(client)
resp = du.vyhledej_zasilku("2026-02-01T00:00:00+01:00", "2026-02-19T23:59:59+01:00", page=1, size=3)
print(f"  Status: {resp.status_code}")
try:
    data = resp.json()
    if isinstance(data, list):
        print(f"  Nalezeno zásilek: {len(data)}")
    else:
        print(f"  Response: {json.dumps(data, ensure_ascii=False)[:400]}")
except Exception:
    print(f"  Body: {resp.text[:300]}")

print("\n=== 3. DejZasilku (první zásilka pro naše IČO) ===")
resp = du.dej_zasilku("53cf7836-6ba9-43b7-a858-319bccf8bd6c")
print(f"  Status: {resp.status_code}")
print(f"  Body:   {resp.text[:500]}")
