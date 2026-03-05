#!/usr/bin/env python3
"""
UlozZasilku – uložení testovací zásilky přes krajska_zdravotni.pfx,
pak pokus o DejZasilku na tu samou zásilku.
"""

import json
import hashlib
import base64
import os
from datetime import datetime, timedelta, timezone

from sez_client import SEZAuth, SEZClient, DocasneUloziste

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

ICO = "25488627"
NRZP_PRACOVNIK = "102129137"  # MRAČENA MRAKOMOROVÁ – testovací lékař
RID_PACIENT = "2667873559"    # MRAČENA MRAKOMOROVÁ – testovací pacientka

auth = SEZAuth(
    client_id=CLIENT_ID,
    p12_path=P12_PATH,
    p12_password=P12_PASSWORD,
    cert_uid=CERT_UID,
)
client = SEZClient(auth)
du = DocasneUloziste(client)

print("=" * 70)
print("UlozZasilku – testovací zásilka")
print("=" * 70)

now = datetime.now(timezone.utc)
datum_od = now.isoformat()
datum_do = (now + timedelta(days=30)).isoformat()

test_content = "Testovací dokument - zpráva z vyšetření pro ověření API."
content_bytes = test_content.encode("utf-8")
content_b64 = base64.b64encode(content_bytes).decode("ascii")
content_hash = hashlib.sha256(content_bytes).hexdigest()

zasilka = {
    "nazev": "Test stazeni - Krajska zdravotni",
    "popis": "Testovaci zasilka pro overeni stazeni pres API",
    "typ": {
        "ciselnikKod": "medical-document-type",
        "kod": "11506-3",
        "verze": "1.0.0"
    },
    "klasifikace": {
        "ciselnikKod": "document-category",
        "kod": "11503-0",
        "verze": "1.0.0"
    },
    "datumOd": datum_od,
    "datumDo": datum_do,
    "autor": NRZP_PRACOVNIK,
    "zdravotnickyPracovnik": NRZP_PRACOVNIK,
    "poskytovatel": ICO,
    "pacient": RID_PACIENT,
    "ispzs": "NIS Krajska zdravotni",
    "adresat": ICO,
    "adresatTyp": {
        "ciselnikKod": "typ-adresata",
        "kod": "PZS",
        "verze": "1.0.0"
    },
    "dokument": [
        {
            "nazev": "Testovaci zprava",
            "popis": "Testovaci zprava z vysetreni",
            "jazyk": {
                "ciselnikKod": "languages",
                "kod": "cs",
                "verze": "5.0.0"
            },
            "typ": {
                "ciselnikKod": "medical-document-type",
                "kod": "67781-5",
                "verze": "1.0.0"
            },
            "klasifikace": {
                "ciselnikKod": "document-category",
                "kod": "11503-0",
                "verze": "1.0.0"
            },
            "autor": NRZP_PRACOVNIK,
            "poskytovatel": ICO,
            "pacient": RID_PACIENT,
            "dostupnost": True,
            "duvernost": {
                "ciselnikKod": "v3-Confidentiality",
                "kod": "N",
                "verze": "2.0.0"
            },
            "format": {
                "ciselnikKod": "format-code",
                "kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient",
                "verze": "1.0.0"
            },
            "mime": {
                "ciselnikKod": "media-type",
                "kod": "text/plain",
                "verze": "1.0.0"
            },
            "hash": content_hash,
            "velikost": len(content_bytes),
            "soubor": {
                "soubor": content_b64
            }
        }
    ]
}

print("\nRequest body (zkráceno):")
preview = json.dumps(zasilka, ensure_ascii=False, indent=2)
print(preview[:1000])
print("...")

print("\n[1] UlozZasilku...")
resp = du.uloz_zasilku(zasilka)
print(f"  Status: {resp.status_code}")

try:
    data = resp.json()
    print(f"  Response: {json.dumps(data, ensure_ascii=False, indent=2)[:1500]}")
except Exception:
    print(f"  Body: {resp.text[:1500]}")

if resp.status_code < 300 and data:
    zasilka_id = data.get("id") or data.get("zasilkaId")
    if zasilka_id:
        os.makedirs("stazene_zasilky", exist_ok=True)
        with open(f"stazene_zasilky/ulozena_zasilka_{zasilka_id}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"\n  Zásilka uložena s ID: {zasilka_id}")

        print(f"\n[2] DejZasilku ({zasilka_id})...")
        resp2 = du.dej_zasilku(zasilka_id)
        print(f"  Status: {resp2.status_code}")
        try:
            d2 = resp2.json()
            print(f"  Response: {json.dumps(d2, ensure_ascii=False, indent=2)[:1500]}")
            if resp2.status_code < 300:
                with open(f"stazene_zasilky/stazena_zasilka_{zasilka_id}.json", "w", encoding="utf-8") as f:
                    json.dump(d2, f, ensure_ascii=False, indent=2)
                print(f"  >>> ZÁSILKA STAŽENA A ULOŽENA!")
        except Exception:
            print(f"  Body: {resp2.text[:800]}")

print(f"\n{'='*70}")
print("HOTOVO")
