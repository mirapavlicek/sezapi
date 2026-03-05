#!/usr/bin/env python3
"""
Pokus o stažení zásilek adresovaných na ICO 25488627 přes DejZasilku.

Dle use case MZČR (https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58949648)
DejZasilku vyžaduje identitu zdravotnického pracovníka (ZP) s oprávněním
v Registru práv a mandátů. Systémový PZS uživatel nemusí projít.
"""

import logging
import json
import sys
import os

from sez_client import SEZAuth, SEZClient, DocasneUloziste

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("test_dej")

CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"
CERT_UID = "85cf28c4-c190-406f-bc96-f92ad25b3202"

ZASILKY_PRO_NAS = [
    ("53cf7836-6ba9-43b7-a858-319bccf8bd6c", "Zprava o vysetreni (PZS, od 47453745)"),
    ("62392836-edf7-4355-87ba-d32dbb8b2a3c", "Lékařská zpráva – hrudník (PZS, od NPEZ/26365804)"),
    ("492b31c7-87b9-4489-bc5f-e85de64f31e5", "Lékařská zpráva – pediatrie (PAT, od nás)"),
    ("0032b0ca-61f3-4a60-97c6-5cba104d5cd9", "Lékařská zpráva – pediatrie 2 (PAT, od nás)"),
]

OUT_DIR = "stazene_zasilky"


def main():
    print("=" * 70)
    print("DejZasilku – pokus o stažení zásilek pro IČO 25488627")
    print("=" * 70)

    auth = SEZAuth(
        client_id=CLIENT_ID,
        p12_path=P12_PATH,
        p12_password=P12_PASSWORD,
        cert_uid=CERT_UID,
    )
    client = SEZClient(auth)
    du = DocasneUloziste(client)

    os.makedirs(OUT_DIR, exist_ok=True)

    for zid, label in ZASILKY_PRO_NAS:
        print(f"\n{'─'*70}")
        print(f"  {label}")
        print(f"  ID: {zid}")
        print(f"{'─'*70}")

        resp = du.dej_zasilku(zid)
        print(f"  Status: {resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            data = None
            print(f"  Body:   {resp.text[:500]}")

        if data:
            preview = json.dumps(data, ensure_ascii=False, indent=2)
            print(f"  Response (prvních 800 znaků):")
            print(f"  {preview[:800]}")

        if resp.status_code < 300 and data:
            fname = os.path.join(OUT_DIR, f"zasilka_{zid}.json")
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"  >>> ULOŽENO do {fname}")
        elif resp.status_code == 400 and data:
            errors = data.get("errors", data.get("Errors", []))
            for e in errors:
                err_code = e.get("error", e.get("Error", ""))
                err_msg = e.get("message", e.get("Message", ""))
                print(f"  CHYBA: {err_code} – {err_msg}")
        elif resp.status_code == 401:
            print("  >>> 401 – problém s autentizací")
        else:
            print(f"  >>> HTTP {resp.status_code}")

    print(f"\n{'='*70}")
    print("HOTOVO")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
