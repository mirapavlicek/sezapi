#!/usr/bin/env python3
"""
Test SEZ API Gateway - dle dokumentace MZČR:
  JWT assertion jde PŘÍMO do hlavičky na gateway, žádný token endpoint.
  mTLS řeší pytloun.p12
"""

import logging
import json
import sys

from sez_client import SEZAuth, SEZClient, KRP, DocasneUloziste, SZZ

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("test")

# --- Konfigurace ---
CLIENT_ID = "25488627_KrajskaZdravotniVerejnyTest"

# Jeden certifikát EZCA II pro mTLS i JWT signing (dle oficiální testovací aplikace MZČR)
P12_PATH = "/Users/mira/Downloads/krajska_zdravotni.pfx"
P12_PASSWORD = "Tre-987set*krajzdra321/"


def main():
    print("=" * 60)
    print("SEZ API Gateway – test (JWT assertion → Gateway)")
    print("=" * 60)

    # 1. Inicializace
    print("\n[1] Načítám certifikát EZCA II...")
    try:
        auth = SEZAuth(
            client_id=CLIENT_ID,
            p12_path=P12_PATH,
            p12_password=P12_PASSWORD,
        )
        print("  OK – certifikát načten (mTLS + JWT signing)")
    except Exception as e:
        print(f"  CHYBA: {e}")
        sys.exit(1)

    # 2. Ukázka JWT assertion
    assertion = auth.build_assertion()
    header_part = assertion.split(".")[0]
    payload_part = assertion.split(".")[1]

    import base64
    pad = lambda s: s + "=" * (4 - len(s) % 4)
    print(f"\n[2] JWT assertion vytvořena:")
    print(f"  Header:  {json.loads(base64.urlsafe_b64decode(pad(header_part)))}")
    print(f"  Payload: {json.loads(base64.urlsafe_b64decode(pad(payload_part)))}")
    print(f"  Token:   {assertion[:60]}...")

    # 3. Test API
    client = SEZClient(auth)

    def show(label, resp, max_len=600):
        print(f"\n{label}")
        print(f"  Status: {resp.status_code}")
        try:
            data = resp.json()
            print(f"  Response: {json.dumps(data, ensure_ascii=False, indent=2)[:max_len]}")
            return data
        except Exception:
            print(f"  Body: {resp.text[:max_len]}")
            return None

    # 3a. KRP – hledání pacienta
    krp = KRP(client)
    show("[3a] KRP – hledání pacienta dle RID", krp.hledat_rid("7706120004"))

    # 3b. Dočasné úložiště
    du = DocasneUloziste(client)
    data = show("[3b] Dočasné úložiště – vyhledání zásilek",
                du.vyhledej_zasilku("2025-01-01T00:00:00+01:00", "2026-02-19T23:59:59+01:00"))
    if data:
        items = data if isinstance(data, list) else data.get("zasilky", data.get("items", []))
        if items and isinstance(items, list) and len(items) > 0:
            zid = items[0].get("zasilkaId") or items[0].get("id")
            if zid:
                resp2 = du.dej_zasilku(zid)
                d2 = show(f"[3c] Stahování zásilky {zid}", resp2, 1000)
                if d2 and resp2.status_code < 300:
                    with open(f"zasilka_{zid}.json", "w", encoding="utf-8") as f:
                        json.dump(d2, f, ensure_ascii=False, indent=2)
                    print(f"  Uloženo do zasilka_{zid}.json")

    # 3d. SZZ – emergentní záznam
    szz = SZZ(client)
    show("[3d] SZZ – alergie", szz.alergie("7706120004"))

    # 3e. eŽádanky – vyhledání
    from sez_client import EZadanky
    ez = EZadanky(client)
    show("[3e] eŽádanky – vyhledání", ez.vyhledej_zadanku({
        "datumOd": "2025-01-01", "datumDo": "2026-02-19",
        "strankovani": {"page": 1, "size": 5}
    }))

    # 3f. Elektronické posudky – vyhledání
    from sez_client import ELP
    elp = ELP(client)
    show("[3f] ELP – vyhledání posudků", elp.vyhledej_posudky({
        "strankovani": {"page": 1, "size": 5}
    }))

    # 3g. Notifikace – vyhledání
    from sez_client import Notifikace
    notif = Notifikace(client)
    show("[3g] Notifikace – katalog kanálů", notif.katalog_kanalu())

    print("\n" + "=" * 60)
    print("HOTOVO")
    print("=" * 60)


if __name__ == "__main__":
    main()
