#!/usr/bin/env python3
"""
Pytloun pro všechno (mTLS + JWT signing) → DejZasilku.
Zkouší různé varianty client_id.
"""

import json
import warnings
from sez_client import SEZAuth, SEZClient, DocasneUloziste, Notifikace

warnings.filterwarnings("ignore")

P12 = "/Users/mira/Downloads/pytloun.p12"
PWD = "apofis"

CLIENT_IDS = [
    "00023833_Testovani_KZR (Pytloun)",
    "00023833_98e113f5c779b51a638c9a562f4a3a13e54b823ad59b68552005033ae325e6b4",
    "00023833_Testovani_KZR",
]

print("=" * 70)
print("Pytloun jako jediný cert (mTLS + JWT) – hledáme správný client_id")
print("=" * 70)

for cid in CLIENT_IDS:
    print(f"\n--- client_id: {cid[:60]}{'...' if len(cid)>60 else ''}")

    try:
        auth = SEZAuth(
            client_id=cid,
            p12_path=P12,
            p12_password=PWD,
        )
    except Exception as e:
        print(f"  Chyba načtení: {e}")
        continue

    client = SEZClient(auth)

    r = Notifikace(client).ping()
    print(f"  Notif ping: {r.status_code}")

    du = DocasneUloziste(client)
    r = du.vyhledej_zasilku("2026-02-01T00:00:00+01:00", "2026-02-20T23:59:59+01:00", size=2)
    print(f"  DÚ Vyhledej: {r.status_code}", end="")
    try:
        d = r.json()
        if isinstance(d, dict) and "zasilka" in d:
            print(f" ({len(d['zasilka'])} zásilek)")
        elif isinstance(d, dict) and "Errors" in d:
            print(f" – {d['Errors'][0].get('Message','')[:80]}")
        else:
            print(f" – {json.dumps(d, ensure_ascii=False)[:120]}")
    except Exception:
        print(f" – {r.text[:120]}")

    if r.status_code < 300:
        items = d.get("zasilka", d) if isinstance(d, dict) else d
        if items and isinstance(items, list):
            zid = items[0]["id"]
            r2 = du.dej_zasilku(zid)
            print(f"  DÚ DejZasilku ({zid[:20]}): {r2.status_code}")
            try:
                d2 = r2.json()
                print(f"    {json.dumps(d2, ensure_ascii=False)[:300]}")
                if r2.status_code < 300:
                    with open(f"stazene_zasilky/zasilka_{zid}.json", "w", encoding="utf-8") as f:
                        json.dump(d2, f, ensure_ascii=False, indent=2)
                    print(f"    >>> ULOŽENO!")
            except Exception:
                print(f"    {r2.text[:300]}")

    auth.cleanup()

print(f"\n{'='*70}")
print("HOTOVO")
