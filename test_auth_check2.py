#!/usr/bin/env python3
"""Kontrola autentizace napříč službami: KRP, DÚ, SZZ, eŽádanky."""

import logging
import json

from sez_client import (
    SEZAuth, SEZClient, KRP, DocasneUloziste, SZZ, ELP, EZadanky, Notifikace
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

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


def show(label, resp):
    status = resp.status_code
    ok = "OK" if status < 300 else "FAIL"
    try:
        body = json.dumps(resp.json(), ensure_ascii=False)[:200]
    except Exception:
        body = resp.text[:200]
    print(f"  {ok:4s} {status:3d}  {label:45s}  {body}")


print("Kontrola autentizace – všechny služby")
print("=" * 90)

show("Notifikace – ping",           Notifikace(client).ping())
show("Notifikace – katalog kanálů", Notifikace(client).katalog_kanalu())
show("KRP – hledání RID 7653800856", KRP(client).hledat_rid("7653800856"))
show("SZZ – alergie RID 7706120004", SZZ(client).alergie("7706120004"))
show("SZZ – léčivé přípravky",       SZZ(client).lecive_pripravky("7706120004"))
show("ELP – vyhledání posudků",       ELP(client).vyhledej_posudky({"strankovani": {"page": 1, "size": 2}}))

show("DÚ – VyhledejZasilku",
     DocasneUloziste(client).vyhledej_zasilku("2026-02-01T00:00:00+01:00", "2026-02-19T23:59:59+01:00", size=2))
show("DÚ – DejZasilku",
     DocasneUloziste(client).dej_zasilku("53cf7836-6ba9-43b7-a858-319bccf8bd6c"))

show("eŽádanky – token",             EZadanky(client).dej_token())

print("=" * 90)
