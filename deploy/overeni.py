#!/usr/bin/env python3
"""Ověření běžící instance SEZ API po nasazení.

    python3 deploy/overeni.py                       # http://127.0.0.1:8004
    python3 deploy/overeni.py http://10.84.7.146:8004

Žádná kontrola nevolá bránu NCEZ ani neposílá údaje pacienta: ověřuje se jen
to, co aplikace odpovídá sama (verze, pravidla, katalogy, validace zpráv).
Řádky „INFO“ závisí na okolí serveru (certifikát, přístup na internet) a na
výsledek nemají vliv. Skript potřebuje jen standardní knihovnu Pythonu.

Návratový kód: 0 = vše prošlo, 1 = některá kontrola selhala, 2 = služba
neodpovídá.
"""

import json
import re
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

TIMEOUT_S = 60
ZPRAVY_IG = {
    "vyjezd-zzs": "0.1.0",
    "laboratorni-vysetreni": "1.0.0",
    "obrazove-vysetreni": "1.0.0",
}
UCAST = {"karcinomProstatyUcast", "karcinomPlicUcast", "aneurysmaAbdominalniAortyUcast"}
STAVY_EZADANKY = {"2": "Neproveditelná", "4": "Dokončená", "5": "Expirovaná"}


def ocekavana_verze():
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
    except OSError:
        return None
    return m.group(1) if m else None


class Sluzba:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def volej(self, metoda, cesta, telo=None, hlavicky=None):
        """Vrací (HTTP kód, hlavičky, tělo jako text)."""
        data = None
        h = dict(hlavicky or {})
        if telo is not None:
            data = json.dumps(telo).encode("utf-8")
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + cesta, data=data, headers=h, method=metoda)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def json(self, metoda, cesta, telo=None, hlavicky=None):
        kod, _, text = self.volej(metoda, cesta, telo, hlavicky)
        if kod != 200:
            raise AssertionError(f"{metoda} {cesta} vrátilo HTTP {kod}")
        return json.loads(text)


def kontroly(s, verze):
    """Generátor dvojic (název, funkce); funkce vrací popis výsledku nebo
    vyhodí AssertionError."""

    def k_verze():
        v = s.json("GET", "/openapi.json")["info"]["version"]
        assert verze is None or v == verze, f"běží verze {v}, balíček má {verze}"
        return v
    yield "Verze aplikace", k_verze

    def k_dashboard():
        kod, _, html = s.volej("GET", "/")
        assert kod == 200, f"HTTP {kod}"
        assert 'id="revize-2026-11"' in html, "chybí box Revize 10. 11. 2026"
        assert "rev-old" in html and "rev-new" in html, "chybí zvýraznění rozdílů"
        return "box Revize 10. 11. 2026 se zvýrazněním"
    yield "Dashboard", k_dashboard

    def k_korelace():
        cid = str(uuid.uuid4())
        _, h, _ = s.volej("GET", "/api/krp/pravidla", hlavicky={"X-Correlation-Id": cid})
        assert h.get("X-Correlation-Id") == cid, "předaný identifikátor se nevrátil"
        _, h, _ = s.volej("GET", "/api/krp/pravidla", hlavicky={"X-Correlation-Id": "neplatne"})
        nahrada = h.get("X-Correlation-Id") or ""
        assert nahrada != "neplatne" and uuid.UUID(nahrada), "neplatná hodnota nebyla nahrazena"
        return "platný se vrací, neplatný se nahrazuje"
    yield "X-Correlation-Id", k_korelace

    pravidla = {}

    def k_pravidla():
        pravidla.update(s.json("GET", "/api/krp/pravidla"))
        assert pravidla["standard"]["verze"] == "1.3", pravidla["standard"]
        return f"Standard KZR 1.3, kontrola jmen: {pravidla['jmena']['rezim']}"
    yield "KRP – pravidla", k_pravidla

    def k_jmena():
        assert pravidla, "přeskočeno – bez pravidel KZR 1.3 by dotaz odešel na KRP"
        rezim = pravidla["jmena"]["rezim"]
        if rezim != "odmitnout":
            return f"přeskočeno (SEZ_KRP_KONTROLA_JMEN={rezim}), dotaz by odešel na KRP"
        j = s.json("POST", "/api/krp/hledat-jmeno",
                   {"jmeno": "Pacient", "prijmeni": "Test", "rodne_cislo": "0000000000"})
        assert j.get("status") == 422 and j.get("odeslano") is False, j
        return "zástupné jméno odmítnuto, na KRP se neodeslalo"
    yield "KRP – kontrola jmen", k_jmena

    def k_drid():
        assert pravidla, "přeskočeno – bez pravidel KZR 1.3 by požadavek odešel na KRP"
        j = s.json("POST", "/api/krp/drid/priradit", {"docasny_rid": "X123", "rid": "0000000000"})
        assert j.get("status") == 422 and j.get("odeslano") is False, j
        return "chybný tvar DRID odmítnut, na KRP se neodeslalo"
    yield "KRP – dočasný RID", k_drid

    def k_notifikace():
        vzor = s.json("GET", "/api/krp/notifikace-vzor")
        rozbor = s.json("POST", "/api/krp/notifikace-zprava", vzor["zprava"])
        assert rozbor.get("platna") is True, rozbor.get("chyby") or rozbor
        return "vzorová zpráva je platná"
    yield "KRP – notifikace", k_notifikace

    def k_szz():
        d = s.json("GET", "/api/szz3/katalog")["data"]
        assert d["verzeStandardu"] == "3.1", d["verzeStandardu"]
        chybi = UCAST - set(d["screeningy"])
        assert not chybi, f"chybí služby účasti: {sorted(chybi)}"
        return f"Standard {d['verzeStandardu']}, API {d['verzeApi']}, tři služby účasti"
    yield "SZZ v3", k_szz

    def k_ezadanky():
        stavy = s.json("GET", "/api/ezadanky/v2/katalog")["stavy"]
        for kod, nazev in STAVY_EZADANKY.items():
            assert stavy.get(kod) == nazev, f"stav {kod} je {stavy.get(kod)!r}, má být {nazev!r}"
        return "stavy 2 Neproveditelná, 4 Dokončená, 5 Expirovaná"
    yield "eŽádanky v2", k_ezadanky

    kategorie = []

    def k_zpravy_katalog():
        typy = {t["kategorie"]: t for t in s.json("GET", "/api/zpravy/katalog")["typy"]}
        kategorie.extend(typy)
        for kat, ig in ZPRAVY_IG.items():
            assert typy[kat]["ig_verze"] == ig, f"{kat}: IG {typy[kat]['ig_verze']}, má být {ig}"
        return ", ".join(f"{k} {typy[k]['ig_verze']}" for k in typy)
    yield "Zprávy eZD – verze IG", k_zpravy_katalog

    def k_zpravy_ukazky():
        assert kategorie, "katalog zpráv se nenačetl"
        for kat in kategorie:
            v = s.json("GET", f"/api/zpravy/ukazka/{kat}")["validace"]
            assert v["valid"], f"{kat}: {v['errors'][:2]}"
        return f"{len(kategorie)} ukázek projde validací"
    yield "Zprávy eZD – ukázky", k_zpravy_ukazky

    def k_lab_zrusena_sekce():
        bundle = s.json("GET", "/api/zpravy/ukazka/laboratorni-vysetreni")["bundle"]
        sekce = bundle["entry"][0]["resource"]["section"]
        sekce.append({"title": "Poznámky",
                      "code": {"coding": [{"system": "http://loinc.org", "code": "48767-8"}]},
                      "text": {"status": "generated",
                               "div": '<div xmlns="http://www.w3.org/1999/xhtml">x</div>'}})
        v = s.json("POST", "/api/zpravy/validovat",
                   {"kategorie": "laboratorni-vysetreni", "bundle": bundle})
        assert not v["valid"], "zpráva se zrušenou sekcí annotations prošla validací"
        return "zrušená sekce annotations neprojde validací"
    yield "Zprávy eZD – laboratoř", k_lab_zrusena_sekce

    def k_epoukaz():
        d = s.json("GET", "/api/sukl/erecept/diagnose")["data"]
        assert d["verzeRozhraniEPoukaz"] == "202605A", d["verzeRozhraniEPoukaz"]
        return f"verze rozhraní 202605A, režim {d.get('mode')}"
    yield "SÚKL ePoukaz", k_epoukaz

    def k_katalog():
        sluzby = s.json("GET", "/api/debug/jwt")["services"]
        assert "SZZ_v3" in sluzby, "v katalogu chybí SZZ_v3"
        assert sluzby["KRP"]["version"].startswith("v3.0.6"), sluzby["KRP"]["version"]
        return f"{len(sluzby)} služeb, KRP v3.0.6, SZZ_v3"
    yield "Katalog služeb", k_katalog


def informace(s):
    """Stav závislý na okolí serveru; výsledek ověření neovlivňuje."""
    kod, _, text = s.volej("GET", "/internal/health")
    try:
        j = json.loads(text)
    except ValueError:
        j = {}
    if kod == 200 and j.get("ok"):
        yield f"interní API: prostředí {j.get('prostredi')}, KRP {j.get('krpVerze')}"
    else:
        yield f"interní API: HTTP {kod} – {j.get('error') or text[:120]}"

    try:
        d = s.json("GET", "/api/sukl/dlp/status")["data"]
        if d.get("chyba"):
            yield f"SÚKL DLP: {d['chyba']}"
        else:
            yield f"SÚKL DLP: {d.get('pocet')} přípravků z {d.get('url')}"
    except (AssertionError, OSError, ValueError, KeyError) as e:
        yield f"SÚKL DLP: {e}"


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8004"
    s = Sluzba(base)
    verze = ocekavana_verze()
    print(f"Ověření {s.base}" + (f" (balíček {verze})" if verze else ""))
    try:
        s.volej("GET", "/openapi.json")
    except OSError as e:
        print(f"CHYBA  služba neodpovídá: {e}")
        return 2

    selhalo = 0
    for nazev, kontrola in kontroly(s, verze):
        try:
            print(f"OK     {nazev}: {kontrola()}")
        except (AssertionError, OSError, ValueError, KeyError, TypeError) as e:
            selhalo += 1
            print(f"CHYBA  {nazev}: {e}")
    for radek in informace(s):
        print(f"INFO   {radek}")

    print(f"Výsledek: {'vše prošlo' if not selhalo else f'selhalo kontrol: {selhalo}'}")
    return 1 if selhalo else 0


if __name__ == "__main__":
    sys.exit(main())
