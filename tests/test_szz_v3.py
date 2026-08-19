"""
Testy SZZ v3.0.0 – Standard EZ SZZ 3.0 (platný od 29. 7. 2026, API 3.0.0).

Bez síťové závislosti – HTTP klient je nahrazen atrapou, která zaznamenává
metodu a cestu volání.

Spuštění:  python3 -m pytest tests/test_szz_v3.py -v
"""

import pytest
from starlette.testclient import TestClient

from sez_api.app import app
from sez_api.client import SZZv2, SZZv3


class _Resp:
    status_code = 200

    def json(self):
        return {}


class _FakeClient:
    """Zaznamenává volání místo odesílání na bránu."""

    def __init__(self):
        self.volani = []

    def _zaznam(self, metoda, path, body=None):
        self.volani.append((metoda, path, body))
        return _Resp()

    def get(self, path, params=None, timeout=None):
        return self._zaznam("GET", path)

    def post(self, path, body=None, timeout=None):
        return self._zaznam("POST", path, body)

    def put(self, path, body=None, timeout=None):
        return self._zaznam("PUT", path, body)

    def patch(self, path, body=None, timeout=None):
        return self._zaznam("PATCH", path, body)


@pytest.fixture
def szz3():
    c = _FakeClient()
    return SZZv3(c), c


# --- cesty API -------------------------------------------------------------

def test_vsechny_cesty_pouzivaji_v3(szz3):
    mod, c = szz3
    mod.ciselniky()
    mod.ciselnik_polozky("krevni-skupina")
    mod.prevence("preventivniProhlidky")["vytvor"]({})
    mod.screening("kolorektalniKarcinomKoloskopie")["vyhledat"]({})
    mod.emergentni("alergie")["uprav"]("42", {})
    mod.lecive_pripravky_vytvor({})
    mod.zdravotni_zaznamy_vyhledat({})
    mod.emergentni_pdf({})

    assert c.volani, "nic se nezavolalo"
    for metoda, path, _ in c.volani:
        assert "/api/v3/" in path, f"{metoda} {path} nepoužívá v3"
        assert "/api/v2/" not in path


def test_konkretni_cesty_dle_standardu(szz3):
    mod, c = szz3
    mod.screening("karcinomProstatyVstupniPsa")["vytvor"]({})
    mod.prevence("preventivniProhlidkyGynekologie")["zneplatnit"]("7")
    mod.emergentni("krevniSkupina")["zpochybnit"]("9")

    cesty = [(m, p) for m, p, _ in c.volani]
    assert ("POST", "/sdilenyZdravotniZaznam/api/v3/screeningy/"
            "karcinomProstatyVstupniPsa") in cesty
    assert ("PATCH", "/sdilenyZdravotniZaznam/api/v3/prevence/"
            "preventivniProhlidkyGynekologie/7/zneplatnit") in cesty
    assert ("PATCH", "/sdilenyZdravotniZaznam/api/v3/emergentniZaznam/"
            "krevniSkupina/9/zpochybnit") in cesty


# --- nové typy vyšetření ---------------------------------------------------

def test_nove_screeningy_ve_v3(szz3):
    """Standard 3.0 přidal pět vyšetření, která v2 neměla."""
    mod, _ = szz3
    for typ in ("kolorektalniKarcinomKoloskopie",
                "karcinomProstatyVstupniPsa",
                "karcinomProstatyUrologickeVysetreni",
                "karcinomProstatyBioptickeVysetreni",
                "karcinomPlicPneumologickeVysetreni"):
        assert typ in SZZv3.SCREENINGY_TYPY, typ
        assert typ not in SZZv2.SCREENINGY_TYPY, f"{typ} už byl ve v2"
        mod.screening(typ)  # nesmí vyhodit


def test_hpv_screening_ma_opraveny_nazev(szz3):
    """Ve v2 byla cesta s dvojitým D (karcinomDDeloznihoHrdlaHpv), v3 to
    opravila – starý zápis se musí dál přijmout jako alias."""
    mod, c = szz3
    assert "karcinomDeloznihoHrdlaHpv" in SZZv3.SCREENINGY_TYPY
    assert "karcinomDDeloznihoHrdlaHpv" not in SZZv3.SCREENINGY_TYPY

    mod.screening("karcinomDDeloznihoHrdlaHpv")["vytvor"]({})
    assert c.volani[0][1].endswith("/screeningy/karcinomDeloznihoHrdlaHpv")


def test_neznamy_typ_vyhodi_chybu(szz3):
    mod, _ = szz3
    with pytest.raises(ValueError, match="Neznámý screening"):
        mod.screening("neexistujiciScreening")
    with pytest.raises(ValueError, match="Neznámý typ prevence"):
        mod.prevence("neexistujiciPrevence")


def test_telo_se_predava_beze_zmeny(szz3):
    """Nové položky (samoplatce, genotypyHpvTestu) prochází transparentně."""
    mod, c = szz3
    telo = {"rid": "2667873559", "samoplatce": True,
            "genotypyHpvTestu": "HPV 16, HPV 18"}
    mod.screening("karcinomDeloznihoHrdlaHpv")["vytvor"](telo)
    assert c.volani[0][2] == telo


# --- kontrola hodnot dle přílohy Validace SZZ 3.0 --------------------------

def test_kontrola_prijme_platne_hodnoty():
    assert SZZv3.zkontroluj({"vyska": 175.5, "vaha": 82.25,
                             "obvodPasu": 95, "samoplatce": False}) == []
    assert SZZv3.zkontroluj({"ntProbnp": 100000}) == []
    assert SZZv3.zkontroluj({"hladinaPsa": 1500.25, "psaDenzita": 0.15}) == []
    assert SZZv3.zkontroluj({"vysledekBbps": 9}) == []


def test_kontrola_odmitne_hodnotu_mimo_rozsah():
    vyhrady = SZZv3.zkontroluj({"ntProbnp": 100001})
    assert vyhrady and "mimo rozsah" in vyhrady[0]
    assert SZZv3.zkontroluj({"hladinaToksUgG": 501})
    assert SZZv3.zkontroluj({"objemProstaty": 1001})
    assert SZZv3.zkontroluj({"psaVelocita": 11})
    assert SZZv3.zkontroluj({"vyska": 5})


def test_kontrola_hlida_desetinna_mista():
    assert SZZv3.zkontroluj({"vyska": 175.1234})  # max 3 desetinná místa
    assert SZZv3.zkontroluj({"vysledekBbps": 4.5})  # celé číslo
    assert SZZv3.zkontroluj({"vyska": 175.123}) == []


def test_kontrola_hlida_typ_samoplatce_a_delku_textu():
    assert SZZv3.zkontroluj({"samoplatce": "ano"})
    assert SZZv3.zkontroluj({"poznamka": "x" * 301})
    assert SZZv3.zkontroluj({"poznamka": "x" * 300}) == []


# --- HTTP rozhraní ---------------------------------------------------------

def test_endpoint_katalog_popisuje_novinky_v3():
    d = TestClient(app).get("/api/szz3/katalog").json()
    assert d["status"] == 200
    data = d["data"]
    assert data["verzeApi"] == "3.0.0"
    assert data["platneOd"] == "2026-07-29"
    assert "kolorektalniKarcinomKoloskopie" in data["screeningyNoveVeV3"]
    assert len(data["screeningyNoveVeV3"]) == 5
    assert data["rozsahy"]["ntProbnp"] == {"min": 0, "max": 100000,
                                           "desetinnaMista": 0}
    assert "szz-ucast-ve-screeningu-aaa" in data["noveCiselniky"]
    assert "samoplatce" in data and "genotypyHpvTestu" in data


def test_endpoint_zkontrolovat():
    c = TestClient(app)
    ok = c.post("/api/szz3/zkontrolovat",
                json={"vyska": 175.5, "samoplatce": True}).json()
    assert ok["data"] == {"validni": True, "vyhrady": []}

    chyba = c.post("/api/szz3/zkontrolovat", json={"ntProbnp": 999999}).json()
    assert chyba["data"]["validni"] is False
    assert "mimo rozsah" in chyba["data"]["vyhrady"][0]


def test_gui_nabizi_nove_screeningy_a_prepinac_verze():
    """Sekce SZZ v UI musí nabídnout nové typy vyšetření, volbu verze API
    a zaškrtnutí samoplátce – jinak novinky nejsou uživateli dostupné."""
    html = TestClient(app).get("/").text
    for marker in ("szz2ApiVerze", "szz2Samoplatce",
                   "kolorektalniKarcinomKoloskopie",
                   "karcinomProstatyVstupniPsa",
                   "karcinomProstatyUrologickeVysetreni",
                   "karcinomProstatyBioptickeVysetreni",
                   "karcinomPlicPneumologickeVysetreni",
                   "szz2HpvscrGenotypy"):
        assert marker in html, marker
    # Volání se směruje podle zvolené verze a HPV typ se převádí.
    assert "_szz2Prefix()" in html
    assert "_szz2TypDleVerze" in html


def test_v2_zustava_dostupna():
    """Verze 2 běží paralelně, aby nasazení nemusela přejít skokem."""
    c = _FakeClient()
    SZZv2(c).screening("karcinomDDeloznihoHrdlaHpv")["vytvor"]({})
    assert "/api/v2/" in c.volani[0][1]


# --- eŽádanky 1.11.20 ------------------------------------------------------

def test_uprav_zadanku_neposila_ignorovany_typ_prijemce():
    """Od verze 1.11.20 server při vyplněném upravenyPrijemce ignoruje
    upravenyPrijemceTyp a adresátem je vždy PZS – neposíláme tedy pole,
    které by v odpovědi stejně nebylo respektováno."""
    from sez_api.client import EZadanky

    c = _FakeClient()
    EZadanky(c).uprav({"id": "abc", "upravenyPrijemce": "25488627",
                       "upravenyPrijemceTyp": "ZP", "verzeRadku": "AAA="})
    _metoda, path, body = c.volani[0]
    assert path.endswith("/UpravZadanku")
    assert "upravenyPrijemceTyp" not in body
    assert body["upravenyPrijemce"] == "25488627"


def test_uprav_zadanku_bez_prijemce_telo_nemeni():
    from sez_api.client import EZadanky

    c = _FakeClient()
    telo = {"id": "abc", "upravenyPrijemceTyp": "ZP"}
    EZadanky(c).uprav(telo)
    assert c.volani[0][2] == telo
