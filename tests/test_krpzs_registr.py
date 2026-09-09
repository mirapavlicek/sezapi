"""
Testy hromadného stažení registru poskytovatelů a lokálního fulltextu.

Vše bez sítě: klient KRPZS je nahrazený falešným, který vrací odpovědi
podle připravených dat a počítá souběžnost.
"""

import json
import threading
import time

import pytest
from starlette.testclient import TestClient

from sez_api import krpzs_registr as kr
from sez_api.app import app
from sez_api import app as app_mod


# ---------------------------------------------------------------------------
# Falešný klient
# ---------------------------------------------------------------------------

class _Odpoved:
    def __init__(self, status, telo=None, headers=None):
        self.status_code = status
        self._telo = telo
        self.headers = headers or {}
        self.text = json.dumps(telo) if telo is not None else ""

    def json(self):
        if self._telo is None:
            raise ValueError("prázdné tělo")
        return self._telo


def _pole(hodnota):
    return {"hodnota": hodnota, "referencni": False, "stav": "Spravny", "zdroj": "NRPZS"}


def _rozhodnuti(typ="VZN", do=None):
    return {"typRozhodnuti": _pole(typ), "platnostOd": _pole("2020-01-01"),
            "platnostDo": _pole(do)}


def _misto(obec, kraj, sluzby=None, luzka=0):
    return {
        "adresa": {"obec": obec, "krajKod": kraj, "ulice": "Hlavní", "psc": 10000},
        "sluzby": sluzby or [],
        "zdravotnickeZarizeni": [{"oddeleni": [{"pocetLuzek": _pole(luzka)}]}] if luzka else [],
    }


def _sluzba(obory, forma="100", druh=None):
    return {"oborPece": [_pole(o) for o in obory], "formaPece": _pole(forma),
            "druhPece": _pole(druh), "nazevSluzby": _pole(None)}


# Data "registru": IČO -> (záznam pro výpis kraje, detail pro hledat/ico)
def _zaznam_vypisu(ico, mista, rozhodnuti, kontakty=None):
    return {
        "ico": ico,
        "opravneni": [{"mistaPoskytovani": mista, "rozhodnuti": rozhodnuti,
                       "spravniOrgan": "KA"}],
        "verejneKontakty": {"datovaSchranka": _pole((kontakty or {}).get("ds")),
                            "email": _pole((kontakty or {}).get("email")),
                            "telefon": _pole(None), "www": None},
    }


def _detail(ico, nazev, obec, kraj, mista, stav="Platny"):
    return {
        "stavZaznamu": stav, "ico": _pole(ico), "poskytovatelNazev": _pole(nazev),
        "adresaSidla": {"obec": obec, "krajKod": kraj, "psc": 15000, "ulice": "V úvalu",
                        "cisloPopisne": 84, "cisloOrientacni": "1"},
        "datovaSchranka": _pole("abc123"), "kontaktniEmail": _pole(f"info@{ico}.cz"),
        "kontaktniTelefon": _pole("+420123"), "kontaktniWeb": _pole(None),
        "typPoskytovatele": None,
        "opravneni": [{"mistaPoskytovani": mista, "rozhodnuti": [_rozhodnuti()]}],
    }


MISTA_MOTOL = [_misto("Praha", "19", [_sluzba(["211", "501"])], luzka=1200),
               _misto("Kladno", "27", [_sluzba(["001"], forma="200")])]
MISTA_KZ = [_misto("Ústí nad Labem", "60", [_sluzba(["101"])], luzka=800)]
MISTA_ZANIKLY = [_misto("Brno", "116")]
MISTA_BEZ = [_misto("Plzeň", "43")]

DATA = {
    # aktivní, ve dvou krajích
    "00064203": (
        {"19": _zaznam_vypisu("00064203", MISTA_MOTOL[:1], [_rozhodnuti("VZN"), _rozhodnuti("ZME")],
                              {"ds": "nk8bxj3"}),
         "27": _zaznam_vypisu("00064203", MISTA_MOTOL[1:], [_rozhodnuti("VZN")])},
        _detail("00064203", "Fakultní nemocnice Motol a Homolka", "Praha", "19", MISTA_MOTOL),
    ),
    "25488627": (
        {"60": _zaznam_vypisu("25488627", MISTA_KZ, [_rozhodnuti("VZN")])},
        _detail("25488627", "Krajská zdravotní, a.s.", "Ústí nad Labem", "60", MISTA_KZ),
    ),
    # zaniklý – hledat/ico ho nevrátí
    "11111111": (
        {"116": _zaznam_vypisu("11111111", MISTA_ZANIKLY,
                               [_rozhodnuti("VZN"), _rozhodnuti("ZAN", do="2021-05-01")])},
        None,
    ),
    # bez rozhodnutí – historický
    "22222222": (
        {"43": _zaznam_vypisu("22222222", MISTA_BEZ, [])},
        None,
    ),
    # aktivní podle výpisu, ale hledat/ico ho nezná (404)
    "33333333": (
        {"19": _zaznam_vypisu("33333333", [_misto("Praha", "19")], [_rozhodnuti("VZN")])},
        None,
    ),
}


class FalesnyKRPZS:
    """Napodobuje KRPZS modul; sdílený mezi všemi klienty testu."""

    def __init__(self, data=DATA, zpozdeni=0.0, chyby=None, odmitnuti_429=None):
        self.data = data
        self.zpozdeni = zpozdeni
        self.chyby = dict(chyby or {})            # ico -> status, nebo Exception
        self.odmitnuti_429 = dict(odmitnuti_429 or {})  # ico -> kolikrát vrátit 429
        self.lock = threading.Lock()
        self.soubezne = 0
        self.max_soubezne = 0
        self.volani = {"misto": 0, "ico": 0}
        self.vlakna = set()

    def _vstup(self, druh):
        with self.lock:
            self.soubezne += 1
            self.max_soubezne = max(self.max_soubezne, self.soubezne)
            self.volani[druh] += 1
            self.vlakna.add(threading.get_ident())

    def _vystup(self):
        with self.lock:
            self.soubezne -= 1

    def hledat_misto(self, kraj_kod=None, ucel="OVERENI", **_):
        self._vstup("misto")
        try:
            time.sleep(self.zpozdeni)
            zaznamy = [vypis[kraj_kod] for vypis, _ in self.data.values() if kraj_kod in vypis]
            if not zaznamy:
                return _Odpoved(404, {"message": "Poskytovatel nebyl nalezen"})
            return _Odpoved(200, {"odpovedData": zaznamy})
        finally:
            self._vystup()

    def hledat_ico(self, ico, ucel="OVERENI"):
        self._vstup("ico")
        try:
            time.sleep(self.zpozdeni)
            with self.lock:
                zbyva = self.odmitnuti_429.get(ico, 0)
                if zbyva:
                    self.odmitnuti_429[ico] = zbyva - 1
                    return _Odpoved(429, {"message": "Too many"}, {"Retry-After": "0"})
            chyba = self.chyby.get(ico)
            if isinstance(chyba, Exception):
                raise chyba
            if chyba:
                return _Odpoved(chyba, {"message": "chyba"})
            detail = self.data.get(ico, (None, None))[1]
            if detail is None:
                return _Odpoved(404, {"message": "Poskytovatel nebyl nalezen"})
            return _Odpoved(200, {"odpovedData": [detail]})
        finally:
            self._vystup()


@pytest.fixture
def falesny(monkeypatch):
    """Nahradí KRPZS modul tak, že každý klient z továrny sdílí jeden falešný."""
    f = FalesnyKRPZS()

    class _KRPZS:
        def __init__(self, client):
            self.c = client
            self.f = f

        def hledat_misto(self, *a, **k):
            return f.hledat_misto(*a, **k)

        def hledat_ico(self, *a, **k):
            return f.hledat_ico(*a, **k)

    import sez_api.client as client_mod
    monkeypatch.setattr(client_mod, "KRPZS", _KRPZS)
    monkeypatch.setattr(kr, "PAUZA_429_S", 0.01)
    monkeypatch.setattr(kr, "PAUZA_SITE_S", (0.01,))
    return f


def _tovarna_pocitaci():
    """Továrna, která počítá, kolik klientů vzniklo."""
    pocet = {"n": 0}
    lock = threading.Lock()

    def tovarna():
        with lock:
            pocet["n"] += 1
        return object()
    tovarna.pocet = pocet
    return tovarna


# ---------------------------------------------------------------------------
# Pomocné funkce
# ---------------------------------------------------------------------------

def test_bez_diakritiky():
    assert kr.bez_diakritiky("Fakultní nemocnice Motol a Homolka") == "fakultni nemocnice motol a homolka"
    assert kr.bez_diakritiky("ÚSTÍ nad Labem") == "usti nad labem"
    assert kr.bez_diakritiky(None) == ""


def test_je_aktivni_podle_rozhodnuti():
    assert kr.je_aktivni(DATA["00064203"][0]["19"])
    assert not kr.je_aktivni(DATA["11111111"][0]["116"]), "ZAN s platnostDo = zaniklý"
    assert not kr.je_aktivni(DATA["22222222"][0]["43"]), "bez rozhodnutí = historický"
    zruseny = _zaznam_vypisu("x", [], [_rozhodnuti("ZRR")])
    assert not kr.je_aktivni(zruseny)


def test_sloucit_podle_ico_spoji_kraje_a_kontakty():
    vypisy = {"19": [DATA["00064203"][0]["19"], DATA["33333333"][0]["19"]],
              "27": [DATA["00064203"][0]["27"]],
              "116": [DATA["11111111"][0]["116"]]}
    s = kr.sloucit_podle_ico(vypisy)
    assert set(s) == {"00064203", "33333333", "11111111"}
    motol = s["00064203"]
    assert motol["kraje"] == {"19", "27"}
    assert motol["obce"] == {"Praha", "Kladno"}
    assert motol["pocetMist"] == 2
    assert motol["aktivni"] is True
    assert motol["kontakty"]["datovaSchranka"] == "nk8bxj3"
    assert s["11111111"]["aktivni"] is False


def test_zkompaktuj_vybere_podstatne():
    z = kr.zkompaktuj(DATA["00064203"][1])
    assert z["ico"] == "00064203"
    assert z["nazev"] == "Fakultní nemocnice Motol a Homolka"
    assert z["sidlo"]["obec"] == "Praha" and z["sidlo"]["krajKod"] == "19"
    assert z["kraje"] == ["19", "27"]
    assert z["obce"] == ["Kladno", "Praha"]
    assert z["oboryPece"] == ["001", "211", "501"]
    assert z["formyPece"] == ["100", "200"]
    assert z["pocetMist"] == 2 and z["pocetLuzek"] == 1200
    assert z["kontakty"]["email"] == "info@00064203.cz"
    # nic objemného z opravneni se nepřenáší
    assert "opravneni" not in z


def test_tovarna_klientu_tichy_404():
    from types import SimpleNamespace
    from sez_api.client import SEZClient
    auth = SimpleNamespace(tls_cert=("cert.pem", "key.pem"), config=None)
    klient = kr.tovarna_klientu(auth)()
    assert isinstance(klient, SEZClient)
    assert 404 in klient.TICHE_STAVY and 500 not in klient.TICHE_STAVY
    assert not SEZClient.TICHE_STAVY, "výchozí klient loguje všechny chyby"


# ---------------------------------------------------------------------------
# Fáze 1 a 2
# ---------------------------------------------------------------------------

def test_stahni_kraje_vsechny_paralelne(falesny):
    falesny.zpozdeni = 0.05
    t0 = time.monotonic()
    vypisy = kr.stahni_kraje(_tovarna_pocitaci())
    trvani = time.monotonic() - t0
    assert set(vypisy) == set(kr.KRAJE)
    assert falesny.volani["misto"] == 14
    assert falesny.max_soubezne > 1, "kraje se mají stahovat souběžně"
    assert trvani < 14 * 0.05, "sekvenčně by to trvalo 0,7 s"
    assert len(vypisy["19"]) == 2 and vypisy["51"] == []


def test_stahni_kraje_odmitne_neznamy_kod(falesny):
    with pytest.raises(ValueError):
        kr.stahni_kraje(_tovarna_pocitaci(), kraje=["999"])


def test_stahni_kraje_chyba_brany_vyhodi(falesny, monkeypatch):
    def rozbite(kraj_kod=None, **_):
        return _Odpoved(500, {"message": "boom"})
    monkeypatch.setattr(falesny, "hledat_misto", rozbite)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        kr.stahni_kraje(_tovarna_pocitaci(), kraje=["19"])


def test_dotahni_detaily_jeden_klient_na_vlakno(falesny):
    falesny.zpozdeni = 0.02
    tovarna = _tovarna_pocitaci()
    icos = [f"{i:08d}" for i in range(40)] + list(DATA)
    vysledky = kr.dotahni_detaily(icos, tovarna, paralelismus=8)
    assert falesny.max_soubezne > 1
    assert falesny.max_soubezne <= 8
    # klientů vzniklo nejvýš tolik, kolik vláken – ne jeden na dotaz
    assert 1 <= tovarna.pocet["n"] <= 8
    assert len(falesny.vlakna) == tovarna.pocet["n"]
    assert vysledky["00064203"]["nazev"].startswith("Fakultní")
    assert vysledky["11111111"] is None
    assert vysledky["00000001"] is None
    assert len(vysledky) == len(set(icos))


def test_dotahni_detaily_paralelismus_je_omezen(falesny):
    falesny.zpozdeni = 0.01
    kr.dotahni_detaily([f"{i:08d}" for i in range(20)], _tovarna_pocitaci(),
                       paralelismus=10_000)
    assert falesny.max_soubezne <= kr.MAX_PARALELISMUS


def test_dotahni_detaily_opakuje_po_429(falesny):
    falesny.odmitnuti_429["00064203"] = 2
    prubeh = kr.Prubeh()
    vysledky = kr.dotahni_detaily(["00064203"], _tovarna_pocitaci(), prubeh=prubeh)
    assert vysledky["00064203"]["nazev"].startswith("Fakultní")
    assert prubeh.snapshot()["pocet429"] == 2
    assert falesny.volani["ico"] == 3


def test_dotahni_detaily_429_po_vycerpani_je_chyba(falesny):
    falesny.odmitnuti_429["00064203"] = kr.OPAKOVANI_429 + 5
    prubeh = kr.Prubeh()
    vysledky = kr.dotahni_detaily(["00064203"], _tovarna_pocitaci(), prubeh=prubeh)
    assert "00064203" not in vysledky
    snap = prubeh.snapshot()
    assert snap["ico"]["chyb"] == 1
    assert snap["chyby"][0]["kde"] == "00064203"
    assert "429" in snap["chyby"][0]["chyba"]


def test_sitova_chyba_se_opakuje(falesny, monkeypatch):
    """Přerušený přenos těla (ChunkedEncodingError) SEZClient neopakuje –
    registr ano, u výpisu kraje i detailu."""
    import requests
    monkeypatch.setattr(kr, "PAUZA_SITE_S", (0.01,))
    puvodni_misto, puvodni_ico = falesny.hledat_misto, falesny.hledat_ico
    selhani = {"misto": 2, "ico": 1}

    def misto(kraj_kod=None, **k):
        if selhani["misto"]:
            selhani["misto"] -= 1
            raise requests.exceptions.ChunkedEncodingError("Connection broken")
        return puvodni_misto(kraj_kod=kraj_kod, **k)

    def ico(i, **k):
        if selhani["ico"]:
            selhani["ico"] -= 1
            raise ConnectionResetError("reset")
        return puvodni_ico(i, **k)

    monkeypatch.setattr(falesny, "hledat_misto", misto)
    monkeypatch.setattr(falesny, "hledat_ico", ico)
    prubeh = kr.Prubeh()
    index = kr.stahni_registr(_tovarna_pocitaci(), kraje=["19"], prubeh=prubeh)
    assert index["kraje"]["19"] == 2
    assert index["pocetChyb"] == 0
    assert index["pocetSitovychChyb"] == 3
    assert prubeh.snapshot()["pocetSitovychChyb"] == 3


def test_sitova_chyba_po_vycerpani_shodi_kraj(falesny, monkeypatch):
    import requests
    monkeypatch.setattr(kr, "PAUZA_SITE_S", (0.01,))

    def misto(kraj_kod=None, **k):
        raise requests.exceptions.ChunkedEncodingError("Connection broken")
    monkeypatch.setattr(falesny, "hledat_misto", misto)
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        kr.stahni_kraje(_tovarna_pocitaci(), kraje=["19"])


def test_dotahni_detaily_chyba_jednoho_ico_nezastavi_ostatni(falesny):
    falesny.chyby["25488627"] = ConnectionError("spadlo spojení")
    falesny.chyby["33333333"] = 500
    prubeh = kr.Prubeh()
    vysledky = kr.dotahni_detaily(list(DATA), _tovarna_pocitaci(), paralelismus=4,
                                  prubeh=prubeh)
    assert "00064203" in vysledky
    assert "25488627" not in vysledky and "33333333" not in vysledky
    snap = prubeh.snapshot()
    assert snap["ico"]["chyb"] == 2
    assert snap["ico"]["hotovo"] == len(DATA)
    assert snap["ico"]["nalezeno"] == 1
    assert snap["ico"]["nenalezeno"] == 2


def test_dotahni_detaily_lze_zastavit(falesny):
    falesny.zpozdeni = 0.02
    stop = threading.Event()
    stop.set()
    with pytest.raises(kr.Zastaveno):
        kr.dotahni_detaily([f"{i:08d}" for i in range(50)], _tovarna_pocitaci(),
                           paralelismus=4, stop=stop)
    assert falesny.volani["ico"] == 0


# ---------------------------------------------------------------------------
# Celý běh a index
# ---------------------------------------------------------------------------

def test_stahni_registr_sestavi_index(falesny, tmp_path):
    soubor = tmp_path / "registr.json"
    prubeh = kr.Prubeh()
    index = kr.stahni_registr(_tovarna_pocitaci(), paralelismus=4, vystup=soubor,
                              prostredi="PROD", prubeh=prubeh)
    assert index["pocetIcoVypis"] == 5
    assert index["pocetIcoAktivnich"] == 3
    assert index["pocetDotazano"] == 3, "historická IČO se nedotazují"
    assert index["pocetNalezeno"] == 2
    assert index["pocetNenalezeno"] == 1
    assert index["pocetChyb"] == 0
    assert index["kraje"]["19"] == 2 and index["kraje"]["51"] == 0
    assert falesny.volani["ico"] == 3

    podle = {z["ico"]: z for z in index["poskytovatele"]}
    assert set(podle) == set(DATA)
    motol = podle["00064203"]
    assert motol["detail"] is True and motol["aktivni"] is True
    assert motol["nazev"] == "Fakultní nemocnice Motol a Homolka"
    assert motol["kraje"] == ["19", "27"]
    assert motol["kontakty"]["datovaSchranka"] == "abc123", "detail má přednost"
    # nenalezený aktivní
    assert podle["33333333"]["detail"] is False
    assert podle["33333333"]["stavZaznamu"] == "Nenalezen"
    # historický – nedotazovaný, ale ve výpisu zůstává s kraji/obcemi
    hist = podle["11111111"]
    assert hist["detail"] is False and hist["aktivni"] is False
    assert hist["stavZaznamu"] == "Nedotazano"
    assert hist["obce"] == ["Brno"]

    ulozeny = kr.nacti_registr(soubor)
    assert ulozeny["pocetNalezeno"] == 2
    assert len(ulozeny["poskytovatele"]) == 5
    snap = prubeh.snapshot()
    assert snap["bezi"] is False and snap["faze"] == "hotovo"
    assert snap["vysledek"]["pocetNalezeno"] == 2
    assert "poskytovatele" not in snap["vysledek"]


def test_stahni_registr_vsechny_a_limit(falesny):
    index = kr.stahni_registr(_tovarna_pocitaci(), jen_aktivni=False, limit=2)
    assert index["pocetDotazano"] == 2
    assert falesny.volani["ico"] == 2
    # limit bere IČO seřazená, tedy 00064203 a 11111111
    podle = {z["ico"]: z for z in index["poskytovatele"]}
    assert podle["00064203"]["detail"] is True
    assert podle["11111111"]["stavZaznamu"] == "Nenalezen"
    assert podle["25488627"]["stavZaznamu"] == "Nedotazano"


def test_stahni_registr_podmnozina_kraju(falesny):
    index = kr.stahni_registr(_tovarna_pocitaci(), kraje=["60"])
    assert list(index["kraje"]) == ["60"]
    assert index["pocetIcoVypis"] == 1
    assert falesny.volani["misto"] == 1


def test_stahni_registr_chyba_kraje_oznaci_prubeh(falesny, monkeypatch):
    def rozbite(kraj_kod=None, **_):
        return _Odpoved(503, {"message": "nedostupné"})
    monkeypatch.setattr(falesny, "hledat_misto", rozbite)
    prubeh = kr.Prubeh()
    with pytest.raises(RuntimeError):
        kr.stahni_registr(_tovarna_pocitaci(), kraje=["19"], prubeh=prubeh)
    snap = prubeh.snapshot()
    assert snap["faze"] == "chyba" and snap["bezi"] is False
    assert "503" in snap["zprava"]


def test_prubeh_snapshot_je_bezpecny_a_pocita_odhad():
    p = kr.Prubeh()
    p.start("detaily")
    p.nastav(ico_celkem=100)
    p.zacatek = time.time() - 60
    p.faze_zacatek = time.time() - 10
    p.pricti(ico_hotovo=50, ico_nalezeno=40, ico_nenalezeno=10)
    snap = p.snapshot()
    assert snap["bezi"] and snap["faze"] == "detaily"
    assert snap["ico"] == {"celkem": 100, "hotovo": 50, "nalezeno": 40,
                           "nenalezeno": 10, "chyb": 0}
    assert 4 <= snap["rychlostZaS"] <= 6
    assert 8 <= snap["odhadZbyvaS"] <= 13
    for i in range(kr.Prubeh.MAX_CHYB + 10):
        p.chyba(str(i), "x")
    snap = p.snapshot()
    assert snap["ico"]["chyb"] == kr.Prubeh.MAX_CHYB + 10
    assert len(snap["chyby"]) == kr.Prubeh.MAX_CHYB


# ---------------------------------------------------------------------------
# Fulltext
# ---------------------------------------------------------------------------

@pytest.fixture
def index(falesny):
    return kr.stahni_registr(_tovarna_pocitaci(), paralelismus=2)


def test_hledat_bez_diakritiky_a_castecne(index):
    for dotaz in ("homolka", "HOMOLKA", "homol", "motol", "fakultni nemocnice motol",
                  "nemocnice homolka", "00064203", "praha motol"):
        nalezeno = kr.hledat(index, dotaz)
        assert [z["ico"] for z in nalezeno] == ["00064203"], dotaz


def test_hledat_vsechna_slova_musi_sedet(index):
    assert kr.hledat(index, "motol krajska") == []
    assert kr.hledat(index, "nemocnice") and len(kr.hledat(index, "nemocnice")) == 1


def test_hledat_radi_presnou_shodu_a_zacatek_nejdriv(index):
    index["poskytovatele"].append({"ico": "99999999", "nazev": "Homolka Plus",
                                  "sidlo": {"obec": "Praha"}, "kraje": ["19"], "obce": []})
    index["poskytovatele"].append({"ico": "88888888", "nazev": "Homolka",
                                  "sidlo": {"obec": "Praha"}, "kraje": ["19"], "obce": []})
    assert [z["ico"] for z in kr.hledat(index, "homolka")] == ["88888888", "99999999", "00064203"]


def test_hledat_filtry(index):
    assert [z["ico"] for z in kr.hledat(index, "", kraj="60")] == ["25488627"]
    assert [z["ico"] for z in kr.hledat(index, "", kraj="27")] == ["00064203"]
    assert kr.hledat(index, "", kraj="51") == []
    assert [z["ico"] for z in kr.hledat(index, "", obor="101")] == ["25488627"]
    assert [z["ico"] for z in kr.hledat(index, "", obec="usti")] == ["25488627"]
    assert [z["ico"] for z in kr.hledat(index, "", obec="kladno")] == ["00064203"]
    assert kr.hledat(index, "homolka", kraj="60") == []


def test_hledat_preskoci_zaznamy_bez_nazvu_a_omezi_pocet(index):
    assert kr.hledat(index, "", kraj="116") == [], "zaniklý bez názvu se nevrací"
    assert len(kr.hledat(index, "", kraj="116", jen_s_nazvem=False)) == 1
    assert len(kr.hledat(index, "a", limit=1)) == 1


# ---------------------------------------------------------------------------
# Endpointy
# ---------------------------------------------------------------------------

@pytest.fixture
def registr_app(falesny, tmp_path, monkeypatch):
    monkeypatch.setattr(kr, "vychozi_soubor",
                        lambda env_key: tmp_path / f"registr_{env_key}.json")
    monkeypatch.setattr(app_mod, "_registr_prubeh", None)
    monkeypatch.setattr(app_mod, "_registr_vlakno", None)
    monkeypatch.setattr(app_mod, "_registr_cache",
                        {"cesta": None, "otisk": None, "index": None})
    monkeypatch.setattr(app_mod, "_auth", object())
    # Továrna staví SEZClient(auth); s falešným KRPZS klient nic nedělá.
    monkeypatch.setattr(kr, "tovarna_klientu", lambda auth: (lambda: object()))
    monkeypatch.setattr(app_mod.SEZConfig, "ENVIRONMENT", "PROD")
    return TestClient(app), tmp_path


def _pockej_na_konec(client, timeout=10):
    konec = time.time() + timeout
    while time.time() < konec:
        stav = client.get("/api/krpzs/registr/stav").json()
        if stav["prubeh"] and not stav["prubeh"]["bezi"]:
            return stav
        time.sleep(0.05)
    raise AssertionError("stahování neskončilo včas")


def test_endpoint_stav_bez_indexu(registr_app):
    client, _ = registr_app
    stav = client.get("/api/krpzs/registr/stav").json()
    assert stav["index"]["existuje"] is False
    assert stav["prubeh"] is None
    assert stav["kraje"]["19"].startswith("Hlavní")
    r = client.get("/api/krpzs/registr/hledat", params={"q": "homolka"}).json()
    assert r["status"] == 404 and r["vysledky"] == []


def test_endpoint_stahnout_a_hledat(registr_app, falesny):
    client, tmp_path = registr_app
    r = client.post("/api/krpzs/registr/stahnout", json={"paralelismus": 500})
    assert r.status_code == 200
    telo = r.json()
    assert telo["ok"] is True
    assert telo["parametry"]["paralelismus"] == kr.MAX_PARALELISMUS
    stav = _pockej_na_konec(client)
    assert stav["prubeh"]["faze"] == "hotovo"
    assert stav["index"]["existuje"] is True
    assert stav["index"]["pocetNalezeno"] == 2
    assert stav["index"]["prostredi"] == "PROD"
    assert (tmp_path / "registr_PROD.json").exists()
    assert (tmp_path / "registr_PROD.prubeh.json").exists()

    r = client.get("/api/krpzs/registr/hledat", params={"q": "homolka"}).json()
    assert r["status"] == 200 and r["pocet"] == 1
    assert r["vysledky"][0]["nazev"] == "Fakultní nemocnice Motol a Homolka"
    r = client.get("/api/krpzs/registr/hledat", params={"q": "", "kraj": "60"}).json()
    assert [z["ico"] for z in r["vysledky"]] == ["25488627"]
    r = client.get("/api/krpzs/registr/hledat", params={"q": ""}).json()
    assert r["status"] == 400


def test_endpoint_stahnout_odmitne_druhy_beh(registr_app, falesny):
    client, _ = registr_app
    falesny.zpozdeni = 0.2
    assert client.post("/api/krpzs/registr/stahnout", json={}).status_code == 200
    r = client.post("/api/krpzs/registr/stahnout", json={})
    assert r.status_code == 409
    r = client.post("/api/krpzs/registr/zastavit")
    assert r.json()["ok"] is True
    stav = _pockej_na_konec(client)
    assert stav["prubeh"]["faze"] == "zastaveno"


def test_endpoint_stahnout_validace(registr_app):
    client, _ = registr_app
    assert client.post("/api/krpzs/registr/stahnout",
                       json={"kraje": ["19", "999"]}).status_code == 400
    assert client.post("/api/krpzs/registr/stahnout",
                       json={"paralelismus": "hodně"}).status_code == 400
    assert client.post("/api/krpzs/registr/stahnout",
                       json={"kraje": "19"}).status_code == 400


def test_endpoint_stahnout_bez_klienta(registr_app, monkeypatch):
    client, _ = registr_app
    monkeypatch.setattr(app_mod, "_auth", None)
    assert client.post("/api/krpzs/registr/stahnout", json={}).status_code == 503


def test_endpoint_stav_vidi_prubeh_jineho_workeru(registr_app):
    client, tmp_path = registr_app
    cizi = kr.Prubeh()
    cizi.start("detaily")
    cizi.nastav(ico_celkem=10, ico_hotovo=3)
    (tmp_path / "registr_PROD.prubeh.json").write_text(json.dumps(cizi.snapshot()))
    stav = client.get("/api/krpzs/registr/stav").json()
    assert stav["prubeh"]["bezi"] is True and stav["prubeh"]["ico"]["hotovo"] == 3
    # druhý worker nesmí spustit souběžný běh
    assert client.post("/api/krpzs/registr/stahnout", json={}).status_code == 409


def test_endpoint_stav_zastaraly_prubeh_je_mrtvy(registr_app):
    client, tmp_path = registr_app
    cizi = kr.Prubeh()
    cizi.start("detaily")
    soubor = tmp_path / "registr_PROD.prubeh.json"
    soubor.write_text(json.dumps(cizi.snapshot()))
    stary = time.time() - app_mod.REGISTR_PRUBEH_CERSTVY_S - 5
    import os
    os.utime(soubor, (stary, stary))
    stav = client.get("/api/krpzs/registr/stav").json()
    assert stav["prubeh"]["bezi"] is False and stav["prubeh"]["faze"] == "přerušeno"
    assert client.post("/api/krpzs/registr/stahnout", json={}).status_code == 200
    _pockej_na_konec(client)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_hledat(falesny, tmp_path, capsys):
    soubor = tmp_path / "r.json"
    kr.stahni_registr(_tovarna_pocitaci(), vystup=soubor)
    assert kr.main(["hledat", "homolka", "--soubor", str(soubor)]) == 0
    out = capsys.readouterr().out
    assert "00064203" in out and "Fakultní nemocnice Motol a Homolka" in out
    assert kr.main(["hledat", "x", "--soubor", str(tmp_path / "neni.json")]) == 1


def test_cli_stahnout(falesny, tmp_path, monkeypatch, capsys):
    tovarna = _tovarna_pocitaci()

    class _Auth:
        def cleanup(self):
            pass
    monkeypatch.setattr(kr, "_tovarna_z_konfigurace", lambda env: (tovarna, _Auth()))
    soubor = tmp_path / "out.json"
    kod = kr.main(["stahnout", "--env", "PROD", "-p", "3", "-o", str(soubor), "--kraj", "19",
                   "--kraj", "60"])
    assert kod == 0
    out = capsys.readouterr().out
    assert "Hotovo" in out and "Uloženo" in out
    index = kr.nacti_registr(soubor)
    assert index["prostredi"] == "PROD" and index["paralelismus"] == 3
    assert set(index["kraje"]) == {"19", "60"}


def test_krpzs_registr_dir_je_absolutni(monkeypatch, tmp_path):
    from sez_api import config as cfg
    monkeypatch.setattr(cfg, "KRPZS_REGISTR_DIR", "")
    monkeypatch.setattr(cfg, "CERT_STORE_DIR", "")
    monkeypatch.setattr(cfg, "CERT_STORE_ZAKLAD", "homolka.pfx")
    monkeypatch.chdir(tmp_path)
    assert cfg.krpzs_registr_dir() == str(tmp_path.resolve() / "krpzs")
    monkeypatch.setattr(cfg, "KRPZS_REGISTR_DIR", "/var/lib/sezapi/krpzs")
    assert cfg.krpzs_registr_dir() == "/var/lib/sezapi/krpzs"
