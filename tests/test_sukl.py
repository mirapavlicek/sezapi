"""
Testy SÚKL integrace – DLP (databáze léčivých přípravků) a eRecept / CÚER.

Bez síťové závislosti: DLP se testuje v offline režimu (SUKL_DLP_URL="" → vzorky).
eRecept běží v simulačním režimu (bez registrace/certifikátu).

Spuštění:  python3 -m pytest tests/test_sukl.py -v
"""

import pytest
from starlette.testclient import TestClient

from sez_api import config as cfg
from sez_api.client import SUKLDLP, SUKLeRecept
from sez_api.app import app


@pytest.fixture(autouse=True)
def _offline_dlp(monkeypatch):
    """Vynutí offline DLP (vzorky), aby testy nezávisely na internetu."""
    monkeypatch.setattr(cfg, "SUKL_DLP_URL", "", raising=False)
    SUKLDLP._index = None
    SUKLDLP._source = None
    yield
    SUKLDLP._index = None


# --------------------------------------------------------------------------
# DLP – databáze léčivých přípravků
# --------------------------------------------------------------------------

def test_dlp_fallback_na_vzorky():
    dlp = SUKLDLP()
    st = dlp.status()
    assert st["zdroj"] == "sample"
    assert st["pocet"] > 0


def test_dlp_hledat_nazev():
    dlp = SUKLDLP()
    r = dlp.hledat(nazev="paralen")
    assert r["pocet"] >= 1
    assert any("PARALEN" in x["nazev"] for x in r["vysledky"])


def test_dlp_hledat_atc():
    dlp = SUKLDLP()
    r = dlp.hledat(atc="M01AE01")  # ibuprofen
    assert r["pocet"] >= 1
    assert all("M01AE01" in x["atc"] for x in r["vysledky"])


def _fake_dlp_zip() -> bytes:
    """Miniaturní balík DLP se stejnou strukturou jako opendata.sukl.cz:
    číselník (dlp_atc) je v archivu PŘED daty, což dřív vedlo k načtení
    nesprávného souboru."""
    import io
    import zipfile
    soubory = {
        "dlp_atc.csv": "ATC;NAZEV\nN02BE01;paracetamol\n",
        "dlp_lecivepripravky.csv": (
            "KOD_SUKL;H;NAZEV;SILA;FORMA;BALENI;CESTA;DRZ;REG;ATC_WHO;LL;VYDEJ\n"
            "0254045;;PARALEN;500MG;TBL NOB;10;POR;OHC;R;N02BE01;1064;V\n"
            "0000009;;ACYLCOFFIN;450MG/50MG;TBL NOB;10;POR;ZNB;R;N02BA51;12,223;F\n"
        ),
        "dlp_organizace.csv": ("ZKR_ORG;ZEM;NAZEV;VYROBCE;DRZITEL\n"
                                "OHC;CZ;Opella Healthcare Czech s.r.o., Praha;;D\n"
                                "ZNB;SK;Zentiva a.s., Bratislava;;D\n"),
        "dlp_stavyreg.csv": "REG;NAZEV\nR;registrovaný léčivý přípravek\n",
        "dlp_vydej.csv": "VYDEJ;NAZEV\nV;vyhrazená léčiva\nF;volně prodejné léčivé přípravky\n",
        "dlp_lecivelatky.csv": ("KOD_LATKY;NAZEV_INN;NAZEV_EN;NAZEV;ZAV\n"
                                 "1064;PARACETAMOLUM;PARACETAMOL;PARACETAMOL;\n"
                                 "12;ACIDUM ACETYLSALICYLICUM;;KYSELINA ACETYLSALICYLOVÁ;\n"
                                 "223;COFFEINUM;;KOFEIN;\n"),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for nazev, obsah in soubory.items():
            zf.writestr(nazev, obsah.encode("cp1250"))
    return buf.getvalue()


def test_dlp_nacte_pripravky_a_ne_ciselnik(monkeypatch):
    """Regrese: archiv DLP obsahuje ~30 CSV a dřív se načetl první z nich
    (dlp_atc.csv), takže vyhledávání přípravků nic nenašlo."""
    data = _fake_dlp_zip()

    class _Resp:
        content = data
        status_code = 200

        def raise_for_status(self):
            return None

    monkeypatch.setattr(cfg, "SUKL_DLP_URL",
                        "https://opendata.sukl.cz/soubory/SOD20260727/DLP20260727.zip",
                        raising=False)
    monkeypatch.setattr("sez_api.client.requests.get", lambda *a, **k: _Resp())
    SUKLDLP._index = None

    dlp = SUKLDLP()
    st = dlp.status()
    assert st["zdroj"] == "opendata", st
    assert st["pocet"] == 2, st

    r = dlp.hledat(nazev="paralen")
    assert r["pocet"] == 1, r
    lek = r["vysledky"][0]
    # Kódy z číselníků musí být přeložené na názvy, původní kód zůstává.
    assert lek["drzitel"] == "Opella Healthcare Czech s.r.o., Praha"
    assert lek["drzitel_kod"] == "OHC"
    assert lek["stav_registrace"] == "registrovaný léčivý přípravek"
    assert lek["vydej"] == "vyhrazená léčiva"
    assert lek["ucinna_latka"] == "PARACETAMOL"
    assert lek["ucinna_latka_kod"] == "1064"


def test_dlp_vice_ucinnych_latek(monkeypatch):
    """Sloupec LL obsahuje kódy oddělené čárkou – přeloží se všechny."""
    data = _fake_dlp_zip()

    class _Resp:
        content = data
        status_code = 200

        def raise_for_status(self):
            return None

    monkeypatch.setattr(cfg, "SUKL_DLP_URL", "https://x/DLP20260727.zip", raising=False)
    monkeypatch.setattr("sez_api.client.requests.get", lambda *a, **k: _Resp())
    SUKLDLP._index = None

    r = SUKLDLP().hledat(nazev="acylcoffin")
    assert r["pocet"] == 1
    assert r["vysledky"][0]["ucinna_latka"] == "KYSELINA ACETYLSALICYLOVÁ, KOFEIN"


def test_dlp_vyber_souboru_preferuje_pripravky():
    vyber = SUKLDLP._vyber_soubor(
        ["dlp_atc.csv", "dlp_formy.csv", "dlp_lecivepripravky.csv", "dlp_zeme.csv"])
    assert vyber == "dlp_lecivepripravky.csv"


def test_dlp_autodetekce_url_z_katalogu(monkeypatch):
    """SÚKL pojmenovává balík datem vydání, pevná URL zastará – "auto" najde
    aktuální odkaz v katalogu a vybere nejnovější."""
    html = """<html><body>
      <a href="https://opendata.sukl.cz/soubory/SOD20260601/DLP20260601.zip">starší</a>
      <a href="https://opendata.sukl.cz/soubory/SOD20260727/DLP20260727.zip">aktuální</a>
      <a href="https://opendata.sukl.cz/soubory/DLP_datove_rozhrani20260701.csv">rozhraní</a>
    </body></html>"""

    class _Resp:
        text = html
        status_code = 200

        def raise_for_status(self):
            return None

    monkeypatch.setattr(cfg, "SUKL_DLP_KATALOG", "https://opendata.sukl.cz/?q=katalog",
                        raising=False)
    monkeypatch.setattr("sez_api.client.requests.get", lambda *a, **k: _Resp())

    url, chyba = SUKLDLP._zjisti_url("auto")
    assert chyba is None, chyba
    assert url == "https://opendata.sukl.cz/soubory/SOD20260727/DLP20260727.zip"

    # Konkrétní URL se nechává být.
    url2, chyba2 = SUKLDLP._zjisti_url("https://priklad/DLP.zip")
    assert (url2, chyba2) == ("https://priklad/DLP.zip", None)


def test_dlp_autodetekce_bez_odkazu_spadne_na_vzorky(monkeypatch):
    class _Resp:
        text = "<html><body>žádný balík</body></html>"
        status_code = 200

        def raise_for_status(self):
            return None

    monkeypatch.setattr(cfg, "SUKL_DLP_URL", "auto", raising=False)
    monkeypatch.setattr("sez_api.client.requests.get", lambda *a, **k: _Resp())
    SUKLDLP._index = None

    st = SUKLDLP().status()
    assert st["zdroj"] == "sample"
    assert "nebyl nalezen odkaz" in (st["chyba"] or "")


def test_dlp_detail():
    dlp = SUKLDLP()
    d = dlp.detail("0031505")
    assert d["nalezeno"] is True
    assert d["pripravek"]["nazev"] == "PARALEN 500"

    d2 = dlp.detail("NEEXISTUJE")
    assert d2["nalezeno"] is False


# --------------------------------------------------------------------------
# eRecept – builder obálek a režim
# --------------------------------------------------------------------------

def test_erecept_mode_je_simulace_bez_konfigurace(monkeypatch):
    monkeypatch.setattr(cfg, "SUKL_REG_ID", "", raising=False)
    monkeypatch.setattr(cfg, "SUKL_ERECEPT_ENDPOINT", "", raising=False)
    monkeypatch.setattr(cfg, "SUKL_ERECEPT_ENDPOINT_TEST", "", raising=False)
    er = SUKLeRecept()
    assert er.mode() == "SIM"


def test_erecept_envelope_obsahuje_verzi_a_operaci():
    er = SUKLeRecept()
    env = er.build_envelope("ZalozeniEReceptu", {"a": 1})
    assert env["operace"] == "ZalozeniEReceptu"
    assert env["hlavicka"]["verzeRozhrani"] == cfg.SUKL_INTERFACE_VERSION
    assert "idKorelace" in env["hlavicka"]


def test_erecept_odeslat_v_simulaci_vraci_marker():
    er = SUKLeRecept()
    r = er.predepsat({"pacient": {"rid": "3740100325"}})
    assert r["_simulace"] is True
    assert r["operace"] == "ZalozeniEReceptu"
    assert r["request"]["hlavicka"]["verzeRozhrani"] == cfg.SUKL_INTERFACE_VERSION


# --------------------------------------------------------------------------
# End-to-end přes REST API (simulační engine)
# --------------------------------------------------------------------------

@pytest.fixture
def client():
    return TestClient(app)


def test_status_obsahuje_sukl_pole(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    d = r.json()
    assert d["sukl_enabled"] is True
    assert d["sukl_mode"] in ("SIM", "LIVE", "OFF")
    assert d["sukl_interface_version"]


def test_erecept_lifecycle_e2e(client):
    client.post("/api/sukl/sim/reset")
    # předpis
    body = {"pacient": {"rid": "3740100325"}, "krzpId": "102129137",
            "polozky": [{"sukl": "0031505", "davkovani": "1-0-1"}]}
    r = client.post("/api/sukl/erecept/predepsat", json=body)
    assert r.status_code == 200
    eid = r.json()["data"]["idERecept"]
    assert r.json()["data"]["stav"]["kod"] == "P"

    # výdej (úplný)
    r = client.post("/api/sukl/erecept/vydej", json={"idERecept": eid, "uplnyVydej": True})
    assert r.json()["data"]["stav"]["kod"] == "V"

    # náhled
    r = client.get(f"/api/sukl/erecept/nahled/{eid}")
    assert r.json()["data"]["idERecept"] == eid

    # lékový záznam
    r = client.get("/api/sukl/erecept/lekovy-zaznam?rid=3740100325")
    assert r.json()["data"]["pocetEReceptu"] >= 1

    # doplatky
    r = client.post("/api/sukl/erecept/doplatky", json={"rid": "3740100325"})
    assert "limitPojistence" in r.json()["data"]


def test_erecept_nahled_neexistujici_vraci_404(client):
    client.post("/api/sukl/sim/reset")
    r = client.get("/api/sukl/erecept/nahled/NEEXISTUJEXX")
    assert r.json()["status"] == 404


def test_vydej_neexistujici_erecept_chyba(client):
    client.post("/api/sukl/sim/reset")
    r = client.post("/api/sukl/erecept/vydej", json={"idERecept": "NOPE"})
    assert r.json()["status"] == 404


def test_sim_seed_a_reset(client):
    r = client.post("/api/sukl/sim/seed")
    assert r.json()["data"]["seeded"] >= 1
    r = client.get("/api/sukl/sim/status")
    assert r.json()["count"] >= 1
    r = client.post("/api/sukl/sim/reset")
    assert r.json()["data"]["count"] == 0


def test_dlp_endpointy(client):
    r = client.get("/api/sukl/dlp/hledat?nazev=ibalgin")
    assert r.status_code == 200
    assert r.json()["data"]["pocet"] >= 1

    r = client.get("/api/sukl/dlp/detail/0100000")
    assert r.json()["data"]["nalezeno"] is True
