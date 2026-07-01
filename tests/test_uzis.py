"""
Testy ÚZIS / NZIS integrace – NRPZS (poskytovatelé), číselníky, Národní
zdravotnické registry a hlášení.

Offline: NRPZS se testuje s prázdnou URL → fallback na vzorky.
NZR hlášení běží v simulačním režimu.

Spuštění:  python3 -m pytest tests/test_uzis.py -v
"""

import pytest
from starlette.testclient import TestClient

from sez_api import config as cfg
from sez_api.client import UZISNrpzs, UZIS
from sez_api.app import app


@pytest.fixture(autouse=True)
def _offline_nrpzs(monkeypatch):
    monkeypatch.setattr(cfg, "UZIS_NRPZS_URL", "", raising=False)
    UZISNrpzs._cache = None
    UZISNrpzs._source = None
    yield
    UZISNrpzs._cache = None


@pytest.fixture
def client():
    return TestClient(app)


# --- NRPZS ----------------------------------------------------------------

def test_nrpzs_fallback():
    m = UZISNrpzs()
    st = m.status()
    assert st["zdroj"] == "sample"
    assert st["pocet"] > 0


def test_nrpzs_hledat_kraj():
    m = UZISNrpzs()
    r = m.hledat(kraj="Ústecký")
    assert r["pocet"] >= 1
    assert all("ústeck" in x["kraj"].lower() for x in r["vysledky"])


def test_nrpzs_hledat_nazev():
    m = UZISNrpzs()
    r = m.hledat(nazev="fakultní")
    assert r["pocet"] >= 1


def test_nrpzs_detail():
    m = UZISNrpzs()
    d = m.detail("25488627")
    assert d["nalezeno"] is True
    assert "Krajská zdravotní" in d["poskytovatel"]["nazev"]


def test_nrpzs_ciselnik_fallback():
    m = UZISNrpzs()
    c = m.ciselnik("kraje")
    assert len(c["polozky"]) >= 1


# --- NZR / hlášení --------------------------------------------------------

def test_uzis_mode_sim(monkeypatch):
    monkeypatch.setattr(cfg, "UZIS_NZR_ENDPOINT", "", raising=False)
    monkeypatch.setattr(cfg, "UZIS_NZR_ENDPOINT_TEST", "", raising=False)
    assert UZIS().mode() == "SIM"


def test_uzis_katalog_registru():
    reg = UZIS().katalog_registru()
    kody = {r["kod"] for r in reg}
    assert {"NRPZS", "NOR", "ISIN"}.issubset(kody)


def test_uzis_envelope():
    env = UZIS().build_envelope("NOR", "Hlaseni", {"diagnoza": "C50"})
    assert env["registr"] == "NOR"
    assert env["operace"] == "Hlaseni"
    assert "idKorelace" in env["hlavicka"]


def test_uzis_hlasit_sim_marker():
    r = UZIS().hlasit("NOR", {"rid": "3740100325"})
    assert r["_simulace"] is True
    assert r["registr"] == "NOR"


# --- End-to-end přes REST -------------------------------------------------

def test_status_obsahuje_uzis(client):
    d = client.get("/api/status").json()
    assert d["uzis_enabled"] is True
    assert d["uzis_mode"] in ("SIM", "LIVE", "OFF")
    assert len(d["uzis_nzr_katalog"]) >= 5


def test_uzis_hlaseni_lifecycle_e2e(client):
    client.post("/api/uzis/sim/reset")
    r = client.post("/api/uzis/hlasit", json={"registr": "NOR",
                    "telo": {"rid": "3740100325", "diagnoza": "C50"}})
    assert r.status_code == 200
    hid = r.json()["data"]["idHlaseni"]
    assert r.json()["data"]["stav"]["kod"] == "PRIJATO"

    r = client.get(f"/api/uzis/hlaseni/NOR/{hid}")
    assert r.json()["data"]["stav"]["kod"] == "ZPRACOVANO"


def test_uzis_hlaseni_neexistujici_404(client):
    client.post("/api/uzis/sim/reset")
    r = client.get("/api/uzis/hlaseni/NOR/NEEXISTUJE")
    assert r.json()["status"] == 404


def test_uzis_nrpzs_endpoint(client):
    r = client.get("/api/uzis/nrpzs/hledat?ico=25488627")
    assert r.status_code == 200
    assert r.json()["data"]["pocet"] >= 1


def test_uzis_registry_endpoint(client):
    r = client.get("/api/uzis/registry")
    assert r.status_code == 200
    assert len(r.json()["data"]["registry"]) >= 5
