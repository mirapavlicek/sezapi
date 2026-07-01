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
