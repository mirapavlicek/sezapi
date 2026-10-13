"""
Lokální vyhledávání v číselnících pro kostru eŽádanky (MKN-10, SNOMED CT CZ sady
výkonů K/FT/Z z HL7 CZ IG) – modul ``sez_api.terminologie_index`` a endpointy
``/api/terminologie/{sady,hledat}``.

Spuštění:  python3 -m pytest tests/test_terminologie_index.py -v
"""

import pytest

from sez_api import terminologie_index as ti


def test_sady_jsou_v_balicku():
    ids = {m["id"] for m in ti.info_sad()}
    assert {"mkn10", "sct-k-procedures", "sct-ft-procedures", "sct-imaging-procedures",
            "sct-conditions", "vzp-odbornost"} <= ids
    mkn = ti.nacti_sadu("mkn10")["meta"]
    assert mkn["pocet"] == 38934 and mkn["uplne"] is True and mkn["version"] == "2025-01"
    assert mkn["system"] == "https://uzis.cz/terminology/CodeSystem/mkn-10"
    ft = ti.nacti_sadu("sct-ft-procedures")["meta"]
    assert ft["pocet"] == 511 and ft["uplne"] is True and ft["system"] == "http://snomed.info/sct"
    assert "11000279109" in ft["version"]  # SNOMED CT CZ edice
    assert ti.nacti_sadu("sct-k-procedures")["meta"]["uplne"] is False  # IG limitedExpansion
    assert set(ti.SADY_VYKONU) == {"K", "FT", "Z"}


def test_hledani_mkn10_bez_diakritiky_a_s_teckou():
    r = ti.hledat("mkn10", "bolest zad")
    assert r["items"][0]["code"] == "M545" and r["items"][0]["display"] == "Bolesti dolní části zad"
    assert ti.hledat("mkn10", "BOLEST ZAD")["items"][0]["code"] == "M545"
    assert ti.hledat("mkn10", "M54.5")["items"][0]["code"] == "M545"
    r = ti.hledat("mkn10", "zlomenina kotnik", limit=5)
    assert len(r["items"]) == 5 and all("kotník" in i["display"] for i in r["items"])
    assert ti.hledat("mkn10", "xyzxyzxyz")["items"] == []
    assert ti.najdi_kod("mkn10", "M54.5")["parent"] == "M54"


def test_hledani_snomed_sad_dle_typu():
    assert ti.hledat(ti.SADY_VYKONU["FT"], "chůze")["items"][0]["display"].startswith("chůze")
    k = ti.hledat(ti.SADY_VYKONU["K"], "kardio")
    assert any(i["code"] == "308471005" for i in k["items"])  # doporučení ke kardiologovi
    z = ti.hledat(ti.SADY_VYKONU["Z"], "CT mozku")
    assert z["items"][0]["code"] == "34227000"
    assert ti.hledat("vzp-odbornost", "fyzio")["items"][0]["code"] == "902"


def test_razeni_presna_shoda_kodu_prvni():
    r = ti.hledat("sct-k-procedures", "11429006")
    assert r["items"][0]["code"] == "11429006" and r["items"][0]["display"] == "konzultace"


def test_neznama_sada():
    with pytest.raises(KeyError):
        ti.hledat("neni", "x")
    assert ti.nacti_sadu("../pyproject") is None


def test_lookup_kod_bez_termx():
    assert ti.lookup_kod(None, ti.SYS_SNOMED, "91251008") is None


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from sez_api import app as app_mod
    yield TestClient(app_mod.app)


def test_api_sady_a_hledat(client):
    j = client.get("/api/terminologie/sady").json()
    assert j["vykonyPodleTypu"]["FT"] == "sct-ft-procedures" and len(j["sady"]) >= 6
    j = client.get("/api/terminologie/hledat", params={"q": "bolest zad"}).json()
    assert j["items"][0]["code"] == "M545" and j["sada"]["id"] == "mkn10"
    j = client.get("/api/terminologie/hledat", params={"typ": "FT", "q": "cvičení", "limit": 3}).json()
    assert len(j["items"]) == 3 and j["sada"]["id"] == "sct-ft-procedures"
    assert client.get("/api/terminologie/hledat", params={"sada": "nope", "q": "x"}).status_code == 404


def test_kostra_s_vybranym_vykonem_a_diagnozou(client):
    dg = ti.hledat("mkn10", "M545")["items"][0]
    vyk = ti.hledat("sct-ft-procedures", "trénink chůze")["items"][0]
    r = client.post("/api/ezadanky/v2/kostra", json=dict(
        typ="FT", pacient="7653800856", poskytovatel="25488627", autor="102129137", icp="72090001",
        adresat="00064165", vykony=[vyk], diagnoza=dg, pocetProcedur=6))
    j = r.json()
    assert r.status_code == 200 and j["vyhrady"] == []
    srs = [e["resource"] for e in j["fhirBundle"]["entry"] if e["resource"]["resourceType"] == "ServiceRequest"]
    assert srs[0]["code"]["coding"][0] == {"system": "http://snomed.info/sct", "version": "http://snomed.info/sct/11000279109",
                                           "code": vyk["code"], "display": vyk["display"]}
    cond = [e["resource"] for e in j["fhirBundle"]["entry"] if e["resource"]["resourceType"] == "Condition"][0]
    assert cond["code"]["coding"][0]["code"] == "M545" and cond["code"]["coding"][0]["display"] == "Bolesti dolní části zad"
