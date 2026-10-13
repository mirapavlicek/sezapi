"""
Testy všech typů eŽádanky (Z, K, FT) dle Manuálu EZ pro PZS a HL7 CZ IG
(img-order pro Z, společný HL7 CZ Order IG hl7.fhir.cz.order pro K a FT).

Pokrývá modul ``sez_api.fhir_order`` (normalizace referencí, analýza Bundle,
příprava podle pravidel brány, kostry K/FT/Z, vzory IG) a nové REST endpointy
``/api/ezadanky/v2/{typy,vzory,kostra,pripravit}``. Stejné kostry i vzory
prošly 13. 10. 2026 živě na T2 (201 Created) – viz docstring modulu.

Spuštění:  python3 -m pytest tests/test_ezadanky_typy.py -v
"""

import copy
import os

import pytest

from sez_api import fhir_order as fo
from sez_api import fhir_imgorder as fi
from sez_api.client import EZadankyV2

RID, KRZP, ICO, ICP, ADRESAT = "7653800856", "102129137", "25488627", "72090001", "00064165"
IDENT = dict(pacient=RID, poskytovatel=ICO, autor=KRZP, icp=ICP, adresat=ADRESAT)


# --- katalog typů ---------------------------------------------------------------

def test_typy_dle_manualu_ez():
    assert set(fo.TYPY) == {"Z", "K", "FT"}
    assert fo.TYPY["K"]["kod"] == fo.LOINC_TYP_K == "57133-1"
    assert fo.TYPY["FT"]["kod"] == fo.LOINC_TYP_FT == "57154-7"
    assert fo.TYPY["Z"]["kod"] == fo.SCT_TYP_Z == "721964003"
    assert fo.TYPY["K"]["ig"] == fo.TYPY["FT"]["ig"] == fo.IG_ORDER_PACKAGE == "hl7.fhir.cz.order"
    assert fo.TYPY["Z"]["ig"] == "hl7.fhir.cz.img-order"
    # shoda s číselníkem typů v klientovi
    for t, v in fo.TYPY.items():
        assert EZadankyV2.TYPY_ZADANKY[t]["kod"] == v["kod"]
    assert fo.KOD_NA_TYP["57154-7"] == "FT"


def test_katalog_typu_ma_vzory_a_pravidla():
    k = fo.katalog_typu()
    assert set(k["typy"]) == {"Z", "K", "FT"}
    for t in k["typy"].values():
        assert t["vzory"] and all(v["dostupny"] for v in t["vzory"])
    kody = {p["kod"] for p in k["pravidla_brany"]}
    assert {"E00024", "E01001", "E01002"} <= kody
    assert any("urn:uuid" in p["pravidlo"] for p in k["pravidla_brany"])
    assert any("intramurál" in p["pravidlo"] for p in k["pravidla_brany"])
    assert k["overeno_t2"] == "2026-10-13"


def test_vzory_ig_order_jsou_soucasti_balicku():
    ex = fo.list_examples()
    assert len(ex) == 8
    assert {e["typ"] for e in ex} == {"K", "FT"}
    assert sum(e["typ"] == "K" for e in ex) == 4 and sum(e["typ"] == "FT" for e in ex) == 4
    for e in ex:
        b = fo.load_example(e["name"])
        assert b["resourceType"] == "Bundle" and b["type"] == "document"
        assert fo.typ_z_bundle(b) == e["typ"]
    assert fo.load_example("neexistuje.json") is None
    assert fo.load_example("../pyproject.toml") is None


# --- normalizace referencí a analýza --------------------------------------------

def test_normalizuj_reference_prevede_na_urn_uuid():
    b = fo.load_example("Bundle-BundleKOrderExample.json")
    before = fo.analyzuj(b)
    assert before["nepresne_reference"]  # IG příklad odkazuje relativně při absolutním fullUrl
    nb, zmeny = fo.normalizuj_reference(copy.deepcopy(b))
    assert zmeny
    assert all(e["fullUrl"].startswith("urn:uuid:") for e in nb["entry"])
    after = fo.analyzuj(nb)
    assert after["nepresne_reference"] == [] and after["nevyresene_reference"] == []
    # id zdroje = uuid z fullUrl (server páruje jen přesný fullUrl), typy zdrojů zachovány
    assert all(e["fullUrl"] == "urn:uuid:" + e["resource"]["id"] for e in nb["entry"])
    assert [e["resource"]["resourceType"] for e in nb["entry"]] == [e["resource"]["resourceType"] for e in b["entry"]]


def test_analyzuj_vsechny_vzory():
    for e in fo.list_examples():
        a = fo.analyzuj(fo.load_example(e["name"]))
        assert a["typ"] == e["typ"]
        assert a["pacient"] and a["autor"]
        assert a["pocet_service_request"] >= 1
    a = fo.analyzuj(fi.load_example("Bundle-BundleKralikRTG.json"))
    assert a["typ"] == "Z" and a["zadatel"]["zdroj"] == "Composition.custodian"


# --- příprava podle pravidel brány -----------------------------------------------

@pytest.mark.parametrize("name", [e["name"] for e in fo.list_examples()] + ["Bundle-BundleKralikRTG.json"])
def test_pripravit_vzor_splni_klientskou_kontrolu(name):
    b = fo.load_example(name) or fi.load_example(name)
    v2 = fo.to_v2(b, **IDENT)
    hl, fb = v2["hlavicka"], v2["fhirBundle"]
    assert hl["pacient"] == RID and hl["zadatel"]["autor"] == KRZP
    assert hl["zadatel"]["poskytovatel"] == ICO and hl["adresat"] == ADRESAT
    assert hl["typZadanky"]["kod"] == fo.TYPY[fo.typ_z_bundle(b)]["kod"]
    vyhrady = EZadankyV2.zkontroluj_pozadavek(v2)
    if "Dermatology" in name:
        # jediná odchylka: priorita 'urgent' není v request-priority-cz
        assert vyhrady and all("urgent" in x for x in vyhrady)
    else:
        assert vyhrady == []
    a = fo.analyzuj(fb)
    assert a["zadatel"] == {"ico": ICO, "icp": ICP, "nazev": a["zadatel"]["nazev"], "zdroj": "Composition.custodian"}
    assert a["performer"]["ico"] == ADRESAT and a["performer"]["pocet"] == 1
    assert a["nepresne_reference"] == []


def test_pripravit_je_idempotentni():
    b = fo.load_example("Bundle-BundleFTExample.json")
    v2 = fo.to_v2(b, **IDENT)
    znovu, zmeny = fo.pripravit(copy.deepcopy(v2["fhirBundle"]), v2["hlavicka"], icp=ICP)
    assert zmeny == []
    assert znovu == v2["fhirBundle"]


def test_pripravit_neadresna_bez_performera():
    b = fo.load_example("Bundle-BundleKOrderExample.json")
    v2 = fo.to_v2(b, pacient=RID, poskytovatel=ICO, autor=KRZP, icp=ICP, adresat=None)
    assert "adresat" not in v2["hlavicka"] or v2["hlavicka"]["adresat"] != ICO
    assert EZadankyV2.zkontroluj_pozadavek(v2) == []


def test_sestav_hlavicku_odvodi_udaje_z_bundle():
    b = fo.load_example("Bundle-BundleFTHipRehabilitation.json")
    hl = fo.sestav_hlavicku(b)
    a = fo.analyzuj(b)
    assert hl["typZadanky"]["kod"] == fo.LOINC_TYP_FT
    assert hl["pacient"] == a["pacient"] and hl["zadatel"]["autor"] == a["autor"]
    hl2 = fo.sestav_hlavicku(b, pacient="X", nadrizena_zadanka_id="abc", dodatecny_prijemce=["111"])
    assert hl2["pacient"] == "X" and hl2["nadrizenaZadankaId"] == "abc" and hl2["dodatecnyPrijemce"] == ["111"]


# --- kostry ----------------------------------------------------------------------

@pytest.mark.parametrize("typ", ["K", "FT"])
def test_kostra_k_ft_dle_ig_order(typ):
    b = fo.kostra(typ, **IDENT, text_pozadavku="Test", diagnoza={"code": "M545", "display": "Bolest dolní části zad"},
                  klinicka_otazka="Otázka?", pocet_procedur=10)
    assert fo.typ_z_bundle(b) == typ
    assert b["meta"]["profile"] == [fo.PROFILE_BUNDLE_ORDER]
    comp = b["entry"][0]["resource"]
    assert comp["resourceType"] == "Composition"
    assert comp["meta"]["profile"] == [fo.TYPY[typ]["composition_profile"]]
    assert comp["type"]["coding"][0]["code"] == fo.TYPY[typ]["kod"]
    assert comp["category"][0]["coding"][0]["code"] == "57133-1"  # Composition.category společná pro K i FT
    assert comp["identifier"] and comp["custodian"] and comp["author"]
    sekce = {s["code"]["coding"][0]["code"] for s in comp["section"]}
    assert {fo.TYPY[typ]["kod"], "104720-8", "87520-3"} <= sekce  # orderInformation, clinicalQuestion, coverage
    srs = [e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "ServiceRequest"]
    assert srs
    for sr in srs:
        assert sr["meta"]["profile"] == [fo.TYPY[typ]["servicerequest_profile"]]
        assert sr["identifier"] and sr["insurance"] and sr["priority"] == "routine"
        assert sr["requester"]["reference"].startswith("urn:uuid:")
        assert sr["performer"]
        if typ == "FT":
            assert sr["quantityQuantity"]["value"] == 10
    # všechny reference jsou přesné urn:uuid a Bundle projde klientskou kontrolou
    a = fo.analyzuj(b)
    assert a["nepresne_reference"] == [] and a["nevyresene_reference"] == []
    v2 = fo.to_v2(b)
    assert v2["hlavicka"]["adresat"] == ADRESAT
    assert EZadankyV2.zkontroluj_pozadavek(v2) == []


def test_kostra_odmitne_neznamou_prioritu_a_typ():
    with pytest.raises(ValueError):
        fo.kostra("K", **IDENT, priorita="urgent")
    with pytest.raises(ValueError):
        fo.kostra("LAB", **IDENT)


def test_kostra_samoplatce_bez_pojistovny():
    b = fo.kostra("K", **IDENT, pojistovna=None)
    cov = [e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Coverage"]
    assert len(cov) == 1
    assert EZadankyV2.zkontroluj_pozadavek(fo.to_v2(b)) == []


def test_kostra_z_pres_img_order():
    b = fo.kostra_z(**IDENT, diagnoza={"code": "S8260", "display": "Zlomenina"})
    assert fo.typ_z_bundle(b) == "Z"
    v2 = fo.to_v2(b)
    assert v2["hlavicka"]["typZadanky"]["kod"] == fo.SCT_TYP_Z
    assert EZadankyV2.zkontroluj_pozadavek(v2) == []
    # reverz přes img-order modul zachová identifikátory
    rec = fi.ImagingOrderBundleParser(b).extract()
    assert rec["patient"]["rid"] == RID


# --- REST endpointy ---------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from sez_api import app as app_mod
    yield TestClient(app_mod.app)


def test_api_typy_a_vzory(client):
    r = client.get("/api/ezadanky/v2/typy")
    assert r.status_code == 200 and set(r.json()["typy"]) == {"Z", "K", "FT"}
    r = client.get("/api/ezadanky/v2/vzory")
    vz = r.json()["vzory"]
    assert {v["typ"] for v in vz} == {"Z", "K", "FT"} and len(vz) == 9
    r = client.get("/api/ezadanky/v2/katalog")
    assert "typy" in r.json() and "pravidla_brany" in r.json()["typy"]


def test_api_vzor_pripraveny(client):
    r = client.get("/api/ezadanky/v2/vzory/Bundle-BundleFTExample.json")
    assert r.status_code == 200 and r.json()["resourceType"] == "Bundle"
    r = client.get("/api/ezadanky/v2/vzory/Bundle-BundleFTExample.json", params=dict(pripravit=1, **IDENT))
    j = r.json()
    assert j["typ"] == "FT" and j["vyhrady"] == []
    assert j["hlavicka"]["zadatel"]["poskytovatel"] == ICO and j["hlavicka"]["adresat"] == ADRESAT
    assert client.get("/api/ezadanky/v2/vzory/neni.json").status_code == 404


@pytest.mark.parametrize("typ", ["K", "FT", "Z"])
def test_api_kostra(client, typ):
    r = client.post("/api/ezadanky/v2/kostra", json=dict(typ=typ, **IDENT, textPozadavku="Test",
                                                        diagnoza={"code": "M545"}, pocetProcedur=6))
    j = r.json()
    assert r.status_code == 200, j
    assert j["typ"] == typ and j["vyhrady"] == []
    assert j["hlavicka"]["typZadanky"]["kod"] == fo.TYPY[typ]["kod"]
    assert j["fhirBundle"]["entry"][0]["resource"]["resourceType"] == "Composition"


def test_api_kostra_validace(client):
    r = client.post("/api/ezadanky/v2/kostra", json={"typ": "K", "pacient": RID})
    assert r.status_code == 400 and "poskytovatel" in r.json()["error"]
    r = client.post("/api/ezadanky/v2/kostra", json=dict(typ="K", **IDENT, priorita="urgent"))
    assert r.status_code == 400


def test_api_pripravit_castecna_hlavicka(client):
    b = fo.load_example("Bundle-BundleNephrologyHandoverExample.json")
    r = client.post("/api/ezadanky/v2/pripravit", json={
        "hlavicka": {"pacient": RID, "zadatel": {"poskytovatel": ICO, "autor": KRZP}, "adresat": ADRESAT},
        "fhirBundle": b, "icp": ICP})
    j = r.json()
    assert r.status_code == 200
    assert j["hlavicka"]["typZadanky"]["kod"] == fo.LOINC_TYP_K
    assert j["zmeny"] and j["vyhrady"] == []
    assert j["analyza"]["zadatel"]["icp"] == ICP and j["analyza"]["performer"]["ico"] == ADRESAT
    r = client.post("/api/ezadanky/v2/pripravit", json={"hlavicka": {}, "fhirBundle": {"resourceType": "Patient"}})
    assert r.status_code == 400


def test_api_zkontroluj_vraci_analyzu(client):
    v2 = fo.to_v2(fo.load_example("Bundle-BundleKOrderExample.json"), **IDENT)
    r = client.post("/api/ezadanky/v2/zkontroluj", json=v2)
    d = r.json()["data"]
    assert d["ok"] is True and d["analyza"]["typ"] == "K"
