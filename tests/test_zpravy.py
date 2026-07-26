"""
Testy builderu zpráv eZD – katalog typů, sekce dle IG, ukázková data,
live náhled a validace.

Pokrývá všech 5 typů zpráv dle HL7 CZ Implementation Guides:
  pacientský souhrn (ps), propouštěcí zpráva (hdr), zpráva z obrazového
  vyšetření (img), zpráva o výjezdu ZZS (cz-ems), laboratorní zpráva (lab).

Offline – bez síťové závislosti.
Spuštění:  python3 -m pytest tests/test_zpravy.py -v
"""

import pytest
from starlette.testclient import TestClient

from sez_api.app import app
from sez_api.fhir_ezd import (
    EZD_KATEGORIE,
    UKAZKY,
    build_ezd_bundle,
    katalog_zprav,
    sekce_katalog,
    ukazka_zpravy,
    validate_ezd_bundle,
)

VSECHNY = sorted(EZD_KATEGORIE)


def _client():
    return TestClient(app)


def _composition(bundle):
    return bundle["entry"][0]["resource"]


def _kody_sekci(bundle):
    return [s["code"]["coding"][0]["code"] for s in _composition(bundle)["section"]]


# --- katalog ------------------------------------------------------------------

def test_katalog_obsahuje_vsech_pet_typu():
    kat = katalog_zprav()
    assert {t["kategorie"] for t in kat} == set(VSECHNY)
    assert len(kat) == 5
    igs = {t["ig"] for t in kat}
    assert igs == {"hl7.fhir.cz.ps", "hl7.fhir.cz.hdr", "hl7.fhir.cz.img",
                    "hl7.fhir.cz.ems", "hl7.fhir.cz.lab"}


@pytest.mark.parametrize("kat", VSECHNY)
def test_katalog_ma_dokumentaci_a_pozadavky(kat):
    t = next(x for x in katalog_zprav() if x["kategorie"] == kat)
    assert t["ig_url"].startswith("https://build.fhir.org/ig/HL7-cz/")
    assert "444/2024" in t["legislativa"]
    assert t["composition_profile"].startswith("https://hl7.cz/fhir/")
    assert t["type_coding"]["code"]
    assert t["du_typ_kod"]
    assert t["pozadavky"]["min_sekci"] >= 1
    assert t["sekce"], "katalog sekcí nesmí být prázdný"


@pytest.mark.parametrize("kat", VSECHNY)
def test_sekce_katalog_povinne_prvni(kat):
    sekce = sekce_katalog(kat)
    povinne = [s for s in sekce if s["povinna"]]
    assert povinne, f"{kat}: musí mít alespoň jednu povinnou sekci"
    # povinné jsou na začátku seznamu
    assert all(s["povinna"] for s in sekce[:len(povinne)])
    # každá sekce má LOINC kód, slice i český název
    for s in sekce:
        assert s["code"] and s["slice"] and s["title"]


def test_sekce_katalog_neznama_kategorie():
    with pytest.raises(ValueError):
        sekce_katalog("neexistuje")


# --- builder s obsahem sekcí ---------------------------------------------------

@pytest.mark.parametrize("kat", VSECHNY)
def test_ukazka_je_validni_a_ma_obsah(kat):
    bundle = ukazka_zpravy(kat)
    v = validate_ezd_bundle(bundle)
    assert v["errors"] == []
    assert v["valid"] and v["kategorie"] == kat
    # ukázka plní i volitelné sekce (kromě lab, kde IG má jen 2 sekce)
    povinnych = len(EZD_KATEGORIE[kat]["required_sections"])
    assert len(_composition(bundle)["section"]) >= povinnych
    # texty sekcí nejsou placeholder
    texty = [s["text"]["div"] for s in _composition(bundle)["section"]]
    assert any("Informace není k dispozici" not in t for t in texty)


def test_volitelna_sekce_jen_s_obsahem():
    bez = build_ezd_bundle("pacientsky-souhrn", rid="1", autor_krzpid="2", ico="3")
    kody_bez = _kody_sekci(bez)
    assert "11369-6" not in kody_bez, "očkování bez obsahu se nesmí přidat"

    s_obsahem = build_ezd_bundle("pacientsky-souhrn", rid="1", autor_krzpid="2",
                                   ico="3", sekce={"sectionImmunizations": "Tetanus 2021"})
    assert "11369-6" in _kody_sekci(s_obsahem)


def test_povinna_sekce_vzdy_pritomna_i_bez_textu():
    b = build_ezd_bundle("propousteci-zprava", rid="1", autor_krzpid="2", ico="3")
    assert "8648-8" in _kody_sekci(b)
    hosp = next(s for s in _composition(b)["section"]
                if s["code"]["coding"][0]["code"] == "8648-8")
    assert "Informace není k dispozici" in hosp["text"]["div"]


def test_obsah_sekce_jako_seznam_i_text():
    b1 = build_ezd_bundle("vyjezd-zzs", rid="1", autor_krzpid="2", ico="3",
                           sekce={"mission": ["Výzva 18:42", "Na místě 18:48"]})
    div = next(s for s in _composition(b1)["section"]
               if s["code"]["coding"][0]["code"] == "67664-3")["text"]["div"]
    assert "Výzva 18:42" in div and "Na místě 18:48" in div

    b2 = build_ezd_bundle("vyjezd-zzs", rid="1", autor_krzpid="2", ico="3",
                           sekce={"mission": "Jediná položka"})
    assert "Jediná položka" in _composition(b2)["section"][0]["text"]["div"]
    # prázdný obsah → placeholder povinné sekce
    b3 = build_ezd_bundle("vyjezd-zzs", rid="1", autor_krzpid="2", ico="3",
                           sekce={"mission": ["  ", ""]})
    assert "Informace není k dispozici" in _composition(b3)["section"][0]["text"]["div"]


def test_autor_jmeno_v_practitioner():
    b = build_ezd_bundle("pacientsky-souhrn", rid="1", autor_krzpid="2", ico="3",
                          autor={"jmeno": "Jan", "prijmeni": "Novák", "titul": "MUDr."})
    pract = next(e["resource"] for e in b["entry"]
                 if e["resource"]["resourceType"] == "Practitioner")
    name = pract["name"][0]
    assert name["family"] == "Novák" and name["given"] == ["Jan"]
    assert name["prefix"] == ["MUDr."]


# --- laboratorní zpráva (nová kategorie) --------------------------------------

def test_laboratorni_zprava_dle_cz_lab():
    meta = EZD_KATEGORIE["laboratorni-vysetreni"]
    assert meta["ig"] == "hl7.fhir.cz.lab" and meta["ig_verze"] == "0.5.0"
    assert meta["composition_profile"].endswith("/cz-composition-lab-report")
    b = ukazka_zpravy("laboratorni-vysetreni")
    comp = _composition(b)
    # cz-composition-lab-report: language 1..1, section 1..*
    assert comp["language"] == "cs"
    assert len(comp["section"]) >= 1
    # cz-bundle-lab: entry:diagnosticReport 1..1
    assert any(e["resource"]["resourceType"] == "DiagnosticReport"
               for e in b["entry"])
    assert validate_ezd_bundle(b)["valid"]


# --- API endpointy -------------------------------------------------------------

def test_api_katalog():
    r = _client().get("/api/zpravy/katalog")
    assert r.status_code == 200
    assert len(r.json()["typy"]) == 5


@pytest.mark.parametrize("kat", VSECHNY)
def test_api_ukazka(kat):
    r = _client().get(f"/api/zpravy/ukazka/{kat}")
    assert r.status_code == 200
    d = r.json()
    assert d["validace"]["valid"] is True
    assert d["bundle"]["resourceType"] == "Bundle"
    assert d["sekce_ukazka"] == UKAZKY[kat]["sekce"]


def test_api_ukazka_neznama_kategorie():
    assert _client().get("/api/zpravy/ukazka/neexistuje").status_code == 404


def test_api_nahled_vraci_hash_a_validaci():
    r = _client().post("/api/zpravy/nahled", json={
        "kategorie": "propousteci-zprava",
        "rid": "2667873559",
        "title": "Test",
        "sekce": {"sectionHospitalCourse": ["Průběh OK"]},
    })
    assert r.status_code == 200
    d = r.json()
    assert d["validace"]["valid"] is True
    assert d["velikost_bytes"] > 0 and len(d["sha256"]) == 64
    assert "Průběh OK" in str(d["bundle"])


def test_api_nahled_neznama_kategorie():
    r = _client().post("/api/zpravy/nahled", json={"kategorie": "xxx"})
    assert r.status_code == 400


def test_api_validovat_vlastni_json():
    c = _client()
    ok = c.post("/api/zpravy/validovat",
                json={"bundle": ukazka_zpravy("vyjezd-zzs")}).json()
    assert ok["valid"] is True
    bad = c.post("/api/zpravy/validovat",
                 json={"bundle": {"resourceType": "Bundle", "type": "collection"}}).json()
    assert bad["valid"] is False and bad["errors"]


def test_api_odeslat_du_bez_pripojeni():
    r = _client().post("/api/zpravy/odeslat-du", json={"kategorie": "vyjezd-zzs"})
    assert r.status_code == 503


def test_gui_obsahuje_builder():
    body = _client().get("/").text
    for marker in ["sec-zpravy", "zpravyInit", "zpravyVybrat",
                    "Zprávy eZD (builder)", "zpravyOdeslatDu",
                    "zpravyValidovatVlastni", "Vyplnit ukázková data"]:
        assert marker in body, f"GUI neobsahuje: {marker}"
