"""
Testy generátoru InterSystems IRIS (ObjectScript) kódu pro zprávy eZD.

Ověřuje, že z obsahu builderu vznikne kód, který v IRIS sestaví tutéž
zprávu přes SEZ.EZD.Builder – pro všech 5 typů dle HL7 CZ IG.

Offline – bez síťové závislosti.
Spuštění:  python3 -m pytest tests/test_iris_ezd.py -v
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from sez_api.app import app
from sez_api.fhir_ezd import EZD_KATEGORIE
from sez_api.iris_ezd import (
    BUILDER_CLS_PATH,
    builder_cls,
    gen_snippet,
    gen_trida,
    gen_vse,
    ukazkovy_balicek,
)

VSECHNY = sorted(EZD_KATEGORIE)
LINTER = Path(".cursor/skills/iris-objectscript/scripts/lint_udl.py")


def _client():
    return TestClient(app)


# --- runtime třída Builder ------------------------------------------------------

def test_builder_cls_existuje_a_ma_klicove_metody():
    src = builder_cls()
    assert BUILDER_CLS_PATH.exists()
    assert "Class SEZ.EZD.Builder Extends %RegisteredObject" in src
    for metoda in ("Sestav", "Validuj", "ZasilkaProDU", "SestavAOdesli",
                    "Metadata", "PovinneSekce", "VolitelneSekce"):
        assert f"ClassMethod {metoda}(" in src, f"chybí metoda {metoda}"


def test_builder_zna_vsech_pet_kategorii():
    src = builder_cls()
    for kat in VSECHNY:
        assert f'pKategorie = "{kat}"' in src, f"Builder nezná {kat}"
    # LOINC kódy dokumentů z profilů
    for kod in ("60591-5", "34105-7", "18748-4", "67796-3", "11502-2"):
        assert f'"typKod": "{kod}"' in src


def test_builder_hlida_pravidla_du_a_ig():
    src = builder_cls()
    # adresát ≠ tvůrce (E01001) a povinné prvky profilů
    assert "E01001" in src
    assert "presentedForm" in src and "diagnosticReport" in src
    assert "https://ncez.mzcr.cz/fhir/sid/rid" in src


# --- generovaný snippet ----------------------------------------------------------

@pytest.mark.parametrize("kat", VSECHNY)
def test_snippet_obsahuje_volani_builderu(kat):
    kod = gen_snippet(kat, sekce={"x": "y"})
    meta = EZD_KATEGORIE[kat]
    assert "##class(SEZ.EZD.Builder).Sestav(" in kod
    assert f'"{kat}"' in kod
    assert "$$$ISERR(sc)" in kod, "musí kontrolovat %Status"
    assert "Validuj" in kod
    assert meta["ig"] in kod and meta["legislativa"] in kod


def test_snippet_prenasi_obsah_sekci():
    kod = gen_snippet("propousteci-zprava", sekce={
        "sectionHospitalCourse": ["První řádek", "Druhý řádek"],
        "sectionAllergies": "Penicilin",
    })
    # víceřádková sekce → %DynamicArray s %Push
    assert "##class(%DynamicArray).%New()" in kod
    assert '%Push("První řádek")' in kod and '%Push("Druhý řádek")' in kod
    # jednořádková → přímý %Set
    assert '%Set("sectionAllergies", "Penicilin")' in kod
    # komentář s názvem a LOINC kódem sekce
    assert "LOINC 8648-8" in kod


def test_snippet_escapuje_uvozovky():
    kod = gen_snippet("vyjezd-zzs", sekce={"mission": 'Pacient řekl "bolí to"'})
    assert '"Pacient řekl ""bolí to"""' in kod


def test_snippet_vynecha_prazdne_sekce():
    kod = gen_snippet("vyjezd-zzs", sekce={"mission": "   ", "dispatch": ""})
    assert "%Set(\"mission\"" not in kod
    assert "%Set(\"dispatch\"" not in kod


def test_snippet_demografie_volitelna():
    bez = gen_snippet("pacientsky-souhrn")
    assert 'Set pacient = ""' in bez
    s_daty = gen_snippet("pacientsky-souhrn",
                          pacient={"jmeno": "Jan", "prijmeni": "Novák",
                                    "datum_narozeni": "1980-01-01"},
                          autor_data={"titul": "MUDr.", "prijmeni": "Lékař"})
    assert '%Set("jmeno", "Jan")' in s_daty
    assert '%Set("datumNarozeni", "1980-01-01")' in s_daty
    assert '%Set("titul", "MUDr.")' in s_daty


def test_snippet_neznama_kategorie():
    with pytest.raises(ValueError):
        gen_snippet("neexistuje")


# --- generovaná třída -------------------------------------------------------------

@pytest.mark.parametrize("kat", VSECHNY)
def test_trida_ma_spravnou_strukturu(kat):
    nazev, src = gen_trida(kat, sekce={"x": "y"})
    assert nazev.startswith("SEZ.EZD.Zpravy.")
    assert f"Class {nazev} Extends %RegisteredObject" in src
    assert src.rstrip().endswith("}")
    for m in ("ClassMethod Sekce(", "ClassMethod Sestav(",
              "ClassMethod Nahled(", "ClassMethod Odesli("):
        assert m in src, f"{kat}: chybí {m}"
    assert f'Parameter KATEGORIE = "{kat}";' in src
    # doc komentáře s odkazem na standard
    assert EZD_KATEGORIE[kat]["ig_url"] in src


def test_nazev_tridy_bez_diakritiky():
    nazev, _ = gen_trida("laboratorni-vysetreni")
    assert nazev == "SEZ.EZD.Zpravy.LaboratorniVysetreni"
    assert re.fullmatch(r"[A-Za-z0-9.]+", nazev)


def test_trida_ma_adresata_ruzneho_od_tvurce():
    _, src = gen_trida("vyjezd-zzs", ico="25488627", ico_adresat="00064165")
    assert 'Parameter ICO = "25488627";' in src
    assert 'Parameter ICOADRESAT = "00064165";' in src
    assert "E01001" in src, "musí upozornit na validaci DÚ"


@pytest.mark.skipif(not LINTER.exists(), reason="linter skillu není k dispozici")
@pytest.mark.parametrize("kat", VSECHNY)
def test_generovana_trida_prochazi_linterem(kat, tmp_path):
    balicek = ukazkovy_balicek(kat)
    f = tmp_path / (balicek["trida_nazev"].split(".")[-1] + ".cls")
    f.write_text(balicek["trida"], encoding="utf-8")
    r = subprocess.run([sys.executable, str(LINTER), str(f)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 error(s)" in r.stdout


@pytest.mark.skipif(not LINTER.exists(), reason="linter skillu není k dispozici")
def test_runtime_builder_prochazi_linterem():
    r = subprocess.run([sys.executable, str(LINTER), str(BUILDER_CLS_PATH)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


# --- balíček a API ------------------------------------------------------------------

@pytest.mark.parametrize("kat", VSECHNY)
def test_gen_vse_vraci_kompletni_balicek(kat):
    b = gen_vse(kat, sekce={"x": "y"})
    assert set(b) >= {"kategorie", "snippet", "trida", "trida_nazev",
                       "builder", "builder_nazev", "poznamka"}
    assert b["builder_nazev"] == "SEZ.EZD.Builder"
    assert "Class SEZ.EZD.Builder" in b["builder"]


def test_ukazkovy_balicek_nese_ukazkova_data():
    b = ukazkovy_balicek("obrazove-vysetreni")
    assert "CT hrudníku" in b["snippet"]
    assert "CT hrudníku" in b["trida"]


def test_api_iris_kod():
    r = _client().post("/api/zpravy/iris-kod", json={
        "kategorie": "propousteci-zprava",
        "sekce": {"sectionHospitalCourse": ["Bez komplikací"]},
    })
    assert r.status_code == 200
    d = r.json()
    assert d["trida_nazev"] == "SEZ.EZD.Zpravy.PropousteciZprava"
    assert "Bez komplikací" in d["snippet"]
    assert "Class SEZ.EZD.Builder" in d["builder"]


def test_api_iris_kod_neznama_kategorie():
    r = _client().post("/api/zpravy/iris-kod", json={"kategorie": "xxx"})
    assert r.status_code == 400


def test_api_iris_builder():
    r = _client().get("/api/zpravy/iris-builder")
    assert r.status_code == 200
    assert r.json()["nazev"] == "SEZ.EZD.Builder"
    assert "ClassMethod Sestav(" in r.json()["zdroj"]


def test_gui_ma_iris_generator():
    body = _client().get("/").text
    for marker in ["zpravyIrisKod", "Generovat IRIS kód", "zpravyIrisStahnout",
                    "zpravy-iris-builder", "SEZ.EZD.Builder"]:
        assert marker in body, f"GUI neobsahuje: {marker}"
