"""
Testy NCPeH integrace – přeshraniční pacientský souhrn (MyHealth@EU/eHDSI).

Pokrývá obě role dle Testovacího rámce interoperability IS PZS s NCPeH ČR
v1.1 (Kraj Vysočina):
  - role A (zdroj dat): getpsexists se STABILNÍM identifikátorem dokumentu,
    generování PS CDA L3 (strukturovaný) a L1 (PDF v CDA) vč. kontrol
    z testovacího rámce (case-sensitive tagy, OIDy, effectiveTime, sekce),
  - role B (konzument): vyhledání pacienta, dokumenty, stažení a parsování
    souhrnu (v SIMULACI vč. „kritického pacienta" s plným souhrnem).

Offline – bez síťové závislosti (režim SIMULACE).
Spuštění:  python3 -m pytest tests/test_ncpeh.py -v
"""

import base64

from starlette.testclient import TestClient

from sez_api.app import app
from sez_api.ncpeh import (
    LOINC_PS,
    NCPeH,
    PS_SEKCE,
    SAMPLE_PACIENTI,
    build_ps_cda_l1,
    build_ps_cda_l3,
    parse_ps_cda,
    zkontroluj_ps_cda,
)

PACIENT = {
    "rid": "2667873559", "jmeno": "MRAČENA", "prijmeni": "MRAKOMOROVÁ",
    "datum_narozeni": "1971-11-26", "pohlavi": "F", "autor_krzpid": "102129137",
    "alergie": [{"text": "Pyl břízy", "kod": "256319004"}],
    "medikace": [{"text": "Ibuprofen 400 mg", "kod": "387207008"}],
    "problemy": [{"text": "Alergická rýma", "kod": "367498001"}],
}


def _client():
    return TestClient(app)


# --- CDA buildery (role A) ----------------------------------------------------

def test_cda_l3_projde_kontrolami_testovaciho_ramce():
    cda = build_ps_cda_l3(PACIENT, ico="25488627", pzs_nazev="Test PZS")
    v = zkontroluj_ps_cda(cda)
    assert v["chyby"] == []
    assert v["valid"] is True
    # case-sensitive kořen + namespace + kód dokumentu
    assert "<ClinicalDocument" in cda
    assert 'xmlns="urn:hl7-org:v3"' in cda
    assert f'code="{LOINC_PS}"' in cda


def test_cda_l3_obsahuje_povinne_sekce():
    cda = build_ps_cda_l3(PACIENT, ico="25488627", pzs_nazev="Test PZS")
    for s in PS_SEKCE:
        if s["povinna"]:
            assert f'code="{s["kod"]}"' in cda, f"chybí sekce {s['nazev']}"
    # SNOMED coded entries
    assert 'code="256319004"' in cda


def test_cda_l1_ma_pdf_v_non_xml_body():
    from sez_api.fhir_ezd import minimal_pdf_base64
    cda = build_ps_cda_l1(PACIENT, ico="25488627", pzs_nazev="Test PZS",
                            pdf_base64=minimal_pdf_base64())
    v = zkontroluj_ps_cda(cda)
    assert v["valid"] is True
    assert "nonXMLBody" in cda
    assert 'mediaType="application/pdf"' in cda


def test_validator_odhali_chyby():
    cda = build_ps_cda_l3(PACIENT, ico="25488627", pzs_nazev="Test PZS")
    v = zkontroluj_ps_cda(cda.replace('code="60591-5"', 'code="11111-1"'))
    assert not v["valid"]
    assert any("60591-5" in ch for ch in v["chyby"])
    v2 = zkontroluj_ps_cda("<foo/>")
    assert not v2["valid"]
    v3 = zkontroluj_ps_cda(cda.replace("<custodian>", "<x>").replace("</custodian>", "</x>"))
    assert any("custodian" in ch for ch in v3["chyby"])


def test_parser_vraci_pacienta_a_sekce():
    cda = build_ps_cda_l3(PACIENT, ico="25488627", pzs_nazev="Test PZS")
    p = parse_ps_cda(cda)
    assert p["pacient"]["prijmeni"] == "MRAKOMOROVÁ"
    assert p["pacient"]["id"] == "2667873559"
    assert p["dokument"]["kod"] == LOINC_PS
    kody = {s["kod"] for s in p["sekce"]}
    assert {"48765-2", "10160-0", "11450-4"} <= kody


# --- role A: stabilní identifikátor (klíčová kontrola rámce) ------------------

def test_getpsexists_stabilni_identifikator():
    """Opakované volání getpsexists NESMÍ generovat nový identifikátor."""
    n = NCPeH()
    r1 = n.get_ps_exists("2667873559")
    r2 = n.get_ps_exists("2667873559")
    assert r1["exists"] and r2["exists"]
    assert r1["cdaL3Id"] == r2["cdaL3Id"]
    assert r1["cdaL1Id"] == r2["cdaL1Id"]
    assert r1["cdaL3Oid"]
    # jiný pacient → jiný identifikátor
    r3 = n.get_ps_exists("7651669233")
    assert r3["cdaL3Id"] != r1["cdaL3Id"]


def test_get_ps_neexistujici_pacient():
    n = NCPeH()
    assert n.get_ps_exists("0000000000") == {"exists": False, "rid": "0000000000"}
    assert n.get_ps("0000000000")["exists"] is False


# --- role B: simulace ----------------------------------------------------------

def test_role_b_kriticky_pacient_ma_plny_souhrn():
    kriticky = [p for p in SAMPLE_PACIENTI if p["kriticky"]][0]
    n = NCPeH()
    r = n.retrieve_document(kriticky["stat"], kriticky["id"], uroven="L3")
    assert r["nalezen"] is True
    assert r["validace"]["valid"] is True
    # kritický pacient má všechny sekce PS (plně vyplněný souhrn)
    kody = {s["kod"] for s in r["parsed"]["sekce"]}
    assert {s["kod"] for s in PS_SEKCE} <= kody


def test_role_b_nenalezeny_pacient():
    n = NCPeH()
    assert n.query_patient("AT", "9999999999")["nalezen"] is False
    assert n.query_documents("AT", "9999999999")["dokumenty"] == []


def test_role_b_dokumenty_maji_stabilni_id():
    n = NCPeH()
    d1 = n.query_documents("AT", "1111241261")["dokumenty"]
    d2 = n.query_documents("AT", "1111241261")["dokumenty"]
    assert d1[0]["id"] == d2[0]["id"]


# --- API endpointy --------------------------------------------------------------

def test_api_status_a_konfigurace():
    c = _client()
    st = c.get("/api/ncpeh/status").json()
    assert st["mode"] == "SIMULACE"
    assert st["role_a"]["endpointy"]
    assert st["dokumentace"]
    cfg = c.get("/api/ncpeh/konfigurace-statu").json()
    assert any(s["stat"] == "AT" for s in cfg["staty"])


def test_api_role_b_flow():
    c = _client()
    r = c.post("/api/ncpeh/b/vyhledat-pacienta",
               json={"stat": "AT", "identifikator": "1111241261"}).json()
    assert r["nalezen"] and r["pacient"]["kriticky_pacient"] is True
    docs = c.post("/api/ncpeh/b/dokumenty",
                  json={"stat": "AT", "identifikator": "1111241261"}).json()
    assert {d["uroven"] for d in docs["dokumenty"]} == {"L3", "L1"}
    dl = c.post("/api/ncpeh/b/stahnout",
                json={"stat": "AT", "identifikator": "1111241261",
                       "uroven": "L1"}).json()
    assert dl["nalezen"] and "nonXMLBody" in dl["cda"]


def test_api_role_a_flow():
    c = _client()
    e1 = c.post("/api/ncpeh/a/get-ps-exists", json={"rid": "2667873559"}).json()
    e2 = c.post("/api/ncpeh/a/get-ps-exists", json={"rid": "2667873559"}).json()
    assert e1["exists"] and e1["cdaL3Id"] == e2["cdaL3Id"]
    ps = c.post("/api/ncpeh/a/get-ps",
                json={"rid": "2667873559", "uroven": "L3"}).json()
    assert ps["validace"]["valid"] is True
    assert "<ClinicalDocument" in ps["cda"]


def test_api_validace_cda():
    c = _client()
    cda = build_ps_cda_l3(PACIENT, ico="25488627", pzs_nazev="Test PZS")
    r = c.post("/api/ncpeh/validace-cda", json={"cda": cda}).json()
    assert r["valid"] is True
    assert r["parsed"]["pacient"]["id"] == "2667873559"
    r2 = c.post("/api/ncpeh/validace-cda", json={"cda": "<spatne/>"}).json()
    assert r2["valid"] is False


def test_gui_obsahuje_ncpeh_sekci():
    body = _client().get("/").text
    for marker in ["NCPeH Pacientský souhrn", "getpsexists", "ClientConnectorProxy",
                    "kritický pacient", "ncpehInit"]:
        assert marker in body, f"GUI neobsahuje: {marker}"


def test_base64_pdf_v_l1_je_dekodovatelne():
    from sez_api.fhir_ezd import minimal_pdf_base64
    cda = build_ps_cda_l1(PACIENT, ico="25488627", pzs_nazev="Test",
                            pdf_base64=minimal_pdf_base64())
    import re
    m = re.search(r'representation="B64">([^<]+)</text>', cda)
    assert m and base64.b64decode(m.group(1)).startswith(b"%PDF")
