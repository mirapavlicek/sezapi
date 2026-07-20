"""
Testy modulu sez_api.fhir_ezd – buildery a L1 validace dokumentů eZD dle
Metodiky testování EHR fáze I (IROP/NPO) a HL7 CZ Implementation Guides:

  - Pacientský souhrn        HL7-cz/ps      0.0.1   (LOINC 60591-5)
  - Propouštěcí zpráva       HL7-cz/hdr     0.1.0   (LOINC 34105-7)
  - Zpráva z obraz. vyšetření HL7-cz/img    0.1.0-b (LOINC 18748-4)
  - Zpráva o výjezdu ZZS     HL7-cz/cz-ems  0.0.2   (LOINC 67796-3)

Offline – bez síťové závislosti.
Spuštění:  python3 -m pytest tests/test_fhir_ezd.py -v
"""

import base64
import copy

import pytest

from sez_api.fhir_ezd import (
    EZD_KATEGORIE,
    PRESENTED_FORM_EXT,
    RID_SYSTEM,
    build_ezd_bundle,
    detect_kategorie,
    minimal_pdf_base64,
    validate_ezd_bundle,
)

RID = "2667873559"
KRZPID = "102129137"
ICO = "25488627"


def _build(kat, **kw):
    return build_ezd_bundle(kat, rid=RID, autor_krzpid=KRZPID, ico=ICO, **kw)


def _composition(bundle):
    return bundle["entry"][0]["resource"]


# --- buildery: všechny prioritní kategorie jsou validní dle L1 --------------

@pytest.mark.parametrize("kat", sorted(EZD_KATEGORIE))
def test_builder_produkuje_validni_bundle(kat):
    bundle = _build(kat)
    v = validate_ezd_bundle(bundle)
    assert v["errors"] == []
    assert v["valid"] is True
    assert v["kategorie"] == kat
    assert v["warnings"] == []


@pytest.mark.parametrize("kat", sorted(EZD_KATEGORIE))
def test_bundle_zaklad(kat):
    bundle = _build(kat)
    meta = EZD_KATEGORIE[kat]
    assert bundle["resourceType"] == "Bundle"
    assert bundle["type"] == "document"
    assert bundle["identifier"]["value"]
    assert bundle["timestamp"]
    assert meta["bundle_profile"] in bundle["meta"]["profile"]
    # první entry je Composition (pravidlo document Bundle)
    assert _composition(bundle)["resourceType"] == "Composition"
    assert all(e.get("fullUrl") for e in bundle["entry"])


def test_hdr_type_dle_ig_34105_7():
    """Propouštěcí zpráva má dle IG LOINC 34105-7, ne 18842-5."""
    comp = _composition(_build("propousteci-zprava"))
    codes = [c["code"] for c in comp["type"]["coding"]]
    assert codes == ["34105-7"]


def test_hdr_novy_canonical_composition_profilu():
    """CI build HDR IG z 10. 7. 2026 přejmenoval canonical composition
    profilu na composition-cz-hdr; starý cz-composition-hdr je alias."""
    meta = EZD_KATEGORIE["propousteci-zprava"]
    assert meta["composition_profile"].endswith("/composition-cz-hdr")
    assert any(a.endswith("/cz-composition-hdr")
                for a in meta["composition_profile_aliasy"])
    # builder deklaruje nový canonical
    comp = _composition(_build("propousteci-zprava"))
    assert meta["composition_profile"] in comp["meta"]["profile"]


def test_hdr_stary_canonical_je_vyhrada_ne_chyba():
    from sez_api.fhir_ezd import validate_ezd_bundle
    bundle = _build("propousteci-zprava")
    comp = _composition(bundle)
    comp["meta"]["profile"] = [
        "https://hl7.cz/fhir/hdr/StructureDefinition/cz-composition-hdr"]
    v = validate_ezd_bundle(bundle)
    assert v["valid"], "starý canonical nesmí být chyba"
    assert any("starší canonical" in w for w in v["warnings"])
    # detekce kategorie funguje i podle aliasu (bez type kódu)
    from sez_api.fhir_ezd import detect_kategorie
    comp["type"] = {"coding": [{"system": "http://loinc.org", "code": "99999-9"}]}
    assert detect_kategorie(bundle) == "propousteci-zprava"


def test_hdr_povinny_encounter_a_prubeh_hospitalizace():
    bundle = _build("propousteci-zprava")
    comp = _composition(bundle)
    assert comp.get("encounter"), "cz-composition-hdr: encounter 1..1"
    section_codes = [s["code"]["coding"][0]["code"] for s in comp["section"]]
    assert "8648-8" in section_codes, "sectionHospitalCourse 1..1 (LOINC 8648-8)"
    assert any(e["resource"]["resourceType"] == "Encounter" for e in bundle["entry"])


def test_ps_presented_form_a_ips_sekce():
    comp = _composition(_build("pacientsky-souhrn"))
    exts = [e for e in comp.get("extension", []) if e["url"] == PRESENTED_FORM_EXT]
    assert exts, "cz-composition-ps: presentedForm 1..*"
    att = exts[0]["valueAttachment"]
    assert att["contentType"] == "application/pdf"
    assert base64.b64decode(att["data"]).startswith(b"%PDF")
    section_codes = {s["code"]["coding"][0]["code"] for s in comp["section"]}
    assert {"10160-0", "48765-2", "11450-4"} <= section_codes, \
        "IPS: Medications + Allergies + Problems"


def test_img_kategorie_sekce_a_diagnostic_report():
    bundle = _build("obrazove-vysetreni")
    comp = _composition(bundle)
    assert comp["language"] == "cs", "cz-composition-imaging: language 1..1"
    assert comp.get("identifier"), "identifier 1..1"
    assert comp.get("confidentiality"), "confidentiality 1..1"
    assert len(comp.get("category", [])) >= 3, "category min=3"
    cat_codes = {c["code"] for cat in comp["category"] for c in cat["coding"]}
    assert "85430-7" in cat_codes
    assert "Medical-Imaging" in cat_codes
    assert len(comp["section"]) >= 4, "section min=4"
    section_codes = {s["code"]["coding"][0]["code"] for s in comp["section"]}
    assert {"18726-0", "55115-0", "11329-0", "55111-9"} <= section_codes
    assert any(e["resource"]["resourceType"] == "DiagnosticReport"
               for e in bundle["entry"]), "cz-bundle-imaging: diagnosticReport 1..*"


def test_ems_type_a_kategorie():
    comp = _composition(_build("vyjezd-zzs"))
    assert comp["type"]["coding"][0]["code"] == "67796-3"
    assert comp["category"][0]["coding"][0]["code"] == "18682-5"


def test_pacient_ma_rid_dle_cz_core():
    bundle = _build("pacientsky-souhrn")
    patient = next(e["resource"] for e in bundle["entry"]
                   if e["resource"]["resourceType"] == "Patient")
    assert any(i["system"] == RID_SYSTEM and i["value"] == RID
               for i in patient["identifier"])


def test_neznama_kategorie_vyhodi_chybu():
    with pytest.raises(ValueError):
        _build("recept")


# --- validátor: negativní případy -------------------------------------------

def test_validace_chybejici_presented_form():
    bundle = _build("propousteci-zprava")
    _composition(bundle).pop("extension")
    v = validate_ezd_bundle(bundle)
    assert not v["valid"]
    assert any("presentedForm" in e for e in v["errors"])


def test_validace_spatny_type_kod():
    bundle = _build("propousteci-zprava")
    _composition(bundle)["type"]["coding"][0]["code"] = "18842-5"
    v = validate_ezd_bundle(bundle, kategorie="propousteci-zprava")
    assert not v["valid"]
    assert any("34105-7" in e for e in v["errors"])


def test_validace_chybejici_povinna_sekce():
    bundle = _build("propousteci-zprava")
    _composition(bundle)["section"] = [
        {"title": "Jiná sekce",
         "code": {"coding": [{"system": "http://loinc.org", "code": "11535-2"}]},
         "text": {"status": "generated", "div": "<div>x</div>"}},
    ]
    v = validate_ezd_bundle(bundle)
    assert not v["valid"]
    assert any("8648-8" in e for e in v["errors"])


def test_validace_chybejici_encounter_hdr():
    bundle = _build("propousteci-zprava")
    _composition(bundle).pop("encounter")
    v = validate_ezd_bundle(bundle)
    assert any("encounter" in e for e in v["errors"])


def test_validace_img_bez_diagnostic_reportu():
    bundle = _build("obrazove-vysetreni")
    bundle["entry"] = [e for e in bundle["entry"]
                        if e["resource"]["resourceType"] != "DiagnosticReport"]
    v = validate_ezd_bundle(bundle)
    assert any("DiagnosticReport" in e for e in v["errors"])


def test_validace_legacy_rid_oid_je_vyhrada():
    bundle = _build("pacientsky-souhrn")
    patient = next(e["resource"] for e in bundle["entry"]
                   if e["resource"]["resourceType"] == "Patient")
    patient["identifier"] = [{"system": "urn:oid:2.16.840.1.113883.4.653",
                               "value": RID}]
    v = validate_ezd_bundle(bundle)
    assert v["valid"], "legacy OID je výhrada, ne chyba"
    assert any("legacy OID" in w for w in v["warnings"])


def test_validace_neni_bundle():
    v = validate_ezd_bundle({"resourceType": "Composition"})
    assert not v["valid"]
    v2 = validate_ezd_bundle("nesmysl")
    assert not v2["valid"]


def test_detekce_kategorie_z_type():
    for kat in EZD_KATEGORIE:
        assert detect_kategorie(_build(kat)) == kat


def test_detekce_kategorie_z_profilu():
    bundle = _build("vyjezd-zzs")
    comp = _composition(bundle)
    # bez type kódu se kategorie určí z meta.profile
    comp["type"] = {"coding": [{"system": "http://loinc.org", "code": "99999-9"}]}
    assert detect_kategorie(bundle) == "vyjezd-zzs"


def test_minimal_pdf_je_validni_base64_pdf():
    raw = base64.b64decode(minimal_pdf_base64())
    assert raw.startswith(b"%PDF-1.4")
    assert raw.rstrip().endswith(b"%%EOF")


def test_bundle_je_serializovatelny_a_nemutuje_definice():
    before = copy.deepcopy(EZD_KATEGORIE)
    for kat in EZD_KATEGORIE:
        b1 = _build(kat)
        b2 = _build(kat)
        assert b1["entry"][0]["fullUrl"] != b2["entry"][0]["fullUrl"]
    assert EZD_KATEGORIE == before
