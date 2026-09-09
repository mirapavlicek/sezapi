"""
Testy k revizi NCEZ zdrojů 9. 9. 2026.

- KRP: NCEZ vypíná v1 i v2 k 15. 9. 2026 → hlavní modul KRP volá v3, verze
  je parametrem; pool interního ztotožnění tvoří klienty ve stejné verzi.
- API endpointy (31. 8. 2026): User-Agent doporučený od 1. 9. 2026,
  povinný od 1. 1. 2027 – klient posílá vždy.
- HL7 CZ img-order IG (build 28. 8. 2026): Composition.type.coding.version
  (SNOMED CT CZ edice), povinná sekce clinicalQuestion, SR.identifier.
- HL7 CZ PS IG (build 15. 8. 2026): sectionPastProblems → sectionProblems.

Spuštění:  python3 -m pytest tests/test_revize_2026_09.py -v
"""

import pytest

from sez_api.client import KRP, KRPZtotozneniV3, KRPv3


class _Zaznam:
    """Atrapa SEZClient – zaznamenává volané cesty."""

    class _Cfg:
        GATEWAY = "https://brana.test"
        KRP_VERZE = "v3"

    def __init__(self, krp_verze="v3"):
        self.config = self._Cfg()
        self.config.KRP_VERZE = krp_verze
        self.cesty: list[tuple[str, str]] = []

    def post(self, path, body=None, **kw):
        self.cesty.append(("POST", path))
        return {"path": path, "body": body}

    def delete(self, path, body=None, **kw):
        self.cesty.append(("DELETE", path))
        return {"path": path, "body": body}


# --------------------------------------------------------------------------- #
# KRP – verze API
# --------------------------------------------------------------------------- #

def test_krp_vychozi_verze_je_v3():
    """Po 15. 9. 2026 brána v2 odmítá – výchozí prefix musí být /api/v3."""
    c = _Zaznam()
    krp = KRP(c)
    assert krp.VERZE == "v3"
    krp.hledat_rid("2667873559")
    krp.hledat_jmeno_rc("Marie", "Dvořáková", "0303091234")
    krp.ciselnik("pohlavi")
    krp.notifikace_zrusit({"x": 1}) if hasattr(krp, "notifikace_zrusit") else None
    assert all(p.startswith("/krp/api/v3/") for _, p in c.cesty), c.cesty
    assert ("POST", "/krp/api/v3/pacient/hledat/rid") in c.cesty
    assert ("POST", "/krp/api/v3/ciselnik/pohlavi") in c.cesty


def test_krp_verze_z_konfigurace_klienta_a_parametru():
    c = _Zaznam(krp_verze="v2")
    assert KRP(c).VERZE == "v2"
    assert KRP(c, verze="v3").VERZE == "v3"
    assert KRP(c, verze="3").VERZE == "v3"
    krp = KRP(c, verze="V2")
    krp.hledat_rid("1")
    assert c.cesty == [("POST", "/krp/api/v2/pacient/hledat/rid")]


def test_krp_v2_a_v3_maji_shodne_telo_pozadavku():
    """Dle swaggerů KRP_v2.0.2 a KRP_v3.0.0 se liší jen prefix cesty."""
    c2, c3 = _Zaznam(), _Zaznam()
    r2 = KRP(c2, verze="v2").hledat_jmeno_dn("Jan", "Novák", "1985-01-01", "CZ")
    r3 = KRP(c3, verze="v3").hledat_jmeno_dn("Jan", "Novák", "1985-01-01", "CZ")
    assert r2["path"].replace("/api/v2/", "/api/v3/") == r3["path"]
    assert r2["body"]["zadostData"] == r3["body"]["zadostData"]
    assert set(r3["body"]["zadostInfo"]) == {"datum", "ucel", "zadostId"}


def test_krp_v3_nema_vykonani_hromadneho_ztotozneni():
    """Endpoint ztotoznihromadne/vykonani je jen ve v2 (ve v3.0.0 není)."""
    c = _Zaznam()
    with pytest.raises(NotImplementedError):
        KRP(c, verze="v3").ztotozneni_vykonani("abc")
    assert c.cesty == []
    KRP(c, verze="v2").ztotozneni_vykonani("abc")
    assert c.cesty == [("POST", "/krp/api/v2/pacient/ztotoznihromadne/vykonani")]


def test_krpv3_a_adapter_pouzivaji_v3():
    c = _Zaznam()
    KRPv3(c).hledat_rid({"zadostData": {"rid": "1"}})
    KRPZtotozneniV3(c).hledat_rid("1")
    assert [p for _, p in c.cesty] == ["/krp/api/v3/pacient/hledat/rid"] * 2


def test_konfigurace_krp_verze():
    from sez_api import config as cfg
    assert cfg.KRP_VERZE == "v3"
    assert cfg.INTERNAL_KRP_VERZE == "v3"


def test_pool_ztotozneni_tvori_klienta_ve_stejne_verzi():
    """Regrese: pool při rozšíření vytvářel KRP v2 bez ohledu na nastavení."""
    from sez_api.app import _novy_krp_klient

    c = _Zaznam()
    assert isinstance(_novy_krp_klient(c, "v3"), KRPZtotozneniV3)
    assert isinstance(_novy_krp_klient(c, None), KRPZtotozneniV3)
    v2 = _novy_krp_klient(c, "v2")
    assert isinstance(v2, KRP) and v2.VERZE == "v2"


def test_katalog_sluzeb_uvadi_krp_v3():
    """Katalog endpointů v /api/debug/jwt (vyžaduje certifikát, proto se
    kontroluje zdroj) – KRP cesty musí být v3, jediná v2 výjimka je
    vykonani (ve v3 neexistuje)."""
    import pathlib
    import re

    src = pathlib.Path("sez_api/app.py").read_text(encoding="utf-8")
    cesty = re.findall(r'"path": "(/krp/api/v[23]/[^"]+)"', src)
    assert "/krp/api/v3/pacient/hledat/rid" in cesty
    v2 = [p for p in cesty if "/api/v2/" in p]
    assert v2 == ["/krp/api/v2/pacient/ztotoznihromadne/vykonani"], v2
    # generátor IRIS kódu nabízí KRP jen ve v3
    gen = pathlib.Path("sez_api/iris_codegen.py").read_text(encoding="utf-8")
    assert "/krp/api/v2" not in gen and "/krp/api/v3" in gen


def test_gui_uvadi_vypnuti_krp_v2():
    from starlette.testclient import TestClient

    from sez_api.app import app

    html = TestClient(app).get("/").text
    assert "15. 9. 2026" in html
    assert "SEZ_KRP_VERZE" in html
    assert "Revize 9. 9. 2026" in html
    # User-Agent: 31. 8. 2026 – doporučený od 1. 9., povinný od 1. 1. 2027
    assert "povinný od 1. 1. 2027" in html
    assert "POVINNÝ už od 1. 9. 2026" not in html


def test_iris_trida_krp_pouziva_parametr_verze():
    import pathlib

    cls = pathlib.Path("docs/analytics/src/cls/SEZ/API/KRP.cls").read_text(encoding="utf-8")
    assert 'Parameter APIVERZE = "v3";' in cls
    assert '/api/v2/' not in cls
    assert '..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/rid"' in cls


# --------------------------------------------------------------------------- #
# User-Agent – klient posílá vždy (nezávisle na termínu povinnosti)
# --------------------------------------------------------------------------- #

def test_user_agent_se_posila_vzdy():
    import re

    from sez_api.client import SEZClient

    ua = SEZClient.user_agent()
    assert re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+ \((Test|Prod); [^;)]+(; [^)]+)?\)$", ua), ua


# --------------------------------------------------------------------------- #
# img-order IG (CI build 2026-08-28)
# --------------------------------------------------------------------------- #

def _ncez_zadanka(s_diagnozou=True):
    z = {
        "zadanka": {
            "id": "ZAD-1",
            "zasilka": {"id": "ZAS-1", "nazev": "RTG hrudníku", "pacient": "2667873559",
                        "autor": "102129137", "poskytovatel": "25488627",
                        "poskytovatelData": {"nazev": "Testovací PZS"}},
            "urgentnost": {"kod": "routine"},
            "pacientPojistovna": {"kod": "111"},
            "datumVytvoreni": "2026-09-09T10:00:00+02:00",
        }
    }
    if s_diagnozou:
        z["zadanka"]["zadankaK"] = {
            "duvodZadanky": {"hlavniDiagnoza": {
                "coding": [{"system": "https://uzis.cz/terminology/CodeSystem/mkn-10",
                            "code": "S01.8", "display": "Otevřená rána jiných částí hlavy"}],
                "text": "pád ze 3 metrů, krvácení z hlavy",
            }},
            "pozadovanaVysetreni": [{"system": "http://snomed.info/sct", "kod": "168537006",
                                     "display": "rentgenový snímek"}],
        }
    return z


def _sekce(comp):
    return {((s.get("code") or {}).get("coding") or [{}])[0].get("code"): s
            for s in comp.get("section", [])}


def test_img_order_composition_type_ma_verzi_sct_cz_edice():
    from sez_api.fhir_imgorder import (EZadankaToImagingOrder, IG_DEPENDENCIES,
                                       IG_VERSION, SCT_CZ_EDITION)

    assert IG_VERSION == "0.1.0"
    assert IG_DEPENDENCIES["hl7.fhir.cz.core"] == "1.0.0"
    b = EZadankaToImagingOrder(_ncez_zadanka()).to_bundle()
    comp = b["entry"][0]["resource"]
    assert comp["resourceType"] == "Composition"
    codings = comp["type"]["coding"]
    assert len(codings) == 1
    assert codings[0]["version"] == SCT_CZ_EDITION == "http://snomed.info/sct/11000279109"
    assert codings[0]["code"] == "721964003"


def test_img_order_ma_povinnou_sekci_clinical_question_s_condition():
    from sez_api.fhir_imgorder import (EZadankaToImagingOrder,
                                       PROFILE_CONDITION_CLINICAL_QUESTION,
                                       ImagingOrderBundleParser)

    b = EZadankaToImagingOrder(_ncez_zadanka()).to_bundle()
    comp = b["entry"][0]["resource"]
    sekce = _sekce(comp)
    assert "55115-0" in sekce and "18785-6" in sekce
    ref = sekce["18785-6"]["entry"][0]["reference"]
    cond = next(e["resource"] for e in b["entry"] if e["fullUrl"] == ref)
    assert cond["resourceType"] == "Condition"
    assert cond["meta"]["profile"] == [PROFILE_CONDITION_CLINICAL_QUESTION]
    assert cond["code"]["text"]  # code.text 1..1
    # ServiceRequest.identifier je v profilu povinný
    sr = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "ServiceRequest")
    assert sr["identifier"] and sr["identifier"][0]["value"].startswith("urn:uuid:")
    # Validace nesmí na vygenerovaný Bundle hlásit chybějící prvky dle IG 8/2026
    issues = ImagingOrderBundleParser(b).validate()
    texty = " | ".join(i.get("diagnostics", "") or i.get("details", {}).get("text", "") or str(i)
                       for i in issues)
    assert "clinicalQuestion" not in texty
    assert "type.coding.version" not in texty
    assert "identifier je v profilu" not in texty


def test_img_order_clinical_question_bez_diagnozy_ma_empty_reason():
    from sez_api.fhir_imgorder import EZadankaToImagingOrder

    b = EZadankaToImagingOrder(_ncez_zadanka(s_diagnozou=False)).to_bundle()
    sekce = _sekce(b["entry"][0]["resource"])
    cq = sekce["18785-6"]
    assert "entry" not in cq
    assert cq["emptyReason"]["coding"][0]["code"] == "unavailable"


def test_img_order_validace_upozorni_na_stary_tvar():
    """Bundle bez version/sekce clinicalQuestion/identifier → varování (ne chyba)."""
    from sez_api.fhir_imgorder import EZadankaToImagingOrder, ImagingOrderBundleParser

    b = EZadankaToImagingOrder(_ncez_zadanka()).to_bundle()
    comp = b["entry"][0]["resource"]
    comp["type"]["coding"][0].pop("version")
    comp["section"] = [s for s in comp["section"]
                       if s["code"]["coding"][0]["code"] != "18785-6"]
    sr = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "ServiceRequest")
    sr.pop("identifier")
    issues = ImagingOrderBundleParser(b).validate()
    texty = [str(i) for i in issues]
    assert any("type.coding.version" in t for t in texty)
    assert any("clinicalQuestion" in t for t in texty)
    assert any("identifier" in t and "ServiceRequest" in t for t in texty)
    assert all(i["severity"] != "error" for i in issues)


def test_img_order_valuesety_maji_nove_kanonicke_url():
    from sez_api.fhir_imgorder import list_valuesets

    urls = {v["id"]: v["url"] for v in list_valuesets()}
    assert urls["cz-imagingProcedureVs"].endswith("/ValueSet/imaging-procedures")
    assert urls["cz-mobilityTypeVs"].endswith("/ValueSet/cz-mobility-type")
    assert urls["cz-mobilityValueVs"].endswith("/ValueSet/cz-mobility-value")
    assert urls["cz-diagnosisConditionVs"].endswith("/ValueSet/cz-diagnosis-condition")


# --------------------------------------------------------------------------- #
# PS IG (CI build 2026-08-15)
# --------------------------------------------------------------------------- #

def test_ps_sekce_past_problems_se_slouci_do_problems():
    from sez_api.fhir_ezd import EZD_KATEGORIE, build_ezd_bundle

    meta = EZD_KATEGORIE["pacientsky-souhrn"]
    kody = {s["code"] for s in meta["optional_sections"]}
    assert "11348-0" not in kody, "Past Problems byla v PS IG 15. 8. 2026 sloučena do Problems"
    assert any(s["slice"] == "sectionAlert" for s in meta["optional_sections"])

    b = build_ezd_bundle("pacientsky-souhrn", rid="2667873559", autor_krzpid="102129137",
                         ico="25488627",
                         sekce={"sectionProblems": "Hypertenze",
                                "sectionPastProblems": ["Apendektomie 2001"],
                                "sectionAlerts": "Kardiostimulátor"})
    comp = b["entry"][0]["resource"]
    sekce = _sekce(comp)
    assert "11348-0" not in sekce
    problemy = sekce["11450-4"]["text"]["div"]
    assert "Hypertenze" in problemy and "Apendektomie 2001" in problemy
    assert "104605-1" in sekce and "Kardiostimulátor" in sekce["104605-1"]["text"]["div"]


# --------------------------------------------------------------------------- #
# KRP v3 – historie pojištění / lékařů vyžaduje datum (PROD 9. 9. 2026)
# --------------------------------------------------------------------------- #

def test_krp_historie_doplni_dnesni_datum():
    """Brána v3 odmítá historii bez ``zadostData.datum`` („Pole Datum je
    povinné"); bez parametru se posílá dnešek ve tvaru YYYY-MM-DD."""
    from datetime import date

    c = _Zaznam()
    krp = KRP(c)
    r = krp.historie_pojisteni("2667873559")
    assert r["path"] == "/krp/api/v3/pacient/hledat/historie_pojisteni"
    assert r["body"]["zadostData"] == {"rid": "2667873559", "datum": date.today().isoformat()}
    r = krp.historie_registrujicich_lekaru("2667873559")
    assert r["body"]["zadostData"]["datum"] == date.today().isoformat()


@pytest.mark.parametrize("vstup, ocekavano", [
    ("2026-09-09", "2026-09-09"),
    ("2026-09-09T00:00:00Z", "2026-09-09T00:00:00Z"),
    # lokální posun brána odmítá („Chybný formát data a času") → převod na UTC
    ("2026-09-09T12:00:00+02:00", "2026-09-09T10:00:00Z"),
    # čas bez zóny brána odmítá → jen datum
    ("2026-09-09T00:00:00", "2026-09-09"),
])
def test_krp_historie_normalizuje_datum(vstup, ocekavano):
    assert KRP._datum_historie(vstup) == ocekavano


def test_krpv3_historie_doplni_datum_do_obalky():
    """Panel KRP v3 v GUI posílá hotovou obálku jen s rid – adaptér datum
    doplní, zadané datum zachová (normalizované)."""
    from datetime import date

    c = _Zaznam()
    k3 = KRPv3(c)
    r = k3.historie_pojisteni({"zadostInfo": {"ucel": "LECBA"}, "zadostData": {"rid": "1"}})
    assert r["body"]["zadostData"] == {"rid": "1", "datum": date.today().isoformat()}
    r = k3.historie_lekaru({"zadostData": {"rid": "1", "datum": "2026-01-01T00:00:00+01:00"}})
    assert r["body"]["zadostData"]["datum"] == "2025-12-31T23:00:00Z"


# --------------------------------------------------------------------------- #
# eŽádanky – stránky číslované od 1 (E01001), GUI přehled pacienta
# --------------------------------------------------------------------------- #

def test_ez_simulator_strankuje_od_jedne_jako_realne_api():
    from sez_api.app import _ez_sim_strankuj

    polozky = [{"id": str(i)} for i in range(5)]
    r = _ez_sim_strankuj(polozky, {"page": 1, "size": 2})
    assert [z["id"] for z in r["zadanky"]] == ["0", "1"]
    assert r["pageNumber"] == 1 and r["nextPage"] == 2 and r["pageCount"] == 3
    assert r["totalCount"] == 5 and r["items"] == r["zadanky"]
    r = _ez_sim_strankuj(polozky, {"page": 3, "size": 2})
    assert [z["id"] for z in r["zadanky"]] == ["4"] and r["nextPage"] is None
    with pytest.raises(ValueError):
        _ez_sim_strankuj(polozky, {"page": 0, "size": 2})


def test_gui_prehled_pacienta_neposila_stranku_nula():
    """Regrese: přehled pacienta volal VyhledejAktivniZadanku s page 0 →
    HTTP 400 E01001 a dlaždice ukazovala „chyba 400"."""
    import pathlib
    import re

    html = pathlib.Path("sez_api/templates/index.html").read_text(encoding="utf-8")
    volani = re.findall(r"vyhledej-aktivni'[^\n]*strankovani:\{page:(\d+)", html)
    assert volani and all(p == "1" for p in volani), volani
    assert 'id="ezSrcPage" value="1" min="1"' in html
    # DÚ vrací pole `zasilka`, eŽádanky `zadanky` + totalCount – počítadlo je zná
    # (dřív se prázdná stránkovaná odpověď počítala jako 1 zásilka)
    pocitadlo = html[html.index("function _nisCount("):html.index("function _nisErr(")]
    assert "'totalCount'" in pocitadlo and "'zasilka'" in pocitadlo and "'zadanky'" in pocitadlo
