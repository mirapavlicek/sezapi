"""
Testy k revizi NCEZ zdrojů 13. 10. 2026 (Manuál EZ pro PZS, 20 swaggerů z brány T2).

- eŽádanky API v2.0.0 (Standard eŽádanka 2.0; T2 od 25. 9., platné od 1. 10. 2026,
  v1.11.25 deprecated): hlavicka + FHIR Bundle, zdrojové cesty /api/v2/zadanka,
  If-Match = verzeZaznamu, 201 při uložení, bez UpravZadanku, stránkování od 0.
- KRZP: brána publikuje v2.0.7 i novou v3.0.4 – shodné cesty, jen přejmenované
  pole ztotozenaOsoba → ztotoznenaOsoba; klient KRZP(verze=…).
- SZZ v3.0.5: souhrn /zdravotniZaznamy/vyhledat ve swaggeru není → klient skládá
  /prevence/vyhledat + /screeningy/vyhledat.
- FHIR most img-order: to_v2() (hlavicka + Bundle beze ztráty), reverz z v2 odpovědi.
- Backend /api/ezadanky/v2/* a GUI (záložka eŽádanky v2, revize na dashboardu).

Spuštění:  python3 -m pytest tests/test_revize_2026_10.py -v
"""

import json
import os

import pytest

from sez_api.client import EZadanky, EZadankyV2, KRZP, SZZv3
from sez_api import fhir_imgorder as fi

PRIKLAD = os.path.join(os.path.dirname(fi.__file__), "fhir_imgorder_examples", "Bundle-BundleKralikRTG.json")


class _Odpoved:
    def __init__(self, status=200, data=None, headers=None):
        self.status_code = status
        self._data = data if data is not None else {}
        self.headers = headers or {}
        self.text = json.dumps(self._data)

    def json(self):
        return self._data


class _Zaznam:
    """Atrapa SEZClient – zaznamenává metodu, cestu, tělo a extra hlavičky."""

    class _Cfg:
        GATEWAY = "https://brana.test"

    def __init__(self, odpoved=None):
        self.config = self._Cfg()
        self.volani: list[tuple] = []
        self._odpoved = odpoved or _Odpoved()

    def _zaznamenej(self, m, path, body, kw):
        self.volani.append((m, path, body, kw.get("extra_headers")))
        return self._odpoved

    def post(self, path, body=None, **kw):
        return self._zaznamenej("POST", path, body, kw)

    def patch(self, path, body=None, **kw):
        return self._zaznamenej("PATCH", path, body, kw)

    def get(self, path, **kw):
        return self._zaznamenej("GET", path, None, kw)

    def put(self, path, body=None, **kw):
        return self._zaznamenej("PUT", path, body, kw)


# --------------------------------------------------------------------------- #
# eŽádanky v2 – klient
# --------------------------------------------------------------------------- #

def test_ezadanky_v1_je_deprecated_a_v2_aktualni():
    assert EZadanky.DEPRECATED is True and EZadanky.VERZE == "v1"
    assert EZadankyV2.DEPRECATED is False and EZadankyV2.VERZE == "v2"
    assert "deprecated" in (EZadanky.__doc__ or "").lower()


def test_v2_cesty_odpovidaji_swaggeru_2_0_0():
    """Všech 9 operací ze stránky API eŽádanky (7. 10. 2026) / Ezadanky_v2.0.0.json."""
    c = _Zaznam()
    ez = EZadankyV2(c)
    ez.uloz({"typZadanky": {"kod": "721964003"}}, {"resourceType": "Bundle", "type": "document"})
    ez.vyhledat({"strankovani": {"page": 0, "size": 5}})
    ez.vyhledat_aktivni({"rid": "1"})
    ez.nacist("ID1", kod_zadanky="K1", cislo_dokladu="D1")
    ez.prijmout("ID1", "V1", kod_zadanky="K1")
    ez.vratit_do_obehu("ID1", "V1", "kapacitni-omezeni", "text")
    ez.zaznacit_neproveditelnost("ID1", "V1", {"kod": "jiny-duvod", "verze": "1"}, None, "K1")
    ez.stornovat("ID1", "V1", "admin-chyba")
    ez.vyridit("ID1", "V1", zpusob_vyrizeni="zasilka", vysledek={"dokument": [{"nazev": "x"}]},
               datum_skutecne_realizace="2026-10-13", zaslat_pacientovi=True)
    cesty = [(m, p) for m, p, _, _ in c.volani]
    assert cesty == [
        ("POST", "/eZadanky/api/v2/zadanka"),
        ("POST", "/eZadanky/api/v2/zadanka/vyhledat"),
        ("POST", "/eZadanky/api/v2/zadanka/vyhledatAktivni"),
        ("POST", "/eZadanky/api/v2/zadanka/ID1/nacist"),
        ("PATCH", "/eZadanky/api/v2/zadanka/ID1/prijmout"),
        ("PATCH", "/eZadanky/api/v2/zadanka/ID1/vratitDoObehu"),
        ("PATCH", "/eZadanky/api/v2/zadanka/ID1/zaznacitNeproveditelnost"),
        ("PATCH", "/eZadanky/api/v2/zadanka/ID1/stornovat"),
        ("PATCH", "/eZadanky/api/v2/zadanka/ID1/vyridit"),
    ]
    assert all("/api/v1/" not in p for _, p in cesty)
    # operace jsou v katalogu třídy ve stejném pořadí jako na stránce NCEZ
    assert [o[0] for o in EZadankyV2.OPERACE] == [
        "ulozitZadanku", "vyhledatZadanky", "vyhledatAktivniZadanky", "nacistZadanku",
        "prijmoutZadanku", "vratitZadankuDoObehu", "zaznacitNeproveditelnostZadanky",
        "stornovatZadanku", "vyriditZadanku"]


def test_v2_telo_pozadavku_je_hlavicka_a_fhir_bundle():
    c = _Zaznam()
    hl = EZadankyV2.sestav_hlavicku(typ_zadanky="Z", pacient="RID", poskytovatel="ICO", autor="K1")
    assert hl == {"typZadanky": {"kod": "721964003"},
                  "zadatel": {"poskytovatel": "ICO", "autor": "K1", "zdravotnickyPracovnik": "K1"},
                  "pacient": "RID"}
    hl_k = EZadankyV2.sestav_hlavicku(typ_zadanky="K", pacient="RID", poskytovatel="ICO", autor="K1",
                                      zdravotnicky_pracovnik="K2", adresat="ICO2",
                                      dodatecny_prijemce=["ICO3"], nadrizena_zadanka_id="N1")
    assert hl_k["typZadanky"] == {"kod": "57133-1"}
    assert hl_k["zadatel"]["zdravotnickyPracovnik"] == "K2"
    assert hl_k["adresat"] == "ICO2" and hl_k["dodatecnyPrijemce"] == ["ICO3"] and hl_k["nadrizenaZadankaId"] == "N1"
    bundle = {"resourceType": "Bundle", "type": "document", "entry": [{"resource": {"resourceType": "Composition"}}]}
    EZadankyV2(c).uloz(hl, bundle)
    _, _, body, _ = c.volani[0]
    assert set(body) == {"hlavicka", "fhirBundle"}
    assert body["fhirBundle"] is bundle
    # celé tělo lze předat i najednou
    EZadankyV2(c).uloz({"hlavicka": hl, "fhirBundle": bundle})
    assert c.volani[1][2] == {"hlavicka": hl, "fhirBundle": bundle}


def test_v2_procesni_operace_posilaji_if_match_a_bez_verze_radku():
    c = _Zaznam()
    ez = EZadankyV2(c)
    ez.prijmout("ID1", "AAA=", datum_planovaneho_vysetreni="2026-10-20")
    m, p, body, hdrs = c.volani[-1]
    assert hdrs == {"If-Match": "AAA="}
    assert "verzeRadku" not in body and "id" not in body
    assert body == {"datumPlanovanehoVysetreni": "2026-10-20"}
    ez.stornovat("ID1", "AAA=", "admin-chyba", "x" * 300)
    body = c.volani[-1][2]
    assert body["duvodStornaZadanky"] == {"kod": "admin-chyba"}
    assert len(body["duvodStornaUpresneni"]) == 250
    with pytest.raises(ValueError):
        ez.prijmout("ID1", None)
    with pytest.raises(ValueError):
        ez.stornovat("ID1", "", "x")


def test_v2_vyridit_vyzaduje_zasilku_s_dokumentem():
    ez = EZadankyV2(_Zaznam())
    with pytest.raises(ValueError):
        ez.vyridit("ID1", "V", zpusob_vyrizeni="x", vysledek={"dokument": []}, datum_skutecne_realizace="2026-10-13")
    with pytest.raises(ValueError):
        ez.vyridit("ID1", "V", zpusob_vyrizeni="x", vysledek=None, datum_skutecne_realizace="2026-10-13")


def test_v2_uprav_zadanku_neexistuje():
    with pytest.raises(NotImplementedError):
        EZadankyV2(_Zaznam()).uprav("ID1", "V", {})
    prevod = {p["v1"]: p for p in EZadankyV2.prevod_z_v1()}
    assert prevod["PATCH /api/v1/eZadanka/UpravZadanku"]["zruseno"] is True
    assert prevod["GET /api/v1/eZadanka/NactiZadanku/{id}"]["v2"] == "POST /api/v2/zadanka/{id}/nacist"
    assert len(prevod) == 10


def test_v2_verze_zaznamu_z_hlavicky_nebo_etag():
    assert EZadankyV2.verze_zaznamu(_Odpoved(data={"hlavicka": {"verzeZaznamu": "H1"}}, headers={"ETag": '"E1"'})) == "H1"
    assert EZadankyV2.verze_zaznamu(_Odpoved(data={}, headers={"ETag": '"E1"'})) == "E1"
    assert EZadankyV2.verze_zaznamu(_Odpoved(data={})) is None


def _konzistentni_bundle(ico="25488627", icp="72090001", adresat="00064165", performer=True,
                         rid="R", krzp="A", priority="routine"):
    """Minimální Bundle splňující serverová pravidla v2 (subject RID / author KRZP /
    custodian + IČP / performer, přesné urn:uuid reference)."""
    entry = [
        {"fullUrl": "urn:uuid:c1", "resource": {"resourceType": "Composition", "id": "c1",
                                                 "subject": {"reference": "urn:uuid:p1"},
                                                 "author": [{"reference": "urn:uuid:pr1"}],
                                                 "custodian": {"reference": "urn:uuid:o1"}}},
        {"fullUrl": "urn:uuid:p1", "resource": {"resourceType": "Patient", "id": "p1", "identifier": [
            {"system": "https://ncez.mzcr.cz/fhir/sid/rid", "value": rid}]}},
        {"fullUrl": "urn:uuid:pr1", "resource": {"resourceType": "PractitionerRole", "id": "pr1",
                                                  "practitioner": {"reference": "urn:uuid:d1"}}},
        {"fullUrl": "urn:uuid:d1", "resource": {"resourceType": "Practitioner", "id": "d1", "identifier": [
            {"system": "https://ncez.mzcr.cz/fhir/sid/krzp", "value": krzp}]}},
        {"fullUrl": "urn:uuid:o1", "resource": {"resourceType": "Organization", "id": "o1", "identifier": [
            {"system": "https://ncez.mzcr.cz/fhir/sid/ico", "value": ico},
            *([{"system": "https://ncez.mzcr.cz/fhir/sid/icp", "value": icp}] if icp else [])]}},
        {"fullUrl": "urn:uuid:s1", "resource": {"resourceType": "ServiceRequest", "id": "s1", "priority": priority,
                                                 "performer": [{"reference": "urn:uuid:o2"}] if performer else []}},
    ]
    if performer:
        entry.append({"fullUrl": "urn:uuid:o2", "resource": {"resourceType": "Organization", "id": "o2", "identifier": [
            {"system": "https://ncez.mzcr.cz/fhir/sid/ico", "value": adresat}]}})
    return {"resourceType": "Bundle", "type": "document", "entry": entry}


def test_v2_klientska_kontrola_pozadavku():
    ok = {"hlavicka": EZadankyV2.sestav_hlavicku(typ_zadanky="Z", pacient="R", poskytovatel="25488627",
                                                 autor="A", adresat="00064165"),
          "fhirBundle": _konzistentni_bundle()}
    assert EZadankyV2.zkontroluj_pozadavek(ok) == []
    spatne = {"hlavicka": {"typZadanky": {}, "zadatel": {}, "ispzs": "NIS"}, "zadanka": {},
              "fhirBundle": {"resourceType": "Bundle", "type": "collection", "entry": []}}
    v = EZadankyV2.zkontroluj_pozadavek(spatne)
    assert any("typZadanky" in x for x in v)
    assert any("ispzs" in x for x in v)          # pole z v1
    assert any("zadanka:" in x for x in v)       # DTO z v1
    assert any("document" in x for x in v)


def test_v2_konzistence_hlavicka_bundle_dle_t2():
    """Pravidla E00024 / E01001 / E01002 ověřená živě na T2 13. 10. 2026."""
    hl = EZadankyV2.sestav_hlavicku(typ_zadanky="Z", pacient="R", poskytovatel="25488627",
                                    autor="A", adresat="00064165")
    # poskytovatel ≠ IČO custodian
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(ico="99999999")})
    assert any("E00024" in x and "poskytovatel" in x for x in v)
    # chybí IČP žadatele
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(icp=None)})
    assert any("E01002" in x for x in v)
    # adresát bez provádějící Organization / jiné IČO
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(performer=False)})
    assert any("provádějící" in x for x in v)
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(adresat="11111111")})
    assert any("adresat (00064165)" in x for x in v)
    # adresát = poskytovatel
    hl2 = dict(hl, adresat="25488627")
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl2, "fhirBundle": _konzistentni_bundle(adresat="25488627")})
    assert any("E01001" in x for x in v)
    # neadresná žádanka bez performer je v pořádku
    hl3 = {k: val for k, val in hl.items() if k != "adresat"}
    assert EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl3, "fhirBundle": _konzistentni_bundle(performer=False)}) == []
    # RID pacienta / KRZP autora (přes PractitionerRole) musí odpovídat hlavičce
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(rid="X")})
    assert any("E00024" in x and "RID" in x for x in v)
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(krzp="X")})
    assert any("E00024" in x and "KRZP" in x for x in v)
    # priorita mimo request-priority-cz (routine | stat)
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": _konzistentni_bundle(priority="urgent")})
    assert any("E01001" in x and "urgent" in x for x in v)
    # relativní reference při absolutním fullUrl – server ji nenajde (přesná shoda fullUrl)
    b = _konzistentni_bundle()
    b["entry"][0]["resource"]["subject"] = {"reference": "Patient/p1"}
    b["entry"][1]["fullUrl"] = "https://example.org/fhir/Patient/p1"
    v = EZadankyV2.zkontroluj_pozadavek({"hlavicka": hl, "fhirBundle": b})
    assert any("fullUrl" in x and "normalizuj_reference" in x for x in v)


def test_v2_typy_zadanky_z_ciselniku_referralorder_types():
    """Ověřeno $expand na apio.csez.gov.cz/terminologie (13. 10. 2026)."""
    assert EZadankyV2.TYPY_ZADANKY["Z"]["kod"] == "721964003"
    assert EZadankyV2.TYPY_ZADANKY["K"]["kod"] == "57133-1"
    assert EZadankyV2.TYPY_ZADANKY["FT"]["kod"] == "57154-7"
    assert EZadankyV2.CISELNIKY["stav"] == "stav-zadanky"
    assert EZadankyV2.CISELNIKY["typZadanky"] == "referralorder-types"


def test_v2_diagnose_nema_vedlejsi_ucinky():
    c = _Zaznam(_Odpoved(404, {"errors": [{"error": "E00002"}]}))
    r = EZadankyV2(c).diagnose()
    assert r["verze"] == "v2" and r["pzs_context"] is True
    assert all("/api/v2/zadanka" in p for _, p, _, _ in c.volani)
    assert not any(p.endswith("/api/v2/zadanka") for m, p, _, _ in c.volani if m == "POST")  # žádné uložení
    assert all(h == {"If-Match": "AAAAAAA="} for m, _, _, h in c.volani if m == "PATCH")


# --------------------------------------------------------------------------- #
# KRZP – verze v2 / v3
# --------------------------------------------------------------------------- #

def test_krzp_vychozi_v2_a_parametr_v3():
    c = _Zaznam()
    assert KRZP(c).VERZE == "v2"
    KRZP(c).hledat_krzpid("X")
    assert c.volani[-1][1] == "/krzp/api/v2/pracovnik/hledat/krzpid"
    k3 = KRZP(c, verze="v3")
    assert k3.VERZE == "v3"
    k3.hledat_krzpid("X")
    k3.ciselnik("obor")
    k3.notifikace_stav("EMAIL")
    assert [p for _, p, _, _ in c.volani[1:]] == [
        "/krzp/api/v3/pracovnik/hledat/krzpid", "/krzp/api/v3/ciselnik/obor", "/krzp/api/v3/notifikace/stav"]
    assert KRZP(c, verze="3").VERZE == "v3"


def test_krzp_verze_z_konfigurace():
    c = _Zaznam()
    c.config.KRZP_VERZE = "v3"
    assert KRZP(c).VERZE == "v3"


def test_krzp_normalizace_ztotoznena_osoba():
    v3 = {"vysledky": [{"ztotoznenaOsoba": {"krzpId": "1"}}]}
    n = KRZP.normalizuj_odpoved(v3)
    assert n["vysledky"][0]["ztotozenaOsoba"] == {"krzpId": "1"}
    assert n["vysledky"][0]["ztotoznenaOsoba"] == {"krzpId": "1"}
    v2 = {"ztotozenaOsoba": {"krzpId": "2"}}
    assert KRZP.normalizuj_odpoved(v2)["ztotoznenaOsoba"] == {"krzpId": "2"}


# --------------------------------------------------------------------------- #
# SZZ v3 – souhrnné vyhledání
# --------------------------------------------------------------------------- #

def test_szz3_souhrn_sklada_prevence_a_screeningy():
    """Swagger SZZ 3.0.5 nemá /zdravotniZaznamy/vyhledat – klient volá skutečné cesty."""
    c = _Zaznam(_Odpoved(200, {"preventivniProhlidky": []}))
    r = SZZv3(c).zdravotni_zaznamy_vyhledat({"rid": "R", "page": 0, "size": 10})
    cesty = [p for _, p, _, _ in c.volani]
    assert cesty == ["/sdilenyZdravotniZaznam/api/v3/prevence/vyhledat",
                     "/sdilenyZdravotniZaznam/api/v3/screeningy/vyhledat"]
    assert "zdravotniZaznamy" not in "".join(cesty)
    assert r.status_code == 200
    data = r.json()
    assert set(data) == {"prevence", "screeningy", "_zdroje"}
    assert data["_zdroje"]["screeningy"]["status"] == 200


# --------------------------------------------------------------------------- #
# FHIR img-order most – v2
# --------------------------------------------------------------------------- #

@pytest.fixture
def kralik():
    with open(PRIKLAD, encoding="utf-8") as f:
        return json.load(f)


def test_img_order_to_v2_zachova_bundle(kralik):
    v2 = fi.ImagingOrderToEZadanka(kralik).to_v2(adresat="25488627", poskytovatel="12345678")
    assert set(v2) == {"hlavicka", "fhirBundle"}
    hl = v2["hlavicka"]
    assert hl["typZadanky"] == {"kod": "721964003"}
    assert hl["zadatel"]["poskytovatel"] == "12345678"
    assert hl["zadatel"]["autor"] == hl["zadatel"]["zdravotnickyPracovnik"] != ""
    assert hl["pacient"] and hl["adresat"] == "25488627"
    assert v2["fhirBundle"]["type"] == "document"
    assert len(v2["fhirBundle"]["entry"]) == len(kralik["entry"])
    # explicitní poskytovatel ≠ custodian v IG vzoru → klientská kontrola to hlásí (server E00024)
    assert any("E00024" in x for x in EZadankyV2.zkontroluj_pozadavek(v2))


def test_img_order_extract_zadatel_z_custodian_a_performer(kralik):
    """IG build 10/2026: žadatel = Composition.custodian (ne první Organization =
    pojišťovna), requester → PractitionerRole, performer v příkladu míří na Device."""
    m = fi.ImagingOrderToEZadanka(kralik)
    assert m.data["organization"]["ico"] == "456789656"       # FN Obláčkov, ne VZP
    assert m.data["organization"]["icp"] == "456789655"
    assert m.data["practitioner"]["krzp"] == "123456788"
    assert m.data["performer"]["count"] == 0 and m.data["performer"]["ico"] is None
    hl = m.to_v2()["hlavicka"]
    assert hl["zadatel"]["poskytovatel"] == "456789656" and "adresat" not in hl
    # icp parametr doplní identifier jen pokud chybí
    v2 = m.to_v2(icp="11111111")
    org = next(e["resource"] for e in v2["fhirBundle"]["entry"] if e["resource"].get("id") == "5bdedd9b-27c5-4593-ae3a-968c5f25d253")
    assert [i["value"] for i in org["identifier"] if i["system"].endswith("/icp")] == ["456789655"]
    texty = [i["diagnostics"] for i in m.data["validation_issues"]]
    assert not any("identifier je v profilu" in t for t in texty)


def test_img_order_generovany_bundle_splnuje_pravidla_v2():
    """v1 záznam → Bundle: PractitionerRole, custodian, IČP, performer Organization
    (adresát) – stejný tvar prošel 13. 10. 2026 na T2 (201 Created)."""
    rec = {"zadanka": {"id": "Z1", "urgentnost": {"kod": "routine"}, "pacientPojistovna": {"kod": "111"},
                       "icpZadatele": "72090001",
                       "zasilka": {"pacient": "7653800856", "autor": "102129137", "poskytovatel": "25488627",
                                   "adresat": "00064165", "nazev": "RTG kolene"}}}
    b = fi.EZadankaToImagingOrder(rec).to_bundle()
    typy = [e["resource"]["resourceType"] for e in b["entry"]]
    assert "PractitionerRole" in typy and typy.count("Organization") == 3  # žadatel, provádějící, pojišťovna
    comp = b["entry"][0]["resource"]
    role = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "PractitionerRole")
    sr = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "ServiceRequest")
    assert comp["custodian"]["reference"] == role["organization"]["reference"]
    assert sr["requester"]["reference"] == f"urn:uuid:{role['id']}"
    assert comp["author"][0]["reference"] == f"urn:uuid:{role['id']}"
    assert sr["insurance"]
    m = fi.ImagingOrderToEZadanka(b)
    assert m.data["organization"] == {"id": m.data["organization"]["id"], "ico": "25488627", "icp": "72090001", "name": None}
    assert m.data["performer"]["ico"] == "00064165" and m.data["performer"]["count"] == 1
    v2 = m.to_v2()
    assert v2["hlavicka"]["adresat"] == "00064165"
    assert EZadankyV2.zkontroluj_pozadavek(v2) == []
    assert m.data["validation_issues"] == []


def test_img_order_reverz_z_odpovedi_v2(kralik):
    b = fi.EZadankaToImagingOrder({"hlavicka": {"id": "X1", "verzeZaznamu": "V"}, "fhirBundle": kralik}).to_bundle()
    assert b["resourceType"] == "Bundle" and len(b["entry"]) == len(kralik["entry"])
    # obalená odpověď backendu {"data": {...}}
    b2 = fi.EZadankaToImagingOrder({"data": {"hlavicka": {"id": "X1"}, "fhirBundle": kralik}}).to_bundle()
    assert b2["entry"][0]["resource"]["resourceType"] == "Composition"


# --------------------------------------------------------------------------- #
# Backend + GUI
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def klient():
    from fastapi.testclient import TestClient
    from sez_api.app import app
    # Bez kontextového manažeru → nespustí se startup event (živé připojení k T2);
    # offline sada musí běžet bez sítě a nesmí ovlivnit ostatní testy.
    yield TestClient(app)


def test_gui_obsahuje_revizi_a_zalozku_v2(klient):
    html = klient.get("/").text
    assert "Revize 13. 10. 2026" in html
    assert 'id="ez-v2-panel"' in html
    assert "/api/ezadanky/v2/vyhledat" in html and "/api/ezadanky/v2/katalog" in html
    assert "If-Match" in html
    assert "UpravZadanku zrušeno" in html
    assert "25488627_KrajskaZdravotniVerejnyTest04" in html
    assert "ztotoznenaOsoba" in html  # KRZP v3 na dashboardu


def test_katalog_v2(klient):
    k = klient.get("/api/ezadanky/v2/katalog").json()
    assert k["verze"] == "2.0.0" and k["v1"]["deprecated"] is True
    assert len(k["operace"]) == 9
    assert sum(1 for o in k["operace"] if o["ifMatch"]) == 5
    assert any(p["zruseno"] for p in k["prevodZV1"])


def test_v2_simulator_workflow(klient):
    assert klient.post("/api/ezadanky/sim/toggle", json={"enabled": True}).json()["enabled"] is True
    try:
        r = klient.post("/api/ezadanky/v2/vyhledat", json={"strankovani": {"page": 0, "size": 2}}).json()
        assert r["status"] == 200 and r["data"]["pageNumber"] == 0
        z = r["data"]["nalezeneZaznamy"][0]
        assert set(z) == {"hlavicka", "udajeProPrijeti"}
        assert "verzeZaznamu" in z["hlavicka"] and "verzeRadku" not in z["hlavicka"]
        assert klient.post("/api/ezadanky/v2/vyhledat", json={"strankovani": {"page": -1}}).json()["status"] == 400

        with open(PRIKLAD, encoding="utf-8") as f:
            bundle = json.load(f)
        # IG vzor: poskytovatel = IČO custodian (FN Obláčkov), neadresná žádanka
        body = {"hlavicka": EZadankyV2.sestav_hlavicku(typ_zadanky="Z", pacient="2066425387",
                                                       poskytovatel="456789656", autor="123456788"),
                "fhirBundle": bundle}
        r = klient.post("/api/ezadanky/v2/uloz", json=body)
        j = r.json()
        assert j["status"] == 201 and r.headers.get("etag")
        zid, vz = j["data"]["hlavicka"]["id"], j["data"]["hlavicka"]["verzeZaznamu"]

        # klientská kontrola zastaví neúplné tělo i nekonzistentní hlavičku (E00024)
        assert klient.post("/api/ezadanky/v2/uloz", json={"hlavicka": {}, "fhirBundle": {}}).json()["status"] == 400
        spatne = dict(body, hlavicka=dict(body["hlavicka"], adresat="25488627"))
        jj = klient.post("/api/ezadanky/v2/uloz", json=spatne).json()
        assert jj["status"] == 400 and jj.get("_klientskaKontrola") is True
        assert any("provádějící" in e["message"] for e in jj["data"]["errors"])

        r = klient.post(f"/api/ezadanky/v2/zadanka/{zid}/nacist", json={}).json()
        assert r["data"]["fhirBundle"]["type"] == "document"

        # špatný If-Match → 409; správný → přechod do Přijatá
        assert klient.patch(f"/api/ezadanky/v2/zadanka/{zid}/prijmout", json={}, headers={"If-Match": "x"}).json()["status"] == 409
        assert klient.patch(f"/api/ezadanky/v2/zadanka/{zid}/prijmout", json={}).json()["status"] == 400
        r = klient.patch(f"/api/ezadanky/v2/zadanka/{zid}/prijmout", json={}, headers={"If-Match": vz}).json()
        assert r["status"] == 200 and r["data"]["hlavicka"]["stav"]["kod"] == "1"
        vz = r["data"]["hlavicka"]["verzeZaznamu"]

        # vyřízení bez dokumentu odmítnuto, s dokumentem projde (verze i v těle)
        vyr = {"verzeZaznamu": vz, "zpusobVyrizeniZadanky": {"kod": "zasilka"},
               "datumSkutecneRealizaceVysetreni": "2026-10-13", "vysledek": {"dokument": []}}
        assert klient.patch(f"/api/ezadanky/v2/zadanka/{zid}/vyridit", json=vyr).json()["status"] == 400
        vyr["vysledek"] = {"dokument": [{"nazev": "zprava"}]}
        r = klient.patch(f"/api/ezadanky/v2/zadanka/{zid}/vyridit", json=vyr).json()
        assert r["status"] == 200 and r["data"]["hlavicka"]["stav"]["kod"] == "2"
        assert r["data"]["hlavicka"]["zasilkyVysledku"]

        assert klient.patch(f"/api/ezadanky/v2/zadanka/{zid}/upravit").json()["status"] == 410
        assert klient.get("/api/ezadanky/v2/diagnose").json()["pzs_context"] is True
    finally:
        klient.post("/api/ezadanky/sim/toggle", json={"enabled": False})


def test_katalog_sluzeb_a_verze_t2(klient):
    """Katalog služeb (/api/debug/jwt → services + swagger_check) zná stav brány k 13. 10. 2026.

    Endpoint potřebuje inicializovaný klient (podpis JWT lokálním certifikátem,
    bez sítě); použije se certifikát z konfigurace, pokud existuje, a globální
    stav aplikace se po testu vrátí."""
    import sez_api.app as app_mod
    from sez_api import config as cfg

    if not (cfg.P12_PATH and os.path.exists(cfg.P12_PATH) and cfg.P12_PASSWORD):
        pytest.skip("katalog služeb není dostupný bez certifikátu")
    puvodni = {k: getattr(app_mod, k) for k in ("_auth", "_client", "_modules", "_connected", "_cert_info", "_cert_stamp")}
    try:
        app_mod._init_client(cfg.CLIENT_ID, cfg.P12_PATH, cfg.P12_PASSWORD, cfg.CERT_UID)
        r = klient.get("/api/debug/jwt")
    finally:
        for k, v in puvodni.items():
            setattr(app_mod, k, v)
    assert r.status_code == 200
    j = r.json()
    ez = j["services"]["eZadanky"]
    cesty = [e["path"] for e in ez["endpoints"]]
    assert "/eZadanky/api/v2/zadanka" in cesty and "/eZadanky/api/v2/zadanka/{id}/nacist" in cesty
    assert ez["versions"]["v2"] == "v2.0.0" and "deprecated" in ez["versions"]["v1"]
    assert j["services"]["KRZP"]["versions"] == {"v2": "v2.0.7", "v3": "v3.0.4"}
    sc = j["swagger_check"]
    assert sc["checked_at"] == "2026-10-13"
    assert sc["current_versions_on_t2"]["EZadanky_v2"] == "v2.0.0"
    assert sc["current_versions_on_t2"]["KRZP_v3"] == "v3.0.4"
    assert sc["current_versions_on_t2"]["SdilenyZdravotniZaznam_v3"] == "v3.0.5"
