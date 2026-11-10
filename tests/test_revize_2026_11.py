"""
Testy revize zdrojů 10. 11. 2026.

Pokrývají změny, které revize do aplikace přinesla:

- SZZ: Standard 3.1 (účast ve screeningu jako samostatné služby), SZZ v2
  s pěti screeningy z verze 2.0.4, rozsah PSA,
- eŽádanky v2: číselník stavů, If-Match bez slabého validátoru, zásilka
  s výsledkem,
- HTTP vrstva: X-Correlation-Id pro celý proces, User-Agent bez diakritiky,
  metoda QUERY,
- KRP: Standard KZR 1.3 (DRID, limit dávky, kontrola jmen, univerzální
  hledání, notifikace),
- zprávy eZD: EMS 0.1.0, lab 1.0.0, img 1.0.0, HDR,
- SÚKL (adresa otevřených dat, verze ePoukazu) a Terminologie,
- dashboard se zvýrazněnými rozdíly, katalog služeb, dokumentace.

Vše běží bez sítě – HTTP klient nahrazuje atrapa.

Spuštění:  python3 -m pytest tests/test_revize_2026_11.py -v
"""

import hashlib
import pathlib
import re
import uuid

import pytest
from starlette.testclient import TestClient

from sez_api import config as cfg
from sez_api import fhir_ezd, kzr_pravidla
from sez_api.app import app
from sez_api.client import (
    KRP,
    EZadankyV2,
    SEZClient,
    SUKLDLP,
    SUKLeRecept,
    SZZv2,
    SZZv3,
    Terminologie,
    aktualni_correlation_id,
    correlation_id_platne,
    korelace,
)

KOREN = pathlib.Path(__file__).resolve().parent.parent


class _Resp:
    status_code = 200
    text = ""

    def __init__(self, data=None):
        self._data = data if data is not None else {}

    def json(self):
        return self._data


class _FakeClient:
    """Zaznamenává volání místo odesílání na bránu."""

    def __init__(self):
        self.volani = []

    def _zaznam(self, metoda, path, body=None, **kw):
        self.volani.append((metoda, path, body, kw))
        return _Resp()

    def get(self, path, params=None, **kw):
        return self._zaznam("GET", path, params, **kw)

    def post(self, path, body=None, **kw):
        return self._zaznam("POST", path, body, **kw)

    def put(self, path, body=None, **kw):
        return self._zaznam("PUT", path, body, **kw)

    def patch(self, path, body=None, params=None, **kw):
        return self._zaznam("PATCH", path, body, **kw)

    def delete(self, path, body=None, **kw):
        return self._zaznam("DELETE", path, body, **kw)


class _FakeAuth:
    def build_assertion(self, extra_headers=None):
        return "assertion"


def _sez_klient():
    c = SEZClient.__new__(SEZClient)
    c.auth = _FakeAuth()
    return c


@pytest.fixture(scope="module")
def klient():
    # Bez kontextového manažeru se nespustí startup (živé připojení k T2).
    yield TestClient(app)


@pytest.fixture(scope="module")
def html(klient):
    return klient.get("/").text


# --------------------------------------------------------------------------- #
# SZZ – Standard 3.1
# --------------------------------------------------------------------------- #

UCASTI = ("karcinomProstatyUcast", "karcinomPlicUcast", "aneurysmaAbdominalniAortyUcast")


def test_szz_verze_odpovida_standardu_3_1():
    assert SZZv3.VERZE_API == "3.0.5"
    assert SZZv3.VERZE_STANDARDU == "3.1"


@pytest.mark.parametrize("typ", UCASTI)
def test_szz_ucast_je_samostatna_sluzba_bez_vyhledat(typ):
    """Standard 3.1, kap. 6: POST, PUT a PATCH zneplatnit/zpochybnit/obnovit;
    operaci …/vyhledat u účasti standard neuvádí."""
    c = _FakeClient()
    operace = SZZv3(c).screening(typ)
    assert sorted(operace) == ["obnovit", "uprav", "vytvor", "zneplatnit", "zpochybnit"]
    operace["vytvor"]({"rid": "2393511146"})
    metoda, cesta = c.volani[0][:2]
    assert metoda == "POST"
    assert cesta == f"/sdilenyZdravotniZaznam/api/v3/screeningy/{typ}"


def test_szz_ucast_ve_v2_neexistuje():
    with pytest.raises(ValueError):
        SZZv2(_FakeClient()).screening("karcinomProstatyUcast")


def test_szz_vpl_ve_v3_neposila_polozky_ucasti():
    telo = {"rid": "2393511146", "vyska": 180,
            "ucastVeScreeninguKarcinomuPlic": {"kod": "01196"},
            "ucastVeScreeninguKarcinomuProstaty": {"kod": "01131"},
            "ucastVeScreeninguAaa": {"kod": "01135"}}
    ocistene = SZZv3.ocisti_vpl(telo)
    assert ocistene == {"rid": "2393511146", "vyska": 180}
    assert len(telo) == 5, "původní tělo se nemění"
    assert set(SZZv3.VPL_ODEBRANE_POLOZKY) == set(telo) - {"rid", "vyska"}


def test_szz_ucast_cilova_skupina():
    assert SZZv3.ucast_mimo_cilovou_skupinu("karcinomProstatyUcast", vek=55, pohlavi="M") is None
    assert SZZv3.ucast_mimo_cilovou_skupinu("karcinomProstatyUcast", vek=55, pohlavi="Z")
    assert SZZv3.ucast_mimo_cilovou_skupinu("aneurysmaAbdominalniAortyUcast", vek=70, pohlavi="M")
    assert SZZv3.ucast_mimo_cilovou_skupinu("karcinomPlicUcast", vek=60, pohlavi="Z") is None
    assert SZZv3.UCAST_VE_SCREENINGU["aneurysmaAbdominalniAortyUcast"]["max_platnych_zaznamu"] == 1


def test_szz_v2_ma_pet_screeningu_z_verze_2_0_4():
    """Wiki 11. 6. (T2) a 29. 6. 2026 (PROD) – klient je dřív odmítal."""
    c = _FakeClient()
    mod = SZZv2(c)
    for typ in ("kolorektalniKarcinomKoloskopie", "karcinomProstatyVstupniPsa",
                "karcinomProstatyUrologickeVysetreni", "karcinomProstatyBioptickeVysetreni",
                "karcinomPlicPneumologickeVysetreni"):
        mod.screening(typ)["vytvor"]({})
        assert c.volani[-1][1] == f"/sdilenyZdravotniZaznam/api/v2/screeningy/{typ}"
    assert len(SZZv2.SCREENINGY_TYPY) == 15


def test_szz_rozsah_psa_dle_swaggeru_3_0_5():
    assert SZZv3.ROZSAHY["hladinaPsaUgL"] == (0, 200, 2)
    assert SZZv3.zkontroluj({"hladinaPsaUgL": 4.5}) == []
    assert SZZv3.zkontroluj({"hladinaPsaUgL": 1500})


# --------------------------------------------------------------------------- #
# eŽádanky v2
# --------------------------------------------------------------------------- #

def test_ezadanky_stavy_dle_standardu():
    assert EZadankyV2.STAVY == {
        "0": "Nová", "1": "Přijatá", "2": "Neproveditelná",
        "3": "Stornovaná", "4": "Dokončená", "5": "Expirovaná"}
    assert "Vrácená do oběhu" not in EZadankyV2.STAVY.values()


def test_ezadanky_simulator_prechody():
    import sez_api.app as app_mod
    prechody = app_mod._EZ_TRANSITIONS["1"]
    assert prechody["vyrid"] == "4"
    assert prechody["neproveditelnost"] == "2"
    assert prechody["vrat"] == "0", "vrácení do oběhu vrací žádanku do stavu Nová"
    assert app_mod._EZ_STAV_NAMES == EZadankyV2.STAVY


def test_ezadanky_if_match_bez_slabeho_validatoru():
    assert EZadankyV2._if_match('W/"AAAAAAAB9E4="') == {"If-Match": "AAAAAAAB9E4="}
    assert EZadankyV2._if_match("AAAAAAAB9E4=") == {"If-Match": "AAAAAAAB9E4="}
    with pytest.raises(ValueError):
        EZadankyV2._if_match("")


def test_ezadanky_zasilka_s_vysledkem_ma_sha256_bajtu():
    obsah = b"vysledek vysetreni"
    z = EZadankyV2.sestav_vysledek(
        obsah, nazev_souboru="vysledek.txt", autor="102129137",
        poskytovatel="05242339", pacient="6534744190")
    assert hashlib.sha256(obsah).hexdigest() in repr(z)
    with pytest.raises(ValueError):
        EZadankyV2.sestav_vysledek(b"", nazev_souboru="x.txt", autor="1",
                                   poskytovatel="2", pacient="3")


# --------------------------------------------------------------------------- #
# HTTP vrstva
# --------------------------------------------------------------------------- #

def test_korelace_jedno_id_pro_cely_proces():
    c = _sez_klient()
    with korelace() as cid:
        prvni = c._headers()["X-Correlation-Id"]
        druhe = c.pruvodni_hlavicky()["X-Correlation-Id"]
        assert prvni == druhe == cid == aktualni_correlation_id()
        with korelace() as vnorene:
            assert vnorene == cid, "vnořený blok přebírá id nadřazeného procesu"
    assert aktualni_correlation_id() is None
    mimo_a = c._headers()["X-Correlation-Id"]
    mimo_b = c._headers()["X-Correlation-Id"]
    assert mimo_a != mimo_b and mimo_a != cid


def test_korelace_odmitne_neplatnou_hodnotu():
    platne = str(uuid.uuid4())
    assert correlation_id_platne(platne)
    assert not correlation_id_platne(str(uuid.uuid1()))
    assert not correlation_id_platne("abc")
    assert not correlation_id_platne(platne + "x" * 200)
    with pytest.raises(ValueError):
        with korelace("neni-uuid"):
            pass
    with korelace(platne) as cid:
        assert cid == platne


def test_middleware_prevezme_a_vraci_correlation_id(klient):
    cid = str(uuid.uuid4())
    r = klient.get("/api/krp/pravidla", headers={"X-Correlation-Id": cid})
    assert r.headers["X-Correlation-Id"] == cid
    r = klient.get("/api/krp/pravidla", headers={"X-Correlation-Id": "neplatne"})
    nove = r.headers["X-Correlation-Id"]
    assert nove != "neplatne" and correlation_id_platne(nove)
    assert correlation_id_platne(klient.get("/api/krp/pravidla").headers["X-Correlation-Id"])


def test_user_agent_bez_diakritiky_a_ridicich_znaku():
    puvodni = (cfg.SEZ_APP_NAME, cfg.SEZ_VENDOR, cfg.SEZ_UA_NOTE)
    try:
        cfg.SEZ_APP_NAME, cfg.SEZ_VENDOR, cfg.SEZ_UA_NOTE = (
            "Nemocniční systém", "Krajská zdravotní, a.s.", "poznámka; (test)\n")
        ua = SEZClient.user_agent()
    finally:
        cfg.SEZ_APP_NAME, cfg.SEZ_VENDOR, cfg.SEZ_UA_NOTE = puvodni
    assert all(32 <= ord(ch) < 127 for ch in ua), ua
    assert ua.startswith("Nemocnicni-system/")
    assert "Krajska zdravotni, a.s." in ua
    # středník a závorky uvnitř položek by rozbily formát „(Test; výrobce; poznámka)“
    assert ua.count("(") == 1 and ua.count(")") == 1 and ua.count(";") == 2, ua


def test_metoda_query():
    c = _sez_klient()
    zaznam = {}

    def _request(method, path, **kw):
        zaznam.update(method=method, path=path, kw=kw)
        return _Resp()

    c._request = _request
    c.query("/krp/api/v4/pacient", {"rid": "1"}, timeout=5)
    assert zaznam["method"] == "QUERY"
    assert zaznam["kw"]["json"] == {"rid": "1"} and zaznam["kw"]["timeout"] == 5


# --------------------------------------------------------------------------- #
# KRP – Standard KZR 1.3
# --------------------------------------------------------------------------- #

def test_kzr_standard_1_3():
    assert kzr_pravidla.STANDARD_VERZE == "1.3"
    assert kzr_pravidla.STANDARD_PLATNOST == "2026-11-03"


def test_drid_tvar_se_vynucuje_pravidlo_13_11_jen_upozorni():
    assert kzr_pravidla.drid_platny("D000000013")
    assert kzr_pravidla.drid_chyba("D000000013") is None
    assert kzr_pravidla.drid_upozorneni("D000000013") is None
    # 143 = 13 × 11 → dělitelné 11, pravidlo 1.3 nesplňuje, tvar ano
    assert not kzr_pravidla.drid_platny("D000000143")
    assert kzr_pravidla.drid_chyba("D000000143") is None
    assert "1.3" in kzr_pravidla.drid_upozorneni("D000000143")
    # starší DRID = náhodné číslice
    assert kzr_pravidla.drid_chyba("D123456789") is None
    for spatne in ("123456789", "D12345", "X123456789", "", None):
        assert kzr_pravidla.drid_chyba(spatne)


def test_krp_priradit_drid_telo_a_kontrola_tvaru():
    c = _FakeClient()
    krp = KRP(c, "v3")
    krp.priradit_docasny_rid("d000000013", "2393511146")
    metoda, cesta, telo = c.volani[0][:3]
    assert cesta.endswith("/pacient/priradit/docasny_rid")
    assert '"docasnyRID": "D000000013"' in _json(telo) and '"rid": "2393511146"' in _json(telo)
    with pytest.raises(ValueError):
        krp.priradit_docasny_rid("12345", "2393511146")
    assert len(c.volani) == 1, "DRID se špatným tvarem se na bránu neposílá"


def test_drid_zasoba_50():
    assert kzr_pravidla.DRID_ZASOBA == 50
    assert kzr_pravidla.drid_pocet_upozorneni(50) is None
    assert kzr_pravidla.drid_pocet_upozorneni(51)


@pytest.mark.parametrize("jmeno,prijmeni", [
    ("Jan", "Novák"), ("Anna-Marie", "O'Brien"), ("Jürgen", "Müller"),
    ("Nguyễn", "Văn An"), ("Testová", "Pacientová"),
])
def test_jmena_prijatelna(jmeno, prijmeni):
    assert kzr_pravidla.kontrola_jmena(jmeno, prijmeni) == []


@pytest.mark.parametrize("jmeno,prijmeni", [
    ("Jan2", "Novák"), ("Jan", "Novák?"), ("18", "Pokusníček"),
    ("Jméno", "Test"), ("Pacient", "Testovaci"), ("Neuvedeno", "Neuvedeno"),
    ("Don", "Corleone"), ("Jan", "@Novák"),
])
def test_jmena_odmitnuta(jmeno, prijmeni):
    assert kzr_pravidla.kontrola_jmena(jmeno, prijmeni)


def test_rezim_kontroly_jmen(monkeypatch):
    monkeypatch.delenv("SEZ_KRP_KONTROLA_JMEN", raising=False)
    assert kzr_pravidla.rezim_kontroly_jmen() == "odmitnout"
    monkeypatch.setenv("SEZ_KRP_KONTROLA_JMEN", "varovat")
    assert kzr_pravidla.rezim_kontroly_jmen() == "varovat"
    monkeypatch.setenv("SEZ_KRP_KONTROLA_JMEN", "nesmysl")
    assert kzr_pravidla.rezim_kontroly_jmen() == "odmitnout"


def test_api_hledat_jmeno_odmitne_zastupne_jmeno(klient, monkeypatch):
    """Dotaz se zástupným jménem se na KRP vůbec neodešle (odpověď vznikne
    dřív, než se sáhne na klienta brány)."""
    monkeypatch.delenv("SEZ_KRP_KONTROLA_JMEN", raising=False)
    r = klient.post("/api/krp/hledat-jmeno", json={
        "jmeno": "Pacient", "prijmeni": "Test", "rodne_cislo": "7705034391"})
    j = r.json()
    assert j["status"] == 422 and j["odeslano"] is False
    assert "neodeslal" in j["error"]


def test_uni_kombinace_dle_kap_4_5_1():
    assert kzr_pravidla.uni_kombinace(
        {"jmeno": "Jan", "prijmeni": "Novák", "datumNarozeni": "1980-01-01"})
    assert kzr_pravidla.uni_upozorneni({"datumNarozeni": "1980-01-01"})
    assert kzr_pravidla.uni_upozorneni({"rid": "2393511146"})
    assert len(kzr_pravidla.UNI_KOMBINACE) == 5


def _davka(pocet):
    pacienti = "\n".join(f"<Pacient><Jmeno>J{i}</Jmeno></Pacient>" for i in range(pocet))
    return f"<Davka><Hlavicka/>\n{pacienti}\n</Davka>"


def test_davka_limit_10000_a_deleni():
    assert kzr_pravidla.DAVKA_MAX_PACIENTU == 10_000
    assert kzr_pravidla.davka_chyba(10_000) is None
    assert "3 dávky" in kzr_pravidla.davka_chyba(25_000)
    xml = _davka(25)
    casti = kzr_pravidla.rozdel_davku(xml, limit=10)
    assert [kzr_pravidla.pocet_pacientu(c) for c in casti] == [10, 10, 5]
    assert all(c.startswith("<Davka><Hlavicka/>") and c.endswith("</Davka>") for c in casti)
    assert kzr_pravidla.rozdel_davku(_davka(3), limit=10) == [_davka(3)]


def test_notifikace_odber_dle_swaggeru_3_0_6():
    telo = kzr_pravidla.notifikace_odber(
        ["2393511146", "6534744190"], "https://nis.example.cz/kzr", "25488627")
    assert telo == {"predmet": [{"rid": "2393511146"}, {"rid": "6534744190"}],
                    "prijemci": {"url": "https://nis.example.cz/kzr"},
                    "subjektId": "25488627"}
    with pytest.raises(ValueError):
        kzr_pravidla.notifikace_odber([])
    with pytest.raises(ValueError):
        kzr_pravidla.notifikace_odber("2393511146", "ftp://spatne")
    # starý tvar GUI: RID v subjektId, adresa v „cil“
    stare = kzr_pravidla.notifikace_odber_z_volneho_tela(
        {"subjektId": "2393511146", "kanalTyp": "URL", "cil": "https://nis.example.cz/kzr"})
    assert stare == {"predmet": [{"rid": "2393511146"}],
                     "prijemci": {"url": "https://nis.example.cz/kzr"}}


def test_krp_notifikace_zrusit_po_jedne_subskripci():
    c = _FakeClient()
    krp = KRP(c, "v3")
    krp.notifikace_zrusit(["a-1", "b-2"])
    assert [v[0] for v in c.volani] == ["DELETE", "DELETE"]
    assert all(v[1].endswith("/notifikace/zrusit/odber") for v in c.volani)
    assert '"idSubskripce": "a-1"' in _json(c.volani[0][2])
    with pytest.raises(ValueError):
        krp.notifikace_zrusit(None)


def test_api_krp_pravidla(klient):
    j = klient.get("/api/krp/pravidla").json()
    assert j["standard"] == {"verze": "1.3", "platnostOd": "2026-11-03", "predchozi": "1.2"}
    assert j["hromadneZtotozneni"]["maxPacientu"] == 10_000
    assert j["drid"]["zasoba"] == 50
    assert len(j["uni"]["kombinace"]) == 5
    # rozpor zdrojů o vypnutí v2 je uveden z obou stran
    assert "15. 9. 2026" in j["verzeApi"]["oznameni_2026_08_27"]
    assert "v2 a v3" in j["verzeApi"]["plan_2026_11_03"]


def test_api_krp_notifikace_vzor_a_zprava(klient):
    vzor = klient.get("/api/krp/notifikace-vzor").json()
    assert vzor["odber"]["predmet"] == [{"rid": "2393511146"}]
    rozbor = klient.post("/api/krp/notifikace-zprava", json=vzor["zprava"]).json()
    assert rozbor["platna"] is True, rozbor
    spatna = klient.post("/api/krp/notifikace-zprava", json=["neni objekt"]).json()
    assert spatna["platna"] is False
    r = klient.post("/api/krp/notifikace-zprava", content=b"{neni json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Zprávy eZD – HL7 CZ IG
# --------------------------------------------------------------------------- #

def test_ezd_verze_ig():
    k = fhir_ezd.EZD_KATEGORIE
    assert k["vyjezd-zzs"]["ig_verze"] == "0.1.0"
    assert k["laboratorni-vysetreni"]["ig_verze"] == "1.0.0"
    assert k["obrazove-vysetreni"]["ig_verze"] == "1.0.0"
    assert k["laboratorni-vysetreni"]["ig_url"].startswith("https://ig.ezdravi.gov.cz/")
    assert k["obrazove-vysetreni"]["ig_url"].startswith("https://ig.ezdravi.gov.cz/")
    assert k["laboratorni-vysetreni"]["composition_profile"].endswith("/composition-cz-lab")


def test_ezd_katalog_nese_rozdily_verzi():
    katalog = {z["kategorie"] if "kategorie" in z else z["id"]: z
               for z in fhir_ezd.katalog_zprav()}
    for klic in ("vyjezd-zzs", "laboratorni-vysetreni", "obrazove-vysetreni"):
        zmeny = katalog[klic]["zmeny_verze"]
        assert zmeny["na"] == fhir_ezd.EZD_KATEGORIE[klic]["ig_verze"]
        assert zmeny["polozky"], klic
        assert all({"typ", "prvek", "bylo", "je"} <= set(p) for p in zmeny["polozky"])


def test_ems_casove_body_z_textu():
    body = fhir_ezd.ems_casove_body([
        "02 2026-07-18T18:42:00+02:00 přijetí výzvy",
        "03 2026-07-18T18:44:00 výjezd",          # bez pásma → Europe/Prague
        "volný text bez kódu",
    ])
    assert set(body) == {"02", "03"}
    assert body["03"].endswith("+02:00")
    assert fhir_ezd.ems_chybejici_casove_body(body) == ["04", "05", "07"]
    assert fhir_ezd.EMS_CASOVE_BODY_POVINNE == ("02", "03", "04", "05", "07")


def _ems_bundle(timeline):
    ukazka = fhir_ezd.UKAZKY["vyjezd-zzs"]
    sekce = dict(ukazka["sekce"])
    sekce["timeline"] = timeline
    return fhir_ezd.build_ezd_bundle(
        "vyjezd-zzs", rid="2393511146", autor_krzpid="102129137", ico="25488627",
        sekce=sekce, cislo_vyjezdu="ZZS-2026-000123")


def test_ems_ukazka_ma_observation_a_encounter():
    bundle = _ems_bundle(fhir_ezd.UKAZKY["vyjezd-zzs"]["sekce"]["timeline"])
    zdroje = [e["resource"] for e in bundle["entry"]]
    casy = [r for r in zdroje if r["resourceType"] == "Observation"
            and fhir_ezd.EMS_OBSERVATION_CAS_PROFILE in r.get("meta", {}).get("profile", [])]
    assert len(casy) == 8 and all("valueDateTime" in r for r in casy)
    enc = [r for r in zdroje if r["resourceType"] == "Encounter"]
    assert len(enc) == 1 and enc[0]["identifier"][0]["value"] == "ZZS-2026-000123"
    assert zdroje[0]["resourceType"] == "Composition" and zdroje[0].get("identifier")
    vysledek = fhir_ezd.validate_ezd_bundle(bundle, "vyjezd-zzs")
    assert vysledek["valid"], vysledek["errors"]


def test_ems_bez_povinnych_casovych_bodu_neprojde():
    bundle = _ems_bundle(["Výjezd proběhl bez komplikací."])
    vysledek = fhir_ezd.validate_ezd_bundle(bundle, "vyjezd-zzs")
    assert not vysledek["valid"]
    assert any("02" in e and "07" in e for e in vysledek["errors"]), vysledek["errors"]


def test_ems_sekce_significant_procedures_je_alias():
    assert fhir_ezd.EZD_KATEGORIE["vyjezd-zzs"]["section_aliases"] == {
        "significantProcedures": "procedure"}


def test_lab_zrusene_sekce_a_kategorie():
    lab = fhir_ezd.EZD_KATEGORIE["laboratorni-vysetreni"]
    zrusene = {z["slice"]: z for z in lab["zrusene_sekce"]}
    assert set(zrusene) == {"annotations", "attachment"}
    assert zrusene["attachment"]["chyba"] is True
    assert lab["category_codings"][0][0]["code"] == "11502-2"
    assert lab["identifier_required"] is True


def test_lab_ukazka_je_validni_a_zrusena_sekce_ne():
    u = fhir_ezd.UKAZKY["laboratorni-vysetreni"]
    bundle = fhir_ezd.build_ezd_bundle(
        "laboratorni-vysetreni", rid="2393511146", autor_krzpid="102129137",
        ico="25488627", sekce=u["sekce"])
    assert fhir_ezd.validate_ezd_bundle(bundle, "laboratorni-vysetreni")["valid"]
    comp = bundle["entry"][0]["resource"]
    comp["section"].append({
        "title": "Přílohy",
        "code": {"coding": [{"system": "http://loinc.org", "code": "77599-9"}]},
        "text": {"status": "generated", "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">x</div>"},
    })
    vysledek = fhir_ezd.validate_ezd_bundle(bundle, "laboratorni-vysetreni")
    assert not vysledek["valid"]
    assert any("77599-9" in e for e in vysledek["errors"]), vysledek["errors"]


def test_hdr_kategorie_a_identifikator():
    hdr = fhir_ezd.EZD_KATEGORIE["propousteci-zprava"]
    assert hdr["category_codings"][0][0]["code"] == "11503-0"
    assert hdr["identifier_required"] is True


def test_img_dve_kategorie_jazyk_doporuceny():
    img = fhir_ezd.EZD_KATEGORIE["obrazove-vysetreni"]
    assert len(img["category_codings"]) == 2
    assert img["language_required"] is False and img["language_recommended"] is True


def test_iris_builder_zna_casove_body_a_nove_profily():
    cls = (KOREN / "docs/analytics/src/cls/SEZ/EZD/Builder.cls").read_text(encoding="utf-8")
    assert 'Parameter EMSCASYPOVINNE = "02,03,04,05,07";' in cls
    assert "composition-cz-lab" in cls
    assert "ClassMethod CasoveBody" in cls and "pCisloVyjezdu" in cls


# --------------------------------------------------------------------------- #
# SÚKL a Terminologie
# --------------------------------------------------------------------------- #

def test_sukl_dlp_katalog_na_nove_adrese():
    assert cfg.SUKL_DLP_KATALOG_VYCHOZI.startswith("https://opendata.sukl.gov.cz/")


def test_sukl_dlp_zkusi_vychozi_katalog_a_vybere_nejnovejsi(monkeypatch):
    stary = "https://opendata.sukl.cz/?q=katalog/databaze-lecivych-pripravku-dlp"
    monkeypatch.setattr(cfg, "SUKL_DLP_KATALOG", stary)
    volane = []

    class _Odpoved:
        text = ('<a href="https://opendata.sukl.gov.cz/soubory/SOD20260927/DLP20260927.zip">'
                '<a href="https://opendata.sukl.gov.cz/soubory/SOD20261027/DLP20261027.zip">')

        def raise_for_status(self):
            pass

    def _get(adresa, timeout=None):
        volane.append(adresa)
        if adresa == stary:
            raise OSError("adresa zrušena")
        return _Odpoved()

    import sez_api.client as client_mod
    monkeypatch.setattr(client_mod.requests, "get", _get)
    url, chyba = SUKLDLP._zjisti_url("auto")
    assert chyba is None
    assert url == "https://opendata.sukl.gov.cz/soubory/SOD20261027/DLP20261027.zip"
    assert volane == [stary, cfg.SUKL_DLP_KATALOG_VYCHOZI]


def test_sukl_epoukaz_ma_vlastni_verzi_rozhrani():
    assert cfg.SUKL_EPOUKAZ_INTERFACE_VERSION == "202605A"
    assert cfg.SUKL_EPOUKAZ_VYPNUTI_STARYCH == "2026-11-30"
    assert "202605A" not in cfg.SUKL_EPOUKAZ_VERZE_VYPINANE
    sukl = SUKLeRecept.__new__(SUKLeRecept)
    sukl._cfg = lambda: cfg
    assert sukl.verze_rozhrani("ZalozeniEPoukazu") == "202605A"
    assert sukl.verze_rozhrani("NahledNaEPoukaz") == "202605A"
    assert sukl.verze_rozhrani("ZalozeniPredpisu") == cfg.SUKL_INTERFACE_VERSION
    obalka = sukl.build_envelope("ZalozeniEPoukazu", {})
    assert obalka["hlavicka"]["verzeRozhrani"] == "202605A"


def test_terminologie_lookup_ma_nove_parametry():
    t = Terminologie.__new__(Terminologie)
    zaznam = {}

    def _request(method, op_path, *, params=None, body=None, timeout=30):
        zaznam.update(method=method, op_path=op_path, params=params)
        return _Resp()

    t._request = _request
    t.codesystem_lookup(code="I10", system="urn:oid:1.2.203.24341.1.3.1",
                        displayLanguage="cs", useSupplement="https://example.cz/supp")
    assert zaznam["op_path"] == "/CodeSystem/$lookup"
    assert zaznam["params"]["displayLanguage"] == "cs"
    assert zaznam["params"]["useSupplement"] == "https://example.cz/supp"
    t.codesystem_validate_code(code="I10", id="mkn-10", displayLanguage="cs")
    assert zaznam["op_path"] == "/CodeSystem/mkn-10/$validate-code"
    assert zaznam["params"]["displayLanguage"] == "cs"


def test_snapshot_apio_terminologie():
    spec = KOREN / "docs/analytics/swagger_specs/Terminologie_v1.0.5_apio_2026-10-08.json"
    text = spec.read_text(encoding="utf-8")
    assert "displayLanguage" in text and "useSupplement" in text


# --------------------------------------------------------------------------- #
# Dashboard – zvýrazněné rozdíly
# --------------------------------------------------------------------------- #

def _box(html):
    a = html.index('id="revize-2026-11"')
    return html[a:html.index("</table>", a)]


def test_dashboard_ma_box_revize_se_zvyraznenim(html):
    assert "Revize 10. 11. 2026 – co se změnilo proti revizi 13. 10. 2026" in html
    box = _box(html)
    assert 'class="rev-table"' in box
    # každý řádek rozdílu má původní i nový stav a štítek druhu změny
    radky = [r for r in re.findall(r"<tr>(.*?)</tr>", box, re.S) if "<td>" in r]
    assert len(radky) >= 20
    for r in radky:
        assert 'class="rev-old"' in r and 'class="rev-new"' in r, r[:120]
        assert re.search(r'class="rev-tag (nove|zmena|oprava|zruseno)"', r), r[:120]
    assert box.count('class="rev-sekce"') == 7


@pytest.mark.parametrize("text", [
    "karcinomProstatyUcast", "Standard 3.1, API 3.0.5",
    "2 Neproveditelná, 4 Dokončená", "jedno UUID pro celý proces",
    "nejvýše 10 000 pacientů v dávce", "dělitelné 13 a nedělitelné 11",
    "composition-cz-lab", "opendata.sukl.gov.cz", "202605A",
    "25488627_KrajskaZdravotniVerejnyTest04",
])
def test_dashboard_box_uvadi_hlavni_zmeny(html, text):
    assert text in _box(html)


def test_dashboard_uvadi_neoverene_a_rozpor(html):
    a = html.index('id="revize-2026-11"')
    zbytek = html[a:a + 30000]
    assert 'class="rev-tag neovereno"' in zbytek
    assert "brána T2 odsud neodpovídá" in zbytek
    assert "Rozpor ve zdrojích – KRP v2" in zbytek
    assert "Jen plán, v aplikaci zatím není" in zbytek
    for odkaz in ("https://www.ezdravi.gov.cz/katalog-sluzeb/dostupnost",
                  "https://www.ezdravi.gov.cz/statistiky",
                  "https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/1044774914",
                  "https://ig.ezdravi.gov.cz/"):
        assert odkaz in zbytek


def test_dashboard_styly_pro_zvyrazneni(html):
    for trida in (".rev-old", ".rev-new", ".rev-tag.nove", ".rev-tag.zmena",
                  ".rev-tag.oprava", ".rev-tag.zruseno", ".rev-tag.neovereno"):
        assert trida + " {" in html, trida


def test_tabulka_verzi_bez_zastaralych_cisel(html):
    a = html.index("<thead><tr><th>Služba</th><th>Verze</th><th>Poslední změna</th></tr></thead>")
    tabulka = html[a:html.index("</table>", a)]
    for verze in ("<code>v3.0.6</code>", "<code>v3.0.5</code>", "<code>v1.11.27</code>",
                  "<code>v1.0.9</code>", "<code>v1.0.8</code>", "<code>v3.0.3</code>",
                  "<code>1.0.0</code> (R4)"):
        assert verze in tabulka, verze
    for stara in ("<code>v1.11.20</code>", "<code>v1.0.6</code>", "<code>v1.0.4</code>",
                  "<code>v3.0.2</code>", "BUILD 28. 8. 2026", "v1 + v2 VYPNUTO"):
        assert stara not in tabulka, stara


def test_ukazky_pouzivaji_aktualni_testovaci_client_id(html):
    stary = re.compile(r"_KrajskaZdravotniVerejnyTest(?!0\d)")
    # jediný výskyt je přeškrtnutý „bylo“ v tabulce rozdílů
    assert len(stary.findall(html)) == 1
    assert len(stary.findall(_box(html))) == 1
    for soubor in ("sez_api/app.py", "sez_api/iris_ezd.py", "docs/analytics/INSTALL.md",
                   "docs/analytics/SEZ_API_Dokumentace.md",
                   "docs/analytics/src/cls/SEZ/IROP/TestRunner.cls",
                   "docs/analytics/src/csp/SEZAPI.csp",
                   "docs/analytics/reference_dotnet/README.md",
                   "docs/analytics/reference_dotnet/Program.cs"):
        text = (KOREN / soubor).read_text(encoding="utf-8")
        assert not stary.search(text), soubor
        assert "_KrajskaZdravotniVerejnyTest04" in text, soubor


# --------------------------------------------------------------------------- #
# Katalog služeb, verze, dokumentace
# --------------------------------------------------------------------------- #

def test_katalog_sluzeb_ma_aktualni_verze():
    """Katalog v /api/debug/jwt potřebuje certifikát, proto se čte zdroj."""
    src = (KOREN / "sez_api/app.py").read_text(encoding="utf-8")
    a = src.index('"services": {')
    katalog = src[a:src.index('"gateway_errors"', a)]
    for nazev, verze in (("/krpzs", "v2.0.4"), ("/docasneUloziste", "v1.11.27"),
                         ("/notifikace", "v1.0.9"), ("/ezca2Certifikaty", "v1.0.8")):
        assert re.search(r'"base": "%s",\s+"version": "%s"' % (re.escape(nazev), re.escape(verze)),
                         katalog), nazev
    for stara in ('"version": "v1.11.17"', '"version": "v1.0.5"', '"version": "v1.0.2"',
                  '"version": "v2.0.2"', '"version": "v3.0.0"', '"version": "v2.0.1"'):
        assert stara not in katalog, stara
    assert '"SZZ_v3": {' in katalog
    for typ in UCASTI:
        assert f"/sdilenyZdravotniZaznam/api/v3/screeningy/{typ}" in katalog
    assert "/elektronickePosudky/api/v3/posudky/ridicskeOpravneni/zalozeni/opravneni" in katalog
    assert "https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/1044774914" in src


def test_verze_balicku():
    import sez_api
    assert sez_api.__version__ == "2.38.0"
    assert 'version = "2.38.0"' in (KOREN / "pyproject.toml").read_text(encoding="utf-8")
    assert "Revize NCEZ zdrojů 2026-11-10" in sez_api.__doc__


def test_dokumentace_popisuje_revizi():
    readme = (KOREN / "README.md").read_text(encoding="utf-8")
    assert "## Revize 10. 11. 2026 – co se změnilo (bylo → je)" in readme
    assert "| Oblast | Bylo | Je |" in readme
    assert "SEZ_KRP_KONTROLA_JMEN" in readme
    dok = (KOREN / "docs/analytics/SEZ_API_Dokumentace.md").read_text(encoding="utf-8")
    assert "### 12.5 Standard EZ SZZ 3.1" in dok
    assert "Standard EZ Kmenové registry 1.3" in dok
    assert "szz.alergie.vyhledat(" not in dok, "příklad volal neexistující metodu"
    assert "Tre-987set" not in dok, "heslo k PFX do ukázek nepatří"
    assert "SEZ_KRP_KONTROLA_JMEN" in (KOREN / ".env.example").read_text(encoding="utf-8")


def _json(telo):
    import json
    return json.dumps(telo, ensure_ascii=False)
