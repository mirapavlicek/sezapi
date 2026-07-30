"""
Testy interního API pro ztotožnění pacienta (POST /internal/v1/ztotozneni).

Bez síťové závislosti – KRP je nahrazeno atrapou, která zaznamenává volané
metody a vrací připravené odpovědi.

Spuštění:  python3 -m pytest tests/test_ztotozneni.py -v
"""

from sez_api.app import _normalizuj_rc, _ztotozni


class _Resp:
    """Odpověď KRP gateway."""

    def __init__(self, status: int, body: dict | None = None):
        self.status_code = status
        self._body = body if body is not None else {}

    def json(self):
        return self._body


def _nalezeny_pacient(rid: str = "2667873559", substav: str = "ZTOTOZNENO") -> dict:
    """Odpověď dle schématu OdpovedVyhledaniPacienta (KRP v2.0.2): atributy
    pacienta jsou objekty KZRString/KZRDate s hodnotou, stav ztotožnění je
    v odpovedInfo.subStav."""
    return {
        "odpovedInfo": {"stav": "OK", "subStav": substav, "chybyZpracovani": []},
        "odpovedData": {
            "rid": rid,
            "jmeno": {"hodnota": "Marie", "zdroj": "KZR"},
            "prijmeni": {"hodnota": "Dvořáková", "zdroj": "KZR"},
            "datumNarozeni": {"hodnota": "1903-03-09", "zdroj": "KZR"},
        },
    }


def _nenalezeno(zprava: str = "Pacient nebyl nalezen.") -> dict:
    return {"odpovedInfo": {"stav": "CHYBA", "subStav": "NENALEZENO",
                             "chybyZpracovani": [{"message": zprava,
                                                   "severity": "ERROR"}]}}


class _FakeKRP:
    """Zaznamenává volání a vrací odpovědi podle názvu metody."""

    def __init__(self, odpovedi: dict | None = None, vychozi: _Resp | None = None):
        self.volani: list[tuple] = []
        self._odpovedi = odpovedi or {}
        self._vychozi = vychozi or _Resp(404, _nenalezeno())

    def _zaznam(self, metoda: str, **kwargs):
        self.volani.append((metoda, kwargs))
        return self._odpovedi.get(metoda, self._vychozi)

    def hledat_jmeno_rc(self, jmeno, prijmeni, rc, ucel="LECBA"):
        return self._zaznam("jmeno_prijmeni_rc", jmeno=jmeno, prijmeni=prijmeni, rc=rc)

    def hledat_jmeno_cp(self, jmeno, prijmeni, cp, ucel="LECBA"):
        return self._zaznam("jmeno_prijmeni_cp", jmeno=jmeno, prijmeni=prijmeni, cp=cp)

    def hledat_jmeno_dn(self, jmeno, prijmeni, dn, so=None, ucel="LECBA"):
        return self._zaznam("jmeno_prijmeni_datum_narozeni", jmeno=jmeno,
                            prijmeni=prijmeni, dn=dn)

    def hledat_cizinec_cp(self, cp, so=None, ucel="LECBA"):
        return self._zaznam("cizinec_cp", cp=cp, so=so)

    def hledat_uni(self, ucel="LECBA", **kwargs):
        return self._zaznam("uni", **kwargs)


# --- volba metody ----------------------------------------------------------

def test_rodne_cislo_bez_jmena_pouzije_univerzalni_hledani():
    """Regrese z produkce: požadavek s rodným číslem, datem narození a číslem
    pojištěnce, ale bez jména, dřív spadl na `cizinec_cp` (hledání cizince)
    a KRP vracelo 404."""
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient())})
    metoda, status, kandidati, chyba, pokusy = _ztotozni(
        krp, jmeno=None, prijmeni=None, rodneCislo="035309/106",
        datumNarozeni="1903-03-09", cisloPojistence="035309106")

    assert metoda == "uni", pokusy
    assert status == 200
    assert kandidati[0].rid == "2667873559"
    assert chyba is None
    assert [p["metoda"] for p in pokusy] == ["uni"]

    # Univerzální hledání dostane všechny známé identifikátory.
    _, kwargs = krp.volani[0]
    assert kwargs["rodneCislo"] == "035309106"
    assert kwargs["datumNarozeni"] == "1903-03-09"
    assert kwargs["cisloPojistence"] == "035309106"


def test_cizinec_cp_se_nepouzije_jako_prvni_pri_rodnem_cisle():
    """Pacient s rodným číslem není cizinec – `cizinec_cp` smí být až fallback."""
    krp = _FakeKRP()
    metoda, _status, _kand, _chyba, pokusy = _ztotozni(
        krp, rodneCislo="035309/106", cisloPojistence="035309106")

    poradi = [p["metoda"] for p in pokusy]
    assert poradi[0] == "uni", poradi
    assert poradi.index("uni") < poradi.index("cizinec_cp")
    assert metoda == "cizinec_cp"  # poslední vyzkoušená, když nic nenašlo


def test_jmeno_a_rodne_cislo_ma_prednost():
    krp = _FakeKRP({"jmeno_prijmeni_rc": _Resp(200, _nalezeny_pacient("111"))})
    metoda, _s, kandidati, _ch, pokusy = _ztotozni(
        krp, jmeno="Marie", prijmeni="Dvořáková", rodneCislo="035309/106")

    assert metoda == "jmeno_prijmeni_rc"
    assert kandidati[0].rid == "111"
    # Při úspěchu se žádná další metoda nevolá.
    assert len(krp.volani) == 1, krp.volani
    assert len(pokusy) == 1


def test_pokracuje_dalsi_metodou_kdyz_prvni_nenajde():
    """Jméno v NIS nemusí odpovídat KRP (přechýlení, dvojí příjmení),
    proto se pokračuje univerzálním hledáním podle rodného čísla."""
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient("222"))})
    metoda, status, kandidati, chyba, pokusy = _ztotozni(
        krp, jmeno="Marie", prijmeni="Dvorakova", rodneCislo="035309/106")

    assert [p["metoda"] for p in pokusy] == ["jmeno_prijmeni_rc", "uni"]
    assert metoda == "uni"
    assert status == 200
    assert kandidati[0].rid == "222"
    assert chyba is None


def test_cizinec_bez_rodneho_cisla_pouzije_cizinec_cp():
    krp = _FakeKRP({"cizinec_cp": _Resp(200, _nalezeny_pacient("333"))})
    metoda, _s, kandidati, _ch, pokusy = _ztotozni(
        krp, cisloPojistence="7712345678", statniObcanstvi="SVK")

    assert metoda == "cizinec_cp"
    assert [p["metoda"] for p in pokusy] == ["cizinec_cp"]
    assert kandidati[0].rid == "333"


def test_samotne_datum_narozeni_je_pripustne():
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient("444"))})
    metoda, _s, _k, _ch, _p = _ztotozni(krp, datumNarozeni="1990-05-14")
    assert metoda == "uni"


def test_bez_identifikatoru_vyhodi_chybu():
    import pytest
    with pytest.raises(ValueError):
        _ztotozni(_FakeKRP(), jmeno="Marie", prijmeni="Dvořáková")


def test_nenalezeno_vraci_chybu_z_upstreamu():
    """Regrese: chyby KRP jsou v odpovedInfo.chybyZpracovani, dřív se čekaly
    v poli `chyby`, takže odpověď měla `chyba: null` bez vysvětlení."""
    krp = _FakeKRP(vychozi=_Resp(404, _nenalezeno("Pacient nebyl nalezen.")))
    _m, status, kandidati, chyba, pokusy = _ztotozni(krp, rodneCislo="035309106")
    assert status == 404
    assert kandidati == []
    assert chyba == "Pacient nebyl nalezen.", chyba
    assert pokusy[-1]["upstreamStatus"] == 404


def test_chyba_z_popisu_kdyz_krp_nevyplni_seznam_chyb():
    krp = _FakeKRP(vychozi=_Resp(
        404, {"odpovedInfo": {"stav": "NENALEZENO", "popis": "Záznam neexistuje"}}))
    _m, _s, _k, chyba, _p = _ztotozni(krp, rodneCislo="035309106")
    assert chyba == "NENALEZENO – Záznam neexistuje", chyba


def test_substav_ztotozneni_se_bere_z_hlavicky_odpovedi():
    """Regrese: pole substavZtotozneni v záznamu pacienta neexistuje,
    KRP ho vrací v odpovedInfo.subStav – dřív bylo vždy null."""
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient(substav="ZTOTOZNENO"))})
    _m, _s, kandidati, _ch, _p = _ztotozni(krp, rodneCislo="035309/106")
    assert kandidati[0].substavZtotozneni == "ZTOTOZNENO"


def test_atributy_pacienta_se_rozbaluji_z_kzr_objektu():
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient())})
    _m, _s, kandidati, _ch, _p = _ztotozni(krp, rodneCislo="035309/106")
    k = kandidati[0]
    assert (k.jmeno, k.prijmeni, k.datumNarozeni) == ("Marie", "Dvořáková", "1903-03-09")


# --- HTTP endpoint ---------------------------------------------------------

def test_endpoint_vraci_rid_a_prehled_pokusu(monkeypatch):
    """Volání POST /internal/v1/ztotozneni tak, jak ho posílá NIS."""
    from starlette.testclient import TestClient
    from sez_api.app import app

    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient("2667873559"))})
    monkeypatch.setattr("sez_api.app._internal_modules",
                        lambda: {"krp": krp, "cert": {}, "auth": None, "client": None})
    monkeypatch.setattr("sez_api.app.cfg.INTERNAL_API_KEY", "", raising=False)

    r = TestClient(app).post("/internal/v1/ztotozneni", json={
        "jmeno": None, "prijmeni": None, "rodneCislo": "035309/106",
        "datumNarozeni": "1903-03-09", "cisloPojistence": "035309106",
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["nalezeno"] is True, d
    assert d["rid"] == "2667873559"
    assert d["metoda"] == "uni"
    assert d["substavZtotozneni"] == "ZTOTOZNENO"
    assert d["upstreamStatus"] == 200
    assert [p["metoda"] for p in d["pokusy"]] == ["uni"]


# --- normalizace rodného čísla ---------------------------------------------

def test_normalizace_rodneho_cisla():
    assert _normalizuj_rc("035309/106") == "035309106"
    assert _normalizuj_rc("800101 1234") == "8001011234"
    assert _normalizuj_rc(" 8001011234 ") == "8001011234"
    assert _normalizuj_rc(None) == ""
    assert _normalizuj_rc("") == ""
