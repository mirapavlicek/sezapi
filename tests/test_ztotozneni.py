"""
Testy interního API pro ztotožnění pacienta (POST /internal/v1/ztotozneni).

Bez síťové závislosti – KRP je nahrazeno atrapou, která zaznamenává volané
metody a vrací připravené odpovědi.

Spuštění:  python3 -m pytest tests/test_ztotozneni.py -v
"""

import pytest
import requests

from sez_api.app import _normalizuj_rc, _ztotozni


def _zt(*args, **kwargs):
    """_ztotozni s rozbaleným přehledem pokusů (poslední návratová hodnota je
    diagnostika: pokusy, trvaniMs, vyprselCas)."""
    metoda, status, kandidati, chyba, diag = _ztotozni(*args, **kwargs)
    return metoda, status, kandidati, chyba, diag["pokusy"]


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
    metoda, status, kandidati, chyba, pokusy = _zt(
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
    metoda, _status, _kand, _chyba, pokusy = _zt(
        krp, rodneCislo="035309/106", cisloPojistence="035309106")

    poradi = [p["metoda"] for p in pokusy]
    assert poradi[0] == "uni", poradi
    assert poradi.index("uni") < poradi.index("cizinec_cp")
    assert metoda == "cizinec_cp"  # poslední vyzkoušená, když nic nenašlo


def test_zaloha_hledani_podle_rc_kdyz_uni_neni_povolene():
    """Když univerzální hledání není na certifikátu povolené (403), zkusí se
    ještě hledání podle rodného čísla."""
    krp = _FakeKRP({
        "uni": _Resp(403, {"odpovedInfo": {"stav": "ZAKAZANO",
                                            "popis": "Metoda není povolena"}}),
        "jmeno_prijmeni_rc": _Resp(200, _nalezeny_pacient("555")),
    })
    metoda, status, kandidati, chyba, pokusy = _zt(krp, rodneCislo="035309/106")

    assert [p["metoda"] for p in pokusy] == ["uni", "jmeno_prijmeni_rc"]
    assert metoda == "jmeno_prijmeni_rc"
    assert status == 200
    assert kandidati[0].rid == "555"
    assert chyba is None
    assert pokusy[0]["upstreamStatus"] == 403


def test_jmeno_a_rodne_cislo_ma_prednost():
    krp = _FakeKRP({"jmeno_prijmeni_rc": _Resp(200, _nalezeny_pacient("111"))})
    metoda, _s, kandidati, _ch, pokusy = _zt(
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
    metoda, status, kandidati, chyba, pokusy = _zt(
        krp, jmeno="Marie", prijmeni="Dvorakova", rodneCislo="035309/106")

    assert [p["metoda"] for p in pokusy] == ["jmeno_prijmeni_rc", "uni"]
    assert metoda == "uni"
    assert status == 200
    assert kandidati[0].rid == "222"
    assert chyba is None


def test_cizinec_bez_rodneho_cisla_pouzije_cizinec_cp():
    krp = _FakeKRP({"cizinec_cp": _Resp(200, _nalezeny_pacient("333"))})
    metoda, _s, kandidati, _ch, pokusy = _zt(
        krp, cisloPojistence="7712345678", statniObcanstvi="SVK")

    assert metoda == "cizinec_cp"
    assert [p["metoda"] for p in pokusy] == ["cizinec_cp"]
    assert kandidati[0].rid == "333"


def test_samotne_datum_narozeni_je_pripustne():
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient("444"))})
    metoda, _s, _k, _ch, _p = _zt(krp, datumNarozeni="1990-05-14")
    assert metoda == "uni"


def test_bez_identifikatoru_vyhodi_chybu():
    with pytest.raises(ValueError):
        _ztotozni(_FakeKRP(), jmeno="Marie", prijmeni="Dvořáková")


def test_nenalezeno_vraci_chybu_z_upstreamu():
    """Regrese: chyby KRP jsou v odpovedInfo.chybyZpracovani, dřív se čekaly
    v poli `chyby`, takže odpověď měla `chyba: null` bez vysvětlení."""
    krp = _FakeKRP(vychozi=_Resp(404, _nenalezeno("Pacient nebyl nalezen.")))
    _m, status, kandidati, chyba, pokusy = _zt(krp, rodneCislo="035309106")
    assert status == 404
    assert kandidati == []
    assert chyba == "Pacient nebyl nalezen.", chyba
    assert pokusy[-1]["upstreamStatus"] == 404


def test_chyba_z_popisu_kdyz_krp_nevyplni_seznam_chyb():
    krp = _FakeKRP(vychozi=_Resp(
        404, {"odpovedInfo": {"stav": "NENALEZENO", "popis": "Záznam neexistuje"}}))
    _m, _s, _k, chyba, _p = _zt(krp, rodneCislo="035309106")
    assert chyba == "NENALEZENO – Záznam neexistuje", chyba


def test_substav_ztotozneni_se_bere_z_hlavicky_odpovedi():
    """Regrese: pole substavZtotozneni v záznamu pacienta neexistuje,
    KRP ho vrací v odpovedInfo.subStav – dřív bylo vždy null."""
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient(substav="ZTOTOZNENO"))})
    _m, _s, kandidati, _ch, _p = _zt(krp, rodneCislo="035309/106")
    assert kandidati[0].substavZtotozneni == "ZTOTOZNENO"


def test_atributy_pacienta_se_rozbaluji_z_kzr_objektu():
    krp = _FakeKRP({"uni": _Resp(200, _nalezeny_pacient())})
    _m, _s, kandidati, _ch, _p = _zt(krp, rodneCislo="035309/106")
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


# --- dodržení časového rozpočtu --------------------------------------------

class _PomalaSession:
    """Brána, která neodpoví – požadavek skončí až vypršením timeoutu."""

    cert = None
    verify = True
    headers: dict = {}

    def __init__(self, zaznam: list):
        self.zaznam = zaznam

    def mount(self, *a, **kw):
        return None

    def request(self, method, url, **kw):
        import time
        self.zaznam.append(kw.get("timeout"))
        time.sleep(kw.get("timeout", 30))
        raise requests.Timeout("brána neodpověděla")

    def close(self):
        return None


def _pomaly_krp(monkeypatch, zaznam, *, timeout=0.4, retries=1, backoff=0.1):
    """KRP klient s atrapou pomalé brány a krátkými limity (rychlý test)."""
    import tempfile
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    from sez_api.client import KRP, SEZAuth, SEZClient, SEZConfig

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    t = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(jm).issuer_name(jm)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(t - timedelta(days=1))
            .not_valid_after(t + timedelta(days=365)).sign(key, hashes.SHA256()))
    p12 = pkcs12.serialize_key_and_certificates(
        name=b"t", key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"x"))
    soubor = tempfile.NamedTemporaryFile(suffix=".p12", delete=False)
    soubor.write(p12)
    soubor.close()

    monkeypatch.setattr(SEZClient, "_new_session",
                        lambda self: _PomalaSession(zaznam))
    icfg = SEZConfig()
    icfg.GATEWAY = "https://brana.test"
    icfg.TOKEN_AUDIENCE = "https://jsu.test/token"
    auth = SEZAuth(client_id="test", p12_path=soubor.name, p12_password="x",
                   config=icfg)
    client = SEZClient(auth)
    client.DEFAULT_TIMEOUT = timeout
    client.MAX_RETRIES = retries
    client.RETRY_BACKOFF = [backoff]
    return KRP(client)


def test_rozpocet_plati_i_uvnitr_jedne_metody(monkeypatch):
    """Regrese: timeout jednoho volání se násobil počtem opakování, takže
    jedna metoda mohla trvat víc než celý rozpočet (3 s + 0,25 s + 3 s = 6,25 s
    při rozpočtu 4 s) a synchronní volající zůstal bez odpovědi."""
    import time

    from sez_api import config as cfg
    monkeypatch.setattr(cfg, "ZTOTOZNENI_BUDGET_MS", 600, raising=False)
    zaznam: list = []
    krp = _pomaly_krp(monkeypatch, zaznam, timeout=0.4, retries=1, backoff=0.1)

    t0 = time.monotonic()
    _m, status, kandidati, chyba, diag = _ztotozni(
        krp, jmeno="Vitalii", prijmeni="Mozeliuk", datumNarozeni="1988-03-08")
    trvani = time.monotonic() - t0

    assert trvani < 0.9, f"trvalo {trvani:.2f}s, rozpočet byl 0,6 s"
    assert diag["vyprselCas"] is True
    assert status == 504
    assert kandidati == []
    assert "neodpověděla" in chyba
    # Druhá metoda se nezahájila, protože by rozpočet přetekla.
    assert "uni" in chyba
    assert [p["metoda"] for p in diag["pokusy"]] == ["jmeno_prijmeni_datum_narozeni"]


def test_timeout_brany_neni_chyba_serveru(monkeypatch):
    """Volající má dostat včas odpověď s vysvětlením, ne HTTP 502."""
    from starlette.testclient import TestClient

    from sez_api import config as cfg
    from sez_api.app import app

    monkeypatch.setattr(cfg, "ZTOTOZNENI_BUDGET_MS", 600, raising=False)
    monkeypatch.setattr(cfg, "INTERNAL_API_KEY", "", raising=False)
    zaznam: list = []
    krp = _pomaly_krp(monkeypatch, zaznam, timeout=0.4, retries=1, backoff=0.1)
    monkeypatch.setattr("sez_api.app._internal_modules",
                        lambda: {"krp": krp, "auth": None, "client": krp.c, "cert": {}})

    r = TestClient(app).post("/internal/v1/ztotozneni", json={
        "jmeno": "Vitalii", "prijmeni": "Mozeliuk", "datumNarozeni": "1988-03-08"})

    assert r.status_code == 200, r.text
    d = r.json()
    assert d["nalezeno"] is False
    assert d["vyprselCas"] is True
    assert d["upstreamStatus"] == 504
    assert d["trvaniMs"] < 900, d["trvaniMs"]
    assert "neodpověděla" in d["chyba"]


def test_klient_zkrati_timeout_na_zbyvajici_cas(monkeypatch):
    """Timeout jednotlivého pokusu se vejde do zbývajícího stropu."""
    zaznam: list = []
    krp = _pomaly_krp(monkeypatch, zaznam, timeout=5.0, retries=0, backoff=0.1)
    krp.c.nastav_deadline(0.5)

    with pytest.raises(requests.Timeout):
        krp.hledat_rid("1234567890")

    assert zaznam, "volání se vůbec neuskutečnilo"
    assert zaznam[0] < 0.5, f"timeout {zaznam[0]} nerespektuje zbývající strop"


def test_klient_bez_deadlinu_pouziva_plny_timeout(monkeypatch):
    zaznam: list = []
    krp = _pomaly_krp(monkeypatch, zaznam, timeout=0.3, retries=0, backoff=0.1)

    with pytest.raises(requests.Timeout):
        krp.hledat_rid("1234567890")
    assert zaznam == [0.3]


def test_ztotozni_safe_neopakuje_pri_timeoutu(monkeypatch):
    """Obnova klienta má smysl při rozbité session, ne při timeoutu – druhý
    průchod by dobu odpovědi zdvojnásobil."""
    from sez_api import app as A

    volani = {"pocet": 0}

    def _falesne_ztotozni(krp, **kw):
        volani["pocet"] += 1
        raise requests.Timeout("brána neodpověděla")

    monkeypatch.setattr(A, "_ztotozni", _falesne_ztotozni)
    monkeypatch.setattr(A, "_internal_modules",
                        lambda: {"krp": object(), "auth": None, "client": None,
                                 "cert": {}})
    resetu = {"pocet": 0}
    monkeypatch.setattr(A, "_internal_reset",
                        lambda: resetu.__setitem__("pocet", resetu["pocet"] + 1))

    with pytest.raises(requests.Timeout):
        A._ztotozni_safe({"rodneCislo": "8001011234"}, "LECBA")

    assert volani["pocet"] == 1, "timeout se nemá opakovat"
    assert resetu["pocet"] == 0, "klient se při timeoutu nemá resetovat"


# --- normalizace rodného čísla ---------------------------------------------

def test_normalizace_rodneho_cisla():
    assert _normalizuj_rc("035309/106") == "035309106"
    assert _normalizuj_rc("800101 1234") == "8001011234"
    assert _normalizuj_rc(" 8001011234 ") == "8001011234"
    assert _normalizuj_rc(None) == ""
    assert _normalizuj_rc("") == ""
