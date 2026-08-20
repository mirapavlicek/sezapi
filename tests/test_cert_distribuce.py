"""
Testy automatické aktualizace certifikátu z centrální distribuce.

Bez sítě – distribuční API je nahrazené atrapou, certifikáty se generují
v testu (self-signed PKCS#12 se stejnou strukturou subjektu, jakou vydává
EZCA: CN = název služby, organizationIdentifier = IČO).

Spuštění:  python3 -m pytest tests/test_cert_distribuce.py -v
"""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509.oid import NameOID
from starlette.testclient import TestClient

from sez_api import certdistribuce as cd
from sez_api import config as cfg
from sez_api.app import app
from sez_api.certstore import CertChyba, CertStore, zkontroluj_pfx

ICO = "00064203"
SLUZBA = "NIS2"


def _vyrob_pfx(heslo: str = "tajne", *, sluzba: str = SLUZBA, ico: str = ICO,
               platny_od_dnu: int = -1, platny_do_dnu: int = 90) -> bytes:
    """PKCS#12 se subjektem ve tvaru, jaký vydává EZCA pro přístup PZS."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jmeno = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fakultni nemocnice"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "pzs"),
        x509.NameAttribute(NameOID.COMMON_NAME, sluzba),
        x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, ico),
    ])
    ted = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(jmeno)
            .issuer_name(jmeno)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ted + timedelta(days=platny_od_dnu))
            .not_valid_after(ted + timedelta(days=platny_do_dnu))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return pkcs12.serialize_key_and_certificates(
        name=b"sez", key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(heslo.encode()))


def _zapis(pfx: bytes, heslo: str = "tajne", **prepis) -> dict:
    """Záznam distribuce odpovídající danému PKCS#12 (souhlasná metadata)."""
    _, cert, _ = pkcs12.load_key_and_certificates(pfx, heslo.encode())
    zapis = {
        "id": "221",
        "serioveCislo": format(cert.serial_number, "X"),
        "uid": "5c08647d-b7c9-4982-9fa9-d2f41987b0f9",
        "nazevSluzby": SLUZBA,
        "nazevSubjektu": "Fakultni nemocnice",
        "externiIdentifikator": ICO,
        "stav": "Valid",
        "platnostOd": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "platnostDo": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "revokovany": 0,
        "active": 1,
        "autoRenew": "1",
        "pfxHash": cert.fingerprint(SHA1()).hex().upper(),
        "pfxSize": len(pfx),
        "password": heslo,
        "pfx": base64.b64encode(pfx).decode(),
    }
    zapis.update(prepis)
    return zapis


@pytest.fixture
def prostredi(tmp_path, monkeypatch):
    """Izolované úložiště, filtr na naši službu a atrapa klienta SEZ."""
    monkeypatch.setattr(cfg, "CERT_STORE_DIR", str(tmp_path / "certs"), raising=False)
    monkeypatch.setattr(cfg, "CERT_API_KEY", "", raising=False)
    monkeypatch.setattr(cfg, "INTERNAL_API_KEY", "", raising=False)
    monkeypatch.setattr(cfg, "CERT_DIST_ICO", ICO, raising=False)
    monkeypatch.setattr(cfg, "CERT_DIST_SLUZBA", SLUZBA, raising=False)
    monkeypatch.setattr(cfg, "CERT_DIST_URL", "https://iris.test/api/ez/certificate",
                        raising=False)
    monkeypatch.setattr(cfg, "CERT_DIST_USER", "jmeno", raising=False)
    monkeypatch.setattr(cfg, "CERT_DIST_PASSWORD", "tajne-heslo", raising=False)
    monkeypatch.setattr(cfg, "CERT_DIST_ENABLED", False, raising=False)
    monkeypatch.setattr(cfg, "ENV_CREDENTIALS",
                        {k: dict(v) for k, v in cfg.ENV_CREDENTIALS.items()},
                        raising=False)
    for atr in ("PROD_P12_PATH", "PROD_P12_PASSWORD",
                "PROD_CLIENT_ID", "PROD_CERT_UID"):
        monkeypatch.setattr(cfg, atr, getattr(cfg, atr, ""), raising=False)

    class _Auth:
        _kid = "kid"

        def build_assertion(self, extra_headers=None):
            return "a.b.c"

        def cleanup(self):
            return None

    class _Resp:
        status_code = 200

        def json(self):
            return {"odpovedData": {}}

    class _KRP:
        def ciselnik(self, nazev, ucel="LECBA"):
            return _Resp()

    monkeypatch.setattr("sez_api.app._build_internal_prod",
                        lambda: {"krp": _KRP(), "auth": _Auth(),
                                 "client": object(), "cert": {}})
    monkeypatch.setattr("sez_api.app._internal_state", {})
    return tmp_path / "certs"


def _podvrhni_api(monkeypatch, zapisy, *, status=200, telo=None):
    """Nahradí volání distribuce. Vrací seznam zachycených volání."""
    volani = []

    class _Odpoved:
        status_code = status

        def json(self):
            if telo is not None:
                return telo
            return zapisy

    def _get(url, **kwargs):
        volani.append({"url": url, **kwargs})
        return _Odpoved()

    monkeypatch.setattr("sez_api.certdistribuce.requests.get", _get)
    return volani


# --- nastavení -------------------------------------------------------------

def test_nastaveni_z_env_a_prepis_ulozenym(prostredi):
    """Výchozí hodnoty jdou z .env, uložený soubor je přepisuje."""
    assert cd.nastaveni()["url"] == "https://iris.test/api/ez/certificate"
    assert cd.nastaveni()["intervalHodin"] == 24.0

    cd.uloz_nastaveni({"url": "https://jiny/api", "intervalHodin": 6})
    assert cd.nastaveni()["url"] == "https://jiny/api"
    assert cd.nastaveni()["intervalHodin"] == 6.0
    # Nezmíněné položky zůstávají.
    assert cd.nastaveni()["uzivatel"] == "jmeno"


def test_prazdne_heslo_neprepise_ulozene(prostredi):
    cd.uloz_nastaveni({"heslo": "nove-heslo"})
    assert cd.nastaveni()["heslo"] == "nove-heslo"

    cd.uloz_nastaveni({"heslo": "", "uzivatel": "jiny"})
    assert cd.nastaveni()["heslo"] == "nove-heslo", "prázdné heslo má ponechat stávající"
    assert cd.nastaveni()["uzivatel"] == "jiny"

    cd.uloz_nastaveni({"smazatHeslo": True})
    assert cd.nastaveni()["heslo"] == ""


def test_nastaveni_nevraci_heslo(prostredi):
    cd.uloz_nastaveni({"heslo": "tajne-heslo"})
    zobrazene = cd.nastaveni_bez_hesla()
    assert "heslo" not in zobrazene
    assert zobrazene["hesloNastaveno"] is True
    assert "tajne-heslo" not in json.dumps(zobrazene)


def test_soubor_nastaveni_ma_prava_0600(prostredi):
    """V souboru je heslo k distribuci v otevřené podobě."""
    cd.uloz_nastaveni({"heslo": "tajne-heslo"})
    assert oct(cd.soubor_nastaveni().stat().st_mode & 0o777) == "0o600"


def test_zaporny_interval_se_odmitne(prostredi):
    with pytest.raises(cd.DistribuceChyba):
        cd.uloz_nastaveni({"intervalHodin": 0})


# --- výběr záznamu ---------------------------------------------------------

def test_vybere_jen_nas_certifikat(prostredi):
    nas = _zapis(_vyrob_pfx())
    cizi_sluzba = _zapis(_vyrob_pfx(sluzba="JINY"), nazevSluzby="JINY")
    cizi_subjekt = _zapis(_vyrob_pfx(ico="12345678"), externiIdentifikator="12345678")
    vybrany, duvody = cd.vyber_zapis([cizi_sluzba, cizi_subjekt, nas], ICO, SLUZBA)
    assert vybrany is nas
    assert len(duvody) == 2


def test_preskoci_revokovany_a_neplatny(prostredi):
    revokovany = _zapis(_vyrob_pfx(), revokovany=1)
    zruseny = _zapis(_vyrob_pfx(), stav="Revoked")
    neaktivni = _zapis(_vyrob_pfx(), active=0)
    vybrany, duvody = cd.vyber_zapis([revokovany, zruseny, neaktivni], ICO, SLUZBA)
    assert vybrany is None
    assert len(duvody) == 3


def test_vybere_nejdele_platny(prostredi):
    kratsi = _zapis(_vyrob_pfx(platny_do_dnu=30))
    delsi = _zapis(_vyrob_pfx(platny_do_dnu=120))
    vybrany, _ = cd.vyber_zapis([kratsi, delsi], ICO, SLUZBA)
    assert vybrany is delsi


# --- integrita a příslušnost ----------------------------------------------

def test_odmitne_nesouhlasny_odstisk(prostredi):
    zapis = _zapis(_vyrob_pfx(), pfxHash="0" * 40)
    with pytest.raises(CertChyba, match="Odstisk"):
        cd.rozbal_a_zkontroluj(zapis, ico=ICO, sluzba=SLUZBA)


def test_odmitne_nesouhlasnou_velikost(prostredi):
    zapis = _zapis(_vyrob_pfx(), pfxSize=123)
    with pytest.raises(CertChyba, match="Velikost"):
        cd.rozbal_a_zkontroluj(zapis, ico=ICO, sluzba=SLUZBA)


def test_odmitne_nesouhlasne_seriove_cislo(prostredi):
    zapis = _zapis(_vyrob_pfx(), serioveCislo="ABCDEF")
    with pytest.raises(CertChyba, match="Sériové číslo"):
        cd.rozbal_a_zkontroluj(zapis, ico=ICO, sluzba=SLUZBA)


def test_odmitne_certifikat_jine_sluzby(prostredi):
    """Kdyby distribuční adresu někdo přesměroval, cizí certifikát se
    nesmí dostat do provozu ani při souhlasných metadatech."""
    pfx = _vyrob_pfx(sluzba="PODVRH", ico="99999999")
    zapis = _zapis(pfx)  # metadata tvrdí, že je náš
    with pytest.raises(CertChyba, match="službu"):
        cd.rozbal_a_zkontroluj(zapis, ico=ICO, sluzba=SLUZBA)


def test_odmitne_spatne_heslo(prostredi):
    pfx = _vyrob_pfx(heslo="spravne")
    zapis = _zapis(pfx, heslo="spravne")
    zapis["password"] = "chybne"
    with pytest.raises(CertChyba, match="nelze otevřít"):
        cd.rozbal_a_zkontroluj(zapis, ico=ICO, sluzba=SLUZBA)


def test_prijme_nas_certifikat(prostredi):
    pfx = _vyrob_pfx()
    pfx_zpet, heslo, popis = cd.rozbal_a_zkontroluj(_zapis(pfx), ico=ICO, sluzba=SLUZBA)
    assert pfx_zpet == pfx
    assert heslo == "tajne"
    assert popis["cn"] == SLUZBA
    assert popis["organizationIdentifier"] == ICO


# --- rozhodnutí, co s nabídkou --------------------------------------------

def _popis(pfx, heslo="tajne"):
    return zkontroluj_pfx(pfx, heslo, vynutit=True)


def test_stejny_certifikat_se_nenasazuje(prostredi):
    pfx = _vyrob_pfx()
    popis = _popis(pfx)
    assert cd.rozhodni(popis, popis)["akce"] == "aktualni"


def test_starsi_certifikat_se_nenasazuje(prostredi):
    aktivni = _popis(_vyrob_pfx(platny_do_dnu=90))
    nabizeny = _popis(_vyrob_pfx(platny_do_dnu=10))
    rozhodnuti = cd.rozhodni(nabizeny, aktivni)
    assert rozhodnuti["akce"] == "starsi"


def test_novejsi_certifikat_se_nasadi(prostredi):
    aktivni = _popis(_vyrob_pfx(platny_do_dnu=10))
    nabizeny = _popis(_vyrob_pfx(platny_do_dnu=90))
    assert cd.rozhodni(nabizeny, aktivni)["akce"] == "nasadit"


def test_predcasny_certifikat_ceka(prostredi):
    """Distribuce nabízí certifikát dopředu – dokud platí stávající, čeká se."""
    aktivni = _popis(_vyrob_pfx(platny_do_dnu=40))
    nabizeny = _popis(_vyrob_pfx(platny_od_dnu=10, platny_do_dnu=120))
    assert cd.rozhodni(nabizeny, aktivni)["akce"] == "pockat"


def test_predcasny_se_nasadi_kdyz_stavajici_neplati(prostredi):
    aktivni = _popis(_vyrob_pfx(platny_od_dnu=-100, platny_do_dnu=-1))
    nabizeny = _popis(_vyrob_pfx(platny_od_dnu=1, platny_do_dnu=120))
    assert cd.rozhodni(nabizeny, aktivni)["akce"] == "nasadit"


def test_vyprsely_certifikat_se_nenasadi(prostredi):
    nabizeny = _popis(_vyrob_pfx(platny_od_dnu=-100, platny_do_dnu=-1))
    assert cd.rozhodni(nabizeny, None)["akce"] == "starsi"


# --- zámek mezi workery ---------------------------------------------------

def test_zamek_pusti_jen_jednoho(prostredi):
    prvni, druhy = cd.Zamek(), cd.Zamek()
    assert prvni.zkus_ziskat() is True
    assert druhy.zkus_ziskat() is False, "kontrolu smí provádět jen jeden worker"
    prvni.uvolni()
    assert druhy.zkus_ziskat() is True
    druhy.uvolni()


def test_osirely_zamek_se_prebere(prostredi):
    """Po zabitém procesu nesmí zámek zablokovat kontrolu navždy."""
    stary = cd.Zamek(max_vek=0)
    assert stary.zkus_ziskat() is True
    assert cd.Zamek(max_vek=0).zkus_ziskat() is True


def test_interval_se_dodrzi(prostredi):
    assert cd.dalsi_kontrola_za() == 0, "bez záznamu o kontrole je čas hned"
    cd.zapis_stav({"posledniKontrolaTs": __import__("time").time()})
    zbyva = cd.dalsi_kontrola_za()
    assert 23 * 3600 < zbyva <= 24 * 3600


# --- API a celý průběh ----------------------------------------------------

def test_api_kontrola_nasadi_novy_certifikat(prostredi, monkeypatch):
    """Hlavní scénář: distribuce má novější certifikát → nasadí se."""
    store = CertStore(prostredi, "PROD")
    stary = _vyrob_pfx(platny_do_dnu=10)
    store.uloz(stary, "tajne", popis=_popis(stary))

    novy = _vyrob_pfx(platny_do_dnu=90)
    volani = _podvrhni_api(monkeypatch, [_zapis(novy)])

    r = TestClient(app).post("/api/cert-distribuce/kontrola")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["akce"] == "nasadit" and d["nasazeno"] is True
    assert store.pfx_path.read_bytes() == novy
    # Předchozí certifikát zůstal v historii pro případný rollback.
    assert len(store.historie()) == 1
    # Volání šlo na nastavenou adresu s basic auth.
    assert volani[0]["url"] == "https://iris.test/api/ez/certificate"
    assert volani[0]["auth"] == ("jmeno", "tajne-heslo")
    # Heslo k PKCS#12 ani k distribuci se nevrací.
    assert "tajne" not in r.text and "tajne-heslo" not in r.text


def test_api_kontrola_jen_zjistit_nic_nemeni(prostredi, monkeypatch):
    store = CertStore(prostredi, "PROD")
    stary = _vyrob_pfx(platny_do_dnu=10)
    store.uloz(stary, "tajne", popis=_popis(stary))
    _podvrhni_api(monkeypatch, [_zapis(_vyrob_pfx(platny_do_dnu=90))])

    d = TestClient(app).post("/api/cert-distribuce/kontrola?jenZjistit=true").json()
    assert d["akce"] == "nasadit" and d["nasazeno"] is False
    assert store.pfx_path.read_bytes() == stary, "jen zjištění nesmí nic nasadit"


def test_api_kontrola_hlasi_chybu_prihlaseni(prostredi, monkeypatch):
    _podvrhni_api(monkeypatch, [], status=401)
    r = TestClient(app).post("/api/cert-distribuce/kontrola")
    assert r.status_code == 502
    assert "401" in r.json()["detail"]


def test_api_kontrola_bez_adresy(prostredi, monkeypatch):
    monkeypatch.setattr(cfg, "CERT_DIST_URL", "", raising=False)
    r = TestClient(app).post("/api/cert-distribuce/kontrola")
    assert r.status_code == 502
    assert "adresa" in r.json()["detail"].lower()


def test_api_stav_a_nastaveni(prostredi):
    c = TestClient(app)
    r = c.put("/api/cert-distribuce", json={"url": "https://novy/api",
                                            "heslo": "tajne-heslo",
                                            "intervalHodin": 12,
                                            "zapnuto": False})
    assert r.status_code == 200, r.text
    assert "tajne-heslo" not in r.text

    d = c.get("/api/cert-distribuce").json()
    assert d["nastaveni"]["url"] == "https://novy/api"
    assert d["nastaveni"]["intervalHodin"] == 12
    assert d["nastaveni"]["hesloNastaveno"] is True
    assert d["filtr"] == {"ico": ICO, "sluzba": SLUZBA}


def test_api_vyzaduje_klic_na_internim_rozhrani(prostredi, monkeypatch):
    monkeypatch.setattr(cfg, "CERT_API_KEY", "tajny-klic", raising=False)
    c = TestClient(app)
    assert c.get("/internal/v1/certifikat/distribuce").status_code == 401
    assert c.get("/internal/v1/certifikat/distribuce",
                 headers={"X-Api-Key": "tajny-klic"}).status_code == 200


def test_stav_zaznamena_chybu_i_uspech(prostredi, monkeypatch):
    """Stav poslední kontroly se zapisuje, aby bylo z čeho hlásit problém."""
    from sez_api.app import _distribuce_kolo

    _podvrhni_api(monkeypatch, [], status=500)
    assert _distribuce_kolo()["akce"] == "chyba"
    assert cd.stav()["posledniChyba"]

    _podvrhni_api(monkeypatch, [_zapis(_vyrob_pfx(platny_do_dnu=90))])
    zprava = _distribuce_kolo(vynutit=True)
    assert zprava["nasazeno"] is True
    assert cd.stav()["posledniChyba"] is None
    assert cd.stav()["posledniNasazeni"]["certifikat"]["serialNumber"]


def test_kolo_respektuje_interval(prostredi, monkeypatch):
    from sez_api.app import _distribuce_kolo

    _podvrhni_api(monkeypatch, [_zapis(_vyrob_pfx(platny_do_dnu=90))])
    assert _distribuce_kolo()["nasazeno"] is True
    # Druhé kolo hned po prvním se má přeskočit – distribuce dostane jeden
    # dotaz za interval, ne jeden za probuzení plánovače.
    assert _distribuce_kolo()["akce"] == "preskoceno"


def test_planovac_bezi_i_s_vypnutou_kontrolou(prostredi):
    """Vlákno musí běžet i při vypnuté kontrole – nastavení se čte při každém
    probuzení, takže zapnutí z GUI se projeví ve všech workerech bez restartu.
    Kdyby se vlákno startovalo jen při zapnuté kontrole, běželo by po zapnutí
    jen v tom workeru, který požadavek obsloužil."""
    from sez_api import app as app_mod

    cd.uloz_nastaveni({"zapnuto": False})
    try:
        app_mod._distribuce_start()
        assert app_mod._distribuce_vlakno.is_alive()
        # Opakované spuštění nesmí založit druhé vlákno.
        prvni = app_mod._distribuce_vlakno
        app_mod._distribuce_start()
        assert app_mod._distribuce_vlakno is prvni
    finally:
        app_mod._distribuce_stop_planovac()
    assert not app_mod._distribuce_vlakno.is_alive()


def test_uloziste_se_nasazenim_neprestehuje(tmp_path, monkeypatch):
    """Regrese: nasazení přepisuje PROD_P12_PATH na cestu DO úložiště. Když se
    z ní adresář úložiště odvozoval, zanořil se po každém nasazení o úroveň
    (certstore/certstore/…) – rozpadla se historie, rollback i sdílený stav
    distribuce mezi workery."""
    monkeypatch.setattr(cfg, "CERT_STORE_DIR", "", raising=False)
    monkeypatch.setattr(cfg, "CERT_STORE_ZAKLAD", str(tmp_path / "homolka.pfx"),
                        raising=False)
    monkeypatch.setattr(cfg, "PROD_P12_PATH", str(tmp_path / "homolka.pfx"),
                        raising=False)
    puvodni = cfg.cert_store_dir()
    assert puvodni == str(tmp_path / "certstore")

    cfg.PROD_P12_PATH = str(tmp_path / "certstore" / "prod.p12")
    assert cfg.cert_store_dir() == puvodni


def test_gui_obsahuje_panel_distribuce(prostredi):
    body = TestClient(app).get("/").text
    for marker in ["Automatická aktualizace", "cdUlozit()", "/api/cert-distribuce"]:
        assert marker in body, f"GUI neobsahuje: {marker}"
