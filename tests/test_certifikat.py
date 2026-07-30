"""
Testy API pro převzetí ostrého certifikátu z centrální distribuce.

Bez síťové závislosti – certifikáty se generují v testu (self-signed PKCS#12),
sestavení klienta a volání brány je nahrazeno atrapou.

Spuštění:  python3 -m pytest tests/test_certifikat.py -v
"""

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from starlette.testclient import TestClient

from sez_api import config as cfg
from sez_api.app import app
from sez_api.certstore import CertChyba, CertStore, dekoduj_pfx, zkontroluj_pfx


def _vyrob_pfx(heslo: str = "tajne", *, cn: str = "NIS Krajska zdravotni",
               platny_od_dnu: int = -1, platny_do_dnu: int = 365) -> bytes:
    """Self-signed PKCS#12 s privátním klíčem – stejná struktura jako z EZCA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jmeno = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Krajska zdravotni a.s."),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
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


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture
def store_dir(tmp_path, monkeypatch):
    """Izolované úložiště certifikátů + prostředí PROD s atrapou klienta."""
    monkeypatch.setattr(cfg, "CERT_STORE_DIR", str(tmp_path / "certs"), raising=False)
    monkeypatch.setattr(cfg, "CERT_API_KEY", "", raising=False)
    monkeypatch.setattr(cfg, "INTERNAL_API_KEY", "", raising=False)
    # Nasazení propisuje certifikát do globální konfigurace. Bez obnovení by
    # další testy hlásily funkční PROD spojení proti certifikátu ve smazaném
    # tmp_path a sada by závisela na pořadí testů.
    monkeypatch.setattr(cfg, "ENV_CREDENTIALS",
                        {k: dict(v) for k, v in cfg.ENV_CREDENTIALS.items()},
                        raising=False)
    for atr in ("PROD_P12_PATH", "PROD_P12_PASSWORD",
                "PROD_CLIENT_ID", "PROD_CERT_UID"):
        monkeypatch.setattr(cfg, atr, getattr(cfg, atr, ""), raising=False)
    return tmp_path / "certs"


@pytest.fixture
def klient_atrapa(monkeypatch):
    """Nahrazuje sestavení PROD klienta – ověří se, že se po nasazení volá."""
    stav = {"postaveno": 0, "reset": 0}

    class _Auth:
        _kid = "kid-z-certifikatu"

        def build_assertion(self, extra_headers=None):
            return "hlavicka.telo.podpis"

        def cleanup(self):
            return None

    class _Resp:
        status_code = 200

        def json(self):
            return {"odpovedData": {}}

    class _KRP:
        def ciselnik(self, nazev, ucel="LECBA"):
            return _Resp()

    def _build():
        stav["postaveno"] += 1
        return {"krp": _KRP(), "auth": _Auth(), "client": object(),
                "cert": {"subject": "CN=NIS", "zdroj": "distribuce"}}

    monkeypatch.setattr("sez_api.app._build_internal_prod", _build)
    monkeypatch.setattr("sez_api.app._internal_state", {})
    return stav


# --- validace vstupu -------------------------------------------------------

def test_dekodovani_toleruje_data_url_a_zalomeni():
    pfx = _vyrob_pfx()
    b64 = _b64(pfx)
    zabalene = "data:application/x-pkcs12;base64," + "\n".join(
        b64[i:i + 64] for i in range(0, len(b64), 64))
    assert dekoduj_pfx(zabalene) == pfx


def test_dekodovani_odmitne_nesmysl():
    for vstup in ("", "   ", "tohle není base64 ###"):
        with pytest.raises(CertChyba):
            dekoduj_pfx(vstup)


def test_kontrola_odmitne_spatne_heslo():
    pfx = _vyrob_pfx(heslo="spravne")
    with pytest.raises(CertChyba, match="nelze otevřít"):
        zkontroluj_pfx(pfx, "chybne")


def test_kontrola_odmitne_expirovany_certifikat():
    pfx = _vyrob_pfx(platny_od_dnu=-400, platny_do_dnu=-10)
    with pytest.raises(CertChyba, match="vypršel"):
        zkontroluj_pfx(pfx, "tajne")
    # S vynucením projde (nasazení v předstihu / diagnostika).
    assert zkontroluj_pfx(pfx, "tajne", vynutit=True)["dnyDoExpirace"] < 0


def test_kontrola_odmitne_certifikat_platny_v_budoucnu():
    pfx = _vyrob_pfx(platny_od_dnu=10, platny_do_dnu=400)
    with pytest.raises(CertChyba, match="začíná platit"):
        zkontroluj_pfx(pfx, "tajne")


def test_kontrola_vraci_popis_certifikatu():
    popis = zkontroluj_pfx(_vyrob_pfx(cn="NIS Test"), "tajne")
    assert "CN=NIS Test" in popis["subject"]
    assert popis["dnyDoExpirace"] > 300
    assert len(popis["fingerprintSha256"]) == 64
    assert popis["kid"]


# --- úložiště --------------------------------------------------------------

def test_store_uklada_s_pravy_0600_a_zalohuje(tmp_path):
    store = CertStore(tmp_path, "PROD")
    prvni = _vyrob_pfx(cn="Prvni")
    store.uloz(prvni, "tajne", popis=zkontroluj_pfx(prvni, "tajne"),
               client_id="25488627_NIS")

    assert store.existuje()
    assert oct(store.pfx_path.stat().st_mode)[-3:] == "600"
    assert oct(store.pass_path.stat().st_mode)[-3:] == "600"
    assert store.heslo() == "tajne"
    assert store.info()["clientId"] == "25488627_NIS"
    assert store.historie() == []

    druhy = _vyrob_pfx(cn="Druhy", heslo="jine")
    store.uloz(druhy, "jine", popis=zkontroluj_pfx(druhy, "jine"))
    assert store.pfx_path.read_bytes() == druhy
    assert store.heslo() == "jine"
    historie = store.historie()
    assert len(historie) == 1
    assert "CN=Prvni" in historie[0]["subject"]


def test_store_rollback_vrati_predchozi(tmp_path):
    store = CertStore(tmp_path, "PROD")
    prvni = _vyrob_pfx(cn="Prvni")
    store.uloz(prvni, "tajne", popis=zkontroluj_pfx(prvni, "tajne"))
    druhy = _vyrob_pfx(cn="Druhy", heslo="jine")
    store.uloz(druhy, "jine", popis=zkontroluj_pfx(druhy, "jine"))

    meta = store.rollback()
    assert "CN=Prvni" in meta["subject"]
    assert store.pfx_path.read_bytes() == prvni
    assert store.heslo() == "tajne"


def test_store_rollback_bez_historie_selze(tmp_path):
    with pytest.raises(CertChyba, match="prázdná"):
        CertStore(tmp_path, "PROD").rollback()


# --- API -------------------------------------------------------------------

def test_api_nasadi_certifikat_a_prestavi_klienta(store_dir, klient_atrapa):
    pfx = _vyrob_pfx(cn="NIS Ostry")
    c = TestClient(app)
    r = c.post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(pfx), "password": "tajne",
        "clientId": "25488627_NIS", "certUid": "85cf28c4-c190",
        "prostredi": "PROD", "zdroj": "centralni-distribuce",
        "poznamka": "obnova 2026",
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] is True and d["aktivovano"] is True
    assert "CN=NIS Ostry" in d["certifikat"]["subject"]
    assert d["certifikat"]["clientId"] == "25488627_NIS"
    assert d["certifikat"]["certUid"] == "85cf28c4-c190"
    assert d["certifikat"]["zdroj"] == "centralni-distribuce"
    assert d["predchozi"] is None
    # Ověření po nasazení: podpis JWT a volání brány.
    assert d["overeni"]["podpisJwt"] is True
    assert d["overeni"]["volaniBrany"]["ok"] is True
    # Klient se po nasazení skutečně přestavěl.
    assert klient_atrapa["postaveno"] >= 1

    # Heslo se nikde nevrací.
    assert "tajne" not in r.text

    ulozeny = store_dir / "prod.p12"
    assert ulozeny.read_bytes() == pfx


def test_api_pouze_overit_neuklada(store_dir, klient_atrapa):
    r = TestClient(app).post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(_vyrob_pfx()), "password": "tajne",
        "pouzeOverit": True,
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] is True and d["aktivovano"] is False
    assert not (store_dir / "prod.p12").exists()


def test_api_odmitne_expirovany_certifikat(store_dir, klient_atrapa):
    r = TestClient(app).post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(_vyrob_pfx(platny_od_dnu=-400, platny_do_dnu=-1)),
        "password": "tajne",
    })
    assert r.status_code == 422, r.text
    assert "vypršel" in r.json()["detail"]
    assert not (store_dir / "prod.p12").exists()


def test_api_odmitne_spatne_heslo(store_dir, klient_atrapa):
    r = TestClient(app).post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(_vyrob_pfx(heslo="spravne")), "password": "chybne",
    })
    assert r.status_code == 422
    assert "nelze otevřít" in r.json()["detail"]


def test_api_vyzaduje_klic_kdyz_je_nastaven(store_dir, klient_atrapa, monkeypatch):
    monkeypatch.setattr(cfg, "CERT_API_KEY", "tajny-klic", raising=False)
    telo = {"pfxBase64": _b64(_vyrob_pfx()), "password": "tajne", "pouzeOverit": True}
    c = TestClient(app)

    assert c.post("/internal/v1/certifikat", json=telo).status_code == 401
    assert c.post("/internal/v1/certifikat", json=telo,
                  headers={"X-Api-Key": "spatny"}).status_code == 401
    assert c.post("/internal/v1/certifikat", json=telo,
                  headers={"X-Api-Key": "tajny-klic"}).status_code == 200


def test_api_info_a_historie_a_rollback(store_dir, klient_atrapa):
    c = TestClient(app)
    prvni, druhy = _vyrob_pfx(cn="Prvni"), _vyrob_pfx(cn="Druhy")
    for pfx in (prvni, druhy):
        assert c.post("/internal/v1/certifikat", json={
            "pfxBase64": _b64(pfx), "password": "tajne"}).status_code == 200

    info = c.get("/internal/v1/certifikat").json()
    assert "CN=Druhy" in info["subject"]
    assert info["dnyDoExpirace"] > 300

    historie = c.get("/internal/v1/certifikat/historie").json()
    assert len(historie["historie"]) == 1
    assert "CN=Prvni" in historie["historie"][0]["subject"]

    r = c.post("/internal/v1/certifikat/rollback")
    assert r.status_code == 200, r.text
    assert "CN=Prvni" in r.json()["certifikat"]["subject"]
    assert "CN=Prvni" in c.get("/internal/v1/certifikat").json()["subject"]


def test_api_rollback_pri_nepouzitelnem_certifikatu(store_dir, monkeypatch):
    """Když s novým certifikátem nelze sestavit klienta, vrátí se předchozí,
    aby provoz nezůstal bez funkčního certifikátu."""
    monkeypatch.setattr("sez_api.app._internal_state", {})
    stav = {"selhat": False}

    class _Auth:
        _kid = "kid"

        def build_assertion(self, extra_headers=None):
            return "a.b.c"

        def cleanup(self):
            return None

    def _build():
        if stav["selhat"]:
            raise RuntimeError("privátní klíč nelze použít")
        return {"krp": None, "auth": _Auth(), "client": object(), "cert": {}}

    monkeypatch.setattr("sez_api.app._build_internal_prod", _build)

    c = TestClient(app)
    dobry = _vyrob_pfx(cn="Dobry")
    assert c.post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(dobry), "password": "tajne",
        "overitVolanim": False}).status_code == 200

    stav["selhat"] = True
    spatny = _vyrob_pfx(cn="Spatny")
    r = c.post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(spatny), "password": "tajne", "overitVolanim": False})
    assert r.status_code == 502, r.text
    assert "Předchozí certifikát byl obnoven" in r.json()["detail"]

    # V provozu zůstal původní certifikát.
    assert (store_dir / "prod.p12").read_bytes() == dobry


def test_nasazeny_certifikat_je_pouzitelny_pro_klienta(store_dir, klient_atrapa):
    """Nejpodstatnější kontrola: z certifikátu převzatého přes API se skutečně
    sestaví autentizace (načtení klíče, podpis JWT) – bez sítě."""
    from sez_api.app import _credentials_pro
    from sez_api.client import SEZAuth, SEZConfig

    pfx = _vyrob_pfx(cn="NIS Ostry")
    r = TestClient(app).post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(pfx), "password": "tajne",
        "clientId": "25488627_NIS", "overitVolanim": False})
    assert r.status_code == 200, r.text

    creds = _credentials_pro("PROD")
    assert creds["p12_path"] == str(store_dir / "prod.p12")
    assert creds["p12_password"] == "tajne"
    assert creds["client_id"] == "25488627_NIS"

    icfg = SEZConfig()
    icfg.TOKEN_AUDIENCE = "https://jsu.example/connect/token"
    auth = SEZAuth(client_id=creds["client_id"], p12_path=creds["p12_path"],
                   p12_password=creds["p12_password"],
                   cert_uid=creds.get("cert_uid") or None, config=icfg)
    try:
        assertion = auth.build_assertion()
        assert assertion.count(".") == 2, assertion
        assert "CN=NIS Ostry" in auth._signing_cert.subject.rfc4514_string()
    finally:
        auth.cleanup()


def test_ostatni_workery_prevezmou_novy_certifikat(store_dir, klient_atrapa):
    """Aplikace běží ve více procesech a nasazení přestaví klienta jen v tom,
    který request obsloužil. Ostatní musí výměnu poznat podle úložiště – jinak
    by až do restartu jely se starým certifikátem."""
    from sez_api.app import _internal_modules, _internal_state

    c = TestClient(app)
    assert c.post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(_vyrob_pfx(cn="Prvni")), "password": "tajne",
        "overitVolanim": False}).status_code == 200

    # Stav "cizího" workeru: klient postavený nad původním certifikátem.
    _internal_modules()
    postaveno = klient_atrapa["postaveno"]

    # Bez změny úložiště se klient nepřestavuje (žádný stat navíc za request).
    _internal_modules()
    assert klient_atrapa["postaveno"] == postaveno

    # Výměna certifikátu mimo tento proces – zápis přímo do úložiště.
    druhy = _vyrob_pfx(cn="Druhy")
    store = CertStore(store_dir, "PROD")
    store.uloz(druhy, "tajne", popis=zkontroluj_pfx(druhy, "tajne"))

    _internal_modules()
    assert klient_atrapa["postaveno"] == postaveno + 1
    assert _internal_state["stamp"] == (store.pfx_path.stat().st_size,
                                        store.pfx_path.stat().st_mtime_ns)


def test_api_nezname_prostredi(store_dir, klient_atrapa):
    r = TestClient(app).post("/internal/v1/certifikat", json={
        "pfxBase64": _b64(_vyrob_pfx()), "password": "tajne",
        "prostredi": "NEEXISTUJE"})
    assert r.status_code == 422
    assert "Neznámé prostředí" in r.json()["detail"]
