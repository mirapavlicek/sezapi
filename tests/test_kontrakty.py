"""
Offline testy kontraktů klienta proti veřejné dokumentaci (swagger).

Bez síťové závislosti – používá se falešný SEZClient, který jen zaznamenává
volání (metoda, cesta, parametry). Ověřuje opravy z revize 2. 7. 2026:

  - Terminologie: ConceptMap/$translate posílá sourceCode/targetSystem
    (dle swaggeru v1.0.5 i v1.1.0), nikoli code/target.
  - Terminologie v1.1.0: GET /manifest.
  - EZCAValidace v1.0.0: POST /ezcaValidace/api/v1/dokumenty/validate.
  - SZZ v2: HPV screening děložního hrdla na cestě se dvěma "D"
    (karcinomDDeloznihoHrdlaHpv) + alias s jedním "D".
  - ELP v1: číselníky GET /api/v1/ciselniky.

Spuštění:  python3 -m pytest tests/test_kontrakty.py -v
"""

import pytest

from sez_api.client import ELP, EZCAValidace, SZZv2, Terminologie


class _FakeResp:
    status_code = 200
    text = "{}"

    def json(self):
        return {}


class _FakeConfig:
    GATEWAY = "https://gw.example"


class _FakeClient:
    """Zaznamenává volání místo HTTP requestů."""

    def __init__(self):
        self.config = _FakeConfig()
        self.calls = []

    def _record(self, method, path, **kw):
        self.calls.append({"method": method, "path": path, **kw})
        return _FakeResp()

    # nízkoúrovňové API použité Terminologií
    def _request(self, method, path, **kw):
        return self._record(method, path, **kw)

    # vysokoúrovňové API použité moduly
    def get(self, path, params=None, timeout=None):
        return self._record("GET", path, params=params)

    def post(self, path, body=None, timeout=None):
        return self._record("POST", path, body=body)

    def put(self, path, body=None, params=None, **kw):
        return self._record("PUT", path, body=body, params=params)

    def patch(self, path, body=None, params=None, **kw):
        return self._record("PATCH", path, body=body, params=params)

    @property
    def last(self):
        return self.calls[-1]


# --- HTTP hlavičky dle API endpointy (aktualizace 17. 7. 2026) ---------------

def test_user_agent_dle_pozadovaneho_formatu():
    """API endpointy (21. 7. 2026): User-Agent 'název-aplikace/verze
    (prostředí; výrobceSW)' – POVINNÝ od 1. 9. 2026; prostředí musí být
    hodnota 'Test' nebo 'Prod'."""
    import re
    from sez_api.client import SEZClient
    ua = SEZClient.user_agent()
    assert re.fullmatch(r"[\w.-]+/[\w.]+ \((Test|Prod); [^)]+\)", ua), ua
    import sez_api
    assert f"sez-api/{sez_api.__version__}" in ua


def test_user_agent_prostredi_test_nebo_prod():
    """Regrese: dřív se posílalo T2/PROD, dokumentace vyžaduje Test/Prod."""
    from sez_api.client import SEZClient, SEZConfig
    puvodni = getattr(SEZConfig, "ENVIRONMENT", "T2")
    try:
        for env, ocekavano in (("T2", "Test"), ("T2_CMS", "Test"),
                                ("PROD", "Prod"), ("PROD_CMS", "Prod"),
                                ("NEZNAME", "Test")):
            SEZConfig.ENVIRONMENT = env
            assert f"({ocekavano};" in SEZClient.user_agent(), env
    finally:
        SEZConfig.ENVIRONMENT = puvodni


def test_iris_objectscript_posila_user_agent():
    """Referenční IRIS třídy musí hlavičku posílat také – %Net.HttpRequest
    jinak doplní vlastní 'Mozilla/4.0 (compatible; ...)', které formátu
    User-Agent podle API endpointy nevyhovuje."""
    import re
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "docs/analytics/src"
    config = (src / "cls/SEZ/API/Config.cls").read_text(encoding="utf-8")
    http = (src / "cls/SEZ/API/HttpClient.cls").read_text(encoding="utf-8")
    csp = (src / "csp/SEZAPI.csp").read_text(encoding="utf-8")

    assert "ClassMethod UserAgent()" in config
    # Každé sestavení %Net.HttpRequest musí hlavičku nastavit.
    for jmeno, kod in (("Config.cls", config), ("HttpClient.cls", http)):
        pocet_req = kod.count("##class(%Net.HttpRequest).%New()")
        pocet_ua = kod.count('SetHeader("User-Agent"')
        assert pocet_ua >= pocet_req, f"{jmeno}: {pocet_ua} UA / {pocet_req} req"
    # Ovládací panel v CSP zobrazuje efektivní hodnotu hlavičky.
    assert "##class(SEZ.API.Config).UserAgent()" in csp

    # Formát sestavovaný v ObjectScriptu odpovídá požadovanému vzoru.
    def _param(nazev, default=""):
        m = re.search(rf'Parameter {nazev} = "([^"]*)"', config)
        return m.group(1) if m else default

    ua = "{}/{} ({}; {})".format(_param("APPNAME"), _param("APPVERSION"),
                                 "Test", _param("VENDOR"))
    assert re.fullmatch(r"[\w.-]+/[\w.]+ \((Test|Prod); [^)]+\)", ua), ua


def test_iris_generator_user_agent_prijima_stejne_hlavicky_jako_python():
    """Samostatný generátor SEZ.API.UserAgent musí uznávat právě ty hlavičky,
    které projdou i v Pythonu – včetně volitelné poznámky za výrobcem."""
    import re
    from pathlib import Path
    zdroj = (Path(__file__).resolve().parents[1]
             / "docs/analytics/src/cls/SEZ/API/UserAgent.cls").read_text(encoding="utf-8")
    for clen in ("ClassMethod Dej(", "ClassMethod Sestav(", "ClassMethod Validuj(",
                 "ClassMethod Token(", "ClassMethod Komentar(", "ClassMethod Prostredi("):
        assert clen in zdroj, clen

    m = re.search(r'Parameter PATTERN = "([^"]+)"', zdroj)
    assert m, "PATTERN nenalezen"
    vzor = re.compile(m.group(1))

    from sez_api.client import SEZClient
    assert vzor.match(SEZClient.user_agent()), SEZClient.user_agent()
    for platna in ("nis-kz/3.4.1 (Prod; Krajska zdravotni a.s.)",
                    "sez-api-iris/1.0.0 (Test; Vyrobce; Nasazeno u ABC)"):
        assert vzor.match(platna), platna
    for neplatna in ("Mozilla/4.0 (compatible; InterSystems IRIS;)",
                      "nis-kz/1.0 (T2; KZ)", "nis kz/1.0 (Test; KZ)", "nis-kz/1.0"):
        assert not vzor.match(neplatna), neplatna


def test_generovany_iris_klient_posila_user_agent():
    """Generátor ObjectScript klienta (sez_api.iris_codegen) musí do volání
    vkládat User-Agent i X-Correlation-Id."""
    from sez_api.iris_codegen import gen_client_class
    kod = gen_client_class("SEZ", "KRP", [])
    assert 'SetHeader("User-Agent", ..UserAgent())' in kod
    assert 'SetHeader("X-Correlation-Id"' in kod
    assert "Method UserAgent() As %String" in kod
    assert 'Property Prostredi As %String(VALUELIST = ",Test,Prod")' in kod


def test_traceparent_odpovida_w3c_specifikaci():
    """traceparent je volitelný, ale pokud se pošle, musí odpovídat W3C
    Trace Context: 00-<32 hex>-<16 hex>-<flags>, id nesmí být nulová."""
    import re
    from sez_api.client import SEZClient
    tp = SEZClient.traceparent()
    m = re.fullmatch(r"00-([0-9a-f]{32})-([0-9a-f]{16})-0[01]", tp)
    assert m, tp
    assert m.group(1) != "0" * 32 and m.group(2) != "0" * 16


def test_traceparent_se_posila_jen_po_zapnuti():
    from sez_api import config as cfg
    from sez_api.client import SEZClient

    class _FakeAuth:
        def build_assertion(self, extra_headers=None):
            return "assertion"

    c = SEZClient.__new__(SEZClient)
    c.auth = _FakeAuth()
    puvodni = cfg.SEZ_SEND_TRACEPARENT
    try:
        cfg.SEZ_SEND_TRACEPARENT = False
        assert "traceparent" not in c._headers()
        cfg.SEZ_SEND_TRACEPARENT = True
        assert c._headers()["traceparent"].startswith("00-")
    finally:
        cfg.SEZ_SEND_TRACEPARENT = puvodni


def test_neposilame_deprecated_hlavicky():
    """X-Request-Id je deprecated a X-Manufacturer-* se nezpracovávají."""
    from sez_api.client import SEZClient

    class _FakeAuth:
        def build_assertion(self, extra_headers=None):
            return "assertion"

    c = SEZClient.__new__(SEZClient)
    c.auth = _FakeAuth()
    h = c._headers()
    for zakazana in ("X-Request-Id", "X-Manufacturer-Company",
                      "X-Manufacturer-Product"):
        assert zakazana not in h


def test_user_agent_lze_prenastavit_konfiguraci():
    from sez_api import config as cfg
    from sez_api.client import SEZClient
    puvodni = (cfg.SEZ_APP_NAME, cfg.SEZ_VENDOR, cfg.SEZ_UA_NOTE)
    try:
        cfg.SEZ_APP_NAME, cfg.SEZ_VENDOR, cfg.SEZ_UA_NOTE = (
            "MojeAplikace", "VyrobceXYZ", "Nasazeno u ABC")
        ua = SEZClient.user_agent()
        assert ua.startswith("MojeAplikace/")
        assert ua.endswith("(Test; VyrobceXYZ; Nasazeno u ABC)"), ua
    finally:
        cfg.SEZ_APP_NAME, cfg.SEZ_VENDOR, cfg.SEZ_UA_NOTE = puvodni


def test_gateway_hlavicky_obsahuji_user_agent_a_correlation_id():
    from sez_api.client import SEZClient

    class _FakeAuth:
        def build_assertion(self, extra_headers=None):
            return "assertion"

    c = SEZClient.__new__(SEZClient)
    c.auth = _FakeAuth()
    h = c._headers()
    assert h["User-Agent"].startswith("sez-api/")
    # X-Correlation-Id: UUID (v4+), povinné od 1. 1. 2027
    import uuid as _uuid
    _uuid.UUID(h["X-Correlation-Id"])


# --- Terminologie ----------------------------------------------------------

class _PrefixResp(_FakeResp):
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text

    def json(self):
        return {}


class _PrefixClient(_FakeClient):
    """Simuluje TermX, který na daných prefixech vrací 406 not-supported."""

    def __init__(self, spatne_prefixy):
        super().__init__()
        self.spatne = spatne_prefixy

    def _request(self, method, path, **kw):
        self.calls.append({"method": method, "path": path, **kw})
        for p in self.spatne:
            if path.startswith(p + "/"):
                return _PrefixResp(
                    406, '{"resourceType":"OperationOutcome","issue":[{"details":'
                          '{"text":"could not find matching enabled interaction '
                          'for: GET /fhir/ValueSet"}}]}')
        return _PrefixResp(200)


def test_termx_gateway_prefix_bez_fhir_dle_swaggeru():
    """Nový TermX (v1.1.0): operace jsou přímo pod /terminologie – klient
    musí primárně volat BEZ /fhir a prefix si zapamatovat."""
    c = _PrefixClient(spatne_prefixy=["/terminologie/fhir"])
    t = Terminologie(c)
    r = t.valueset_expand(url="http://example/vs")
    assert r.status_code == 200
    assert c.calls[0]["path"] == "/terminologie/ValueSet/$expand"
    assert t._gateway_prefix == "/terminologie"
    # další volání už jde rovnou na zapamatovaný prefix (1 request)
    n = len(c.calls)
    t.valueset_expand(url="http://example/vs")
    assert len(c.calls) == n + 1


def test_termx_gateway_fallback_na_legacy_fhir():
    """Regrese: starší nasazení TermX routuje jen /terminologie/fhir –
    při 406 na novém prefixu klient automaticky přejde na legacy."""
    c = _PrefixClient(spatne_prefixy=["/terminologie"])
    # pozor: /terminologie/fhir/... začíná také na /terminologie/ –
    # simulace musí odmítat jen cesty bez /fhir
    c.spatne = []

    def _req(method, path, **kw):
        c.calls.append({"method": method, "path": path, **kw})
        if path.startswith("/terminologie/fhir/"):
            return _PrefixResp(200)
        return _PrefixResp(406, "could not find matching enabled interaction")

    c._request = _req
    t = Terminologie(c)
    r = t.codesystem_lookup(code="11506-3", system="http://loinc.org")
    assert r.status_code == 200
    assert [x["path"] for x in c.calls] == [
        "/terminologie/CodeSystem/$lookup",
        "/terminologie/fhir/CodeSystem/$lookup",
    ]
    assert t._gateway_prefix == "/terminologie/fhir"

def test_translate_posila_source_code_dle_swaggeru():
    c = _FakeClient()
    t = Terminologie(c)
    t.conceptmap_translate(code="11506-3", system="http://loinc.org",
                           target="http://example/cs")
    call = c.last
    assert call["path"].endswith("/ConceptMap/$translate")
    params = call["params"]
    assert params["sourceCode"] == "11506-3"
    assert params["targetSystem"] == "http://example/cs"
    # nespecifikované parametry se nesmí posílat
    assert "code" not in params
    assert "target" not in params
    assert "source" not in params


def test_translate_prima_nativni_parametry():
    c = _FakeClient()
    t = Terminologie(c)
    t.conceptmap_translate(sourceCode="A", targetSystem="B", targetCode="C",
                           id="map-1")
    call = c.last
    assert "/ConceptMap/map-1/$translate" in call["path"]
    assert call["params"]["sourceCode"] == "A"
    assert call["params"]["targetSystem"] == "B"
    assert call["params"]["targetCode"] == "C"


def test_manifest_v_1_1_0():
    c = _FakeClient()
    t = Terminologie(c)
    t.manifest(lastUpdate="2026-01-01")
    call = c.last
    assert call["method"] == "GET"
    assert call["path"].endswith("/manifest")
    assert call["params"] == {"lastUpdate": "2026-01-01"}


# --- EZCA Validace ---------------------------------------------------------

def test_ezca_validace_online():
    c = _FakeClient()
    v = EZCAValidace(c)
    v.validate_online("doc-1", "ab" * 64)
    call = c.last
    assert call["method"] == "POST"
    assert call["path"] == "/ezcaValidace/api/v1/dokumenty/validate"
    assert call["body"]["typValidace"] == "online"
    assert call["body"]["typDokumentu"] == "elp"
    assert call["body"]["dokumentId"] == "doc-1"
    assert call["body"]["dokumentHash"] == "ab" * 64


def test_ezca_validace_offline():
    c = _FakeClient()
    v = EZCAValidace(c)
    v.validate_offline("doc-2", "2026-05-04", "2013-03-03", "SVATÁ")
    body = c.last["body"]
    assert body["typValidace"] == "offline"
    assert body["datumVystaveni"] == "2026-05-04"
    assert body["datumNarozeni"] == "2013-03-03"
    assert body["prijmeni"] == "SVATÁ"


# --- SZZ v2 – HPV screening (dvojité D dle swaggeru) ------------------------

def test_szz2_hpv_screening_cesta_se_dvema_d():
    c = _FakeClient()
    szz2 = SZZv2(c)
    szz2.screening("karcinomDDeloznihoHrdlaHpv")["vytvor"]({"rid": "1"})
    assert c.last["path"] == \
        "/sdilenyZdravotniZaznam/api/v2/screeningy/karcinomDDeloznihoHrdlaHpv"


def test_szz2_hpv_screening_alias_s_jednim_d():
    c = _FakeClient()
    szz2 = SZZv2(c)
    szz2.screening("karcinomDeloznihoHrdlaHpv")["vyhledat"]({"rid": "1"})
    assert c.last["path"] == \
        "/sdilenyZdravotniZaznam/api/v2/screeningy/karcinomDDeloznihoHrdlaHpv/vyhledat"


def test_szz2_neznamy_screening_vyhodi_chybu():
    szz2 = SZZv2(_FakeClient())
    with pytest.raises(ValueError):
        szz2.screening("neexistujici")


# --- ELP v1 – číselníky ------------------------------------------------------

def test_elp_v1_ciselniky():
    c = _FakeClient()
    elp = ELP(c)
    elp.ciselniky()
    assert c.last["path"] == "/elektronickePosudky/api/v1/ciselniky"
    elp.ciselnik_polozky("harmonizovane-kody")
    assert c.last["path"] == \
        "/elektronickePosudky/api/v1/ciselniky/harmonizovane-kody/polozky"
