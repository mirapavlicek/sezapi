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
    """API endpointy (17. 7. 2026): User-Agent 'název-aplikace/verze
    (prostředí; výrobceSW)' – doporučený od 9/2026, POVINNÝ od 1. 1. 2027."""
    import re
    from sez_api.client import SEZClient
    ua = SEZClient.user_agent()
    assert re.fullmatch(r"[\w.-]+/[\w.]+ \([^;]+; [^)]+\)", ua), ua
    import sez_api
    assert f"sez-api/{sez_api.__version__}" in ua


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
