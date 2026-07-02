"""
Testy IROP/NPO testovacího rámce – hodnocení dle metodiky (VYHOVUJE /
VYHOVUJE S VÝHRADAMI / NEVYHOVUJE), matice povinných scénářů a registr
scénářů dle Metodiky testování EHR fáze I.

Offline – bez připojení k T2 (endpointy vyžadující klienta vrací 503).
Spuštění:  python3 -m pytest tests/test_irop.py -v
"""

from starlette.testclient import TestClient

from sez_api.app import (
    app,
    IROP_SCENARIOS,
    IROP_POVINNE_SCENARE,
    _irop_adresat,
    _irop_attach_req_resp,
    _irop_hodnoceni_scenare,
    _irop_hodnoceni_celkove,
    _irop_obs2,
    _irop_tech4,
    _irop_tech5,
    _irop_tech6,
)


class _FakeResp:
    def __init__(self, data, status=200):
        self._d = data
        self.status_code = status
        self.headers = {"content-type": "application/json"}
        self.url = "https://example/api"
        self.text = str(data)

    def json(self):
        return self._d


def _client():
    return TestClient(app)


# --- hodnocení dle kapitoly „Hodnocení a výsledky" --------------------------

def _step(passed=True, note=None):
    s = {"name": "krok", "passed": passed, "status": 200, "elapsed_ms": 1,
         "data": None, "error": None}
    if note:
        s["note"] = note
    return s


def test_hodnoceni_vyhovuje():
    assert _irop_hodnoceni_scenare({"steps": [_step(), _step()]}) == "VYHOVUJE"


def test_hodnoceni_s_vyhradami():
    r = {"steps": [_step(), _step(note="nepodstatná odchylka")]}
    assert _irop_hodnoceni_scenare(r) == "VYHOVUJE S VÝHRADAMI"


def test_hodnoceni_nevyhovuje():
    assert _irop_hodnoceni_scenare({"steps": [_step(), _step(passed=False)]}) \
        == "NEVYHOVUJE"


def test_hodnoceni_prazdne_nevyhovuje():
    assert _irop_hodnoceni_scenare({"steps": []}) == "NEVYHOVUJE"


def test_agregace_dle_metodiky():
    # všechny VYHOVUJE → VYHOVUJE
    assert _irop_hodnoceni_celkove(["VYHOVUJE", "VYHOVUJE"]) == "VYHOVUJE"
    # alespoň jedno s výhradami → S VÝHRADAMI
    assert _irop_hodnoceni_celkove(["VYHOVUJE", "VYHOVUJE S VÝHRADAMI"]) \
        == "VYHOVUJE S VÝHRADAMI"
    # alespoň jedno NEVYHOVUJE → NEVYHOVUJE (má přednost)
    assert _irop_hodnoceni_celkove(
        ["VYHOVUJE", "VYHOVUJE S VÝHRADAMI", "NEVYHOVUJE"]) == "NEVYHOVUJE"
    assert _irop_hodnoceni_celkove([]) == "NEVYHOVUJE"


# --- registr scénářů dle metodiky --------------------------------------------

def test_registr_obsahuje_scenare_dle_metodiky():
    """Scénáře z wiki: TS-TECH-1, 2A(=TS-TECH-2), 2B, 3, 5, 6, 8, 9,
    TS-OBS-1, TS-OBS-2."""
    for sid in ["TS-TECH-1", "TS-TECH-2", "TS-TECH-2B", "TS-TECH-3",
                "TS-TECH-5", "TS-TECH-6", "TS-TECH-8", "TS-TECH-9",
                "TS-OBS-1", "TS-OBS-2"]:
        assert sid in IROP_SCENARIOS, f"chybí scénář {sid}"


def test_matice_povinnych_scenaru():
    """Tabulka povinných scénářů dle kategorií žadatele (wiki)."""
    assert set(IROP_POVINNE_SCENARE) == {"A", "B", "ZZS"}
    a = IROP_POVINNE_SCENARE["A"]["ezd"]
    assert a["pacientsky-souhrn"] == ["TS-OBS-1", "TS-OBS-2"]
    assert a["obrazove-vysetreni"] == ["TS-OBS-1", "TS-OBS-2"]
    assert a["propousteci-zprava"] == ["TS-OBS-1", "TS-OBS-2"]
    assert a["vyjezd-zzs"] == ["TS-OBS-1"]
    b = IROP_POVINNE_SCENARE["B"]["ezd"]
    assert b["obrazove-vysetreni"] == ["TS-OBS-1"]
    assert "vyjezd-zzs" not in b
    zzs = IROP_POVINNE_SCENARE["ZZS"]["ezd"]
    assert zzs["vyjezd-zzs"] == ["TS-OBS-1", "TS-OBS-2"]
    assert zzs["pacientsky-souhrn"] == ["TS-OBS-1"]


# --- API endpointy ------------------------------------------------------------

def test_api_scenarios_list():
    r = _client().get("/api/irop/scenarios")
    assert r.status_code == 200
    ids = {s["id"] for s in r.json()}
    assert "TS-TECH-2B" in ids
    assert "TS-OBS-2" in ids


def test_api_povinne_scenare():
    r = _client().get("/api/irop/povinne-scenare")
    assert r.status_code == 200
    data = r.json()
    assert set(data["kategorie_zadatelu"]) == {"A", "B", "ZZS"}
    ezd = data["kategorie_ezd"]
    assert ezd["propousteci-zprava"]["ig"] == "hl7.fhir.cz.hdr"
    assert ezd["pacientsky-souhrn"]["ig_url"].endswith("/ps/")
    assert "444/2024" in ezd["vyjezd-zzs"]["legislativa"]


def test_api_protokol_bez_pripojeni_503():
    r = _client().post("/api/irop/protokol", json={})
    assert r.status_code == 503


# --- TS-TECH-4: Over s ID z číselníků (regrese HTTP 500) ----------------------

class _FakeRO:
    def __init__(self, over_status=200):
        self.over_calls = []
        self.over_status = over_status

    def sluzby_ez(self):
        return _FakeResp({"page": [
            {"id": 3, "kod": "DU", "nazev": "Dočasné úložiště"},
            {"id": 7, "kod": "SZZ", "nazev": "Sdílený zdravotní záznam"}],
            "totalCount": 2})

    def typy_dokumentaci(self):
        return _FakeResp({"page": [
            {"id": 11, "kod": "PZ", "nazev": "Propouštěcí zpráva"}],
            "totalCount": 1})

    def over(self, id_sluzby, id_typu, r1, h1, r2, h2):
        self.over_calls.append((id_sluzby, id_typu, r1, r2))
        if self.over_status != 200:
            return _FakeResp({"error": {"message": "Interní chyba backendu RO"}},
                             self.over_status)
        return _FakeResp({"stav": "Povoleno"})


def test_tech4_pouziva_id_z_ciselniku_ne_hardcoded():
    """Regrese: Over se dřív volal s natvrdo ID 1/5 → HTTP 500 z backendu RO."""
    ro = _FakeRO()
    r = _irop_tech4({}, {"ro": ro}, None)
    assert r["passed"] == r["total"] == 4
    assert _irop_hodnoceni_scenare(r) == "VYHOVUJE"
    # obě Over volání používají ID z číselníků (3=DÚ, 11=první typ)
    assert ro.over_calls == [
        (3, 11, "Pacient", "PoskytovatelZdravotnickychSluzeb"),
        (3, 11, "PoskytovatelZdravotnickychSluzeb", "ZdravotnickyPracovnik"),
    ]


def test_tech4_500_z_backendu_propise_abp_chybu():
    ro = _FakeRO(over_status=500)
    r = _irop_tech4({}, {"ro": ro}, None)
    over_steps = [s for s in r["steps"] if s["name"].startswith("Over")]
    assert all(not s["passed"] for s in over_steps)
    assert all(s["error"] == "Interní chyba backendu RO" for s in over_steps)
    assert _irop_hodnoceni_scenare(r) == "NEVYHOVUJE"


# --- TS-TECH-5: metadata/Provenance jen informativní --------------------------

class _FakeTermX:
    """Simuluje server dle swaggeru v1.1.0: /metadata a /Provenance 404."""

    def metadata(self):
        return _FakeResp({"resourceType": "OperationOutcome"}, 404)

    def valueset_search(self, **kw):
        return _FakeResp({"resourceType": "Bundle", "entry": [{}]})

    def valueset_expand(self, **kw):
        return _FakeResp({"resourceType": "ValueSet",
                          "expansion": {"contains": [{"code": "11506-3"},
                                                       {"code": "67781-5"}]}})

    def valueset_validate_code(self, **kw):
        return _FakeResp({"resourceType": "Parameters",
                          "parameter": [{"name": "result", "valueBoolean": True}]})

    def codesystem_lookup(self, **kw):
        return _FakeResp({"resourceType": "Parameters",
                          "parameter": [{"name": "display",
                                          "valueString": "Progress note"}]})

    def provenance_search(self, **kw):
        return _FakeResp({"resourceType": "OperationOutcome"}, 404)


# --- TS-TECH-6 / TS-OBS-2: adresát ≠ tvůrce (regrese DÚ E01001) ---------------

class _FakeDU:
    last_request_debug = None

    def __init__(self):
        self.zasilky = []

    def uloz_zasilku(self, z):
        self.zasilky.append(z)
        return _FakeResp({"id": f"z-{len(self.zasilky)}"})

    def vyhledej_zasilku(self, od, do, rid=None, **kw):
        return _FakeResp({"zasilka": [{"id": f"z-{len(self.zasilky)}"}]})

    def dej_zasilku(self, zid):
        return _FakeResp({"id": zid, "dokument": []})


def test_irop_adresat_nikdy_neshodny_s_tvurcem():
    """DÚ E01001: Zasilka.poskytovatel a Zasilka.adresat nesmí mít stejné IČO."""
    # výchozí: jiné testovací PZS
    assert _irop_adresat({}, "25488627") == "00064165"
    # tvůrce = výchozí adresát → přepne na dalšího kandidáta
    assert _irop_adresat({}, "00064165") == "00064203"
    # explicitní adresát se respektuje
    assert _irop_adresat({"ico_adresat": "00179906"}, "25488627") == "00179906"
    # explicitní adresát shodný s tvůrcem se ignoruje (jinak by DÚ vrátilo E01001)
    assert _irop_adresat({"ico_adresat": "25488627"}, "25488627") != "25488627"


def test_tech6_zasilka_ma_adresata_jineho_pzs():
    du = _FakeDU()
    r = _irop_tech6({"ico": "25488627"}, {"du": du}, None)
    assert r["passed"] == r["total"]
    z = du.zasilky[0]
    assert z["poskytovatel"] == "25488627"
    assert z["adresat"] == "00064165"
    assert z["adresat"] != z["poskytovatel"]


def test_obs2_zasilka_ma_adresata_jineho_pzs():
    du = _FakeDU()
    r = _irop_obs2({"ico": "25488627", "doc_type": "propousteci-zprava"},
                    {"du": du}, None)
    assert r["passed"] == r["total"]
    z = du.zasilky[0]
    assert z["adresat"] != z["poskytovatel"]
    # explicitní adresát z parametrů
    du2 = _FakeDU()
    _irop_obs2({"ico": "25488627", "ico_adresat": "00179906",
                "doc_type": "pacientsky-souhrn"}, {"du": du2}, None)
    assert du2.zasilky[0]["adresat"] == "00179906"


# --- request/response debug u každého kroku -----------------------------------

def test_kazdy_krok_ma_request_a_response():
    """Každý krok musí po _irop_attach_req_resp obsahovat 'request'
    (co se posílá) a 'response' (návratové hodnoty) pro debug."""
    result = {
        "steps": [
            # krok s HTTP voláním (debug z SEZClient.last_request_debug)
            {"name": "Over", "passed": True, "status": 200, "elapsed_ms": 5,
             "data": {"stav": "Povoleno"},
             "_debug": {"method": "GET",
                          "url": "https://gw/registrOpravneni/api/v1/Opravneni/Over",
                          "params": {"IdSluzbyEZ": 3},
                          "body": None,
                          "headers": {"Authorization": "Bearer xx..."}}},
            # lokální krok bez HTTP volání
            {"name": "Generování FHIR Bundle", "passed": True, "status": 200,
             "elapsed_ms": 0, "data": {"entries": 4}, "_debug": {}},
            # DÚ krok s debug informacemi v du_debug
            {"name": "UlozZasilku", "passed": True, "status": 200, "elapsed_ms": 9,
             "data": {"id": "z-1"},
             "_debug": {"du_debug": {"method": "POST",
                                        "url": "https://gw/docasneUloziste/api/v1/Zasilka/UlozZasilku",
                                        "body": {"nazev": "x"}}}},
        ],
    }
    _irop_attach_req_resp(result)
    s1, s2, s3 = result["steps"]

    assert s1["request"]["method"] == "GET"
    assert s1["request"]["url"].endswith("/Opravneni/Over")
    assert s1["request"]["params"] == {"IdSluzbyEZ": 3}
    assert s1["response"] == {"status": 200, "body": {"stav": "Povoleno"}}

    assert s2["request"] is None, "lokální krok nemá HTTP volání"
    assert s2["response"]["body"] == {"entries": 4}

    assert s3["request"]["method"] == "POST"
    assert s3["request"]["body"] == {"nazev": "x"}
    assert s3["response"]["status"] == 200


def test_api_scenario_endpoint_vraci_request_response():
    """Endpoint /api/irop/scenario vrací u kroků request/response
    (offline: klient nepřipojen → 503; ověříme přes run-all impl na fake)."""
    ro = _FakeRO()
    r = _irop_tech4({}, {"ro": ro}, None)
    _irop_attach_req_resp(r)
    for step in r["steps"]:
        assert "request" in step
        assert "response" in step
        assert step["response"]["status"] == step["status"]


def test_iris_irop_endpoint_vraci_tridy():
    r = _client().get("/api/codegen/iris/irop")
    assert r.status_code == 200
    data = r.json()
    assert "SEZ.IROP.TestRunner" in data["classes"]
    assert "SEZ.IROP.VolaniLog" in data["classes"]
    runner = data["classes"]["SEZ.IROP.TestRunner"]
    log = data["classes"]["SEZ.IROP.VolaniLog"]
    assert "Class SEZ.IROP.TestRunner Extends %RegisteredObject" in runner
    assert "Class SEZ.IROP.VolaniLog Extends %Persistent" in log
    # runner loguje request i response každého volání
    assert "VolaniLog).Zapis" in runner
    assert "RequestBody" in log and "ResponseBody" in log and "HttpStatus" in log
    # scénáře dle metodiky
    for m in ("RunTech1", "RunTech2A", "RunTech2B", "RunTech4", "RunTech5",
              "RunTech6", "RunObs1", "RunAll"):
        assert m in runner, f"chybí metoda {m}"


def test_tech5_informativni_kroky_nesrazi_scenar():
    """metadata a Provenance nejsou v metodice; na Terminologii v1.1.0
    (odstraněné endpointy) nesmí jejich 404 scénář shodit."""
    mod = _FakeTermX()
    r = _irop_tech5({}, {"termx": mod, "termx_pub": mod}, object())
    assert r["passed"] == r["total"], "informativní kroky nesmí scénář shodit"
    assert _irop_hodnoceni_scenare(r) == "VYHOVUJE S VÝHRADAMI"
    noted = [s for s in r["steps"] if s.get("note")]
    assert len(noted) == 2, "výhrada právě u metadata a Provenance"
    # povinné kroky metodiky prošly bez výhrad
    povinne = [s for s in r["steps"] if "metodika krok" in s["name"]]
    assert len(povinne) == 2 and all(s["passed"] and not s.get("note")
                                       for s in povinne)
