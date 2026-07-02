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
    _irop_hodnoceni_scenare,
    _irop_hodnoceni_celkove,
)


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
