"""
Smoke test webového GUI – ověřuje, že se SPA (sez_api/templates/index.html)
korektně vyrenderuje přes GET / a obsahuje klíčové sekce.

Regrese: stará signatura ``templates.TemplateResponse("index.html",
{"request": request})`` padala na novějším Starlette
(TypeError: unhashable type: 'dict').

Spuštění:  python3 -m pytest tests/test_gui.py -v
"""

from starlette.testclient import TestClient

from sez_api.app import app


def test_gui_index_renders():
    client = TestClient(app)
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    # anti-cache hlavičky (UI se často aktualizuje)
    assert "no-store" in r.headers.get("cache-control", "")


def test_gui_obsahuje_klicove_sekce():
    body = TestClient(app).get("/").text
    for marker in [
        "Dashboard",
        "eHealth NIS",
        "IROP/NPO Testy",
        "Závazné standardy eZD",       # tabulka HL7 CZ IG standardů
        "TS-TECH-2B",                   # scénář KRZP dle metodiky
        "Vygenerovat protokol o testu",  # protokol o provedení testu
    ]:
        assert marker in body, f"GUI neobsahuje: {marker}"
