"""
Společná izolace pro celou testovací sadu.

Aplikace si mezi workery předává aktivní prostředí souborem v `/tmp`
(`_ENV_STATE_FILE`). Na stroji, kde běží i samotná služba, by ho testy
přečetly jako skutečný stav, přepnuly se na produkci a začaly stavět klienta
proti ostré bráně – sada by pak volala síť a její výsledek by závisel na
pořadí testů i na tom, co má zapsaná služba.
"""

import pytest


@pytest.fixture(autouse=True)
def izolovany_stav_prostredi(tmp_path, monkeypatch):
    from sez_api import app as app_mod

    monkeypatch.setattr(app_mod, "_ENV_STATE_FILE",
                        tmp_path / "sez-api-env-state.json", raising=False)
    # Throttling synchronizace si drží čas poslední kontroly; bez vynulování
    # by se první požadavek v testu podle okolností přeskočil.
    monkeypatch.setattr(app_mod, "_last_sync_check", 0.0, raising=False)
    yield
