#!/usr/bin/env python3
"""
Zpětná kompatibilita – původní plochý klient `sez_client` byl sloučen do
balíčku `sez_api` (jediný zdroj pravdy je sez_api/client.py).

Starší skripty s `from sez_client import SEZAuth, SEZClient, ...` fungují
beze změny; nově dostávají plnohodnotné implementace z balíčku (všechny
služby, retry logika, prostředí T2/PROD, ...).

Pozn.: legacy metody EZadanky.dej_token / dej_vizual / dej_prilohy byly
odstraněny – endpointy DejToken / DejVizualZadanky / DejPrilohyZadanky
už v aktuálním API eŽádanek neexistují (viz Manuál EZ pro PZS, 7. 4. 2026).

Preferovaný import: `from sez_api import ...`
"""

from sez_api.client import (  # noqa: F401
    SEZ_ENVIRONMENTS,
    SEZConfig,
    SEZAuth,
    SEZClient,
    KRP,
    KRPv3,
    KRZP,
    KRPZS,
    DocasneUloziste,
    RegistrOpravneni,
    RegistrOpravneniNcpeh,
    SZZ,
    SZZv2,
    ELP,
    ELPv2,
    ELPv3,
    EZadanky,
    Notifikace,
    EZCA2,
    EZCA2SpravaCertifikatu,
    EZCAValidace,
    Terminologie,
    TermX,
)
