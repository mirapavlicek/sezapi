"""
SEZ API klient – Python knihovna pro práci se Sdíleným elektronickým zdravotnictvím.

Podporované služby:
  - KRP (Kmenový registr pacientů)
  - KRZP (Kmenový registr zdravotnických pracovníků)
  - DÚ (Dočasné úložiště)
  - SZZ (Sdílený zdravotní záznam)
  - ELP (Elektronické posudky v1)
  - ELPv2 (Elektronické posudky v2)
  - eŽádanky (vč. simulačního enginu)
  - Notifikace
  - EZCA2 (Služby vytvářející důvěru)
"""

from sez_api.client import (
    SEZ_ENVIRONMENTS,
    SEZConfig,
    SEZAuth,
    SEZClient,
    KRP,
    KRZP,
    DocasneUloziste,
    SZZ,
    ELP,
    ELPv2,
    EZadanky,
    Notifikace,
    EZCA2,
)

__version__ = "2.1.0"

__all__ = [
    "SEZ_ENVIRONMENTS",
    "SEZConfig",
    "SEZAuth",
    "SEZClient",
    "KRP",
    "KRZP",
    "DocasneUloziste",
    "SZZ",
    "ELP",
    "ELPv2",
    "EZadanky",
    "Notifikace",
    "EZCA2",
]
