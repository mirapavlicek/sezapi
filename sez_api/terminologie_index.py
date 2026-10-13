"""
Lokální fulltextové vyhledávání v číselnících pro eŽádanky (MKN-10, SNOMED CT).

Proč lokálně: TermX (`termx-api-t2-pub.csez.cz`) při ``ValueSet/$expand``
parametr ``filter`` ignoruje a expanzi ořezává na 5 000 položek, SNOMED CT
v něm není jako obsah (``content: not-present``, funguje jen ``$lookup``)
a veřejný Snowstorm SNOMED International programový přístup odmítá.
Balíček proto nese komprimované snímky (``terminologie_data/*.json.gz``):

- ``mkn10`` – kompletní MKN-10 (Mkn10_5, ÚZIS, 38 934 položek vč. 5. znaku),
  stažené z TermX ``CodeSystem/mkn-10--2025-01`` 13. 10. 2026;
- ``sct-k-procedures`` / ``sct-ft-procedures`` / ``sct-imaging-procedures`` /
  ``sct-conditions`` / ``vzp-odbornost`` – expanze ValueSetů HL7 CZ Order IG
  a img-order IG (``expansions.json`` z build.fhir.org) s **českými**
  displayi SNOMED CT CZ edice 20260618. U sad, které IG publikuje ořezané
  (``limitedExpansion``, 1 000 položek), je v metadatech ``uplne: false``;
  kód mimo snímek lze ověřit přes TermX ``$lookup`` (``lookup_kod``).

Vyhledávání je bez diakritiky, všechna slova dotazu musí být v kódu nebo
názvu (AND), řazení: shoda kódu > začátek názvu > začátek slova > podřetězec.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import threading
import unicodedata
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "terminologie_data")

# Mapování typu žádanky → sada výkonů; sady diagnóz
SADY_VYKONU = {"K": "sct-k-procedures", "FT": "sct-ft-procedures", "Z": "sct-imaging-procedures"}
SADY_DIAGNOZ = {"mkn10": "mkn10", "sct": "sct-conditions"}
SYS_SNOMED = "http://snomed.info/sct"
SCT_CZ_EDITION = "http://snomed.info/sct/11000279109"

_lock = threading.Lock()
_cache: dict[str, dict] = {}


def _bez_diakritiky(s: str) -> str:
    s = unicodedata.normalize("NFD", s or "")
    return "".join(ch for ch in s if unicodedata.category(ch) != "Mn").lower()


def _tokeny(q: str) -> list[str]:
    # tečka v kódu MKN-10 (M54.5) se v číselníku nepíše
    return [t.replace(".", "") for t in re.split(r"[\s,;/]+", _bez_diakritiky(q).strip()) if t.replace(".", "")]


def seznam_sad() -> list[str]:
    if not os.path.isdir(DATA_DIR):
        return []
    return sorted(f[:-8] for f in os.listdir(DATA_DIR) if f.endswith(".json.gz"))


def nacti_sadu(nazev: str) -> dict | None:
    """Načte (a zaindexuje) sadu; vrací ``{"meta", "items", "index"}`` nebo None."""
    if nazev in _cache:
        return _cache[nazev]
    path = os.path.join(DATA_DIR, f"{nazev}.json.gz")
    if not re.fullmatch(r"[a-z0-9-]+", nazev or "") or not os.path.isfile(path):
        return None
    with _lock:
        if nazev in _cache:
            return _cache[nazev]
        with gzip.open(path, "rt", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("items") or []
        index = [(_bez_diakritiky(it[0]), _bez_diakritiky(it[1] if len(it) > 1 else "")) for it in items]
        by_code = {it[0]: it for it in items}
        sada = {"meta": data.get("meta") or {}, "items": items, "index": index, "by_code": by_code}
        sada["meta"] = dict(sada["meta"], id=nazev, pocet=len(items))
        _cache[nazev] = sada
        return sada


def info_sad() -> list[dict]:
    out = []
    for n in seznam_sad():
        s = nacti_sadu(n)
        if s:
            out.append(s["meta"])
    return out


def _polozka(sada: dict, it: list) -> dict:
    meta = sada["meta"]
    d = {"code": it[0], "display": it[1] if len(it) > 1 else "", "system": meta.get("system")}
    if meta.get("version"):
        d["version"] = meta["version"]
    if len(it) > 2 and it[2]:
        d["parent"] = it[2]
    return d


def hledat(nazev: str, q: str, limit: int = 20) -> dict:
    """Vyhledá v sadě. Vrací ``{"sada": meta, "q", "total", "items": [...]}``."""
    sada = nacti_sadu(nazev)
    if sada is None:
        raise KeyError(f"Neznámá sada '{nazev}' (dostupné: {', '.join(seznam_sad())})")
    toks = _tokeny(q)
    limit = max(1, min(int(limit or 20), 200))
    if not toks:
        items = sada["items"][:limit]
        return {"sada": sada["meta"], "q": q, "total": len(sada["items"]),
                "items": [_polozka(sada, it) for it in items]}
    q_norm = " ".join(toks)
    scored: list[tuple[int, int, int]] = []
    for i, (code, disp) in enumerate(sada["index"]):
        text = code + " " + disp
        if not all(t in text for t in toks):
            continue
        # skóre: menší = lepší
        if code == q_norm or code == q_norm.replace(".", ""):
            score = 0
        elif code.startswith(q_norm.replace(".", "")):
            score = 1
        elif disp.startswith(q_norm):
            score = 2
        elif all(re.search(r"(^|[\s(\-/,;])" + re.escape(t), disp) for t in toks):
            score = 3
        else:
            score = 4
        scored.append((score, len(disp), i))
    scored.sort()
    items = [_polozka(sada, sada["items"][i]) for _, _, i in scored[:limit]]
    return {"sada": sada["meta"], "q": q, "total": len(scored), "items": items}


def najdi_kod(nazev: str, code: str) -> dict | None:
    sada = nacti_sadu(nazev)
    if not sada:
        return None
    it = sada["by_code"].get(code) or sada["by_code"].get(code.replace(".", ""))
    return _polozka(sada, it) if it else None


def lookup_kod(termx, system: str, code: str) -> dict | None:
    """Ověří kód přes TermX ``CodeSystem/$lookup`` (pro kódy mimo lokální snímek).
    Vrací ``{"code","display","system","version","designace":[...]}`` nebo None.
    ``termx`` je instance ``sez_api.client.TermX`` (nebo None)."""
    if termx is None or not code:
        return None
    try:
        r = termx.codesystem_lookup(system=system, code=code, property="designation")
        d = r.json()
    except Exception:
        return None
    if d.get("resourceType") != "Parameters":
        return None
    out: dict[str, Any] = {"code": code, "system": system, "designace": [], "zdroj": "termx-lookup"}
    for p in d.get("parameter", []):
        n = p.get("name")
        if n == "display":
            out["display"] = p.get("valueString")
        elif n == "version":
            out["version"] = p.get("valueString")
        elif n == "designation":
            parts = {x.get("name"): (x.get("valueString") or x.get("valueCode")) for x in p.get("part", [])}
            if parts.get("value"):
                out["designace"].append({"jazyk": parts.get("language"), "hodnota": parts["value"]})
    # česká designace má přednost
    cs = next((x["hodnota"] for x in out["designace"] if (x.get("jazyk") or "").startswith("cs")), None)
    if cs:
        out["display_cs"] = cs
    return out if out.get("display") else None
