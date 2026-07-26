"""
Generátor InterSystems IRIS (ObjectScript) kódu pro zprávy eZD.

Z obsahu builderu zpráv (typ dokumentu, pacient, autor, sekce) vygeneruje:

  * ``gen_snippet()``    – krátký ObjectScript úryvek pro terminál/metodu,
    který tutéž zprávu sestaví přes ``SEZ.EZD.Builder``, zvaliduje ji a
    volitelně uloží do Dočasného úložiště,
  * ``gen_trida()``      – hotovou ``.cls`` třídu ``<Package>.<Nazev>``
    s metodou ``Sestav()`` (obsah sekcí zadrátovaný jako výchozí hodnoty)
    a ``Odesli()`` pro uložení do DÚ,
  * ``builder_cls()``    – zdrojový kód runtime třídy ``SEZ.EZD.Builder``
    (docs/analytics/src/cls/SEZ/EZD/Builder.cls), na které generovaný
    kód staví.

Konvence dle skillu iris-objectscript: idiomatický UDL, PascalCase příkazy,
``%Status`` / ``$$$ThrowOnError`` v Try/Catch, ``%DynamicObject`` pro JSON,
``///`` doc komentáře.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from sez_api.fhir_ezd import EZD_KATEGORIE, UKAZKY, sekce_katalog

BUILDER_CLS_PATH = (Path(__file__).parent.parent / "docs" / "analytics" / "src"
                    / "cls" / "SEZ" / "EZD" / "Builder.cls")


def builder_cls() -> str:
    """Zdrojový kód runtime třídy ``SEZ.EZD.Builder``."""
    try:
        return BUILDER_CLS_PATH.read_text(encoding="utf-8")
    except Exception as exc:  # pragma: no cover – jen pokud chybí soubor
        return f"// Builder.cls nenalezen: {BUILDER_CLS_PATH} ({exc})"


def _os_str(value) -> str:
    """ObjectScript řetězcový literál (uvozovky se zdvojují)."""
    return '"' + str(value if value is not None else "").replace('"', '""') + '"'


def _class_name(kategorie: str) -> str:
    """pacientsky-souhrn → PacientskySouhrn (bez diakritiky)."""
    prevod = str.maketrans("áčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ",
                            "acdeeinorstuuyzACDEEINORSTUUYZ")
    parts = re.split(r"[-_\s]+", kategorie.translate(prevod))
    return "".join(p.capitalize() for p in parts if p) or "Zprava"


def _norm_sekce(sekce: dict | None) -> dict[str, list[str]]:
    """Normalizuje obsah sekcí na ``{slice: [řádky]}`` (prázdné vynechá)."""
    out: dict[str, list[str]] = {}
    for slice_name, hodnota in (sekce or {}).items():
        if isinstance(hodnota, (list, tuple)):
            radky = [str(v).strip() for v in hodnota if str(v).strip()]
        else:
            radky = [r.strip() for r in str(hodnota).splitlines() if r.strip()]
        if radky:
            out[slice_name] = radky
    return out


def _sekce_bloky(kategorie: str, sekce: dict[str, list[str]],
                  promenna: str = "sekce", odsazeni: str = "    ") -> list[str]:
    """Řádky ObjectScriptu plnící %DynamicObject s obsahem sekcí."""
    katalog = {s["slice"]: s for s in sekce_katalog(kategorie)}
    radky = [f"{odsazeni}Set {promenna} = ##class(%DynamicObject).%New()"]
    for slice_name, hodnoty in sekce.items():
        meta = katalog.get(slice_name)
        popis = f"  ; {meta['title']} (LOINC {meta['code']})" if meta else ""
        if len(hodnoty) == 1:
            radky.append(f"{odsazeni}Do {promenna}.%Set({_os_str(slice_name)}, "
                          f"{_os_str(hodnoty[0])}){popis}")
        else:
            radky.append(f"{odsazeni}Set pole = ##class(%DynamicArray).%New(){popis}")
            for h in hodnoty:
                radky.append(f"{odsazeni}Do pole.%Push({_os_str(h)})")
            radky.append(f"{odsazeni}Do {promenna}.%Set({_os_str(slice_name)}, pole)")
    return radky


def gen_snippet(kategorie: str, *, rid: str = "2667873559",
                 autor: str = "102129137", ico: str = "25488627",
                 pzs_nazev: str = "Krajská zdravotní, a.s.",
                 title: str | None = None,
                 sekce: dict | None = None,
                 pacient: dict | None = None,
                 autor_data: dict | None = None,
                 ico_adresat: str = "00064165") -> str:
    """ObjectScript úryvek, který sestaví, zvaliduje a odešle danou zprávu."""
    meta = EZD_KATEGORIE.get(kategorie)
    if meta is None:
        raise ValueError(f"Neznámá kategorie eZD: {kategorie!r}")
    sekce = _norm_sekce(sekce)
    pacient = pacient or {}
    autor_data = autor_data or {}

    L = [
        f"// {meta['nazev']} – FHIR document Bundle dle {meta['ig']} {meta['ig_verze']}",
        f"// Standard: {meta['ig_url']}",
        f"// Legislativa: {meta['legislativa']}",
        f"// Vygenerováno builderem zpráv eZD {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "// Vyžaduje třídy SEZ.EZD.Builder a SEZ.API.* (Config, HttpClient, DocasneUloziste).",
        "",
        "// 1) Obsah sekcí dokumentu",
    ]
    L += _sekce_bloky(kategorie, sekce, promenna="sekce", odsazeni="")

    if pacient.get("jmeno") or pacient.get("prijmeni") or pacient.get("datum_narozeni"):
        L += ["", "// 2) Demografie pacienta (volitelné)",
              "Set pacient = ##class(%DynamicObject).%New()"]
        if pacient.get("jmeno"):
            L.append(f"Do pacient.%Set(\"jmeno\", {_os_str(pacient['jmeno'])})")
        if pacient.get("prijmeni"):
            L.append(f"Do pacient.%Set(\"prijmeni\", {_os_str(pacient['prijmeni'])})")
        if pacient.get("datum_narozeni"):
            L.append(f"Do pacient.%Set(\"datumNarozeni\", {_os_str(pacient['datum_narozeni'])})")
    else:
        L += ["", "Set pacient = \"\""]

    if autor_data.get("jmeno") or autor_data.get("prijmeni"):
        L += ["", "// 3) Autor dokumentu (volitelné)",
              "Set autorData = ##class(%DynamicObject).%New()"]
        for klic, hodnota in (("titul", autor_data.get("titul")),
                               ("jmeno", autor_data.get("jmeno")),
                               ("prijmeni", autor_data.get("prijmeni"))):
            if hodnota:
                L.append(f"Do autorData.%Set({_os_str(klic)}, {_os_str(hodnota)})")
    else:
        L += ["", "Set autorData = \"\""]

    L += [
        "",
        "// 4) Sestavení dokumentu (hlavička dle IG profilu, úroveň L1)",
        "Set bundle = ##class(SEZ.EZD.Builder).Sestav(",
        f"    {_os_str(kategorie)}, {_os_str(rid)}, {_os_str(autor)}, {_os_str(ico)},",
        f"    .sekce, .sc, {_os_str(pzs_nazev)}, {_os_str(title or '')}, \"\", pacient, autorData)",
        "If $$$ISERR(sc) { Do $System.Status.DisplayError(sc) Quit }",
        "",
        "// 5) Lokální kontrola L1 (plná validace: https://validator.fhir.org/)",
        f"Set validace = ##class(SEZ.EZD.Builder).Validuj(bundle, {_os_str(kategorie)})",
        "Write \"Validní: \", validace.valid, !",
        "If 'validace.valid { Write validace.chyby.%ToJSON(), ! Quit }",
        "Write bundle.%ToJSON(), !",
        "",
        "// 6) Odeslání do Dočasného úložiště (adresát musí být JINÉ PZS než tvůrce)",
        f"Set config = ##class(SEZ.API.Config).%New({_os_str(ico + '_KrajskaZdravotniVerejnyTest')})",
        "Set config.P12CertFile = \"/opt/certs/krajska_zdravotni.pfx\"",
        "Set sc = ##class(SEZ.EZD.Builder).SestavAOdesli(config,",
        f"    {_os_str(kategorie)}, {_os_str(rid)}, {_os_str(autor)}, {_os_str(ico)},",
        f"    {_os_str(ico_adresat)}, .sekce, .odpoved)",
        "If $$$ISERR(sc) { Do $System.Status.DisplayError(sc) Quit }",
        "Write \"ID zásilky: \", odpoved.id, !",
    ]
    return "\n".join(L)


def gen_trida(kategorie: str, *, package: str = "SEZ.EZD.Zpravy",
               rid: str = "2667873559", autor: str = "102129137",
               ico: str = "25488627",
               pzs_nazev: str = "Krajská zdravotní, a.s.",
               title: str | None = None,
               sekce: dict | None = None,
               ico_adresat: str = "00064165") -> tuple[str, str]:
    """Vygeneruje hotovou ``.cls`` třídu pro daný typ zprávy.

    Vrací ``(nazev_tridy, zdrojovy_kod)``. Třída má metodu ``Sestav()``
    s předvyplněným obsahem sekcí a ``Odesli()`` pro uložení do DÚ.
    """
    meta = EZD_KATEGORIE.get(kategorie)
    if meta is None:
        raise ValueError(f"Neznámá kategorie eZD: {kategorie!r}")
    sekce = _norm_sekce(sekce)
    cls_short = _class_name(kategorie)
    cls_name = f"{package}.{cls_short}"
    povinne = [s for s in sekce_katalog(kategorie) if s["povinna"]]

    L = [
        f"/// {meta['nazev']} – generátor FHIR document Bundle dle {meta['ig']} {meta['ig_verze']}.",
        f"/// Standard: {meta['ig_url']}",
        f"/// Legislativa: {meta['legislativa']}",
        "///",
        f"/// Typ dokumentu: LOINC {meta['type_coding']['code']} "
        f"({meta['type_coding'].get('display', '')}), kód pro DÚ: {meta['du_typ_kod']}.",
        "/// Povinné sekce dle profilu: "
        + ", ".join(f"{s['title']} ({s['code']})" for s in povinne) + ".",
        "///",
        f"/// Vygenerováno builderem zpráv eZD {datetime.now().strftime('%Y-%m-%d %H:%M')}.",
        "/// Staví na SEZ.EZD.Builder a SEZ.API.* (Config, HttpClient, DocasneUloziste).",
        f"Class {cls_name} Extends %RegisteredObject",
        "{",
        "",
        f"Parameter KATEGORIE = {_os_str(kategorie)};",
        "",
        f"Parameter RID = {_os_str(rid)};",
        "",
        f"Parameter AUTOR = {_os_str(autor)};",
        "",
        f"Parameter ICO = {_os_str(ico)};",
        "",
        "/// IČO adresáta zásilky – MUSÍ být jiné PZS než tvůrce (DÚ chyba E01001).",
        f"Parameter ICOADRESAT = {_os_str(ico_adresat)};",
        "",
        "/// Vrátí předvyplněný obsah sekcí dokumentu.",
        "ClassMethod Sekce() As %DynamicObject",
        "{",
    ]
    L += _sekce_bloky(kategorie, sekce, promenna="sekce", odsazeni="    ")
    L += [
        "    Quit sekce",
        "}",
        "",
        "/// Sestaví dokument a vrátí ho jako %DynamicObject (FHIR Bundle).",
        "ClassMethod Sestav(Output pSC As %Status, pRid As %String = {..#RID}) As %DynamicObject",
        "{",
        "    Set sekce = ..Sekce()",
        "    Quit ##class(SEZ.EZD.Builder).Sestav(..#KATEGORIE, pRid, ..#AUTOR, ..#ICO,",
        f"        .sekce, .pSC, {_os_str(pzs_nazev)}, {_os_str(title or meta['nazev'])})",
        "}",
        "",
        "/// Sestaví dokument, zkontroluje ho dle L1 kritérií a vypíše JSON.",
        "ClassMethod Nahled() As %Status",
        "{",
        "    Set sc = $$$OK",
        "    Try {",
        "        Set bundle = ..Sestav(.sc)",
        "        $$$ThrowOnError(sc)",
        "        Set validace = ##class(SEZ.EZD.Builder).Validuj(bundle, ..#KATEGORIE)",
        "        Write \"Validní (L1): \", validace.valid, !",
        "        If 'validace.valid {",
        "            Write \"Chyby: \", validace.chyby.%ToJSON(), !",
        "        }",
        "        Write bundle.%ToJSON(), !",
        "    }",
        "    Catch ex {",
        "        Set sc = ex.AsStatus()",
        "    }",
        "    Quit sc",
        "}",
        "",
        "/// Sestaví dokument a uloží ho jako zásilku do Dočasného úložiště.",
        "ClassMethod Odesli(pConfig As SEZ.API.Config, Output pResponse As %DynamicObject) As %Status",
        "{",
        "    Set sekce = ..Sekce()",
        "    Quit ##class(SEZ.EZD.Builder).SestavAOdesli(pConfig, ..#KATEGORIE, ..#RID,",
        "        ..#AUTOR, ..#ICO, ..#ICOADRESAT, .sekce, .pResponse)",
        "}",
        "",
        "}",
        "",
    ]
    return cls_name, "\n".join(L)


def gen_vse(kategorie: str, **kwargs) -> dict:
    """Kompletní balíček pro IRIS: snippet + třída + runtime Builder."""
    ico_adresat = kwargs.pop("ico_adresat", "00064165")
    package = kwargs.pop("package", "SEZ.EZD.Zpravy")
    # gen_trida nepracuje s demografií pacienta ani autora – ta patří
    # do runtime volání (snippet), třída nese jen obsah sekcí.
    trida_kwargs = {k: v for k, v in kwargs.items()
                     if k not in ("pacient", "autor_data")}
    cls_name, cls_src = gen_trida(kategorie, package=package,
                                   ico_adresat=ico_adresat, **trida_kwargs)
    return {
        "kategorie": kategorie,
        "snippet": gen_snippet(kategorie, ico_adresat=ico_adresat, **kwargs),
        "trida_nazev": cls_name,
        "trida": cls_src,
        "builder_nazev": "SEZ.EZD.Builder",
        "builder": builder_cls(),
        "poznamka": ("Import: Do $System.OBJ.Load(\"Builder.cls\",\"ck\") nebo přes "
                      "VS Code ObjectScript. Runtime třída SEZ.EZD.Builder je "
                      "společná pro všechny typy zpráv, generovaná třída nese "
                      "konkrétní obsah sekcí."),
    }


def ukazkovy_balicek(kategorie: str) -> dict:
    """Balíček s ukázkovými daty daného typu zprávy."""
    u = UKAZKY.get(kategorie, {})
    return gen_vse(kategorie, title=u.get("title"), sekce=u.get("sekce"),
                    pacient={"jmeno": "MRAČENA", "prijmeni": "MRAKOMOROVÁ",
                              "datum_narozeni": "1971-11-26"},
                    autor_data={"titul": "MUDr.", "jmeno": "Jan",
                                 "prijmeni": "Novák"})
