"""
Hromadné stažení registru poskytovatelů (KRPZS) a lokální fulltext.

KRPZS umí hledat jen podle IČO, přesného názvu a kraje. Výpis podle kraje
(`hledat/misto`) vrátí všechny poskytovatele v kraji, ale bez názvu – ten
je jen v odpovědi `hledat/ico`. Sestavení lokálního indexu má proto dvě fáze:

1. Stáhnout výpisy všech krajů (14 dotazů, paralelně), sloučit podle IČO
   a rozlišit aktivní poskytovatele od historických záznamů (zaniklá
   nebo zrušená oprávnění, případně bez rozhodnutí) – ty `hledat/ico`
   stejně nevrátí.
2. Pro každé IČO dotáhnout detail (`hledat/ico`) a uložit z něj kompaktní
   záznam: název, stav, sídlo, kontakty, kraje a obce míst poskytování,
   kódy oborů/forem/druhů péče. Plný záznam má i stovky kB (FN Motol
   274 kB), index se tedy drží řádově v desítkách MB.

Druhá fáze běží v ``ThreadPoolExecutor`` – `SEZClient` není bezpečný pro
sdílení mezi vlákny (reset session při opakování, `last_*` atributy), proto
si každé vlákno vytvoří vlastního klienta přes předanou továrnu. Sdílet lze
`SEZAuth` (podepisování JWT nic nemění).

Nad uloženým indexem pak `hledat()` dělá fulltext bez ohledu na diakritiku
a velikost písmen s volitelným filtrem na kraj a obor péče.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

logger = logging.getLogger("sez_api.krpzs_registr")

# Kódy krajů (VÚSC dle ČSÚ/RÚIAN) – hodnota `krajKod`, kterou KRPZS vrací
# v adresách a přijímá v `hledat/misto`.
KRAJE = {
    "19": "Hlavní město Praha",
    "27": "Středočeský kraj",
    "35": "Jihočeský kraj",
    "43": "Plzeňský kraj",
    "51": "Karlovarský kraj",
    "60": "Ústecký kraj",
    "78": "Liberecký kraj",
    "86": "Královéhradecký kraj",
    "94": "Pardubický kraj",
    "108": "Kraj Vysočina",
    "116": "Jihomoravský kraj",
    "124": "Olomoucký kraj",
    "132": "Moravskoslezský kraj",
    "141": "Zlínský kraj",
}

# Typy rozhodnutí, po kterých oprávnění zaniklo (ZAN = zánik, ZRR = zrušení).
ROZHODNUTI_ZANIK = {"ZAN", "ZRR"}

# Kolikrát opakovat dotaz, který brána odmítla přetížením (HTTP 429), než se
# IČO odloží jako chyba. Pauza roste geometricky od PAUZA_429_S.
OPAKOVANI_429 = 6
PAUZA_429_S = 1.0
# Opakování po síťové chybě (přerušený přenos, reset spojení) a pauzy mezi
# pokusy. Souběžné stahování velkých výpisů krajů občas spojení přeruší.
OPAKOVANI_SITE = 3
PAUZA_SITE_S = (2.0, 5.0, 10.0)

# Měřeno na ostré bráně (září 2026): propustnost hledat/ico roste do cca 16
# souběžných dotazů (~6/s), pak už jen roste latence – při 64 vláknech trval
# každý dotaz ~20 s a propustnost klesla na 3/s. Vyšší paralelismus navíc
# zpomaluje všechna ostatní volání téhož klienta (GUI).
VYCHOZI_PARALELISMUS = 16
MAX_PARALELISMUS = 32

# Továrna na klienta: bez parametrů vrátí nový `SEZClient` (jeden na vlákno).
TovarnaKlienta = Callable[[], object]


class Zastaveno(Exception):
    """Běh byl zastaven zvenčí (stop událost)."""


def tovarna_klientu(auth) -> TovarnaKlienta:
    """Továrna na `SEZClient` nad sdíleným `SEZAuth` (jeden klient na vlákno).

    404 u `hledat/ico` je při hromadném dotazování běžná odpověď (historická
    IČO), proto se neloguje jako chyba."""
    from sez_api.client import SEZClient

    def vytvor():
        klient = SEZClient(auth)
        klient.TICHE_STAVY = frozenset({404})
        return klient
    return vytvor


# ---------------------------------------------------------------------------
# Průběh
# ---------------------------------------------------------------------------

class Prubeh:
    """Průběh stahování bezpečný pro čtení z jiného vlákna (stav v GUI)."""

    MAX_CHYB = 50

    def __init__(self):
        self._lock = threading.Lock()
        self.bezi = False
        self.faze = "nezahájeno"
        self.zprava = ""
        self.kraje_celkem = 0
        self.kraje_hotovo = 0
        self.kraje_zaznamu = 0
        self.ico_celkem = 0
        self.ico_hotovo = 0
        self.ico_nalezeno = 0
        self.ico_nenalezeno = 0
        self.ico_chyb = 0
        self.pocet_429 = 0
        self.pocet_sitovych_chyb = 0
        self.chyby: list[dict] = []
        self.zacatek: float | None = None
        self.faze_zacatek: float | None = None
        self.konec: float | None = None
        self.vysledek: dict | None = None

    def start(self, faze: str) -> None:
        with self._lock:
            self.bezi = True
            self.faze = faze
            self.zacatek = self.zacatek or time.time()
            self.faze_zacatek = time.time()
            self.konec = None

    def nastav(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, v)

    def pricti(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)

    def chyba(self, kde: str, text: str) -> None:
        with self._lock:
            self.ico_chyb += 1
            if len(self.chyby) < self.MAX_CHYB:
                self.chyby.append({"kde": kde, "chyba": text[:300]})

    def hotovo(self, faze: str, vysledek: dict | None = None,
               zprava: str = "") -> None:
        with self._lock:
            self.bezi = False
            self.faze = faze
            self.konec = time.time()
            self.zprava = zprava
            if vysledek is not None:
                self.vysledek = vysledek

    def snapshot(self) -> dict:
        with self._lock:
            trvani = None
            if self.zacatek:
                trvani = round((self.konec or time.time()) - self.zacatek, 1)
            # Rychlost se měří od začátku fáze detailů, ne od začátku běhu –
            # stažení krajů by odhad zbývajícího času zkreslovalo.
            rychlost = None
            if self.faze_zacatek and self.ico_hotovo and self.bezi:
                ubehlo = time.time() - self.faze_zacatek
                if ubehlo > 0:
                    rychlost = round(self.ico_hotovo / ubehlo, 1)
            zbyva = None
            if rychlost and self.ico_celkem > self.ico_hotovo:
                zbyva = round((self.ico_celkem - self.ico_hotovo) / rychlost)
            return {
                "bezi": self.bezi,
                "faze": self.faze,
                "zprava": self.zprava,
                "kraje": {"celkem": self.kraje_celkem, "hotovo": self.kraje_hotovo,
                          "zaznamu": self.kraje_zaznamu},
                "ico": {"celkem": self.ico_celkem, "hotovo": self.ico_hotovo,
                        "nalezeno": self.ico_nalezeno,
                        "nenalezeno": self.ico_nenalezeno, "chyb": self.ico_chyb},
                "pocet429": self.pocet_429,
                "pocetSitovychChyb": self.pocet_sitovych_chyb,
                "rychlostZaS": rychlost,
                "odhadZbyvaS": zbyva,
                "trvaniS": trvani,
                "zacatek": _iso(self.zacatek),
                "konec": _iso(self.konec),
                "chyby": list(self.chyby),
                "vysledek": self.vysledek,
            }


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Pomocné
# ---------------------------------------------------------------------------

def _hodnota(pole):
    """KRPZS balí hodnoty do {hodnota, referencni, stav, zdroj}."""
    if isinstance(pole, dict):
        return pole.get("hodnota")
    return pole


def bez_diakritiky(text: str | None) -> str:
    """Malá písmena bez diakritiky pro porovnávání."""
    if not text:
        return ""
    norm = unicodedata.normalize("NFD", str(text))
    return "".join(ch for ch in norm if unicodedata.category(ch) != "Mn").lower()


def _odpoved_data(resp) -> list:
    """Vrátí `odpovedData` z odpovědi KRPZS jako seznam (nebo prázdný)."""
    try:
        telo = resp.json()
    except Exception:
        return []
    if not isinstance(telo, dict):
        return []
    data = telo.get("odpovedData")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _zkontroluj_stop(stop) -> None:
    if stop is not None and stop.is_set():
        raise Zastaveno()


class _KlientNaVlakno:
    """Každému vláknu poolu dá vlastního klienta (a KRPZS modul)."""

    def __init__(self, tovarna: TovarnaKlienta):
        self._tovarna = tovarna
        self._local = threading.local()

    def krpzs(self):
        from sez_api.client import KRPZS
        modul = getattr(self._local, "krpzs", None)
        if modul is None:
            modul = KRPZS(self._tovarna())
            self._local.krpzs = modul
        return modul


def _pockej(stop, sekundy: float) -> None:
    if stop is not None:
        if stop.wait(sekundy):
            raise Zastaveno()
    else:
        time.sleep(sekundy)


def _volej_odolne(fn, prubeh: Prubeh | None, stop, popis: str):
    """Zavolá `fn()` a zopakuje po síťové chybě, kterou SEZClient neřeší
    (přerušený přenos těla – ChunkedEncodingError, reset spojení). Při
    velkých výpisech krajů stahovaných souběžně k tomu dochází."""
    import requests as _rq
    for pokus in range(OPAKOVANI_SITE + 1):
        _zkontroluj_stop(stop)
        try:
            return fn()
        except Zastaveno:
            raise
        except (_rq.RequestException, OSError) as exc:
            if pokus == OPAKOVANI_SITE:
                raise
            pauza = PAUZA_SITE_S[min(pokus, len(PAUZA_SITE_S) - 1)]
            if prubeh:
                prubeh.pricti(pocet_sitovych_chyb=1)
            logger.warning("%s: %s: %s – čekám %.0fs a opakuji (%d/%d)", popis,
                           type(exc).__name__, str(exc)[:120], pauza, pokus + 1,
                           OPAKOVANI_SITE)
            _pockej(stop, pauza)
    raise AssertionError("nedosažitelné")  # pragma: no cover


def _volej_s_opakovanim_429(fn, prubeh: Prubeh | None, stop, popis: str):
    """Zavolá `fn()`; na HTTP 429 počká a zopakuje (SEZClient 429 neopakuje).

    Respektuje hlavičku Retry-After, jinak geometrický backoff. Síťové chyby
    řeší `_volej_odolne`."""
    pauza = PAUZA_429_S
    for pokus in range(OPAKOVANI_429 + 1):
        _zkontroluj_stop(stop)
        resp = _volej_odolne(fn, prubeh, stop, popis)
        if resp.status_code != 429:
            return resp
        if prubeh:
            prubeh.pricti(pocet_429=1)
        if pokus == OPAKOVANI_429:
            return resp
        try:
            cekat = float(resp.headers.get("Retry-After") or 0) or pauza
        except (TypeError, ValueError):
            cekat = pauza
        logger.warning("HTTP 429 %s – čekám %.1fs (pokus %d/%d)",
                       popis, cekat, pokus + 1, OPAKOVANI_429)
        _pockej(stop, cekat)
        pauza = min(pauza * 2, 30.0)
    return resp  # pragma: no cover


# ---------------------------------------------------------------------------
# Fáze 1 – výpisy krajů
# ---------------------------------------------------------------------------

def stahni_kraje(tovarna: TovarnaKlienta, kraje: Iterable[str] | None = None,
                 paralelismus: int | None = None, prubeh: Prubeh | None = None,
                 stop=None, ucel: str = "OVERENI") -> dict[str, list]:
    """Stáhne výpisy `hledat/misto` pro dané kraje (výchozí všechny).

    Vrací {krajKod: [záznam, ...]}. Kraj, který se nepodařilo stáhnout,
    vyvolá výjimku – neúplný registr by tiše zahodil část poskytovatelů."""
    kody = list(kraje) if kraje else list(KRAJE)
    for kod in kody:
        if kod not in KRAJE:
            raise ValueError(f"Neznámý kód kraje '{kod}'. Známé: {', '.join(KRAJE)}")
    pool = _KlientNaVlakno(tovarna)
    vlaken = max(1, min(paralelismus or len(kody), len(kody)))
    if prubeh:
        prubeh.start("kraje")
        prubeh.nastav(kraje_celkem=len(kody), kraje_hotovo=0, kraje_zaznamu=0)

    def jeden(kod: str) -> tuple[str, list]:
        _zkontroluj_stop(stop)
        t0 = time.monotonic()
        resp = _volej_s_opakovanim_429(
            lambda: pool.krpzs().hledat_misto(kraj_kod=kod, ucel=ucel),
            prubeh, stop, f"kraj {kod}")
        if resp.status_code == 404:
            zaznamy = []
        elif resp.status_code != 200:
            raise RuntimeError(
                f"Kraj {kod} ({KRAJE[kod]}): HTTP {resp.status_code} "
                f"{(resp.text or '')[:200]}")
        else:
            zaznamy = _odpoved_data(resp)
        logger.info("Kraj %s (%s): %d záznamů za %.1fs", kod, KRAJE[kod],
                    len(zaznamy), time.monotonic() - t0)
        if prubeh:
            prubeh.pricti(kraje_hotovo=1, kraje_zaznamu=len(zaznamy))
        return kod, zaznamy

    vysledky: dict[str, list] = {}
    with ThreadPoolExecutor(max_workers=vlaken, thread_name_prefix="krpzs-kraj") as ex:
        futures = [ex.submit(jeden, kod) for kod in kody]
        try:
            for f in as_completed(futures):
                kod, zaznamy = f.result()
                vysledky[kod] = zaznamy
        except BaseException:
            for f in futures:
                f.cancel()
            raise
    return vysledky


def je_aktivni(zaznam: dict) -> bool:
    """Heuristika: poskytovatel má rozhodnutí a žádné z nich neukončuje
    oprávnění (platnostDo nebo typ ZAN/ZRR). Ostatní `hledat/ico` nevrátí
    (ověřeno na vzorku ostrých dat)."""
    rozhodnuti = [r for o in (zaznam.get("opravneni") or [])
                  for r in (o.get("rozhodnuti") or [])]
    if not rozhodnuti:
        return False
    for r in rozhodnuti:
        if _hodnota(r.get("platnostDo")):
            return False
        if _hodnota(r.get("typRozhodnuti")) in ROZHODNUTI_ZANIK:
            return False
    return True


def sloucit_podle_ico(vypisy: dict[str, list]) -> dict[str, dict]:
    """Sloučí výpisy krajů do souhrnu na IČO.

    Poskytovatel s místy ve více krajích je v každém z nich; do souhrnu se
    sbírají kraje a obce míst poskytování, počet míst a příznak aktivní."""
    souhrn: dict[str, dict] = {}
    for kod, zaznamy in vypisy.items():
        for z in zaznamy:
            ico = _hodnota(z.get("ico"))
            if not ico:
                continue
            s = souhrn.setdefault(ico, {
                "ico": ico, "kraje": set(), "obce": set(), "pocetMist": 0,
                "aktivni": False, "kontakty": {},
            })
            s["kraje"].add(kod)
            for o in z.get("opravneni") or []:
                for m in o.get("mistaPoskytovani") or []:
                    adresa = m.get("adresa") or {}
                    if adresa.get("obec"):
                        s["obce"].add(adresa["obec"])
                    if adresa.get("krajKod"):
                        s["kraje"].add(str(adresa["krajKod"]))
                    s["pocetMist"] += 1
            s["aktivni"] = s["aktivni"] or je_aktivni(z)
            vk = z.get("verejneKontakty") or {}
            for klic, pole in (("datovaSchranka", "datovaSchranka"), ("email", "email"),
                               ("telefon", "telefon"), ("web", "www")):
                hodnota = _hodnota(vk.get(pole))
                if hodnota and not s["kontakty"].get(klic):
                    s["kontakty"][klic] = hodnota
    return souhrn


# ---------------------------------------------------------------------------
# Fáze 2 – detaily podle IČO
# ---------------------------------------------------------------------------

def zkompaktuj(zaznam: dict) -> dict:
    """Z plné odpovědi `hledat/ico` vybere, co je potřeba k hledání."""
    sidlo = zaznam.get("adresaSidla") or {}
    kraje, obce, obory, formy, druhy = set(), set(), set(), set(), set()
    pocet_mist = 0
    luzka = 0
    for o in zaznam.get("opravneni") or []:
        for m in o.get("mistaPoskytovani") or []:
            pocet_mist += 1
            adresa = m.get("adresa") or {}
            if adresa.get("krajKod"):
                kraje.add(str(adresa["krajKod"]))
            if adresa.get("obec"):
                obce.add(adresa["obec"])
            for s in m.get("sluzby") or []:
                for ob in s.get("oborPece") or []:
                    if _hodnota(ob):
                        obory.add(str(_hodnota(ob)))
                if _hodnota(s.get("formaPece")):
                    formy.add(str(_hodnota(s.get("formaPece"))))
                if _hodnota(s.get("druhPece")):
                    druhy.add(str(_hodnota(s.get("druhPece"))))
            for zz in m.get("zdravotnickeZarizeni") or []:
                for odd in zz.get("oddeleni") or []:
                    try:
                        luzka += int(_hodnota(odd.get("pocetLuzek")) or 0)
                    except (TypeError, ValueError):
                        pass
    return {
        "ico": _hodnota(zaznam.get("ico")),
        "nazev": _hodnota(zaznam.get("poskytovatelNazev")),
        "stavZaznamu": zaznam.get("stavZaznamu"),
        "typPoskytovatele": _hodnota(zaznam.get("typPoskytovatele")),
        "sidlo": {
            "obec": sidlo.get("obec"),
            "psc": sidlo.get("psc"),
            "ulice": sidlo.get("ulice"),
            "cisloPopisne": sidlo.get("cisloPopisne"),
            "cisloOrientacni": sidlo.get("cisloOrientacni"),
            "krajKod": str(sidlo["krajKod"]) if sidlo.get("krajKod") else None,
        },
        "kontakty": {
            "datovaSchranka": _hodnota(zaznam.get("datovaSchranka")),
            "email": _hodnota(zaznam.get("kontaktniEmail")),
            "telefon": _hodnota(zaznam.get("kontaktniTelefon")),
            "web": _hodnota(zaznam.get("kontaktniWeb")),
        },
        "kraje": sorted(kraje, key=lambda k: int(k) if k.isdigit() else 0),
        "obce": sorted(obce),
        "pocetMist": pocet_mist,
        "pocetLuzek": luzka,
        "oboryPece": sorted(obory),
        "formyPece": sorted(formy),
        "druhyPece": sorted(druhy),
    }


def dotahni_detaily(icos: Iterable[str], tovarna: TovarnaKlienta,
                    paralelismus: int = VYCHOZI_PARALELISMUS,
                    prubeh: Prubeh | None = None, stop=None,
                    ucel: str = "OVERENI") -> dict[str, dict | None]:
    """Paralelně zavolá `hledat/ico` pro každé IČO.

    Vrací {ico: kompaktní záznam | None (404 – v registru není) }. IČO, jehož
    dotaz skončil chybou (síť, 5xx po vyčerpání opakování), ve výsledku
    chybí a je zapsané v `prubeh.chyby`."""
    seznam = list(dict.fromkeys(i for i in icos if i))
    vlaken = max(1, min(int(paralelismus or 1), MAX_PARALELISMUS, max(len(seznam), 1)))
    pool = _KlientNaVlakno(tovarna)
    if prubeh:
        prubeh.start("detaily")
        prubeh.nastav(ico_celkem=len(seznam), ico_hotovo=0, ico_nalezeno=0,
                      ico_nenalezeno=0)

    def jeden(ico: str):
        _zkontroluj_stop(stop)
        resp = _volej_s_opakovanim_429(
            lambda: pool.krpzs().hledat_ico(ico, ucel=ucel), prubeh, stop, f"IČO {ico}")
        if resp.status_code == 200:
            data = _odpoved_data(resp)
            if not data:
                return ico, None
            zaznam = zkompaktuj(data[0])
            zaznam["ico"] = zaznam["ico"] or ico
            return ico, zaznam
        if resp.status_code == 404:
            return ico, None
        raise RuntimeError(f"HTTP {resp.status_code} {(resp.text or '')[:200]}")

    vysledky: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=vlaken, thread_name_prefix="krpzs-ico") as ex:
        futures = {ex.submit(jeden, ico): ico for ico in seznam}
        try:
            for f in as_completed(futures):
                ico = futures[f]
                try:
                    _, zaznam = f.result()
                except Zastaveno:
                    raise
                except Exception as exc:
                    if prubeh:
                        prubeh.chyba(ico, f"{type(exc).__name__}: {exc}")
                        prubeh.pricti(ico_hotovo=1)
                    logger.warning("IČO %s: %s", ico, exc)
                    continue
                vysledky[ico] = zaznam
                if prubeh:
                    prubeh.pricti(ico_hotovo=1,
                                  **({"ico_nalezeno": 1} if zaznam else {"ico_nenalezeno": 1}))
        except BaseException:
            for f in futures:
                f.cancel()
            raise
    return vysledky


# ---------------------------------------------------------------------------
# Celý běh
# ---------------------------------------------------------------------------

def stahni_registr(tovarna: TovarnaKlienta, *,
                   paralelismus: int = VYCHOZI_PARALELISMUS,
                   jen_aktivni: bool = True,
                   kraje: Iterable[str] | None = None,
                   limit: int | None = None,
                   vystup: str | os.PathLike | None = None,
                   prostredi: str = "",
                   prubeh: Prubeh | None = None,
                   stop=None,
                   ucel: str = "OVERENI") -> dict:
    """Stáhne registr poskytovatelů a sestaví lokální index.

    - `paralelismus`: počet souběžných dotazů `hledat/ico` (do MAX_PARALELISMUS).
    - `jen_aktivni`: dotahovat detail jen pro IČO s platným oprávněním
      (historické záznamy `hledat/ico` nevrátí – cca 55 % výpisu).
    - `kraje`: podmnožina kódů krajů (výchozí všechny).
    - `limit`: max. počet IČO pro detail (ladění/zkušební běh).
    - `vystup`: cesta JSON souboru; zapisuje se atomicky.

    Vrací index: {"stazeno", "prostredi", "trvaniS", "kraje": {kod: počet},
    "pocetIcoVypis", "pocetIcoAktivnich", "pocetDotazano", "pocetNalezeno",
    "pocetNenalezeno", "pocetChyb", "poskytovatele": [záznam...]}.
    Záznamy bez detailu (jen z výpisu) mají `"detail": False`."""
    prubeh = prubeh or Prubeh()
    t0 = time.monotonic()
    try:
        vypisy = stahni_kraje(tovarna, kraje=kraje, prubeh=prubeh, stop=stop, ucel=ucel)
        souhrn = sloucit_podle_ico(vypisy)
        aktivni = [ico for ico, s in souhrn.items() if s["aktivni"]]
        k_dotazu = aktivni if jen_aktivni else list(souhrn)
        k_dotazu.sort()
        if limit:
            k_dotazu = k_dotazu[:int(limit)]
        prubeh.nastav(zprava=f"Výpis: {len(souhrn)} IČO, aktivních {len(aktivni)}, "
                             f"k dotazu {len(k_dotazu)}")
        detaily = dotahni_detaily(k_dotazu, tovarna, paralelismus=paralelismus,
                                  prubeh=prubeh, stop=stop, ucel=ucel)
    except Zastaveno:
        prubeh.hotovo("zastaveno", zprava="Stahování bylo zastaveno.")
        raise
    except Exception as exc:
        prubeh.hotovo("chyba", zprava=f"{type(exc).__name__}: {exc}")
        raise

    poskytovatele = []
    dotazano = set(k_dotazu)
    for ico in sorted(souhrn):
        s = souhrn[ico]
        zaznam = detaily.get(ico)
        if zaznam:
            zaznam["detail"] = True
            zaznam["aktivni"] = s["aktivni"]
            # Kraje/obce z výpisu doplní ty z detailu (mohou se lišit).
            zaznam["kraje"] = sorted(set(zaznam["kraje"]) | s["kraje"],
                                     key=lambda k: int(k) if k.isdigit() else 0)
            zaznam["obce"] = sorted(set(zaznam["obce"]) | s["obce"])
            for k, v in s["kontakty"].items():
                zaznam["kontakty"][k] = zaznam["kontakty"].get(k) or v
        else:
            # Nenalezen = hledat/ico vrátilo 404; Chyba = dotaz selhal (viz
            # prubeh.chyby); Nedotazano = historický záznam přeskočený filtrem.
            if ico in detaily:
                stav = "Nenalezen"
            elif ico in dotazano:
                stav = "Chyba"
            else:
                stav = "Nedotazano"
            zaznam = {
                "ico": ico, "nazev": None, "stavZaznamu": stav,
                "detail": False, "aktivni": s["aktivni"],
                "kraje": sorted(s["kraje"], key=lambda k: int(k) if k.isdigit() else 0),
                "obce": sorted(s["obce"]), "pocetMist": s["pocetMist"],
                "kontakty": dict(s["kontakty"]),
            }
        poskytovatele.append(zaznam)

    index = {
        "stazeno": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "prostredi": prostredi,
        "trvaniS": round(time.monotonic() - t0, 1),
        "paralelismus": int(paralelismus),
        "jenAktivni": bool(jen_aktivni),
        "kraje": {kod: len(z) for kod, z in sorted(vypisy.items(), key=lambda kv: int(kv[0]))},
        "pocetIcoVypis": len(souhrn),
        "pocetIcoAktivnich": len(aktivni),
        "pocetDotazano": len(k_dotazu),
        "pocetNalezeno": sum(1 for v in detaily.values() if v),
        "pocetNenalezeno": sum(1 for v in detaily.values() if not v),
        "pocetChyb": len(k_dotazu) - len(detaily),
        "pocet429": prubeh.snapshot()["pocet429"],
        "pocetSitovychChyb": prubeh.snapshot()["pocetSitovychChyb"],
        "poskytovatele": poskytovatele,
    }
    if vystup:
        uloz_registr(index, vystup)
        index["soubor"] = str(vystup)
    souhrn_bez_zaznamu = {k: v for k, v in index.items() if k != "poskytovatele"}
    prubeh.hotovo("hotovo", vysledek=souhrn_bez_zaznamu,
                  zprava=f"Hotovo: {index['pocetNalezeno']} poskytovatelů s názvem "
                         f"z {index['pocetIcoVypis']} IČO za {index['trvaniS']} s")
    return index


def uloz_registr(index: dict, cesta: str | os.PathLike) -> None:
    from sez_api.certstore import zapis_atomicky
    data = json.dumps(index, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    zapis_atomicky(Path(cesta), data, prava=0o644)


def nacti_registr(cesta: str | os.PathLike) -> dict | None:
    p = Path(cesta)
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Fulltext nad indexem
# ---------------------------------------------------------------------------

def hledat(index: dict, dotaz: str, *, kraj: str | None = None,
           obor: str | None = None, obec: str | None = None,
           jen_s_nazvem: bool = True, limit: int = 50) -> list[dict]:
    """Fulltext nad indexem: všechna slova dotazu musí být (bez diakritiky,
    bez ohledu na velikost) obsažena v názvu, IČO nebo obci sídla.

    Řadí: přesná shoda názvu, začátek názvu, ostatní; v rámci skupiny podle
    názvu. `kraj` filtruje podle kódu kraje míst poskytování (nebo sídla),
    `obor` podle kódu oboru péče, `obec` podle obce míst/sídla."""
    slova = [s for s in bez_diakritiky(dotaz).split() if s]
    kraj = (kraj or "").strip() or None
    obor = (obor or "").strip() or None
    obec_n = bez_diakritiky(obec) if obec else None
    vysledky = []
    for z in index.get("poskytovatele") or []:
        nazev = z.get("nazev")
        if jen_s_nazvem and not nazev:
            continue
        if kraj and kraj not in (z.get("kraje") or []) \
                and kraj != ((z.get("sidlo") or {}).get("krajKod")):
            continue
        if obor and obor not in (z.get("oboryPece") or []):
            continue
        if obec_n:
            obce = [bez_diakritiky(o) for o in (z.get("obce") or [])]
            obce.append(bez_diakritiky((z.get("sidlo") or {}).get("obec")))
            if not any(obec_n in o for o in obce):
                continue
        nazev_n = bez_diakritiky(nazev)
        text = " ".join([nazev_n, z.get("ico") or "",
                         bez_diakritiky((z.get("sidlo") or {}).get("obec"))])
        if not all(s in text for s in slova):
            continue
        dotaz_n = " ".join(slova)
        if nazev_n == dotaz_n:
            poradi = 0
        elif nazev_n.startswith(dotaz_n):
            poradi = 1
        else:
            poradi = 2
        vysledky.append((poradi, nazev_n, z))
    vysledky.sort(key=lambda t: (t[0], t[1]))
    return [z for _, _, z in vysledky[:max(1, int(limit))]]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _tovarna_z_konfigurace(env_key: str) -> tuple[TovarnaKlienta, object]:
    """Továrna na klienty pro dané prostředí z .env (sdílený SEZAuth)."""
    from sez_api import config as cfg
    from sez_api.client import SEZ_ENVIRONMENTS, SEZAuth, SEZConfig

    envdef = SEZ_ENVIRONMENTS.get(env_key)
    if not envdef:
        raise SystemExit(f"Neznámé prostředí '{env_key}'. Známá: {', '.join(SEZ_ENVIRONMENTS)}")
    creds = dict(cfg.ENV_CREDENTIALS.get(env_key) or {})
    # Certifikát převzatý z distribuce má přednost před cestou v .env.
    try:
        from sez_api.certstore import CertStore
        zaklad = env_key[:-4] if env_key.endswith("_CMS") else env_key
        store = CertStore(cfg.cert_store_dir(), zaklad)
        if store.existuje():
            meta = store.metadata()
            creds["client_id"] = meta.get("clientId") or creds.get("client_id")
            creds["p12_path"] = str(store.pfx_path)
            creds["p12_password"] = store.heslo()
            creds["cert_uid"] = meta.get("certUid") or creds.get("cert_uid")
    except Exception as exc:  # pragma: no cover - závisí na prostředí
        logger.debug("Úložiště certifikátů nedostupné: %s", exc)
    if not creds.get("p12_path"):
        raise SystemExit(f"Chybí certifikát pro prostředí {env_key} (SEZ_*_P12_PATH).")
    icfg = SEZConfig()
    icfg.GATEWAY = envdef["gateway"]
    icfg.TOKEN_AUDIENCE = envdef["jsu_audience"]
    icfg.ENVIRONMENT = env_key
    auth = SEZAuth(client_id=creds["client_id"], p12_path=creds["p12_path"],
                   p12_password=creds["p12_password"],
                   cert_uid=creds.get("cert_uid") or None, config=icfg)
    return tovarna_klientu(auth), auth


def vychozi_soubor(env_key: str) -> Path:
    from sez_api import config as cfg
    return Path(cfg.krpzs_registr_dir()) / f"registr_{env_key}.json"


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="python -m sez_api.krpzs_registr",
        description="Stáhne registr poskytovatelů (KRPZS) do lokálního indexu "
                    "s paralelními dotazy, nebo v indexu hledá.")
    sub = p.add_subparsers(dest="prikaz")

    s = sub.add_parser("stahnout", help="Stáhnout registr")
    s.add_argument("--env", default="PROD", help="Prostředí (PROD, T2, …), výchozí PROD")
    s.add_argument("-p", "--paralelismus", type=int, default=VYCHOZI_PARALELISMUS,
                   help=f"Souběžné dotazy hledat/ico (max {MAX_PARALELISMUS}), "
                        f"výchozí {VYCHOZI_PARALELISMUS}")
    s.add_argument("--vsechny", action="store_true",
                   help="Dotazovat i historická IČO (výchozí jen aktivní)")
    s.add_argument("--kraj", action="append", help="Jen daný kraj (kód, opakovatelné)")
    s.add_argument("--limit", type=int, help="Max. počet IČO pro detail (zkušební běh)")
    s.add_argument("-o", "--vystup", help="Cesta výstupního JSON (výchozí adresář registru)")

    h = sub.add_parser("hledat", help="Fulltext v uloženém indexu")
    h.add_argument("dotaz", nargs="+")
    h.add_argument("--env", default="PROD")
    h.add_argument("--soubor", help="Cesta indexu (výchozí adresář registru)")
    h.add_argument("--kraj")
    h.add_argument("--obor")
    h.add_argument("--obec")
    h.add_argument("--limit", type=int, default=20)

    args = p.parse_args(argv)
    if not args.prikaz:
        p.print_help()
        return 2

    if args.prikaz == "hledat":
        soubor = args.soubor or vychozi_soubor(args.env)
        index = nacti_registr(soubor)
        if not index:
            print(f"Index {soubor} neexistuje – nejdřív spusťte 'stahnout'.", file=sys.stderr)
            return 1
        nalezeno = hledat(index, " ".join(args.dotaz), kraj=args.kraj, obor=args.obor,
                          obec=args.obec, limit=args.limit)
        print(f"Index z {index.get('stazeno')}, {index.get('pocetNalezeno')} poskytovatelů; "
              f"nalezeno {len(nalezeno)}:")
        for z in nalezeno:
            sidlo = z.get("sidlo") or {}
            print(f"  {z['ico']}  {z.get('nazev')}  ({sidlo.get('obec')}, "
                  f"kraje {','.join(z.get('kraje') or [])}, míst {z.get('pocetMist')})")
        return 0

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    tovarna, auth = _tovarna_z_konfigurace(args.env)
    vystup = Path(args.vystup) if args.vystup else vychozi_soubor(args.env)
    prubeh = Prubeh()
    stop = threading.Event()

    def hlaseni():
        posledni = None
        while not stop.wait(5):
            snap = prubeh.snapshot()
            if not snap["bezi"]:
                continue
            radek = (f"[{snap['faze']}] kraje {snap['kraje']['hotovo']}/{snap['kraje']['celkem']} "
                     f"| IČO {snap['ico']['hotovo']}/{snap['ico']['celkem']} "
                     f"(nalezeno {snap['ico']['nalezeno']}, chyb {snap['ico']['chyb']}, "
                     f"429: {snap['pocet429']}, síť: {snap['pocetSitovychChyb']}) "
                     f"{snap['rychlostZaS'] or 0}/s, "
                     f"zbývá ~{snap['odhadZbyvaS'] or '?'} s")
            if radek != posledni:
                print(radek, flush=True)
                posledni = radek

    vlakno = threading.Thread(target=hlaseni, daemon=True)
    vlakno.start()
    try:
        index = stahni_registr(tovarna, paralelismus=args.paralelismus,
                               jen_aktivni=not args.vsechny, kraje=args.kraj,
                               limit=args.limit, vystup=vystup, prostredi=args.env,
                               prubeh=prubeh, stop=stop)
    except KeyboardInterrupt:
        stop.set()
        print("\nPřerušeno.", file=sys.stderr)
        return 130
    except Exception as exc:
        logger.debug("Stahování selhalo", exc_info=True)
        print(f"Stahování selhalo: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        stop.set()
        try:
            auth.cleanup()
        except Exception:
            pass
    print(f"Hotovo za {index['trvaniS']} s: výpis {index['pocetIcoVypis']} IČO, "
          f"aktivních {index['pocetIcoAktivnich']}, dotázáno {index['pocetDotazano']}, "
          f"s názvem {index['pocetNalezeno']}, nenalezeno {index['pocetNenalezeno']}, "
          f"chyb {index['pocetChyb']}, HTTP 429: {index['pocet429']}, "
          f"síťových chyb (zopakováno): {index['pocetSitovychChyb']}")
    print(f"Uloženo: {vystup} ({os.path.getsize(vystup) / 1e6:.1f} MB)")
    return 0 if not index["pocetChyb"] else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
