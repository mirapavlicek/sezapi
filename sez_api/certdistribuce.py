"""
Automatická aktualizace klientského certifikátu z centrální distribuce.

Certifikáty pro přístup do SEZ vydává EZCA a centrální distribuce (IRIS) je
drží připravené ke stažení – včetně těch, které si sama obnovila
(``autoRenew``). Tento modul se distribuce v zadaném intervalu ptá, jestli pro
nás není novější certifikát, a když ano, předá ho k nasazení.

Očekávaný formát odpovědi je pole záznamů (viz ``UKAZKA_ZAPISU`` na konci
souboru), z nichž nás zajímá:

* ``pfx`` – PKCS#12 v base64,
* ``password`` – heslo k PKCS#12 (u IRIS to bývá cesta ke streamu, ale je to
  skutečné heslo, ne odkaz),
* ``serioveCislo``, ``pfxHash``, ``pfxSize`` – kontrola integrity,
* ``nazevSluzby`` + ``externiIdentifikator`` – čí certifikát to je,
* ``stav``, ``revokovany``, ``active``, ``platnostOd``, ``platnostDo``.

Bezpečnostní zásady, na kterých modul stojí:

* **Certifikát se přijme jen tehdy, když patří nám** – CN musí odpovídat
  názvu služby a identifikátor subjektu ICO z konfigurace. Kdyby distribuční
  URL kdokoli přesměroval, cizí certifikát se nenasadí.
* **Integrita se kontroluje proti metadatům** – sériové číslo, SHA-1 odstisk
  (``pfxHash``) i velikost PKCS#12 musí odpovídat.
* **Nikdy se nenasazuje starší certifikát** než ten v provozu, takže
  odpověď „ze zálohy“ nemůže provoz vrátit zpátky.
* **Heslo se nikam neloguje ani nevrací** žádným API.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from sez_api import config as cfg
from sez_api.certstore import CertChyba, dekoduj_pfx, zapis_atomicky, zkontroluj_pfx

logger = logging.getLogger("sez_api.certdistribuce")

# Jak dlouho se drží zámek, než ho jiný worker prohlásí za osiřelý. Kontrola
# je jedno HTTP volání a nasazení certifikátu, minuty jsou velká rezerva.
ZAMEK_MAX_VEK_S = 600

# OID organizationIdentifier – v subjectu certifikátu EZCA nese ICO subjektu.
_OID_ORG_ID = "2.5.4.97"

# Klíče nastavení, které se smí uložit (a jejich typ). Cokoli jiného z těla
# požadavku se ignoruje, ať se do souboru nedostanou cizí položky.
_POLE_NASTAVENI = {
    "url": str,
    "uzivatel": str,
    "heslo": str,
    "intervalHodin": float,
    "zapnuto": bool,
    "overovatTls": str,
    "timeout": float,
    "overitVolanim": bool,
    "prostredi": str,
}


class DistribuceChyba(RuntimeError):
    """Distribuci se nepodařilo zeptat nebo odpověď nedává smysl."""


def _nyni() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Nastavení a stav – soubory v úložišti certifikátů
# ---------------------------------------------------------------------------

def _dir() -> Path:
    return Path(cfg.cert_store_dir())


def soubor_nastaveni() -> Path:
    return _dir() / "distribuce.json"


def soubor_stavu() -> Path:
    return _dir() / "distribuce-stav.json"


def soubor_zamku() -> Path:
    return _dir() / "distribuce.lock"


def _vychozi_nastaveni() -> dict:
    """Výchozí hodnoty z .env – uložené nastavení je přepisuje."""
    return {
        "url": cfg.CERT_DIST_URL.strip(),
        "uzivatel": cfg.CERT_DIST_USER.strip(),
        "heslo": cfg.CERT_DIST_PASSWORD,
        "intervalHodin": float(cfg.CERT_DIST_INTERVAL_H),
        "zapnuto": bool(cfg.CERT_DIST_ENABLED),
        "overovatTls": str(cfg.CERT_DIST_VERIFY).strip(),
        "timeout": float(cfg.CERT_DIST_TIMEOUT),
        "overitVolanim": bool(cfg.CERT_DIST_OVERIT_VOLANIM),
        "prostredi": (cfg.CERT_DIST_PROSTREDI or "PROD").upper(),
    }


def _cti_json(cesta: Path) -> dict:
    try:
        return json.loads(cesta.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logger.warning("Soubor %s nelze přečíst: %s", cesta.name, exc)
        return {}


def nastaveni() -> dict:
    """Aktuální nastavení: výchozí hodnoty z .env přepsané uloženými.

    Čte se ze souboru při každém použití – aplikace běží ve více workerech a
    změna z GUI se tak projeví ve všech, bez restartu."""
    hodnoty = _vychozi_nastaveni()
    ulozene = _cti_json(soubor_nastaveni())
    for klic, typ in _POLE_NASTAVENI.items():
        if klic not in ulozene:
            continue
        try:
            hodnoty[klic] = typ(ulozene[klic]) if typ is not bool else bool(ulozene[klic])
        except (TypeError, ValueError):
            logger.warning("Nastavení distribuce: %s má nepoužitelnou hodnotu", klic)
    hodnoty["prostredi"] = (hodnoty.get("prostredi") or "PROD").upper()
    return hodnoty


def uloz_nastaveni(zmeny: dict) -> dict:
    """Uloží změněné položky. Prázdné heslo znamená „ponechat stávající“,
    aby GUI nemuselo heslo zobrazovat ani posílat zpět."""
    ulozene = _cti_json(soubor_nastaveni())
    for klic, typ in _POLE_NASTAVENI.items():
        if klic not in zmeny or zmeny[klic] is None:
            continue
        hodnota = zmeny[klic]
        if klic == "heslo":
            if zmeny.get("smazatHeslo"):
                ulozene["heslo"] = ""
            elif str(hodnota) != "":
                ulozene["heslo"] = str(hodnota)
            continue
        try:
            ulozene[klic] = bool(hodnota) if typ is bool else typ(hodnota)
        except (TypeError, ValueError):
            raise DistribuceChyba(f"Položka '{klic}' má nepoužitelnou hodnotu.")
    if zmeny.get("smazatHeslo") and "heslo" not in zmeny:
        ulozene["heslo"] = ""
    if ulozene.get("intervalHodin") is not None:
        try:
            if float(ulozene["intervalHodin"]) <= 0:
                raise DistribuceChyba("Interval musí být větší než nula.")
        except (TypeError, ValueError):
            raise DistribuceChyba("Interval musí být číslo v hodinách.")
    ulozene["zmenenoV"] = _nyni().isoformat()
    # Heslo k distribuci je v souboru v otevřené podobě, proto práva 0600
    # (stejně jako u hesla k PKCS#12 v úložišti).
    zapis_atomicky(soubor_nastaveni(),
                   json.dumps(ulozene, ensure_ascii=False, indent=2).encode())
    return nastaveni()


def nastaveni_bez_hesla(hodnoty: dict | None = None) -> dict:
    """Nastavení pro zobrazení – bez hesla, jen s příznakem, že je zadané."""
    hodnoty = dict(hodnoty or nastaveni())
    heslo = hodnoty.pop("heslo", "")
    hodnoty["hesloNastaveno"] = bool(heslo)
    return hodnoty


def stav() -> dict:
    return _cti_json(soubor_stavu())


def zapis_stav(zmeny: dict) -> dict:
    """Zapíše výsledek kontroly. Stav je informativní – když se zapsat
    nepodaří, kontrola se tím nemaří."""
    novy = stav()
    novy.update(zmeny)
    try:
        zapis_atomicky(soubor_stavu(),
                       json.dumps(novy, ensure_ascii=False, indent=2).encode(),
                       prava=0o640)
    except OSError as exc:
        logger.warning("Stav distribuce nelze zapsat: %s", exc)
    return novy


# ---------------------------------------------------------------------------
# Plánování – kdy je čas se zeptat a kdo se ptá
# ---------------------------------------------------------------------------

def dalsi_kontrola_za(hodnoty: dict | None = None, aktualni_stav: dict | None = None) -> float:
    """Kolik sekund zbývá do další kontroly (0 = je čas)."""
    hodnoty = hodnoty or nastaveni()
    aktualni_stav = stav() if aktualni_stav is None else aktualni_stav
    interval = max(60.0, float(hodnoty.get("intervalHodin") or 24) * 3600)
    posledni = aktualni_stav.get("posledniKontrolaTs")
    if not posledni:
        return 0.0
    try:
        zbyva = interval - (time.time() - float(posledni))
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, zbyva)


class Zamek:
    """Zámek mezi workery – kontrolu provede vždy jen jeden proces.

    Aplikace běží ve více workerech a každý má vlastní plánovač. Bez zámku by
    se distribuce ptalo N procesů zároveň a nasazovaly by certifikát přes
    sebe. Zámek je soubor vytvořený přes ``O_CREAT|O_EXCL``; osiřelý (po
    zabitém procesu) se po ``ZAMEK_MAX_VEK_S`` přebírá."""

    def __init__(self, cesta: Path | None = None, max_vek: float = ZAMEK_MAX_VEK_S):
        self.cesta = cesta or soubor_zamku()
        self.max_vek = max_vek
        self.ziskan = False

    def zkus_ziskat(self) -> bool:
        self.cesta.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(self.cesta), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if self._je_osirely():
                try:
                    self.cesta.unlink()
                except OSError:
                    return False
                return self.zkus_ziskat()
            return False
        except OSError as exc:
            logger.warning("Zámek distribuce nelze vytvořit: %s", exc)
            return False
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"pid": os.getpid(), "od": _nyni().isoformat()}))
        self.ziskan = True
        return True

    def _je_osirely(self) -> bool:
        try:
            return (time.time() - self.cesta.stat().st_mtime) > self.max_vek
        except OSError:
            return False

    def uvolni(self) -> None:
        if not self.ziskan:
            return
        try:
            self.cesta.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Zámek distribuce nelze uvolnit: %s", exc)
        self.ziskan = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.uvolni()
        return False


# ---------------------------------------------------------------------------
# Volání distribuce a kontrola nabízeného certifikátu
# ---------------------------------------------------------------------------

def _verify_parametr(hodnota: str):
    """Hodnota pro requests ``verify``: True/False, nebo cesta k CA bundle."""
    text = (hodnota or "").strip()
    if text.lower() in ("0", "false", "no", "ne", "off"):
        return False
    if text.lower() in ("1", "true", "yes", "ano", "on", ""):
        return True
    return text


def stahni_zapisy(hodnoty: dict | None = None) -> list:
    """Zeptá se distribuce na certifikáty. Vrací seznam záznamů."""
    hodnoty = hodnoty or nastaveni()
    url = (hodnoty.get("url") or "").strip()
    if not url:
        raise DistribuceChyba("Není nastavená adresa distribučního API.")
    uzivatel = (hodnoty.get("uzivatel") or "").strip()
    auth = (uzivatel, hodnoty.get("heslo") or "") if uzivatel else None
    verify = _verify_parametr(hodnoty.get("overovatTls"))
    if verify is False:
        logger.warning("Distribuce %s: TLS certifikát serveru se neověřuje", url)
    try:
        resp = requests.get(url, auth=auth, timeout=float(hodnoty.get("timeout") or 30),
                            verify=verify, headers={"Accept": "application/json"})
    except requests.RequestException as exc:
        raise DistribuceChyba(f"Distribuci se nepodařilo zeptat: {exc}") from exc
    if resp.status_code == 401:
        raise DistribuceChyba("Distribuce odmítla přihlášení (HTTP 401) – "
                              "zkontrolujte jméno a heslo.")
    if resp.status_code >= 400:
        raise DistribuceChyba(f"Distribuce vrátila HTTP {resp.status_code}.")
    try:
        data = resp.json()
    except ValueError as exc:
        raise DistribuceChyba("Odpověď distribuce není JSON "
                              f"(HTTP {resp.status_code}).") from exc
    if isinstance(data, dict):
        # Tolerance k zabalení do obálky {"data": [...]} / {"result": [...]}.
        for klic in ("data", "result", "certificates", "certifikaty"):
            if isinstance(data.get(klic), list):
                data = data[klic]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        raise DistribuceChyba("Odpověď distribuce není seznam certifikátů.")
    return data


def _text(zapis: dict, klic: str) -> str:
    hodnota = zapis.get(klic)
    return "" if hodnota is None else str(hodnota).strip()


def _je_pravda(hodnota, vychozi: bool = False) -> bool:
    """API posílá 0/1 jako číslo i jako string, podle verze IRIS."""
    if hodnota is None or hodnota == "":
        return vychozi
    if isinstance(hodnota, bool):
        return hodnota
    if isinstance(hodnota, (int, float)):
        return hodnota != 0
    return str(hodnota).strip().lower() in ("1", "true", "yes", "ano", "on")


def popis_zapisu(zapis: dict) -> dict:
    """Krátký popis záznamu pro log a UI (bez hesla a bez PKCS#12)."""
    return {
        "id": _text(zapis, "id"),
        "serioveCislo": _text(zapis, "serioveCislo"),
        "uid": _text(zapis, "uid"),
        "nazevSluzby": _text(zapis, "nazevSluzby"),
        "nazevSubjektu": _text(zapis, "nazevSubjektu"),
        "externiIdentifikator": _text(zapis, "externiIdentifikator"),
        "stav": _text(zapis, "stav"),
        "platnostOd": _text(zapis, "platnostOd"),
        "platnostDo": _text(zapis, "platnostDo"),
        "revokovany": _je_pravda(zapis.get("revokovany")),
        "sablona": _text(zapis, "sablona"),
        "typCertifikatuText": _text(zapis, "typCertifikatuText"),
    }


def vyber_zapis(zapisy: list, ico: str = "", sluzba: str = "") -> tuple:
    """Vybere záznam, který je náš a je použitelný. Vrací (záznam, důvody).

    Důvody popisují, proč ostatní záznamy vypadly – jsou to jediná stopa,
    když distribuce vrátí certifikáty, ale žádný nasaditelný."""
    if not ico and not sluzba:
        ico, sluzba = cfg.cert_dist_ocekavane()
    duvody, vhodne = [], []
    for zapis in zapisy:
        if not isinstance(zapis, dict):
            duvody.append("záznam není objekt")
            continue
        popis = popis_zapisu(zapis)
        oznaceni = popis["serioveCislo"] or popis["id"] or "?"
        if sluzba and popis["nazevSluzby"].lower() != sluzba.lower():
            duvody.append(f"{oznaceni}: jiná služba ({popis['nazevSluzby']})")
            continue
        if ico and popis["externiIdentifikator"] != ico:
            duvody.append(f"{oznaceni}: jiný subjekt ({popis['externiIdentifikator']})")
            continue
        if popis["stav"] and popis["stav"].lower() != "valid":
            duvody.append(f"{oznaceni}: stav {popis['stav']}")
            continue
        if popis["revokovany"]:
            duvody.append(f"{oznaceni}: revokovaný")
            continue
        if not _je_pravda(zapis.get("active"), vychozi=True):
            duvody.append(f"{oznaceni}: neaktivní")
            continue
        if not _text(zapis, "pfx"):
            duvody.append(f"{oznaceni}: bez PKCS#12")
            continue
        vhodne.append(zapis)
    if not vhodne:
        return None, duvody
    # Nejdelší platnost = nejnovější certifikát; při shodě rozhodne id.
    vhodne.sort(key=lambda z: (_text(z, "platnostDo"), _text(z, "id")), reverse=True)
    return vhodne[0], duvody


def _org_identifikator(cert) -> str:
    for atribut in cert.subject:
        if atribut.oid.dotted_string == _OID_ORG_ID:
            return str(atribut.value).strip()
    return ""


def _cn(cert) -> str:
    try:
        return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value).strip()
    except (IndexError, ValueError):
        return ""


def rozbal_a_zkontroluj(zapis: dict, *, ico: str = "", sluzba: str = "") -> tuple:
    """Dekóduje PKCS#12 ze záznamu a ověří, že opravdu odpovídá metadatům
    a že patří nám. Vrací (pfx, heslo, popis certifikátu).

    Vyhazuje ``CertChyba`` – nasazení se v takovém případě vůbec nezkusí."""
    if not ico and not sluzba:
        ico, sluzba = cfg.cert_dist_ocekavane()
    heslo = zapis.get("password")
    heslo = "" if heslo is None else str(heslo)
    pfx = dekoduj_pfx(_text(zapis, "pfx"))

    # Pozor: CertChyba dědí z ValueError, takže převod na int musí být
    # v samostatném try – jinak by si ho vlastní except spolkl.
    try:
        ocekavana_velikost = int(zapis.get("pfxSize"))
    except (TypeError, ValueError):
        ocekavana_velikost = None
    if ocekavana_velikost is not None and ocekavana_velikost != len(pfx):
        raise CertChyba(
            f"Velikost PKCS#12 nesouhlasí s metadaty distribuce "
            f"({len(pfx)} B vs. {ocekavana_velikost} B) – přenos je poškozený.")

    # Heslo z distribuce musí PKCS#12 otevřít; platnost prověříme sami níž,
    # ať můžeme rozlišit „ještě neplatí“ od „už vypršel“.
    popis = zkontroluj_pfx(pfx, heslo, vynutit=True)
    _, cert, _ = pkcs12.load_key_and_certificates(
        pfx, heslo.encode() if heslo else None)

    seriove = _text(zapis, "serioveCislo").upper().lstrip("0")
    if seriove:
        skutecne = format(cert.serial_number, "X").lstrip("0")
        if seriove != skutecne:
            raise CertChyba("Sériové číslo certifikátu nesouhlasí s metadaty "
                            "distribuce – záznam a soubor k sobě nepatří.")
    odstisk = _text(zapis, "pfxHash").upper().replace(":", "").replace(" ", "")
    if odstisk:
        skutecny = cert.fingerprint(SHA1()).hex().upper()
        if odstisk != skutecny:
            raise CertChyba("Odstisk certifikátu (pfxHash) nesouhlasí – "
                            "soubor není ten, který distribuce popisuje.")

    # Kontrola, že certifikát je náš. Bez ní by přesměrování distribuční URL
    # znamenalo nasazení cizího certifikátu.
    if sluzba:
        cn = _cn(cert)
        if cn.lower() != sluzba.lower():
            raise CertChyba(f"Certifikát je vystavený pro službu '{cn}', "
                            f"očekává se '{sluzba}'.")
    if ico:
        org = _org_identifikator(cert)
        if org and org != ico:
            raise CertChyba(f"Certifikát je vystavený pro subjekt '{org}', "
                            f"očekává se '{ico}'.")

    popis["cn"] = _cn(cert)
    popis["organizationIdentifier"] = _org_identifikator(cert)
    return pfx, heslo, popis


def rozhodni(popis_novy: dict, popis_aktivni: dict | None) -> dict:
    """Porovná nabízený certifikát s tím v provozu.

    Vrací ``{"akce": ..., "duvod": ...}``, kde akce je ``nasadit``,
    ``aktualni`` (nabízený je ten, který už běží), ``starsi`` (nabízený by
    provoz vrátil zpátky) nebo ``pockat`` (platnost ještě nezačala)."""
    ted = _nyni()
    platny_od = _datum(popis_novy.get("platnyOd"))
    platny_do = _datum(popis_novy.get("platnyDo"))
    if platny_do and platny_do <= ted:
        return {"akce": "starsi",
                "duvod": f"Nabízený certifikát vypršel {platny_do.date().isoformat()}."}

    aktivni_do = _datum((popis_aktivni or {}).get("platnyDo"))
    if popis_aktivni and _stejny(popis_novy, popis_aktivni):
        return {"akce": "aktualni",
                "duvod": "V provozu už je tentýž certifikát."}

    if platny_od and platny_od > ted:
        # Distribuce nabízí certifikát dopředu. Nasadit ho teď by znamenalo
        # provoz bez platného certifikátu – necháme běžet stávající.
        if aktivni_do and aktivni_do > ted:
            return {"akce": "pockat",
                    "duvod": f"Nový certifikát začíná platit "
                             f"{platny_od.date().isoformat()}, stávající platí do "
                             f"{aktivni_do.date().isoformat()}."}
        return {"akce": "nasadit",
                "duvod": f"Stávající certifikát už neplatí, nasazuje se nový "
                         f"(platný od {platny_od.date().isoformat()})."}

    if aktivni_do and platny_do and platny_do <= aktivni_do:
        return {"akce": "starsi",
                "duvod": f"Nabízený certifikát platí do "
                         f"{platny_do.date().isoformat()}, stávající do "
                         f"{aktivni_do.date().isoformat()} – nenasazuje se."}

    do_kdy = platny_do.date().isoformat() if platny_do else "?"
    return {"akce": "nasadit",
            "duvod": f"Distribuce má novější certifikát (platný do {do_kdy})."}


def _stejny(a: dict, b: dict) -> bool:
    """Tentýž certifikát – podle odstisku, jinak podle sériového čísla."""
    for klic in ("fingerprintSha256", "serialNumber"):
        prvni, druhy = (a.get(klic) or ""), (b.get(klic) or "")
        if prvni and druhy:
            return str(prvni).upper().lstrip("0") == str(druhy).upper().lstrip("0")
    return False


def _datum(hodnota) -> datetime | None:
    """Datum z ISO tvaru i z tvaru 'RRRR-MM-DD HH:MM:SS', vždy v UTC."""
    if not hodnota:
        return None
    if isinstance(hodnota, datetime):
        return hodnota if hodnota.tzinfo else hodnota.replace(tzinfo=timezone.utc)
    text = str(hodnota).strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        vysledek = datetime.fromisoformat(text)
    except ValueError:
        return None
    return vysledek if vysledek.tzinfo else vysledek.replace(tzinfo=timezone.utc)


# Ukázka jednoho záznamu z distribuce – slouží jako dokumentace kontraktu
# (heslo a PKCS#12 jsou vypuštěné).
UKAZKA_ZAPISU = {
    "id": "221",
    "serioveCislo": "14000006DF487411293F6531680000000006DF",
    "iczId": 40982,
    "uid": "5c08647d-b7c9-4982-9fa9-d2f41987b0f9",
    "nazevSluzby": "NIS2",
    "nazevSubjektu": "Fakultní nemocnice Motol a Homolka",
    "stav": "Valid",
    "platnostOd": "2026-08-20 05:26:53",
    "platnostDo": "2026-11-20 05:26:53",
    "typCertifikatuText": "Přístupový certifikát pro subjekt",
    "ucel": "Autentizace",
    "typDrzitele": "Subjekt",
    "sablona": "ExtendedAutSubject",
    "externiIdentifikator": "00064203",
    "revokovany": 0,
    "autoRenew": "1",
    "active": 1,
    "pfxHash": "558C5FD28C466043AE25A1FC228695E4A6E64D38",
    "pfxSize": 9419,
    "daysToExpiry": 92,
    "password": "<heslo k PKCS#12>",
    "pfx": "<PKCS#12 v base64>",
}
