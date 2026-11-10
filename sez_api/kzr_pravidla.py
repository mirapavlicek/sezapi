"""Pravidla Kmenových registrů (KRP) dle Standardu EZ Kmenové registry 1.3.

Zdroje (revize 10. 11. 2026):

* Standard EZ Kmenové registry 1.3, platnost od 3. 11. 2026 – kap. 1.3.1
  (struktura RID a DRID), 4.4.3 a 4.4.4 (dočasný RID), 4.4.5 (hromadné
  ztotožnění), 4.5.1 (univerzální vyhledání), 4.5.3 (notifikace).
* „Novinky a plány v systémech EZ – update 2026/11/03“ – kontrola jmen,
  limit a doba zpracování dávky hromadného ztotožnění.
* Swagger KRP 3.0.6 (28. 7. 2026) – drátová podoba těl notifikací.

Modul nevolá bránu. Obsahuje jen čisté funkce, které používá klient, backend
i GUI, aby pravidla byla na jednom místě. Co z toho brána skutečně vynucuje,
se z této sítě ověřit nedalo (T2 je geograficky blokované) – proto se tvrdě
odmítá jen to, co je nesporně chybný vstup, a zbytek se vrací jako upozornění.
"""

from __future__ import annotations

import os
import re
import unicodedata

STANDARD_VERZE = "1.3"
STANDARD_PLATNOST = "2026-11-03"
STANDARD_PREDCHOZI = "1.2"

# ---------------------------------------------------------------------------
# RID a dočasný RID (kap. 1.3.1, 4.4.3, 4.4.4)
# ---------------------------------------------------------------------------

_RID_RE = re.compile(r"^[1-9]\d{9}$")
_DRID_RE = re.compile(r"^D\d{9}$")

# Kap. 4.4.3: „Pro PZS jsou nastavena pravidla pro počet předgenerovaných DRID,
# na 50 ks.“ (verze 1.2: „v řádu desítek až stovek ks“). Jde o zásobu, ne o
# doložený strop parametru ``pocet`` jednoho volání.
DRID_ZASOBA = 50

DRID_UCEL = (
    "Dočasný RID (DRID) je provizorní identifikátor pro interní evidenci "
    "pacienta, jehož totožnost není známa a je mu nutné poskytnout péči "
    "(občan ČR i cizinec), dále pro výpadek sítě nebo vyhlášení traumaplánu. "
    "DRID neslouží k založení novorozence v KRP – ten se zakládá metodou "
    "zalozit/pacient. Každý DRID smí být použit jen jednou; duplicitnímu "
    "použití musí zabránit systém poskytovatele.")


def rid_platny(hodnota) -> bool:
    """Trvalý RID: 10 číslic, nezačíná nulou, dělitelný 13 a nedělitelný 11."""
    h = str(hodnota or "").strip()
    if not _RID_RE.fullmatch(h):
        return False
    n = int(h)
    return n % 13 == 0 and n % 11 != 0


def drid_tvar(hodnota) -> bool:
    """Tvar DRID platný ve verzi 1.2 i 1.3: písmeno ``D`` a 9 číslic."""
    return bool(_DRID_RE.fullmatch(str(hodnota or "").strip()))


def drid_kontrolni_cislo(hodnota) -> bool:
    """Pravidlo verze 1.3: devítimístné číslo za ``D`` je dělitelné 13
    a není dělitelné 11."""
    h = str(hodnota or "").strip()
    if not _DRID_RE.fullmatch(h):
        return False
    n = int(h[1:])
    return n % 13 == 0 and n % 11 != 0


def drid_platny(hodnota) -> bool:
    """DRID dle Standardu 1.3 – tvar i kontrolní pravidlo."""
    return drid_kontrolni_cislo(hodnota)


def drid_chyba(hodnota) -> str | None:
    """Chyba, pro kterou se DRID na bránu vůbec neposílá (špatný tvar)."""
    if drid_tvar(hodnota):
        return None
    return ("Dočasný RID musí mít tvar D + 9 číslic (např. D000000013); "
            f"zadáno: {str(hodnota or '').strip()!r}.")


def drid_upozorneni(hodnota) -> str | None:
    """Neblokující upozornění: DRID má správný tvar, ale nesplňuje kontrolní
    pravidlo verze 1.3. DRID vydané před 3. 11. 2026 byly „náhodné číslice“
    a pravidlo splňovat nemusí – přiřadit je proto musí jít dál."""
    if not drid_tvar(hodnota) or drid_kontrolni_cislo(hodnota):
        return None
    return ("DRID nesplňuje pravidlo Standardu KZR 1.3 (číslo za D dělitelné 13 "
            "a nedělitelné 11). U DRID vydaných před 3. 11. 2026 je to v pořádku "
            "(tehdy šlo o náhodné číslice); u nově vydaného DRID zkontrolujte "
            "opis.")


def rid_upozorneni(hodnota) -> str | None:
    h = str(hodnota or "").strip()
    if not h or rid_platny(h):
        return None
    return (f"RID {h!r} nesplňuje pravidlo Standardu KZR (10 číslic, nezačíná "
            "nulou, dělitelné 13 a nedělitelné 11).")


def drid_pocet_upozorneni(pocet) -> str | None:
    try:
        n = int(pocet)
    except (TypeError, ValueError):
        return None
    if n <= DRID_ZASOBA:
        return None
    return (f"Standard KZR 1.3 (kap. 4.4.3) stanovuje zásobu předgenerovaných "
            f"DRID na {DRID_ZASOBA} ks; požadováno {n}. Zda brána větší počet "
            "odmítne, není ověřeno.")


# ---------------------------------------------------------------------------
# Jméno a příjmení (plány MZ ČR, 3. 11. 2026)
# ---------------------------------------------------------------------------

# „ve jméně ani v příjmení nesmí být obsaženy jiné znaky než velká a malá
# písmena abecedy, pomlčka (spojovník), apostrof a mezera.“ Písmenem se rozumí
# písmeno libovolné abecedy (Müller, Łukasiewicz, Nguyễn). Typografický
# apostrof U+2019 zdroj nejmenuje; přijímá se, aby neodpadl běžný zápis O’Brien.
_JMENO_ODDELOVACE = " -'\u2019"

# Příklady zjevně chybných dat, které MZ ČR jmenuje („Don Corleone“, „Jméno
# Test“, „Pacient Testovaci“, „18 Pokusníček“, „Neřekl“, „Neví“, „Neuvedeno“).
# Porovnává se celé slovo bez diakritiky a velikosti písmen – „Testová“ ani
# „Pacientová“ tím neodpadnou.
JMENA_ZAKAZANA_SLOVA = frozenset({
    "test", "testovaci", "pacient", "pokusnicek", "nerekl", "nevi", "neuvedeno",
})
JMENA_ZAKAZANA_CELA = frozenset({"don corleone"})

REZIM_ODMITNOUT = "odmitnout"
REZIM_VAROVAT = "varovat"
REZIM_VYPNUTO = "vypnuto"


def rezim_kontroly_jmen() -> str:
    """``SEZ_KRP_KONTROLA_JMEN``: ``odmitnout`` (výchozí) – dotaz se na KRP
    neodešle; ``varovat`` – odešle se a odpověď nese upozornění; ``vypnuto``."""
    r = (os.environ.get("SEZ_KRP_KONTROLA_JMEN") or REZIM_ODMITNOUT).strip().lower()
    return r if r in (REZIM_ODMITNOUT, REZIM_VAROVAT, REZIM_VYPNUTO) else REZIM_ODMITNOUT


def _bez_diakritiky(text: str) -> str:
    rozlozeno = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in rozlozeno if unicodedata.category(ch) != "Mn").casefold()


def _slova(text: str) -> list[str]:
    return [s for s in re.split(r"[ \-'\u2019]+", _bez_diakritiky(text)) if s]


def jmeno_chyba(text, pole: str = "jméno") -> str | None:
    """Vrátí důvod, proč hodnota nesmí jít do KRP jako jméno/příjmení, nebo
    ``None``. Prázdná hodnota chybou není (povinnost řeší volající)."""
    s = unicodedata.normalize("NFC", str(text or "")).strip()
    if not s:
        return None
    nepovolene = sorted({ch for ch in s
                         if not (unicodedata.category(ch)[0] in ("L", "M")
                                 or ch in _JMENO_ODDELOVACE)})
    if nepovolene:
        return (f"Pole {pole} obsahuje nepovolené znaky "
                f"({' '.join(repr(ch) for ch in nepovolene[:8])}); povolena jsou jen "
                "písmena, spojovník, apostrof a mezera.")
    if not any(unicodedata.category(ch)[0] == "L" for ch in s):
        return f"Pole {pole} neobsahuje žádné písmeno."
    zakazana = [w for w in _slova(s) if w in JMENA_ZAKAZANA_SLOVA]
    if zakazana:
        return (f"Pole {pole} obsahuje zástupnou hodnotu ({s!r}), ne jméno "
                "skutečné osoby.")
    return None


def kontrola_jmena(jmeno=None, prijmeni=None) -> list[str]:
    """Všechny důvody, proč dvojici jméno + příjmení neposílat do KRP."""
    chyby = [ch for ch in (jmeno_chyba(jmeno, "jméno"),
                           jmeno_chyba(prijmeni, "příjmení")) if ch]
    cele = " ".join(_slova(f"{jmeno or ''} {prijmeni or ''}"))
    if cele in JMENA_ZAKAZANA_CELA and not chyby:
        chyby.append(f"Jméno a příjmení „{str(jmeno).strip()} {str(prijmeni).strip()}“ "
                     "je zástupná hodnota, ne skutečná osoba.")
    return chyby


JMENA_DUVOD = (
    "MZ ČR (3. 11. 2026): zjevně chybná jména zatěžují KRP a způsobují nadměrné "
    "dotazy do ISZR; ve jméně ani příjmení nesmí být jiné znaky než písmena, "
    "spojovník, apostrof a mezera.")


# ---------------------------------------------------------------------------
# Univerzální vyhledání (kap. 4.5.1, metoda VyhledejUni)
# ---------------------------------------------------------------------------

UNI_KOMBINACE = (
    ("rodneCislo", "Jméno + Příjmení + Rodné číslo"),
    ("cisloPojistence", "Jméno + Příjmení + Číslo pojištěnce"),
    ("datumNarozeni", "Jméno + Příjmení + Datum narození"),
    ("adresaPobytu", "Jméno + Příjmení + Adresa pobytu"),
    ("doklady", "Jméno + Příjmení + Doklad"),
)

# Kombinace, které verze 1.2 u univerzálního hledání uváděla a 1.3 už ne.
UNI_ODEBRANE_KOMBINACE = (
    "samotné RID (použijte hledat/rid)",
    "samotný doklad (použijte hledat/doklady)",
    "rodné příjmení místo příjmení",
    "státní občanství + číslo pojištěnce (použijte hledat/cizinec_cp)",
)


def _vyplneno(hodnota) -> bool:
    if hodnota is None:
        return False
    if isinstance(hodnota, str):
        return bool(hodnota.strip())
    if isinstance(hodnota, (list, tuple, dict, set)):
        return bool(hodnota)
    return True


def uni_kombinace(data: dict) -> str | None:
    """Název první povolené kombinace Standardu 1.3, kterou vstup splňuje."""
    d = data or {}
    if not (_vyplneno(d.get("jmeno")) and _vyplneno(d.get("prijmeni"))):
        return None
    for pole, nazev in UNI_KOMBINACE:
        if _vyplneno(d.get(pole)):
            return nazev
    return None


def uni_upozorneni(data: dict) -> str | None:
    if uni_kombinace(data):
        return None
    return ("Vstup neodpovídá žádné kombinaci univerzálního hledání dle Standardu "
            "KZR 1.3 (kap. 4.5.1): "
            + "; ".join(n for _, n in UNI_KOMBINACE)
            + ". Swagger KRP 3.0.6 kombinace nevynucuje; zda je vynucuje brána, "
              "není ověřeno.")


# ---------------------------------------------------------------------------
# Hromadné ztotožnění (kap. 4.4.5)
# ---------------------------------------------------------------------------

# 1.2: „Velikost souboru je omezena na 2 GB. Je doporučeno omezit … dávku do
# 1 milionu záznamů.“ → 1.3: „Velikost dávky je omezena na 10 000 pacientů.“
DAVKA_MAX_PACIENTU = 10_000
# Plány MZ ČR 3. 11. 2026: „zpracování jednoho souboru trvá cca 30 minut“.
DAVKA_DOBA_ZPRACOVANI_MIN = 30
# Jak dlouho má klient na výsledek čekat (rezerva nad provozní odhad).
DAVKA_CEKANI_S = 45 * 60

_PACIENT_RE = re.compile(r"<Pacient\b[^>]*>.*?</Pacient\s*>", re.S)


def pocet_pacientu(xml_text: str) -> int:
    return len(_PACIENT_RE.findall(xml_text or ""))


def rozdel_davku(xml_text: str, limit: int = DAVKA_MAX_PACIENTU) -> list[str]:
    """Rozdělí XML dávku ``<Davka>`` na části po nejvýše ``limit`` pacientech.
    Hlavička, patička i jednotlivé elementy ``<Pacient>`` zůstávají beze změny."""
    if limit < 1:
        raise ValueError("Limit dávky musí být kladný.")
    nalezy = list(_PACIENT_RE.finditer(xml_text or ""))
    if len(nalezy) <= limit:
        return [xml_text]
    hlava = xml_text[:nalezy[0].start()]
    pata = xml_text[nalezy[-1].end():]
    oddelovac = xml_text[nalezy[0].end():nalezy[1].start()]
    casti = []
    for i in range(0, len(nalezy), limit):
        blok = oddelovac.join(m.group(0) for m in nalezy[i:i + limit])
        casti.append(hlava + blok + pata)
    return casti


def davka_chyba(pocet: int, limit: int = DAVKA_MAX_PACIENTU) -> str | None:
    if pocet <= limit:
        return None
    davek = -(-pocet // limit)
    return (f"Dávka obsahuje {pocet} pacientů, KRP přijímá nejvýše {limit} "
            f"v jedné dávce (Standard KZR 1.3, kap. 4.4.5). Rozdělte ji na "
            f"{davek} dávky a každou podejte samostatně.")


# ---------------------------------------------------------------------------
# Notifikace z KRP (kap. 4.5.3)
# ---------------------------------------------------------------------------

NOTIFIKACE_UDALOSTI = {
    "ZmenaUdaje": "Běžná změna některého z kmenových údajů subjektu",
    "UmrtiPacienta": "Zaznamenání úmrtí pacienta",
    "Reklamace": "Událost vzniklá v rámci reklamačního řízení k údajům subjektu",
    "ZmenaRid": "Změna rezortního identifikátoru, například při ztotožnění záznamů",
}
# Typy, u nichž seznam ``data`` obsahuje vždy právě jednu položku.
NOTIFIKACE_UDALOSTI_JEDNA_POLOZKA = ("UmrtiPacienta", "ZmenaRid")

NOTIFIKACE_OBJEKTY_ZMENY = (
    "Jmeno", "Prijmeni", "RodnePrijmeni", "RodneCislo", "DatumNarozeni",
    "DatumUmrti", "Pohlavi", "CisloPojistence", "KodPojistovny",
    "ZdravotniPojisteniPacientaPlatneOd", "ZdravotniPojisteniPacientaPlatneDo",
    "ObcanstviKod", "TrvalaAdresa", "KontaktniAdresa", "KontaktniEmail",
    "KontaktniTelefon", "DatovaSchranka", "PreferovanyJazyk", "MistoNarozeni",
    "MistoNarozeniZemeKod", "MistoNarozeniSvetNazev", "TypDokladu",
    "CisloDokladu", "TypDokladuStatKod", "OmezeniSvepravnosti",
    "OpravneniZbraneMunice", "RegistrujiciLekar", "RegistrujiciLekarPlatnostOd",
    "RegistrujiciLekarPlatnostDo", "ReferencniOsobaPacientaJmeno",
    "ReferencniOsobaPacientaPrijmeni", "PacientStav", "PacientTyp", "RID",
)

NOTIFIKACE_TYP_ZPRAVY = "KZR.Notifikace"
NOTIFIKACE_VERZE_ZPRAVY = "1.1"

# Příklad zprávy složený z polí uvedených ve Standardu 1.3, kap. 4.5.3.6
# (závorky příkladu v PDF nejsou validní JSON – struktura je dopočítaná).
NOTIFIKACE_PRIKLAD = {
    "udalostId": "5d1c8c0e-6f0b-4c53-9a54-3f1f5b0f6a11",
    "udalostType": NOTIFIKACE_TYP_ZPRAVY,
    "udalostVerze": NOTIFIKACE_VERZE_ZPRAVY,
    "casovaZnacka": "2026-09-18T08:15:00Z",
    "zdroj": "KRP",
    "korelaceId": "0b7f1a52-3c0d-4d55-8f0e-2a9d6c1e7b42",
    "data": [{
        "typPredmetu": "RID",
        "id": "2393511146",
        "typUdalosti": "ZmenaUdaje",
        "puvodniHodnota": "Libor",
        "novaHodnota": "Petr",
        "objektZmeny": "Jmeno",
    }],
    "prijemce": {
        "typ": "IČO",
        "id": "00064165",
        "url": ["https://api.vfn.cz/kzr/notifikace/prijem"],
    },
}


def _seznam(hodnota) -> list:
    if hodnota is None or hodnota == "":
        return []
    if isinstance(hodnota, (list, tuple)):
        return [h for h in hodnota if h not in (None, "")]
    return [hodnota]


def notifikace_odber(rid, url: str | None = None, subjekt_id: str | None = None) -> dict:
    """Tělo ``zadostData`` pro ``POST …/notifikace/zalozit/odber``.

    Standard 1.3 (4.5.3.1) uvádí vstupy RID [1..*], URL [0..1] a subjektId
    [0..1] (IČO); swagger 3.0.6 je přenáší jako ``predmet[].rid``,
    ``prijemci.url`` a ``subjektId``. Bez URL se použije výchozí adresa
    poskytovatele uložená v KRPZS."""
    ridy = [str(r).strip() for r in _seznam(rid) if str(r).strip()]
    if not ridy:
        raise ValueError("Pro založení odběru notifikací zadejte alespoň jeden RID.")
    data: dict = {"predmet": [{"rid": r} for r in ridy]}
    if url and str(url).strip():
        adresa = str(url).strip()
        if not re.match(r"^https?://", adresa, re.I):
            raise ValueError("URL pro příjem notifikací musí začínat http:// nebo https://.")
        data["prijemci"] = {"url": adresa}
    if subjekt_id and str(subjekt_id).strip():
        data["subjektId"] = str(subjekt_id).strip()
    return data


def notifikace_odber_z_volneho_tela(telo: dict) -> dict:
    """Převede starší tvary těla (GUI před revizí 11/2026: ``subjektId`` = RID,
    ``kanalTyp``, ``cil``, ``typyUdalosti``; panel v3: ``Rid``, ``CallbackUrl``)
    na tělo dle swaggeru 3.0.6. Tělo, které už ``predmet`` má, se jen očistí
    od polí, která schéma nezná (``additionalProperties: false``)."""
    t = dict(telo or {})
    if isinstance(t.get("zadostData"), dict):
        t = dict(t["zadostData"])
    if isinstance(t.get("data"), dict):
        t = dict(t["data"])
    if t.get("predmet"):
        ridy = [(p.get("rid") if isinstance(p, dict) else p) for p in _seznam(t["predmet"])]
        prijemci = t.get("prijemci") or {}
        url = prijemci.get("url") if isinstance(prijemci, dict) else None
        return notifikace_odber(ridy, url or t.get("url"), t.get("subjektId"))
    ridy = _seznam(t.get("rid") or t.get("Rid") or t.get("RID") or t.get("ridy"))
    subjekt = t.get("ico") or t.get("subjektIco")
    if not ridy and t.get("subjektId") and "cil" in t:
        # starý tvar GUI: RID pacienta se posílal v subjektId
        ridy = _seznam(t.get("subjektId"))
    elif t.get("subjektId"):
        subjekt = subjekt or t.get("subjektId")
    url = t.get("url") or t.get("URL") or t.get("CallbackUrl") or t.get("callbackUrl") or t.get("cil")
    return notifikace_odber(ridy, url, subjekt)


def notifikace_zprava(zprava) -> dict:
    """Rozebere příchozí zprávu ``KZR.Notifikace`` (Standard 1.3, kap. 4.5.3.4
    až 4.5.3.6) a ověří pravidla, která standard uvádí.

    Vrací ``{platna, chyby, upozorneni, rid, typyUdalosti, udalosti, …}``.
    Neznámý typ události ani neznámý ``objektZmeny`` zprávu neznehodnotí –
    hodnota se zachová a jen se na ni upozorní."""
    chyby: list[str] = []
    upozorneni: list[str] = []
    if not isinstance(zprava, dict):
        return {"platna": False, "chyby": ["Zpráva není JSON objekt."],
                "upozorneni": [], "udalosti": [], "typyUdalosti": [], "rid": None}

    if "data" not in zprava and ("idKorelace" in zprava or "zdrojovySystem" in zprava):
        return {
            "platna": False,
            "tvar": "PushPZSMessageRequest",
            "chyby": ["Zpráva má obálku centrálního systému notifikací "
                      "(PushPZSMessageRequest), ne tvar KZR.Notifikace ze "
                      "Standardu KZR 1.3."],
            "upozorneni": [], "udalosti": [], "typyUdalosti": [], "rid": None,
            "korelaceId": zprava.get("idKorelace"),
            "zdroj": zprava.get("zdrojovySystem"),
        }

    typ = zprava.get("udalostType")
    if typ != NOTIFIKACE_TYP_ZPRAVY:
        upozorneni.append(f"udalostType je {typ!r}, očekává se {NOTIFIKACE_TYP_ZPRAVY!r}.")
    verze = zprava.get("udalostVerze")
    if verze not in (None, NOTIFIKACE_VERZE_ZPRAVY):
        upozorneni.append(f"udalostVerze je {verze!r}; parser odpovídá verzi "
                          f"{NOTIFIKACE_VERZE_ZPRAVY}.")
    for pole in ("udalostId", "casovaZnacka", "zdroj"):
        if not zprava.get(pole):
            upozorneni.append(f"Chybí pole {pole}.")

    data = zprava.get("data")
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        chyby.append("Seznam data je prázdný – standard uvádí, že prázdný není nikdy.")
        data = []

    udalosti = []
    for i, polozka in enumerate(data):
        if not isinstance(polozka, dict):
            chyby.append(f"data[{i}] není objekt.")
            continue
        typ_udalosti = polozka.get("typUdalosti")
        objekty = [str(o) for o in _seznam(polozka.get("objektZmeny"))]
        if not typ_udalosti:
            chyby.append(f"data[{i}] nemá typUdalosti.")
        elif typ_udalosti not in NOTIFIKACE_UDALOSTI:
            upozorneni.append(f"data[{i}]: neznámý typUdalosti {typ_udalosti!r}.")
        nezname = [o for o in objekty if o not in NOTIFIKACE_OBJEKTY_ZMENY]
        if nezname:
            upozorneni.append(f"data[{i}]: neznámý objektZmeny {', '.join(nezname)}.")
        if not polozka.get("id"):
            chyby.append(f"data[{i}] nemá id (RID pacienta).")
        udalosti.append({
            "typPredmetu": polozka.get("typPredmetu"),
            "id": None if polozka.get("id") is None else str(polozka.get("id")),
            "typUdalosti": typ_udalosti,
            "popisUdalosti": NOTIFIKACE_UDALOSTI.get(typ_udalosti),
            "objektZmeny": objekty,
            "puvodniHodnota": polozka.get("puvodniHodnota"),
            "novaHodnota": polozka.get("novaHodnota"),
        })

    ridy = sorted({u["id"] for u in udalosti if u["id"]})
    if len(ridy) > 1:
        chyby.append("Události jedné zprávy se musí týkat téhož RID; zpráva "
                     f"obsahuje {', '.join(ridy)}.")
    typy = []
    for u in udalosti:
        if u["typUdalosti"] and u["typUdalosti"] not in typy:
            typy.append(u["typUdalosti"])
    for jedina in NOTIFIKACE_UDALOSTI_JEDNA_POLOZKA:
        if jedina in typy and len(udalosti) != 1:
            chyby.append(f"Zpráva typu {jedina} musí obsahovat právě jednu položku "
                         f"data, obsahuje {len(udalosti)}.")

    prijemce = zprava.get("prijemce") if isinstance(zprava.get("prijemce"), dict) else {}
    return {
        "platna": not chyby,
        "tvar": NOTIFIKACE_TYP_ZPRAVY,
        "chyby": chyby,
        "upozorneni": upozorneni,
        "udalostId": zprava.get("udalostId"),
        "udalostType": typ,
        "udalostVerze": verze,
        "casovaZnacka": zprava.get("casovaZnacka"),
        "zdroj": zprava.get("zdroj"),
        "korelaceId": zprava.get("korelaceId"),
        "rid": ridy[0] if len(ridy) == 1 else None,
        "typyUdalosti": typy,
        "umrti": "UmrtiPacienta" in typy,
        "zmenaRid": "ZmenaRid" in typy,
        "udalosti": udalosti,
        "prijemce": {
            "typ": prijemce.get("typ"),
            "id": prijemce.get("id"),
            "url": [str(u) for u in _seznam(prijemce.get("url"))],
        },
    }


# ---------------------------------------------------------------------------
# Vypínání starších verzí API KRP
# ---------------------------------------------------------------------------

VERZE_API_STAV = {
    "oznameni_2026_08_27": "Ke dni 15. 9. 2026 bude vypnuto API KRP pro PZS verze "
                           "v1 a v2. K dispozici je API verze v3. (Novinky EZ)",
    "plan_2026_11_03": "Rádi bychom do konce roku vypnuli podporu v1 API, zůstane "
                       "pouze v2 a v3. (Novinky a plány, odstavec KZR i SZZ)",
    "zaver": "Oba zdroje si odporují v osudu v2 a z této sítě se vypnutí nedalo "
             "ověřit. Výchozí je v3 (zůstává podle obou); v2 lze zapnout přes "
             "SEZ_KRP_VERZE=v2 a jeho dostupnost je nutné ověřit na bráně.",
}


def pravidla() -> dict:
    """Přehled pravidel pro GUI a dokumentaci (``GET /api/krp/pravidla``)."""
    return {
        "standard": {"verze": STANDARD_VERZE, "platnostOd": STANDARD_PLATNOST,
                     "predchozi": STANDARD_PREDCHOZI},
        "drid": {
            "vzor": "^D\\d{9}$",
            "pravidlo": "číslo za D je dělitelné 13 a není dělitelné 11",
            "zasoba": DRID_ZASOBA,
            "ucel": DRID_UCEL,
        },
        "rid": {"vzor": "^[1-9]\\d{9}$",
                "pravidlo": "dělitelné 13 a není dělitelné 11"},
        "jmena": {
            "rezim": rezim_kontroly_jmen(),
            "povoleneZnaky": "písmena, spojovník, apostrof, mezera",
            "zakazanaSlova": sorted(JMENA_ZAKAZANA_SLOVA),
            "zakazanaCela": sorted(JMENA_ZAKAZANA_CELA),
            "duvod": JMENA_DUVOD,
        },
        "uni": {"kombinace": [n for _, n in UNI_KOMBINACE],
                "odebraneKombinace": list(UNI_ODEBRANE_KOMBINACE)},
        "hromadneZtotozneni": {
            "maxPacientu": DAVKA_MAX_PACIENTU,
            "dobaZpracovaniMin": DAVKA_DOBA_ZPRACOVANI_MIN,
            "cekaniS": DAVKA_CEKANI_S,
        },
        "notifikace": {
            "typZpravy": NOTIFIKACE_TYP_ZPRAVY,
            "verzeZpravy": NOTIFIKACE_VERZE_ZPRAVY,
            "udalosti": NOTIFIKACE_UDALOSTI,
            "objektyZmeny": list(NOTIFIKACE_OBJEKTY_ZMENY),
            "priklad": NOTIFIKACE_PRIKLAD,
        },
        "verzeApi": VERZE_API_STAV,
    }
