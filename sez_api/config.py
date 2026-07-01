"""
Konfigurace SEZ API klienta.
Načítá se z proměnných prostředí nebo .env souboru.
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    _env_file = Path.cwd() / ".env"
    if _env_file.exists():
        load_dotenv(_env_file)
except ImportError:
    pass


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


CLIENT_ID = env("SEZ_CLIENT_ID", "")
P12_PATH = env("SEZ_P12_PATH", "")
P12_PASSWORD = env("SEZ_P12_PASSWORD", "")
CERT_UID = env("SEZ_CERT_UID", "")
GATEWAY = env("SEZ_GATEWAY", "https://gwy-ext-sec-t2.csez.cz")
HOST = env("SEZ_HOST", "0.0.0.0")
PORT = int(env("SEZ_PORT", "8004"))
WORKERS = int(env("SEZ_WORKERS", "1"))

# Interní API (ztotožnění → RID). Když je SEZ_INTERNAL_API_KEY neprázdné,
# vyžaduje se hlavička X-Api-Key. Prázdné = bez ochrany (jen interní síť).
INTERNAL_API_KEY = env("SEZ_INTERNAL_API_KEY", "")
# Prostředí, proti kterému interní API ztotožňuje (default produkce).
INTERNAL_ENV = env("SEZ_INTERNAL_ENV", "PROD")

PROD_CLIENT_ID = env("SEZ_PROD_CLIENT_ID", "")
PROD_P12_PATH = env("SEZ_PROD_P12_PATH", "")
PROD_P12_PASSWORD = env("SEZ_PROD_P12_PASSWORD", "")
PROD_CERT_UID = env("SEZ_PROD_CERT_UID", "")
PROD_GATEWAY = env("SEZ_PROD_GATEWAY", "")
PROD_JSU_AUDIENCE = env("SEZ_PROD_JSU_AUDIENCE", "")

# CMS2 = alternativní cesta pro PZS přes neveřejnou síť (vs. Internet).
# Stejné credentials/cert jako pro Internet – jen jiný gateway hostname.
T2_CMS_GATEWAY = env("SEZ_T2_CMS_GATEWAY", "")
PROD_CMS_GATEWAY = env("SEZ_PROD_CMS_GATEWAY", "")

PEER_URLS: list[str] = [
    u.strip() for u in env("SEZ_PEER_URLS", "").split(",") if u.strip()
]

# ---------------------------------------------------------------------------
# SÚKL – eRecept / CÚER a Databáze léčivých přípravků (DLP)
# ---------------------------------------------------------------------------
# eRecept (CÚER) je samostatný systém SÚKL (SOAP web services, verze rozhraní
# 202501A, dokumentace na epreskripce.gov.cz). Vyžaduje registraci SW u SÚKL
# (registrační ID) a certifikát. Bez těchto přístupů běží integrace v režimu
# SIMULACE (in-memory engine + builder request obálek). Když jsou nakonfigurovány
# SUKL_ERECEPT_ENDPOINT + SUKL_REG_ID (+ volitelně certifikát), přepne se na ŽIVÉ volání.
#
# DLP (Databáze léčivých přípravků) jsou VEŘEJNÁ otevřená data (opendata.sukl.cz),
# napojují se reálně bez certifikátu.

def _env_bool(key: str, default: bool = True) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "ano", "on")


SUKL_ENABLED = _env_bool("SUKL_ENABLED", True)
SUKL_INTERFACE_VERSION = env("SUKL_INTERFACE_VERSION", "202501A")
# Textová identifikace výrobce SW (posílá se v hlavičce eRecept requestu).
SUKL_VYROBCE = env("SUKL_VYROBCE", "SEZ API Web (mirapavlicek/sezapi)")
# Registrační ID přidělené SÚKL (12 znaků eRecept / 9 znaků ePoukaz). Prázdné = simulace.
SUKL_REG_ID = env("SUKL_REG_ID", "")
# Endpoint testovacího/produkčního eRecept rozhraní (SOAP). Prázdné = simulace.
SUKL_ERECEPT_ENDPOINT_TEST = env("SUKL_ERECEPT_ENDPOINT_TEST", "")
SUKL_ERECEPT_ENDPOINT = env("SUKL_ERECEPT_ENDPOINT", "")
# Certifikát pro mTLS k eRecept (volitelné, když se liší od SEZ certifikátu).
SUKL_CERT_PATH = env("SUKL_CERT_PATH", "")
SUKL_CERT_PASSWORD = env("SUKL_CERT_PASSWORD", "")
# DLP – URL aktuálního balíku otevřených dat a lokální cache.
SUKL_DLP_URL = env(
    "SUKL_DLP_URL",
    "https://opendata.sukl.cz/soubory/SOD20260101/DLP_CADORE.zip",
)
SUKL_DLP_CACHE_DIR = env("SUKL_DLP_CACHE_DIR", "/tmp/sukl_dlp")


def sukl_erecept_endpoint(env_key: str = "T2") -> str:
    """Vrátí aktivní eRecept endpoint dle prostředí (PROD/T2)."""
    if env_key == "PROD" and SUKL_ERECEPT_ENDPOINT:
        return SUKL_ERECEPT_ENDPOINT
    return SUKL_ERECEPT_ENDPOINT_TEST or SUKL_ERECEPT_ENDPOINT


def sukl_mode(env_key: str = "T2") -> str:
    """LIVE pokud je nakonfigurován endpoint i registrační ID, jinak SIM."""
    if not SUKL_ENABLED:
        return "OFF"
    if sukl_erecept_endpoint(env_key) and SUKL_REG_ID:
        return "LIVE"
    return "SIM"


# Vzorové léčivé přípravky (offline fallback pro DLP, když stažení dat selže).
# Zdroj: veřejná Databáze léčivých přípravků SÚKL (ilustrativní výběr).
SUKL_DLP_SAMPLE = [
    {"kod": "0031505", "nazev": "PARALEN 500", "sila": "500MG", "forma": "TBL NOB",
     "baleni": "24", "atc": "N02BE01", "ucinna_latka": "PARACETAMOLUM", "cesta": "POR",
     "drzitel": "sanofi-aventis, s.r.o., Praha", "stav_registrace": "R", "vydej": "volný"},
    {"kod": "0100000", "nazev": "IBALGIN 400", "sila": "400MG", "forma": "TBL FLM",
     "baleni": "30", "atc": "M01AE01", "ucinna_latka": "IBUPROFENUM", "cesta": "POR",
     "drzitel": "Zentiva, k.s., Praha", "stav_registrace": "R", "vydej": "volný"},
    {"kod": "0184756", "nazev": "AUGMENTIN 1 G", "sila": "875MG/125MG", "forma": "TBL FLM",
     "baleni": "14", "atc": "J01CR02", "ucinna_latka": "AMOXICILLINUM/ACIDUM CLAVULANICUM",
     "cesta": "POR", "drzitel": "GlaxoSmithKline, Praha", "stav_registrace": "R", "vydej": "Rp."},
    {"kod": "0207684", "nazev": "EUTHYROX 100 MICROGRAMU", "sila": "100MCG", "forma": "TBL NOB",
     "baleni": "100", "atc": "H03AA01", "ucinna_latka": "LEVOTHYROXINUM NATRICUM", "cesta": "POR",
     "drzitel": "Merck spol. s r.o., Praha", "stav_registrace": "R", "vydej": "Rp."},
    {"kod": "0149671", "nazev": "WARFARIN ORION 5 MG", "sila": "5MG", "forma": "TBL NOB",
     "baleni": "100", "atc": "B01AA03", "ucinna_latka": "WARFARINUM NATRICUM", "cesta": "POR",
     "drzitel": "Orion Corporation, Espoo", "stav_registrace": "R", "vydej": "Rp."},
    {"kod": "0056022", "nazev": "APO-OME 20", "sila": "20MG", "forma": "CPS ETD",
     "baleni": "28", "atc": "A02BC01", "ucinna_latka": "OMEPRAZOLUM", "cesta": "POR",
     "drzitel": "Apotex Europe B.V.", "stav_registrace": "R", "vydej": "volný"},
    {"kod": "0242631", "nazev": "METFORMIN MYLAN 1000 MG", "sila": "1000MG", "forma": "TBL FLM",
     "baleni": "60", "atc": "A10BA02", "ucinna_latka": "METFORMINI HYDROCHLORIDUM", "cesta": "POR",
     "drzitel": "Viatris (Mylan), Praha", "stav_registrace": "R", "vydej": "Rp."},
    {"kod": "0100742", "nazev": "PREDNISON 5 LÉČIVA", "sila": "5MG", "forma": "TBL NOB",
     "baleni": "20", "atc": "H02AB07", "ucinna_latka": "PREDNISONUM", "cesta": "POR",
     "drzitel": "Zentiva, k.s., Praha", "stav_registrace": "R", "vydej": "Rp."},
]

# Vzorové identifikátory eReceptu pro rychlé vyplnění v UI (simulace).
SUKL_TEST_ERECEPTY = [
    {"id": "1234567890AB", "pacient_rid": "3740100325", "popis": "MUSÍLEK METODĚJ – ukázka"},
    {"id": "ABCDEF123456", "pacient_rid": "5785446836", "popis": "NOSKOVÁ PETRA – ukázka"},
]

# ---------------------------------------------------------------------------
# ÚZIS ČR – NZIS (Národní zdravotnický informační systém)
# ---------------------------------------------------------------------------
# NRPZS (Národní registr poskytovatelů zdravotních služeb) má VEŘEJNÉ REST API
# (nrpzs.uzis.cz/api/v1, OAS 2.0) – napojuje se reálně, s offline fallbackem.
# Národní zdravotnické registry (NZR) a hlášení do NZIS jsou cert-authenticated
# (EREG/EZCA) → běží v režimu SIMULACE, dokud není nakonfigurován endpoint + cert.
UZIS_ENABLED = _env_bool("UZIS_ENABLED", True)
UZIS_NRPZS_URL = env("UZIS_NRPZS_URL", "https://nrpzs.uzis.cz/api/v1")
# Endpoint pro hlášení do Národních zdravotnických registrů (restAPI EREG/EZCA).
UZIS_NZR_ENDPOINT_TEST = env("UZIS_NZR_ENDPOINT_TEST", "")
UZIS_NZR_ENDPOINT = env("UZIS_NZR_ENDPOINT", "")
# Certifikát pro NZIS (volitelné; prázdné = použije se cert CSEZ/EZCA klienta).
UZIS_CERT_PATH = env("UZIS_CERT_PATH", "")
UZIS_CERT_PASSWORD = env("UZIS_CERT_PASSWORD", "")


def uzis_nzr_endpoint(env_key: str = "T2") -> str:
    if env_key == "PROD" and UZIS_NZR_ENDPOINT:
        return UZIS_NZR_ENDPOINT
    return UZIS_NZR_ENDPOINT_TEST or UZIS_NZR_ENDPOINT


def uzis_mode(env_key: str = "T2") -> str:
    if not UZIS_ENABLED:
        return "OFF"
    if uzis_nzr_endpoint(env_key):
        return "LIVE"
    return "SIM"


# Katalog Národních zdravotnických registrů (NZR) spravovaných ÚZIS ČR.
UZIS_NZR_KATALOG = [
    {"kod": "NRPZS", "nazev": "Národní registr poskytovatelů zdravotních služeb", "typ": "registr", "verejny": True},
    {"kod": "NRZP", "nazev": "Národní registr zdravotnických pracovníků", "typ": "registr", "verejny": False},
    {"kod": "NOR", "nazev": "Národní onkologický registr", "typ": "registr", "verejny": False},
    {"kod": "NRHOSP", "nazev": "Národní registr hospitalizovaných", "typ": "registr", "verejny": False},
    {"kod": "NRRZ", "nazev": "Národní registr reprodukčního zdraví", "typ": "registr", "verejny": False},
    {"kod": "NRNAR", "nazev": "Národní registr novorozenců (rodiček)", "typ": "registr", "verejny": False},
    {"kod": "NRVAR", "nazev": "Národní registr vrozených vad", "typ": "registr", "verejny": False},
    {"kod": "NRKN", "nazev": "Národní registr kardiovaskulárních operací a intervencí", "typ": "registr", "verejny": False},
    {"kod": "NRPCNP", "nazev": "Národní registr pitev a toxikologických vyšetření", "typ": "registr", "verejny": False},
    {"kod": "NRLPZ", "nazev": "Národní registr léčby uživatelů drog", "typ": "registr", "verejny": False},
    {"kod": "ISIN", "nazev": "Informační systém infekčních nemocí", "typ": "systém", "verejny": False},
    {"kod": "OCKO", "nazev": "Registr očkování (ISIN – ocko.uzis.cz)", "typ": "systém", "verejny": False},
    {"kod": "NRPZS_HLAS", "nazev": "Roční výkaz o činnosti poskytovatele (NZIS)", "typ": "hlášení", "verejny": False},
]

# Vzorové číselníky NZIS (offline fallback). Zdroj: resortní číselníky ÚZIS/NRPZS.
UZIS_CISELNIKY_SAMPLE = {
    "kraje": [
        {"kod": "CZ010", "nazev": "Hlavní město Praha"},
        {"kod": "CZ031", "nazev": "Jihočeský kraj"},
        {"kod": "CZ042", "nazev": "Ústecký kraj"},
        {"kod": "CZ080", "nazev": "Moravskoslezský kraj"},
        {"kod": "CZ064", "nazev": "Jihomoravský kraj"},
    ],
    "obory_pece": [
        {"kod": "001", "nazev": "všeobecné praktické lékařství"},
        {"kod": "002", "nazev": "praktické lékařství pro děti a dorost"},
        {"kod": "101", "nazev": "vnitřní lékařství"},
        {"kod": "501", "nazev": "chirurgie"},
        {"kod": "705", "nazev": "radiologie a zobrazovací metody"},
        {"kod": "801", "nazev": "klinická biochemie"},
    ],
    "forma_pece": [
        {"kod": "A", "nazev": "ambulantní péče"},
        {"kod": "L", "nazev": "lůžková péče"},
        {"kod": "1D", "nazev": "jednodenní péče"},
        {"kod": "DP", "nazev": "domácí péče"},
    ],
    "druh_pece": [
        {"kod": "P", "nazev": "primární"},
        {"kod": "S", "nazev": "specializovaná"},
        {"kod": "N", "nazev": "následná"},
    ],
}

# Vzoroví poskytovatelé (offline fallback pro NRPZS, když API není dostupné).
UZIS_NRPZS_SAMPLE = [
    {"icz": "42100000", "ico": "25488627", "nazev": "Krajská zdravotní, a.s.",
     "obec": "Ústí nad Labem", "kraj": "Ústecký kraj", "psc": "40113",
     "obor": "vnitřní lékařství", "forma": "lůžková péče", "druh": "specializovaná",
     "adresa": "Sociální péče 3316/12A, Ústí nad Labem", "web": "www.kzcr.eu"},
    {"icz": "00064165", "ico": "00064165", "nazev": "Všeobecná fakultní nemocnice v Praze",
     "obec": "Praha 2", "kraj": "Hlavní město Praha", "psc": "12808",
     "obor": "vnitřní lékařství", "forma": "lůžková péče", "druh": "specializovaná",
     "adresa": "U Nemocnice 499/2, Praha 2", "web": "www.vfn.cz"},
    {"icz": "00179906", "ico": "00179906", "nazev": "Fakultní nemocnice Hradec Králové",
     "obec": "Hradec Králové", "kraj": "Královéhradecký kraj", "psc": "50005",
     "obor": "chirurgie", "forma": "lůžková péče", "druh": "specializovaná",
     "adresa": "Sokolská 581, Hradec Králové", "web": "www.fnhk.cz"},
    {"icz": "00669806", "ico": "00669806", "nazev": "Fakultní nemocnice Plzeň",
     "obec": "Plzeň", "kraj": "Plzeňský kraj", "psc": "30460",
     "obor": "radiologie a zobrazovací metody", "forma": "lůžková péče", "druh": "specializovaná",
     "adresa": "Edvarda Beneše 1128/13, Plzeň", "web": "www.fnplzen.cz"},
    {"icz": "28821599", "ico": "28821599", "nazev": "Gynekologie Jičín s.r.o.",
     "obec": "Jičín", "kraj": "Královéhradecký kraj", "psc": "50601",
     "obor": "gynekologie a porodnictví", "forma": "ambulantní péče", "druh": "specializovaná",
     "adresa": "Fügnerova 39, Jičín", "web": ""},
    {"icz": "28375556", "ico": "28375556", "nazev": "Praktický lékař pro děti a dorost s.r.o.",
     "obec": "Kutná Hora", "kraj": "Středočeský kraj", "psc": "28401",
     "obor": "praktické lékařství pro děti a dorost", "forma": "ambulantní péče", "druh": "primární",
     "adresa": "Nádražní 254, Kutná Hora", "web": ""},
]

# CMS2 sdílí credentials s odpovídajícím Internet prostředím.
ENV_CREDENTIALS = {
    "T2": {
        "client_id": CLIENT_ID,
        "p12_path": P12_PATH,
        "p12_password": P12_PASSWORD,
        "cert_uid": CERT_UID,
    },
    "T2_CMS": {
        "client_id": CLIENT_ID,
        "p12_path": P12_PATH,
        "p12_password": P12_PASSWORD,
        "cert_uid": CERT_UID,
    },
    "PROD": {
        "client_id": PROD_CLIENT_ID,
        "p12_path": PROD_P12_PATH,
        "p12_password": PROD_P12_PASSWORD,
        "cert_uid": PROD_CERT_UID,
    },
    "PROD_CMS": {
        "client_id": PROD_CLIENT_ID,
        "p12_path": PROD_P12_PATH,
        "p12_password": PROD_P12_PASSWORD,
        "cert_uid": PROD_CERT_UID,
    },
}

TEST_PATIENTS = [
    {"rid": "3740100325", "name": "MUSÍLEK METODĚJ", "born": "1929-01-30", "rc": "290130126"},
    {"rid": "6534744190", "name": "VOSÁHLO ZORAN", "born": "1977-05-03", "rc": "7705034392"},
    {"rid": "4568822375", "name": "ZIKMUNDOVÁ ZITA", "born": "1971-12-31", "rc": "7162314412"},
    {"rid": "4464682573", "name": "SCHRÁNKA STANDA", "born": "1990-09-09", "rc": "9009094413"},
    {"rid": "3976789440", "name": "HOÂNG TUÂŃ MINH", "born": "1957-06-19", "rc": "5706197794"},
    {"rid": "6938376705", "name": "CHALOUPKA CHRUDOŠ", "born": "1928-05-24", "rc": "280524480"},
    {"rid": "9058642060", "name": "KRÁL IVAN", "born": "2010-04-20", "rc": "1004200010"},
    {"rid": "6551441377", "name": "TICHOŠLÁPEK TADEÁŠ", "born": "1931-07-10", "rc": "310710113"},
    {"rid": "7457267194", "name": "KONOPNÍČEK JONATAN VIKTOR", "born": "1976-06-08", "rc": "7606084398"},
    {"rid": "6259251557", "name": "SVATÁ ANNA", "born": "2013-03-03"},
    {"rid": "7582120377", "name": "ROLNIČKOVÁ RAIMUNDA", "born": "1978-02-10", "rc": "7852104403"},
    {"rid": "6653225891", "name": "ROLNIČKA MAREK", "born": "1968-01-11", "rc": "6801117389"},
    {"rid": "3349564010", "name": "ZVONEČEK ZVONIMÍR", "born": "2007-12-17", "rc": "0712179886"},
    {"rid": "4151841863", "name": "ZVONEČKOVÁ ZAIRA ZLATICA", "born": "2007-12-17", "rc": "0762179880"},
    {"rid": "1294606612", "name": "ROAMANČENÍK JOSEF", "born": "2020-05-15", "rc": "2005152215"},
    {"rid": "8675569448", "name": "ŠÍLENÁ ŠTĚPÁNA", "born": "1963-03-13", "rc": "6353138385"},
    {"rid": "4376319051", "name": "RELOODON ROLAND", "born": "1976-01-03", "rc": "7601034353"},
    {"rid": "2667873559", "name": "MRAKOMOROVÁ MRAČENA", "born": "1971-11-26", "rc": "7161264528"},
    {"rid": "8754287763", "name": "ZASNĚŽENÁ VILEMÍNA", "born": "1971-06-07", "rc": "7156074530"},
    {"rid": "6668063870", "name": "ROZKOV VALERYI", "born": "1938-05-27", "rc": "380527092"},
    {"rid": "3919805409", "name": "NGUYEN THU VAN THI", "born": "1959-09-19", "rc": "5909197668"},
    {"rid": "8949617456", "name": "SUÁREZ DOMINICA", "born": "1985-12-25"},
    {"rid": "6224935470", "name": "EINSTEIN OSVOJENEC", "born": "2009-10-28", "rc": "0910288863"},
    {"rid": "4860149476", "name": "REQUEST ZDENĚČEK", "born": "1968-04-14"},
    {"rid": "5785446836", "name": "NOSKOVÁ PETRA", "born": "1981-09-26", "rc": "8159260010"},
    {"rid": "3751233551", "name": "PETŘÍK ALOIS", "born": "1971-01-01"},
    {"rid": "1252851691", "name": "PETŘÍKOVÁ ALENA", "born": "2007-09-30"},
    {"rid": "1156887069", "name": "KOMÁRKOVÁ HANA", "born": "1981-04-09"},
    {"rid": "9214531872", "name": "BANGLADEŽO DEŽO", "born": "1958-06-25"},
    {"rid": "7651532629", "name": "PYRENEJSKÁ BOROVICE", "born": "1947-07-14"},
    {"rid": "7649628051", "name": "KAVKAZSKÁ LETNÍ JEDLE", "born": "1947-12-09"},
    {"rid": "7651669233", "name": "LETNÍ ŽALUD", "born": "1947-12-24"},
    {"rid": "6907824768", "name": "DVOŘÁKOVÁ DARJA", "born": "1998-07-11"},
    {"rid": "4967435668", "name": "DVOŘÁKOVÁ PAVLA", "born": "1955-06-07"},
    {"rid": "4538984060", "name": "ADMIRÁL EUSTACH", "born": "2006-04-04"},
    {"rid": "7028236631", "name": "BROUK BOHUMIL", "born": "2013-11-11"},
    {"rid": "4422081352", "name": "MATKA UKONČENÁ KOSTELECKÁ ANEŽKA", "born": "1991-01-01"},
    {"rid": "7324290493", "name": "ČERMÁKOVÁ ELIŠKA", "born": "2010-10-10"},
]

TEST_WORKERS = [
    {"krzpid": "191331954", "name": "LUDMILA LÉKAŘSKÁ", "born": "1992-07-05", "role": "Lékař"},
    {"krzpid": "108765745", "name": "Adrian Christoph Liebert", "born": "1986-12-08", "role": "Lékař"},
    {"krzpid": "100939278", "name": "Christian Udo Malý", "born": "1992-01-25", "role": "Lékař"},
    {"krzpid": "102129137", "name": "MRAČENA MRAKOMOROVÁ", "born": "1971-11-26", "role": "Lékař"},
    {"krzpid": "158350302", "name": "NORBERT NĚMEČEK", "born": "1988-08-08", "role": "Zubní lékař"},
    {"krzpid": "175702010", "name": "PETRA NOSKOVÁ", "born": "1981-09-26", "role": "Lékař"},
    {"krzpid": "111665378", "name": "ZDENĚK AL-OSIMI", "born": "1973-11-09", "role": "Všeob. sestra"},
    {"krzpid": "152816631", "name": "HANA AMBROSOVÁ", "born": "1956-03-02", "role": "Lékař"},
    {"krzpid": "161690144", "name": "Ivan Grabau", "born": "1984-10-28", "role": "Lékař"},
    {"krzpid": "182630602", "name": "JOSEF Prchal", "born": "1983-01-30", "role": "Lékař"},
    {"krzpid": "177550538", "name": "BOROVICE PYRENEJSKÁ", "born": "1947-07-14", "role": "Lékař"},
    {"krzpid": "182481024", "name": "RAIMUNDA ROLNIČKOVÁ", "born": "1978-02-10", "role": "Dětská sestra"},
    {"krzpid": "110683738", "name": "SERVÁC SOUKUP", "born": "1988-08-08", "role": "Lékař"},
    {"krzpid": "155348468", "name": "PAVLA DVOŘÁKOVÁ", "born": "1955-06-07", "role": "Lékař"},
    {"krzpid": "195435779", "name": "JAN Válek", "born": "1953-08-02", "role": "Lékař"},
]

TEST_WORKERS_PZS = [
    {"krzpid": "155348468", "name": "PAVLA DVOŘÁKOVÁ", "ico": "47911492"},
    {"krzpid": "175702010", "name": "PETRA NOSKOVÁ", "ico": "28821599"},
    {"krzpid": "177550538", "name": "BOROVICE PYRENEJSKÁ", "ico": "28375556"},
    {"krzpid": "195435779", "name": "JAN Válek", "ico": "829013"},
]

# Testovací PZS identity v testovacím prostředí T2 (zdroj: MZČR Confluence
# /Podklady pro testování napojení na CSEZ - 529793025).
# Pole "zastupce" / "zastupce_rid" mapují statutárního zástupce přiřazeného
# k danému PZS (viz Testovací identity osob výše v TEST_PATIENTS).
TEST_PZS = [
    {"ico": "25488627", "name": "Krajská zdravotní, a.s.", "city": "Ústí nad Labem", "note": "Náš testovací PZS"},
    # Statutární zástupce: Petra Nosková (RID 5785446836)
    {"ico": "26834022", "name": "Bohumínská městská nemocnice, a.s.", "city": "Bohumín", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "00064165", "name": "Všeobecná fakultní nemocnice v Praze", "city": "Praha 2", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "00179906", "name": "Fakultní nemocnice Hradec Králové", "city": "Hradec Králové", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "27520536", "name": "Nemocnice Pardubického kraje, a.s. - Pardubická nemocnice", "city": "Pardubice", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "27256456", "name": "Oblastní nemocnice Mladá Boleslav, a.s.", "city": "Mladá Boleslav", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "00669806", "name": "Fakultní nemocnice Plzeň", "city": "Plzeň", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "28971906", "name": "Nemocnice Vršovice", "city": "Praha 10", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "47714913", "name": "Nemocnice Ostrov s.r.o.", "city": "Ostrov", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "64827232", "name": "Nemocnice Vrchlabí", "city": "Vrchlabí", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "25443801", "name": "Nemocnice Roudnice nad Labem s.r.o.", "city": "Roudnice nad Labem", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "65269705", "name": "Fakultní nemocnice Brno", "city": "Brno", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "00159816", "name": "Fakultní nemocnice U Svaté Anny", "city": "Brno", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    {"ico": "25897551", "name": "Nemocnice AGEL Český Těšín a.s.", "city": "Český Těšín", "zastupce": "NOSKOVÁ PETRA", "zastupce_rid": "5785446836"},
    # Statutární zástupce: Vilemína Zasněžená (RID 8754287763)
    {"ico": "00064211", "name": "Fakultní nemocnice Bulovka", "city": "Praha 8", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "27283933", "name": "Krajská nemocnice Liberec, a.s.", "city": "Liberec", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "00843904", "name": "Fakultní nemocnice Ostrava", "city": "Ostrava", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "00023001", "name": "Institut klinické a experimentální medicíny", "city": "Praha 4", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "26865858", "name": "Bílovecká nemocnice a.s.", "city": "Bílovec", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "60726636", "name": "EUC Klinika Zlín", "city": "Zlín", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "00064173", "name": "Fakultní nemocnice Královské Vinohrady", "city": "Praha 10", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "00098892", "name": "Fakultní nemocnice Olomouc", "city": "Olomouc", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "00064190", "name": "Fakultní Thomayerova nemocnice", "city": "Praha 4", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "26365804", "name": "Karlovarská krajská nemocnice a.s. - Nemocnice Karlovy Vary", "city": "Karlovy Vary", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "49686356", "name": "MEDITERRA", "city": "", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    {"ico": "05421888", "name": "MMN Semily", "city": "Semily", "zastupce": "ZASNĚŽENÁ VILEMÍNA", "zastupce_rid": "8754287763"},
    # Statutární zástupce: Pyrenejská Borovice (RID 7651532629)
    {"ico": "41197518", "name": "Nemocnice Duchcov", "city": "Duchcov", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "25479300", "name": "Nemocnice Kadaň", "city": "Kadaň", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "00879444", "name": "Nemocnice na Františku", "city": "Praha 1", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "63145766", "name": "Nemocnice Tanvald", "city": "Tanvald", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "28892950", "name": "OB klinika a.s.", "city": "Praha 8", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "00023728", "name": "Revmatologický ústav", "city": "Praha 2", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "00023698", "name": "Ústav pro péči o matku a dítě", "city": "Praha 4", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "26000202", "name": "Oblastní nemocnice Náchod a.s.", "city": "Náchod", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "62061731", "name": "Nemocnice Rychnov nad Kněžnou o.z.", "city": "Rychnov nad Kněžnou", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "25262238", "name": "Městská nemocnice a.s. (Dvůr Králové)", "city": "Dvůr Králové n. Labem", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "27661989", "name": "Krajská nemocnice T. Bati, a.s.", "city": "Zlín", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "00064220", "name": "Psychiatrická nemocnice Bohnice", "city": "Praha 8", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "26432471", "name": "Centrum léčby pohybového aparátu", "city": "Praha 9", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    {"ico": "00023736", "name": "Ústav hematologie a krevní transfuze Praha", "city": "Praha 2", "zastupce": "PYRENEJSKÁ BOROVICE", "zastupce_rid": "7651532629"},
    # Statutární zástupce: Pavla Dvořáková (RID 4967435668)
    {"ico": "26068877", "name": "Nemocnice České Budějovice", "city": "České Budějovice", "zastupce": "DVOŘÁKOVÁ PAVLA", "zastupce_rid": "4967435668"},
    {"ico": "00090638", "name": "Nemocnice Jihlava", "city": "Jihlava", "zastupce": "DVOŘÁKOVÁ PAVLA", "zastupce_rid": "4967435668"},
    {"ico": "66183596", "name": "Městská nemocnice Odry", "city": "Odry", "zastupce": "DVOŘÁKOVÁ PAVLA", "zastupce_rid": "4967435668"},
    {"ico": "00193011", "name": "Ústav chirurgie ruky a plastické chirurgie, p.o.", "city": "Vysoké nad Jizerou", "zastupce": "DVOŘÁKOVÁ PAVLA", "zastupce_rid": "4967435668"},
    # Další PZS, které byly v původním seznamu (mimo oficiální tabulku zástupců)
    {"ico": "60470488", "name": "AeskuLab k.s.", "city": "Praha 6"},
    {"ico": "47911492", "name": "Městská poliklinika u sv. Alžběty, s.r.o.", "city": "Uherské Hradiště"},
    {"ico": "28821599", "name": "Gynekologie Jičín s.r.o.", "city": "Jičín"},
    {"ico": "28375556", "name": "Praktický lékař pro děti a dorost s.r.o.", "city": "Kutná Hora"},
    {"ico": "00829013", "name": "Zdravotnická záchranná služba Ústeckého kraje", "city": "Ústí nad Labem"},
    {"ico": "02233664", "name": "Mračena poskytuje zdravotní služby", "city": "Říčany"},
    {"ico": "25706381", "name": "Canadian Medical s.r.o.", "city": "Praha 6"},
    {"ico": "47453745", "name": "Poliklinika Týniště nad Orlicí, s.r.o.", "city": "Týniště nad Orlicí"},
]

# Společní zdravotničtí pracovníci dostupní pro všechny testovací PZS identity
# (zdroj: MZČR Confluence – Podklady pro testování napojení na CSEZ).
TEST_COMMON_WORKERS = [
    {"krzpid": "102129137", "name": "MRAČENA MRAKOMOROVÁ", "rid": "2667873559", "role": "Zdrav. pracovník 1"},
    {"krzpid": "201210303", "name": "LETNÍ ŽALUD", "rid": "7651669233", "role": "Zdrav. pracovník 2"},
]


def validate():
    missing = []
    if not CLIENT_ID:
        missing.append("SEZ_CLIENT_ID")
    if not P12_PATH:
        missing.append("SEZ_P12_PATH")
    if not P12_PASSWORD:
        missing.append("SEZ_P12_PASSWORD")
    if missing:
        raise SystemExit(
            "Chybí povinná konfigurace. Nastavte proměnné prostředí nebo vytvořte .env soubor.\n"
            f"Chybí: {', '.join(missing)}\n"
            "Viz .env.example pro vzor."
        )
