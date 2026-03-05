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

PROD_CLIENT_ID = env("SEZ_PROD_CLIENT_ID", "")
PROD_P12_PATH = env("SEZ_PROD_P12_PATH", "")
PROD_P12_PASSWORD = env("SEZ_PROD_P12_PASSWORD", "")
PROD_CERT_UID = env("SEZ_PROD_CERT_UID", "")
PROD_GATEWAY = env("SEZ_PROD_GATEWAY", "")
PROD_JSU_AUDIENCE = env("SEZ_PROD_JSU_AUDIENCE", "")

ENV_CREDENTIALS = {
    "T1": {
        "client_id": CLIENT_ID,
        "p12_path": P12_PATH,
        "p12_password": P12_PASSWORD,
        "cert_uid": CERT_UID,
    },
    "T2": {
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

TEST_PZS = [
    {"ico": "00064203", "name": "Fakultní nemocnice v Motole", "city": "Praha 5"},
    {"ico": "25488627", "name": "Krajská zdravotní, a.s.", "city": "Ústí nad Labem", "note": "Testovací PZS"},
    {"ico": "60470488", "name": "AeskuLab k.s.", "city": "Praha 6"},
    {"ico": "27661989", "name": "Krajská nemocnice T. Bati, a. s.", "city": "Zlín"},
    {"ico": "47911492", "name": "Městská poliklinika u sv. Alžběty, s.r.o.", "city": "Uherské Hradiště"},
    {"ico": "28821599", "name": "Gynekologie Jičín s.r.o.", "city": "Jičín"},
    {"ico": "28375556", "name": "Praktický lékař pro děti a dorost s.r.o.", "city": "Kutná Hora"},
    {"ico": "829013", "name": "Zdravotnická záchranná služba Ústeckého kraje", "city": "Ústí nad Labem"},
    {"ico": "02233664", "name": "Mračena poskytuje zdravotní služby", "city": "Říčany"},
    {"ico": "25706381", "name": "Canadian Medical s.r.o.", "city": "Praha 6"},
    {"ico": "47453745", "name": "Poliklinika Týniště nad Orlicí, s. r. o.", "city": "Týniště nad Orlicí"},
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
