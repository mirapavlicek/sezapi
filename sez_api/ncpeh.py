"""
NCPeH – Národní kontaktní místo pro elektronické zdravotnictví,
služba Pacientský souhrn (přeshraniční výměna v rámci MyHealth@EU / eHDSI).

Zdroje (veřejná dokumentace):
  - Testovací rámec interoperability IS PZS s NCPeH ČR v1.1 (Kraj Vysočina,
    12. 4. 2023) – příloha stránky „Testovaná komponenta - NCPeH" v Manuálu
    EZ pro PZS (Testovací rámec IROP/NPO).
  - www.nixzd.cz – standard rozhraní pro úlohu A, vzorové CDA dokumenty
    (kritický pacient), podmínky připojení, provozní řád.
  - ncez.mzcr.cz – Napojení na NCPeH (role A + role B povinné dle výzev),
    Metodika vedení a sdílení pacientského souhrnu v ČR.

Role dle testovacího rámce:
  * Country A (role A) – NIS/PZS je POSKYTOVATEL dat: implementuje na své
    straně endpoint dle specifikace nixzd.cz/standard, který volá národní
    konektor NCPeH (NCPNC). Klíčové kontroly z testovacího rámce:
      - case-sensitive XML tagy dle dokumentace,
      - správné OIDy v cdaLxOid a cdaLxId,
      - opakované volání getpsexists NESMÍ generovat nový identifikátor,
      - korektní effectiveTime.
    Výstupy: PS CDA L1 (PDF v CDA obálce) a PS CDA L3 (strukturované)
    ve Friendly (národní) variantě; Pivot (mezinárodní) variantu generuje
    NCPeH.
  * Country B (role B) – NIS je KONZUMENT: přes služby ClientConnectorProxy
    a konfigurační službu NCPeH vyhledá zahraničního pacienta (dle struktury
    identifikátorů dané země), získá seznam dokumentů a stáhne PS
    (CDA L3 pivot + L1 PDF), který zobrazí.

Prostředí: PPT (testovací, přes veřejný internet, po registraci IP adres
u týmu NCPeH), PROD (výhradně neveřejná síť CMS2 / síť AKČR).
Připojení: žádost datovou schránkou MZČR (x2de458) + dotazník
www.nixzd.cz/dotaznik; podpora cz-ehealth-dsi-support@nixzd.cz.

Bez nakonfigurovaného endpointu (NCPEH_PPT_URL) běží integrace v režimu
SIMULACE – role B vrací vzorové zahraniční pacienty (vč. „kritického
pacienta" s plně vyplněným souhrnem dle vzorových CDA), role A generuje
reálné CDA dokumenty z lokálních testovacích dat.
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _x

LOINC_PS = "60591-5"
# eHDSI Patient Summary templateId (pivot i friendly vychází z eHDSI PS)
EHDSI_PS_TEMPLATE_OID = "1.3.6.1.4.1.12559.11.10.1.3.1.1.3"
# RID pacienta (OID používaný v CDA hlavičce; ve FHIR odpovídá
# https://ncez.mzcr.cz/fhir/sid/rid)
RID_OID = "2.16.840.1.113883.4.653"

# Sekce pacientského souhrnu (eHN PS Guidelines / eHDSI wave)
PS_SEKCE = [
    {"kod": "48765-2", "nazev": "Alergie a intolerance", "klic": "alergie", "povinna": True},
    {"kod": "10160-0", "nazev": "Medikace", "klic": "medikace", "povinna": True},
    {"kod": "11450-4", "nazev": "Problémy (diagnózy)", "klic": "problemy", "povinna": True},
    {"kod": "47519-4", "nazev": "Provedené výkony", "klic": "vykony", "povinna": False},
    {"kod": "11369-6", "nazev": "Očkování", "klic": "ockovani", "povinna": False},
    {"kod": "46264-8", "nazev": "Zdravotnické prostředky", "klic": "prostredky", "povinna": False},
    {"kod": "8716-3", "nazev": "Vitální funkce", "klic": "vitalni", "povinna": False},
    {"kod": "29762-2", "nazev": "Sociální anamnéza", "klic": "socialni", "povinna": False},
]

ENVIRONMENTS = {
    "PPT": {
        "name": "NCPeH PPT (testovací)",
        "info": ("Testovací prostředí – komunikace přes veřejný internet po "
                  "registraci vstupní/výstupní IP adresy u týmu NCPeH "
                  "(cz-ehealth-dsi-support@nixzd.cz)."),
    },
    "PROD": {
        "name": "NCPeH PROD",
        "info": "Produkce – výhradně neveřejná síť CMS2 / síť AKČR.",
    },
}

DOKUMENTACE = [
    {"nazev": "Podmínky pro připojení IS k NCPeH",
     "url": "https://www.nixzd.cz/podminky-pro-pripojeni-is-k-ncpeh-c85"},
    {"nazev": "Standard rozhraní pro úlohu A (poskytovatel dat)",
     "url": "https://www.nixzd.cz/standard"},
    {"nazev": "Vzorové CDA dokumenty (kritický pacient)",
     "url": "https://www.nixzd.cz/vzorove-cda-dokumenty-c21"},
    {"nazev": "Dotazník pro žádost o připojení",
     "url": "https://www.nixzd.cz/dotaznik"},
    {"nazev": "Provozní řád NCPeH",
     "url": "https://www.nixzd.cz/provozni-rad-ncpeh-c84"},
    {"nazev": "Napojení na NCPeH (NCEZ – požadavky výzev)",
     "url": "https://ncez.mzcr.cz/cs/node/5517"},
    {"nazev": "Metodika vedení a sdílení pacientského souhrnu v ČR",
     "url": "https://ncez.mzcr.cz/cs/milnik-c-3/metodika-vedeni-sdileni-pacientskeho-souhrnu-v-cr"},
    {"nazev": "Připojení poskytovatelé (stav)",
     "url": "https://www.nixzd.cz/poskytovatele"},
]

# Konfigurační služba NCPeH pro roli B poskytuje strukturu vyhledávacích
# identifikátorů dle země. Toto je orientační snapshot pro simulaci
# (LIVE režim načítá konfiguraci z konfigurační služby NCPeH).
STATY_KONFIGURACE = [
    {"stat": "AT", "nazev": "Rakousko",
     "identifikatory": [{"nazev": "Sozialversicherungsnummer (SVN)",
                           "oid": "1.2.40.0.10.1.4.3.1", "priklad": "1111241261"}]},
    {"stat": "DE", "nazev": "Německo",
     "identifikatory": [{"nazev": "Krankenversichertennummer (KVNR)",
                           "oid": "1.2.276.0.76.4.8", "priklad": "X110403565"}]},
    {"stat": "SK", "nazev": "Slovensko",
     "identifikatory": [{"nazev": "Rodné číslo",
                           "oid": "1.2.703.1.1", "priklad": "8501011234"}]},
    {"stat": "PL", "nazev": "Polsko",
     "identifikatory": [{"nazev": "PESEL",
                           "oid": "1.2.616.1.113883.3.4424.1.1.616", "priklad": "85010112345"}]},
]


def _now_hl7() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S+0000")


# ---------------------------------------------------------------------------
# CDA buildery (role A – Friendly / národní varianta)
# ---------------------------------------------------------------------------

def _cda_header(pacient: dict, doc_id: str, ico: str, pzs_nazev: str,
                 effective_time: str = None) -> str:
    """Hlavička ClinicalDocument dle eHDSI PS (Friendly CZ)."""
    jmeno = _x(pacient.get("jmeno", ""))
    prijmeni = _x(pacient.get("prijmeni", ""))
    rid = _x(pacient.get("rid", ""))
    narozeni = re.sub(r"-", "", pacient.get("datum_narozeni", "") or "")
    pohlavi = {"M": "M", "F": "F", "muz": "M", "zena": "F"}.get(
        pacient.get("pohlavi", ""), "UN")
    et = effective_time or _now_hl7()
    return f"""  <realmCode code="CZ"/>
  <typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>
  <templateId root="{EHDSI_PS_TEMPLATE_OID}"/>
  <id root="{RID_OID}.1" extension="{_x(doc_id)}"/>
  <code code="{LOINC_PS}" codeSystem="2.16.840.1.113883.6.1"
        codeSystemName="LOINC" displayName="Patient summary Document"/>
  <title>Pacientský souhrn – {prijmeni} {jmeno}</title>
  <effectiveTime value="{et}"/>
  <confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25"/>
  <languageCode code="cs-CZ"/>
  <recordTarget>
    <patientRole>
      <id root="{RID_OID}" extension="{rid}"/>
      <patient>
        <name><given>{jmeno}</given><family>{prijmeni}</family></name>
        <administrativeGenderCode code="{pohlavi}"
            codeSystem="2.16.840.1.113883.5.1"/>
        <birthTime value="{narozeni}"/>
      </patient>
    </patientRole>
  </recordTarget>
  <author>
    <time value="{et}"/>
    <assignedAuthor>
      <id root="{RID_OID}.2" extension="{_x(pacient.get('autor_krzpid', ''))}"/>
      <assignedAuthoringDevice>
        <softwareName>sez-api NCPeH modul</softwareName>
      </assignedAuthoringDevice>
    </assignedAuthor>
  </author>
  <custodian>
    <assignedCustodian>
      <representedCustodianOrganization>
        <id root="{RID_OID}.3" extension="{_x(ico)}"/>
        <name>{_x(pzs_nazev)}</name>
      </representedCustodianOrganization>
    </assignedCustodian>
  </custodian>"""


def _cda_section(kod: str, nazev: str, polozky: list) -> str:
    if not polozky:
        radky = "<item>Bez záznamu / informace není dostupná</item>"
    else:
        radky = "".join(
            f"<item>{_x(str(p.get('text') if isinstance(p, dict) else p))}</item>"
            for p in polozky)
    entries = ""
    for p in polozky or []:
        if isinstance(p, dict) and p.get("kod"):
            system = _x(p.get("system", "2.16.840.1.113883.6.96"))  # SNOMED CT
            entries += f"""
        <entry>
          <observation classCode="OBS" moodCode="EVN">
            <code code="{_x(str(p['kod']))}" codeSystem="{system}"
                  displayName="{_x(str(p.get('text', '')))}"/>
          </observation>
        </entry>"""
    return f"""    <component>
      <section>
        <code code="{kod}" codeSystem="2.16.840.1.113883.6.1"
              codeSystemName="LOINC" displayName="{_x(nazev)}"/>
        <title>{_x(nazev)}</title>
        <text><list>{radky}</list></text>{entries}
      </section>
    </component>"""


def build_ps_cda_l3(pacient: dict, *, ico: str, pzs_nazev: str,
                     doc_id: str = None, effective_time: str = None) -> str:
    """Sestaví PS CDA L3 (strukturovaný, Friendly/CZ varianta).

    ``pacient`` obsahuje demografii (rid, jmeno, prijmeni, datum_narozeni,
    pohlavi) a klinické sekce dle klíčů :data:`PS_SEKCE` (alergie, medikace,
    problemy, …) – každá jako seznam textů nebo dictů {text, kod, system}.
    """
    doc_id = doc_id or str(uuid.uuid4())
    sekce_xml = "".join(
        _cda_section(s["kod"], s["nazev"], pacient.get(s["klic"]) or [])
        for s in PS_SEKCE if s["povinna"] or pacient.get(s["klic"]))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
{_cda_header(pacient, doc_id, ico, pzs_nazev, effective_time)}
  <component>
    <structuredBody>
{sekce_xml}
    </structuredBody>
  </component>
</ClinicalDocument>"""


def build_ps_cda_l1(pacient: dict, *, ico: str, pzs_nazev: str,
                     pdf_base64: str, doc_id: str = None,
                     effective_time: str = None) -> str:
    """Sestaví PS CDA L1 – PDF vizuál v CDA obálce (nonXMLBody)."""
    doc_id = doc_id or str(uuid.uuid4())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
{_cda_header(pacient, doc_id, ico, pzs_nazev, effective_time)}
  <component>
    <nonXMLBody>
      <text mediaType="application/pdf" representation="B64">{pdf_base64}</text>
    </nonXMLBody>
  </component>
</ClinicalDocument>"""


# ---------------------------------------------------------------------------
# CDA parser (role B – zobrazení přijatého souhrnu)
# ---------------------------------------------------------------------------

def parse_ps_cda(xml_text: str) -> dict:
    """Zjednodušený parser PS CDA pro lidsky čitelné zobrazení.

    Vrací hlavičku (pacient, dokument) a sekce s položkami. Není to plná
    CDA validace – pro strukturální validaci slouží eHDSI Gazelle.
    """
    out = {"dokument": {}, "pacient": {}, "sekce": [], "chyby": []}
    if not xml_text or "<ClinicalDocument" not in xml_text:
        out["chyby"].append("Obsah není CDA ClinicalDocument")
        return out

    def _attr(pattern):
        m = re.search(pattern, xml_text)
        return m.group(1) if m else None

    out["dokument"]["id"] = _attr(r'<id root="[^"]*"\s+extension="([^"]+)"')
    out["dokument"]["kod"] = _attr(r'<code code="([^"]+)"[^>]*codeSystemName="LOINC"')
    m = re.search(r"<title>([^<]*)</title>", xml_text)
    out["dokument"]["titulek"] = m.group(1) if m else None
    out["dokument"]["effectiveTime"] = _attr(r'<effectiveTime value="([^"]+)"')
    out["dokument"]["jazyk"] = _attr(r'<languageCode code="([^"]+)"')
    out["dokument"]["l1_pdf"] = "nonXMLBody" in xml_text

    pr = re.search(r"<recordTarget>.*?</recordTarget>", xml_text, re.S)
    if pr:
        blok = pr.group(0)
        rid = re.search(r'extension="([^"]+)"', blok)
        given = re.search(r"<given>([^<]*)</given>", blok)
        family = re.search(r"<family>([^<]*)</family>", blok)
        birth = re.search(r'<birthTime value="([^"]+)"', blok)
        gender = re.search(r'<administrativeGenderCode code="([^"]+)"', blok)
        out["pacient"] = {
            "id": rid.group(1) if rid else None,
            "jmeno": given.group(1) if given else None,
            "prijmeni": family.group(1) if family else None,
            "datum_narozeni": birth.group(1) if birth else None,
            "pohlavi": gender.group(1) if gender else None,
        }

    for sm in re.finditer(r"<section>(.*?)</section>", xml_text, re.S):
        blok = sm.group(1)
        kod = re.search(r'<code code="([^"]+)"', blok)
        title = re.search(r"<title>([^<]*)</title>", blok)
        polozky = re.findall(r"<item>([^<]*)</item>", blok)
        out["sekce"].append({
            "kod": kod.group(1) if kod else None,
            "nazev": title.group(1) if title else None,
            "polozky": polozky,
        })
    return out


def zkontroluj_ps_cda(xml_text: str) -> dict:
    """Lokální kontroly PS CDA dle kontrol testovacího rámce NCPeH
    (case-sensitive tagy, id/OIDy, effectiveTime, kód dokumentu).
    Plnou strukturální validaci provádí eHDSI Gazelle."""
    chyby, varovani = [], []
    if not xml_text or not xml_text.strip():
        return {"valid": False, "chyby": ["Prázdný dokument"], "varovani": []}
    if "<clinicaldocument" in xml_text.lower() and "<ClinicalDocument" not in xml_text:
        chyby.append("Kořenový element musí být case-sensitive <ClinicalDocument>")
    if "<ClinicalDocument" not in xml_text:
        chyby.append("Chybí kořenový element ClinicalDocument")
    if 'xmlns="urn:hl7-org:v3"' not in xml_text:
        chyby.append("Chybí namespace urn:hl7-org:v3")
    if f'code="{LOINC_PS}"' not in xml_text:
        chyby.append(f"Chybí kód dokumentu {LOINC_PS} (Patient summary, LOINC)")
    if not re.search(r'<effectiveTime value="\d{14}', xml_text):
        chyby.append("Chybí/neplatný effectiveTime (YYYYMMDDHHMMSS…)")
    if not re.search(r'<id root="[0-9.]+"\s+extension="[^"]+"', xml_text):
        chyby.append("Chybí id dokumentu s OID root + extension (cdaLxOid/cdaLxId)")
    if "<recordTarget>" not in xml_text:
        chyby.append("Chybí recordTarget (pacient)")
    if "<custodian>" not in xml_text:
        chyby.append("Chybí custodian (správce dokumentu)")
    if EHDSI_PS_TEMPLATE_OID not in xml_text:
        varovani.append(f"Chybí eHDSI PS templateId {EHDSI_PS_TEMPLATE_OID}")
    if "structuredBody" not in xml_text and "nonXMLBody" not in xml_text:
        chyby.append("Chybí tělo dokumentu (structuredBody L3 / nonXMLBody L1)")
    if "structuredBody" in xml_text:
        for s in PS_SEKCE:
            if s["povinna"] and f'code="{s["kod"]}"' not in xml_text:
                chyby.append(f"Chybí povinná sekce {s['nazev']} (LOINC {s['kod']})")
    return {"valid": not chyby, "chyby": chyby, "varovani": varovani}


# ---------------------------------------------------------------------------
# Simulace – Country B (vzoroví zahraniční pacienti)
# ---------------------------------------------------------------------------

# „Kritický pacient" dle testovacího rámce = uměle vytvořený profil
# s maximálním rozsahem dat (všechny sekce PS vyplněné) – vzory viz
# https://www.nixzd.cz/vzorove-cda-dokumenty-c21
SAMPLE_PACIENTI = [
    {
        "stat": "AT", "id": "1111241261", "oid": "1.2.40.0.10.1.4.3.1",
        "jmeno": "Franz", "prijmeni": "Beispiel",
        "datum_narozeni": "1961-12-24", "pohlavi": "M",
        "kriticky": True,
        "alergie": [{"text": "Penicilin – anafylaxe", "kod": "294513009"},
                     {"text": "Arašídy", "kod": "91935009"}],
        "medikace": [{"text": "Metformin 1000 mg 2×denně", "kod": "109081006"},
                      {"text": "Ramipril 5 mg 1×denně", "kod": "386872004"},
                      {"text": "Warfarin 3 mg dle INR", "kod": "372756006"}],
        "problemy": [{"text": "Diabetes mellitus 2. typu", "kod": "44054006"},
                      {"text": "Fibrilace síní", "kod": "49436004"},
                      {"text": "Hypertenze", "kod": "38341003"}],
        "vykony": [{"text": "PCI se stentem (2019)", "kod": "415070008"}],
        "ockovani": [{"text": "Tetanus (2021)", "kod": "127786006"},
                      {"text": "COVID-19 mRNA (2023)", "kod": "1119349007"}],
        "prostredky": [{"text": "Koronární stent", "kod": "65818007"}],
        "vitalni": ["TK 145/90", "P 88 nepravidelný"],
        "socialni": ["Exkuřák (od 2015)", "Alkohol příležitostně"],
    },
    {
        "stat": "DE", "id": "X110403565", "oid": "1.2.276.0.76.4.8",
        "jmeno": "Anna", "prijmeni": "Musterfrau",
        "datum_narozeni": "1985-06-15", "pohlavi": "F",
        "kriticky": False,
        "alergie": [],
        "medikace": [{"text": "Levothyroxin 50 µg 1×denně", "kod": "126202002"}],
        "problemy": [{"text": "Hypotyreóza", "kod": "40930008"}],
    },
    {
        "stat": "SK", "id": "8501011234", "oid": "1.2.703.1.1",
        "jmeno": "Ján", "prijmeni": "Vzorový",
        "datum_narozeni": "1985-01-01", "pohlavi": "M",
        "kriticky": False,
        "alergie": [{"text": "Latex", "kod": "300916003"}],
        "medikace": [],
        "problemy": [{"text": "Astma bronchiale", "kod": "195967001"}],
    },
]


def _sim_najdi_pacienta(stat: str, identifikator: str) -> dict | None:
    for p in SAMPLE_PACIENTI:
        if p["stat"] == (stat or "").upper() and p["id"] == (identifikator or "").strip():
            return p
    return None


# ---------------------------------------------------------------------------
# Klient
# ---------------------------------------------------------------------------

class NCPeH:
    """Klient NCPeH pro obě role dle testovacího rámce.

    Role B (konzument): ``query_patient`` / ``query_documents`` /
    ``retrieve_document`` – v LIVE režimu volá ClientConnectorProxy
    (URL z konfigurace, dostupné až po registraci u týmu NCPeH),
    jinak SIMULACE nad vzorovými pacienty.

    Role A (poskytovatel dat): ``get_ps_exists`` / ``get_ps`` – generuje
    PS CDA L1/L3 (Friendly) z lokálních dat. Identifikátor dokumentu je
    pro daného pacienta STABILNÍ (deterministický) – opakované volání
    getpsexists nesmí generovat nový identifikátor (kontrola testovacího
    rámce NCPeH).
    """

    def __init__(self, client=None):
        self.c = client

    def _cfg(self):
        from sez_api import config as _cfg
        return _cfg

    def mode(self) -> str:
        cfg = self._cfg()
        url = getattr(cfg, "NCPEH_PPT_URL", "") or getattr(cfg, "NCPEH_PROD_URL", "")
        return "LIVE" if url else "SIMULACE"

    def endpoint(self) -> str:
        cfg = self._cfg()
        return getattr(cfg, "NCPEH_PPT_URL", "") or getattr(cfg, "NCPEH_PROD_URL", "")

    def status(self) -> dict:
        return {
            "mode": self.mode(),
            "endpoint": self.endpoint() or None,
            "environments": ENVIRONMENTS,
            "role_a": {
                "popis": "PZS jako poskytovatel dat – endpoint pro NCPNC "
                          "(getpsexists/getps, CDA L1+L3 Friendly)",
                "endpointy": ["/api/ncpeh/a/get-ps-exists", "/api/ncpeh/a/get-ps"],
            },
            "role_b": {
                "popis": "PZS jako konzument – ClientConnectorProxy + "
                          "konfigurační služba (vyhledání, dokumenty, stažení PS)",
                "endpointy": ["/api/ncpeh/b/vyhledat-pacienta",
                                "/api/ncpeh/b/dokumenty", "/api/ncpeh/b/stahnout"],
            },
            "pripojeni": {
                "zadost": "datová schránka MZČR x2de458 + dotazník www.nixzd.cz/dotaznik",
                "podpora": "cz-ehealth-dsi-support@nixzd.cz / info@nixzd.cz",
                "ppt": "veřejný internet po registraci IP adres",
                "prod": "neveřejná síť CMS2 / síť AKČR",
            },
            "dokumentace": DOKUMENTACE,
            "sim_pacienti": [
                {"stat": p["stat"], "id": p["id"], "jmeno": p["jmeno"],
                  "prijmeni": p["prijmeni"], "kriticky": p["kriticky"]}
                for p in SAMPLE_PACIENTI
            ] if self.mode() == "SIMULACE" else None,
        }

    # ------------------------------------------------------------------
    # Role B – konzument (Country B)
    # ------------------------------------------------------------------

    def konfigurace_statu(self) -> dict:
        """Konfigurační služba: struktura vyhledávacích identifikátorů
        dle země (v SIMULACI orientační snapshot)."""
        return {"mode": self.mode(), "staty": STATY_KONFIGURACE}

    def query_patient(self, stat: str, identifikator: str, oid: str = None) -> dict:
        if self.mode() == "LIVE":
            return self._live_post("/queryPatient", {
                "stat": stat, "identifikator": identifikator, "oid": oid})
        p = _sim_najdi_pacienta(stat, identifikator)
        if not p:
            return {"_simulace": True, "nalezen": False, "stat": stat,
                    "identifikator": identifikator,
                    "hint": "Vzoroví pacienti: " + ", ".join(
                        f"{x['stat']}:{x['id']}" for x in SAMPLE_PACIENTI)}
        return {"_simulace": True, "nalezen": True,
                "pacient": {"stat": p["stat"], "id": p["id"], "oid": p["oid"],
                              "jmeno": p["jmeno"], "prijmeni": p["prijmeni"],
                              "datum_narozeni": p["datum_narozeni"],
                              "pohlavi": p["pohlavi"],
                              "kriticky_pacient": p["kriticky"]}}

    def query_documents(self, stat: str, identifikator: str) -> dict:
        if self.mode() == "LIVE":
            return self._live_post("/queryDocuments", {
                "stat": stat, "identifikator": identifikator})
        p = _sim_najdi_pacienta(stat, identifikator)
        if not p:
            return {"_simulace": True, "nalezen": False, "dokumenty": []}
        doc_id = self._stable_doc_id(p["stat"] + p["id"])
        return {"_simulace": True, "nalezen": True, "dokumenty": [
            {"id": doc_id, "typ": "PS", "uroven": "L3", "format": "CDA R4/XML",
             "kod": LOINC_PS, "nazev": "Patient Summary (pivot CDA L3)"},
            {"id": doc_id + "-L1", "typ": "PS", "uroven": "L1", "format": "PDF v CDA",
             "kod": LOINC_PS, "nazev": "Patient Summary (PDF, CDA L1)"},
        ]}

    def retrieve_document(self, stat: str, identifikator: str,
                           dokument_id: str = None, uroven: str = "L3") -> dict:
        if self.mode() == "LIVE":
            return self._live_post("/retrieveDocument", {
                "stat": stat, "identifikator": identifikator,
                "dokumentId": dokument_id, "uroven": uroven})
        p = _sim_najdi_pacienta(stat, identifikator)
        if not p:
            return {"_simulace": True, "nalezen": False}
        doc_id = dokument_id or self._stable_doc_id(p["stat"] + p["id"])
        pac = dict(p)
        pac["autor_krzpid"] = "NCPEH-B-SIM"
        if uroven.upper() == "L1":
            from sez_api.fhir_ezd import minimal_pdf_base64
            cda = build_ps_cda_l1(pac, ico="NCPEH", pzs_nazev="NCPeH simulace",
                                    pdf_base64=minimal_pdf_base64(), doc_id=doc_id)
        else:
            cda = build_ps_cda_l3(pac, ico="NCPEH", pzs_nazev="NCPeH simulace",
                                    doc_id=doc_id)
        return {"_simulace": True, "nalezen": True, "dokumentId": doc_id,
                "uroven": uroven.upper(), "cda": cda,
                "parsed": parse_ps_cda(cda),
                "validace": zkontroluj_ps_cda(cda)}

    def _live_post(self, path: str, body: dict) -> dict:
        """LIVE volání ClientConnectorProxy (dostupné po připojení k NCPeH)."""
        import requests
        url = self.endpoint().rstrip("/") + path
        try:
            if self.c is not None and hasattr(self.c, "session"):
                resp = self.c.session.post(url, json=body, timeout=60)
            else:
                resp = requests.post(url, json=body, timeout=60)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text[:2000]}
            return {"_live": True, "http_status": resp.status_code, "data": data}
        except Exception as exc:
            return {"_live": True, "error": str(exc), "url": url}

    # ------------------------------------------------------------------
    # Role A – poskytovatel dat (Country A)
    # ------------------------------------------------------------------

    @staticmethod
    def _stable_doc_id(seed: str) -> str:
        """Deterministický identifikátor dokumentu – opakované volání
        getpsexists NESMÍ generovat nový identifikátor (testovací rámec)."""
        return str(uuid.UUID(hashlib.sha256(f"sez-api-ps:{seed}".encode()).hexdigest()[:32]))

    def get_ps_exists(self, rid: str, pacient: dict = None) -> dict:
        """Role A: existence PS pro pacienta + stabilní identifikátor
        dokumentu (cdaLxId) a OID (cdaLxOid)."""
        pac = pacient or self._lokalni_pacient(rid)
        if not pac:
            return {"exists": False, "rid": rid}
        doc_id = self._stable_doc_id(rid)
        return {
            "exists": True, "rid": rid,
            "cdaL1Oid": f"{RID_OID}.1", "cdaL1Id": doc_id + "-L1",
            "cdaL3Oid": f"{RID_OID}.1", "cdaL3Id": doc_id,
            "effectiveTime": _now_hl7(),
        }

    def get_ps(self, rid: str, uroven: str = "L3", pacient: dict = None,
                ico: str = None, pzs_nazev: str = None) -> dict:
        """Role A: vydání PS CDA L1/L3 (Friendly) pro NCPNC."""
        pac = pacient or self._lokalni_pacient(rid)
        if not pac:
            return {"exists": False, "rid": rid}
        cfg = self._cfg()
        ico = ico or getattr(cfg, "CLIENT_ID", "").split("_")[0] or "00000000"
        pzs_nazev = pzs_nazev or "SEZ API Test PZS"
        doc_id = self._stable_doc_id(rid)
        if uroven.upper() == "L1":
            from sez_api.fhir_ezd import minimal_pdf_base64
            cda = build_ps_cda_l1(pac, ico=ico, pzs_nazev=pzs_nazev,
                                    pdf_base64=minimal_pdf_base64(),
                                    doc_id=doc_id + "-L1")
        else:
            cda = build_ps_cda_l3(pac, ico=ico, pzs_nazev=pzs_nazev, doc_id=doc_id)
        return {"exists": True, "rid": rid, "uroven": uroven.upper(),
                "dokumentId": doc_id if uroven.upper() != "L1" else doc_id + "-L1",
                "cda": cda, "validace": zkontroluj_ps_cda(cda)}

    @staticmethod
    def _lokalni_pacient(rid: str) -> dict | None:
        """Testovací lokální data pacienta pro roli A (zdroj: testovací
        identity T2 + demonstrační klinická data)."""
        pacienti = {
            "2667873559": {
                "rid": "2667873559", "jmeno": "MRAČENA", "prijmeni": "MRAKOMOROVÁ",
                "datum_narozeni": "1971-11-26", "pohlavi": "F",
                "autor_krzpid": "102129137",
                "alergie": [{"text": "Pyl břízy", "kod": "256319004"}],
                "medikace": [{"text": "Ibuprofen 400 mg dle potřeby", "kod": "387207008"}],
                "problemy": [{"text": "Sezónní alergická rýma", "kod": "367498001"}],
            },
            "7651669233": {
                "rid": "7651669233", "jmeno": "LETNÍ", "prijmeni": "ŽALUD",
                "datum_narozeni": "1980-07-15", "pohlavi": "M",
                "autor_krzpid": "201210303",
                "alergie": [],
                "medikace": [],
                "problemy": [{"text": "Hypertenze", "kod": "38341003"}],
            },
        }
        return pacienti.get(str(rid or "").strip())


def base64_cda(cda_xml: str) -> str:
    return base64.b64encode(cda_xml.encode("utf-8")).decode()
