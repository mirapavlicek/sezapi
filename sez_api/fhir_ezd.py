"""
FHIR eZD – prioritní kategorie elektronických zdravotních dokumentů dle
Metodiky testování EHR fáze I (IROP/NPO) a HL7 CZ Implementation Guides.

Zdroj metodiky (MZČR Confluence, Testovací rámec – informace k testování
splnění IROP/NPO):
  - Testovací scénáře - Testování obsahu dokumentů eZD (TS-OBS-1/2)
  - Postup testování - Testování interoperability - validace obsahu
    dokumentů eZD (kritéria shody, odkazy na IG)

Prioritní kategorie a závazné technické standardy (HL7 CZ IG):

  ==================== ===================================== ==============
  Kategorie eZD        Implementation Guide                  Ověřená verze
  ==================== ===================================== ==============
  Pacientský souhrn    https://build.fhir.org/ig/HL7-cz/ps/     0.0.1
  Propouštěcí zpráva   https://build.fhir.org/ig/HL7-cz/hdr/    0.1.0
  Zpráva z obrazového  https://build.fhir.org/ig/HL7-cz/img/    0.1.0-ballot
  vyšetření
  Zpráva o výjezdu ZZS https://build.fhir.org/ig/HL7-cz/cz-ems/ 0.0.2
  ==================== ===================================== ==============

Legislativní rámec: vyhláška č. 444/2024 Sb., o zdravotnické dokumentaci
(příloha č. 2 – pacientský souhrn; příloha č. 1 bod 4 – propouštěcí zpráva;
bod 3C – zpráva z obrazového vyšetření; bod 6B – zpráva o výjezdu).

Modul implementuje úroveň L1 dle metodiky: „Hlavička musí odpovídat hlavičce
dle příslušné implementační specifikace pro danou kategorii dokumentu
v rozsahu úrovně L1; tělo není vyžadováno; vizuální podoba: platný PDF/A
(presentedForm)."

Poskytuje:
  * ``build_ezd_bundle(kategorie, ...)`` – sestaví FHIR R4 document Bundle
    konformní s příslušným IG profilem (hlavička L1 + presentedForm PDF).
  * ``validate_ezd_bundle(bundle, kategorie=None)`` – lokální L1 validace
    (syntaktická kontrola FHIR + IG požadavky: profily, fixní LOINC kódy,
    povinné elementy a sekce). Pro plnou validaci metodika odkazuje na
    https://validator.fhir.org/ – lokální kontrola pokrývá kritéria shody
    z kapitoly „Kritéria shody pro vytvořený dokument".
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Konstanty dle HL7 CZ IG
# ---------------------------------------------------------------------------

LOINC = "http://loinc.org"
RID_SYSTEM = "https://ncez.mzcr.cz/fhir/sid/rid"          # cz-core Patient.identifier:RID
KRZPID_SYSTEM = "https://ncez.mzcr.cz/fhir/sid/krzpid"    # zdravotnický pracovník
ICO_SYSTEM = "https://ncez.mzcr.cz/fhir/sid/ico"          # organizace (IČO)
PRESENTED_FORM_EXT = "https://hl7.cz/fhir/core/StructureDefinition/presentedForm"
CZ_PATIENT_PROFILE = "https://hl7.cz/fhir/core/StructureDefinition/cz-patient-core"

# Minimální validní jednostránkové PDF (placeholder za PDF/A vizuál L1;
# reálný SUT dodává svou vizuální podobu dokumentu).
_MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n"
    b"0000000052 00000 n \n0000000101 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


# Definice prioritních kategorií eZD. Klíče odpovídají hodnotám ``doc_type``
# používaným v UI a IROP scénářích.
EZD_KATEGORIE = {
    "pacientsky-souhrn": {
        "nazev": "Pacientský souhrn",
        "ig": "hl7.fhir.cz.ps",
        "ig_verze": "0.0.1",
        "ig_url": "https://build.fhir.org/ig/HL7-cz/ps/",
        "legislativa": "vyhláška č. 444/2024 Sb., příloha č. 2",
        "bundle_profile": "https://hl7.cz/fhir/ps/StructureDefinition/cz-bundle-ps",
        "composition_profile": "https://hl7.cz/fhir/ps/StructureDefinition/cz-composition-ps",
        # Composition.type – patternCodeableConcept dle cz-composition-ps
        "type_coding": {"system": LOINC, "code": "60591-5",
                         "display": "Patient summary Document"},
        # Composition.category – pattern dle profilu
        "category_codings": [[{"system": LOINC, "code": "11503-0"}]],
        "presented_form_required": True,
        "encounter_required": False,
        "language_required": False,
        "identifier_required": False,
        "confidentiality_required": False,
        # IPS povinné sekce (Composition-uv-ips: Problems/Medications/Allergies 1..1)
        "required_sections": [
            {"slice": "sectionMedications", "code": "10160-0",
             "title": "Medikace"},
            {"slice": "sectionAllergies", "code": "48765-2",
             "title": "Alergie a intolerance"},
            {"slice": "sectionProblems", "code": "11450-4",
             "title": "Problémy"},
        ],
        "min_sections": 1,
        # Volitelné sekce dle cz-composition-ps (0..1) – pro interaktivní
        # builder v GUI. Povinné sekce jsou v required_sections.
        "optional_sections": [
            {"slice": "sectionImmunizations", "code": "11369-6", "title": "Očkování"},
            {"slice": "sectionResults", "code": "30954-2", "title": "Výsledky vyšetření"},
            {"slice": "sectionProceduresHx", "code": "47519-4", "title": "Historie výkonů"},
            {"slice": "sectionMedicalDevices", "code": "46264-8", "title": "Zdravotnické prostředky"},
            {"slice": "sectionAdvanceDirectives", "code": "42348-3", "title": "Dříve vyslovená přání"},
            {"slice": "sectionAlerts", "code": "104605-1", "title": "Upozornění"},
            {"slice": "sectionFunctionalStatus", "code": "47420-5", "title": "Funkční stav"},
            {"slice": "sectionPregnancyHx", "code": "10162-6", "title": "Anamnéza gravidity"},
            {"slice": "sectionPatientStory", "code": "10164-2", "title": "Anamnéza dle pacienta"},
            {"slice": "sectionPlanOfCare", "code": "18776-5", "title": "Plán péče"},
            {"slice": "sectionSocialHistory", "code": "29762-2", "title": "Sociální anamnéza"},
            {"slice": "sectionVitalSigns", "code": "8716-3", "title": "Vitální funkce"},
            {"slice": "sectionTravelHx", "code": "10182-4", "title": "Cestovní anamnéza"},
            {"slice": "sectionPatientHx", "code": "11329-0", "title": "Anamnéza"},
            {"slice": "sectionPastProblems", "code": "11348-0", "title": "Dřívější problémy"},
            {"slice": "sectionAttachments", "code": "77599-9", "title": "Přílohy"},
        ],
        # kód pro DÚ metadata (číselník medical-document-type)
        "du_typ_kod": "60591-5",
    },
    "propousteci-zprava": {
        "nazev": "Propouštěcí zpráva",
        "ig": "hl7.fhir.cz.hdr",
        "ig_verze": "0.1.0",
        "ig_url": "https://build.fhir.org/ig/HL7-cz/hdr/",
        "legislativa": "vyhláška č. 444/2024 Sb., příloha č. 1 bod 4",
        "bundle_profile": "https://hl7.cz/fhir/hdr/StructureDefinition/cz-bundle-hdr",
        # CI build IG z 10. 7. 2026 přejmenoval canonical composition profilu
        # (cz-composition-hdr → composition-cz-hdr); constraints beze změny
        # (typ 34105-7, encounter 1..1, presentedForm 1..*, sekce 8648-8).
        "composition_profile": "https://hl7.cz/fhir/hdr/StructureDefinition/composition-cz-hdr",
        "composition_profile_aliasy": [
            "https://hl7.cz/fhir/hdr/StructureDefinition/cz-composition-hdr",
        ],
        # POZOR: dle IG je typ 34105-7 (Hospital Discharge summary),
        # nikoli 18842-5 (Discharge summary) používaný v číselníku DÚ.
        "type_coding": {"system": LOINC, "code": "34105-7",
                         "display": "Hospital Discharge summary"},
        "category_codings": [],
        "presented_form_required": True,
        "encounter_required": True,   # Composition.encounter 1..1
        "language_required": False,
        "identifier_required": False,
        "confidentiality_required": False,
        # sectionHospitalCourse 1..1 (LOINC 8648-8)
        "required_sections": [
            {"slice": "sectionHospitalCourse", "code": "8648-8",
             "title": "Průběh hospitalizace"},
        ],
        "min_sections": 1,
        "optional_sections": [
            {"slice": "sectionAdmissionEvaluation", "code": "67851-6", "title": "Vyhodnocení při příjmu"},
            {"slice": "sectionPatientHx", "code": "35090-0", "title": "Anamnéza"},
            {"slice": "sectionAllergies", "code": "48765-2", "title": "Alergie a intolerance"},
            {"slice": "sectionAlert", "code": "104605-1", "title": "Upozornění"},
            {"slice": "sectionProblemList", "code": "11450-4", "title": "Seznam problémů"},
            {"slice": "sectionDiagnosticSummary", "code": "11535-2", "title": "Souhrn diagnóz"},
            {"slice": "sectionSignificantProcedures", "code": "10185-7", "title": "Významné výkony"},
            {"slice": "sectionSignificantResults", "code": "30954-2", "title": "Významné výsledky"},
            {"slice": "sectionPhysicalFindings", "code": "29545-1", "title": "Fyzikální nález"},
            {"slice": "sectionVitalSigns", "code": "8716-3", "title": "Vitální funkce"},
            {"slice": "sectionFunctionalStatus", "code": "47420-5", "title": "Funkční stav"},
            {"slice": "sectionMedicalDevices", "code": "57080-4", "title": "Zdravotnické prostředky"},
            {"slice": "sectionPharmacotherapy", "code": "87232-5", "title": "Farmakoterapie"},
            {"slice": "sectionDischargeMedications", "code": "75311-1", "title": "Medikace při propuštění"},
            {"slice": "sectionDischargeDetails", "code": "8650-4", "title": "Podrobnosti propuštění"},
            {"slice": "sectionDischargeInstructions", "code": "8653-8", "title": "Instrukce při propuštění"},
            {"slice": "sectionSynthesis", "code": "67781-5", "title": "Souhrnná zpráva"},
            {"slice": "sectionCareTeam", "code": "85847-2", "title": "Tým péče"},
            {"slice": "sectionPlanOfCare", "code": "18776-5", "title": "Plán péče"},
            {"slice": "sectionAdvanceDirectives", "code": "42348-3", "title": "Dříve vyslovená přání"},
            {"slice": "sectionPayers", "code": "48768-6", "title": "Plátci"},
            {"slice": "sectionAttachments", "code": "77599-9", "title": "Přílohy"},
        ],
        "du_typ_kod": "18842-5",
    },
    "obrazove-vysetreni": {
        "nazev": "Zpráva z obrazového vyšetření",
        "ig": "hl7.fhir.cz.img",
        "ig_verze": "0.1.0-ballot",
        "ig_url": "https://build.fhir.org/ig/HL7-cz/img/",
        "legislativa": "vyhláška č. 444/2024 Sb., příloha č. 1 bod 3C",
        "bundle_profile": "https://hl7.cz/fhir/img/StructureDefinition/cz-bundle-imaging",
        "composition_profile": "https://hl7.cz/fhir/img/StructureDefinition/cz-composition-imaging",
        # Composition.type – binding na imaging-document-types (bez fixního
        # patternu); 18748-4 = Diagnostic imaging study
        "type_coding": {"system": LOINC, "code": "18748-4",
                         "display": "Diagnostic imaging study"},
        # Composition.category min=3: document-category + imaging-report
        # (85430-7) + eEHRxF Medical-Imaging
        "category_codings": [
            [{"system": LOINC, "code": "18748-4"}],  # document-category slice
            [{"system": LOINC, "code": "85430-7"}],  # imaging-report slice
            [{"system": "http://hl7.eu/fhir/health-data-api/CodeSystem/"
                        "eehrxf-document-priority-category-cs",
              "code": "Medical-Imaging"}],
        ],
        "presented_form_required": False,
        "encounter_required": False,
        "language_required": True,        # Composition.language 1..1
        "identifier_required": True,      # Composition.identifier 1..1
        "confidentiality_required": True,  # Composition.confidentiality 1..1
        # section min=4; povinné slice: imagingstudy/order/history/procedure
        "required_sections": [
            {"slice": "imagingstudy", "code": "18726-0",
             "title": "Obrazové vyšetření"},
            {"slice": "order", "code": "55115-0", "title": "Žádanka"},
            {"slice": "history", "code": "11329-0", "title": "Anamnéza"},
            {"slice": "procedure", "code": "55111-9",
             "title": "Provedené výkony"},
        ],
        "min_sections": 4,
        "diagnostic_report_required": True,  # Bundle.entry:diagnosticReport 1..*
        "optional_sections": [
            {"slice": "clinicalQuestion", "code": "18785-6", "title": "Klinická otázka"},
            {"slice": "comparison", "code": "18834-2", "title": "Srovnání s předchozími"},
            {"slice": "findings", "code": "59776-5", "title": "Nález"},
            {"slice": "impression", "code": "19005-8", "title": "Závěr / hodnocení"},
            {"slice": "recommendation", "code": "18783-1", "title": "Doporučení"},
            {"slice": "communication", "code": "73568-8", "title": "Komunikace s ošetřujícím"},
            {"slice": "report", "code": "LP173421-1", "title": "Text zprávy"},
        ],
        "du_typ_kod": "18748-4",
    },
    "vyjezd-zzs": {
        "nazev": "Zpráva o výjezdu ZZS",
        "ig": "hl7.fhir.cz.ems",
        "ig_verze": "0.0.2",
        "ig_url": "https://build.fhir.org/ig/HL7-cz/cz-ems/",
        "legislativa": "vyhláška č. 444/2024 Sb., příloha č. 1 bod 6B",
        "bundle_profile": "https://hl7.cz/fhir/cz-ems/StructureDefinition/cz-bundle-ems",
        "composition_profile": "https://hl7.cz/fhir/cz-ems/StructureDefinition/cz-composition-ems",
        "type_coding": {"system": LOINC, "code": "67796-3",
                         "display": "EMS note"},
        "category_codings": [[{"system": LOINC, "code": "18682-5"}]],
        "presented_form_required": True,
        "encounter_required": False,
        "language_required": False,
        "identifier_required": False,
        "confidentiality_required": False,
        "required_sections": [
            {"slice": "mission", "code": "67664-3", "title": "Výjezd"},
        ],
        "min_sections": 1,
        "optional_sections": [
            {"slice": "dispatch", "code": "67660-1", "title": "Výzva / dispečink"},
            {"slice": "timeline", "code": "67667-6", "title": "Časová osa výjezdu"},
            {"slice": "patientHx", "code": "11329-0", "title": "Anamnéza"},
            {"slice": "allergies", "code": "48765-2", "title": "Alergie a intolerance"},
            {"slice": "alert", "code": "75310-3", "title": "Upozornění"},
            {"slice": "findings", "code": "29545-1", "title": "Nález na místě"},
            {"slice": "procedure", "code": "29554-3", "title": "Provedené výkony"},
            {"slice": "significantProcedures", "code": "10185-7", "title": "Významné výkony"},
            {"slice": "medicalDevices", "code": "57080-4", "title": "Zdravotnické prostředky"},
            {"slice": "diagnosticSummary", "code": "11450-4", "title": "Diagnostický souhrn"},
            {"slice": "courseOfTreatment", "code": "18682-5", "title": "Průběh ošetření"},
            {"slice": "recommendations", "code": "18776-5", "title": "Doporučení"},
            {"slice": "payers", "code": "48768-6", "title": "Plátci"},
            {"slice": "attachments", "code": "34109-9", "title": "Přílohy"},
        ],
        "du_typ_kod": "67796-3",
    },
    "laboratorni-vysetreni": {
        "nazev": "Laboratorní zpráva",
        "ig": "hl7.fhir.cz.lab",
        "ig_verze": "0.5.0",
        "ig_url": "https://build.fhir.org/ig/HL7-cz/cz-lab/",
        "legislativa": "vyhláška č. 444/2024 Sb., příloha č. 1 bod 3B",
        "bundle_profile": "https://hl7.cz/fhir/lab/StructureDefinition/cz-bundle-lab",
        "composition_profile": "https://hl7.cz/fhir/lab/StructureDefinition/cz-composition-lab-report",
        # Composition.type má binding na cz-lab-report-types-VS (bez fixního
        # patternu); 11502-2 = Laboratory report
        "type_coding": {"system": LOINC, "code": "11502-2",
                         "display": "Laboratory report"},
        "category_codings": [],
        "presented_form_required": False,
        "encounter_required": False,
        "language_required": True,        # Composition.language 1..1
        "identifier_required": False,
        "confidentiality_required": False,
        # cz-composition-lab-report: section 1..*; slices attachment (77599-9)
        # a annotations (48767-8) jsou 0..*. Laboratorní výsledky nesou
        # DiagnosticReport + Observation (Bundle entry), zde je textová sekce.
        "required_sections": [
            {"slice": "annotations", "code": "48767-8", "title": "Komentář k výsledkům"},
        ],
        "min_sections": 1,
        "optional_sections": [
            {"slice": "attachment", "code": "77599-9", "title": "Přílohy"},
        ],
        # Bundle.entry:diagnosticReport 1..1 (povinné dle cz-bundle-lab)
        "diagnostic_report_required": True,
        "du_typ_kod": "11502-2",
    },
}


def sekce_katalog(kategorie: str) -> list[dict]:
    """Vrátí všechny sekce kategorie pro interaktivní builder – povinné
    (dle IG) i volitelné, s LOINC kódem, českým názvem a příznakem
    ``povinna``. Pořadí: nejprve povinné, pak volitelné."""
    meta = EZD_KATEGORIE.get(kategorie)
    if meta is None:
        raise ValueError(f"Neznámá kategorie eZD: {kategorie!r}")
    out = [{**s, "povinna": True} for s in meta["required_sections"]]
    out += [{**s, "povinna": False} for s in meta.get("optional_sections", [])]
    return out


def katalog_zprav() -> list[dict]:
    """Katalog typů zpráv eZD pro GUI: metadata, standard, legislativa
    a seznam sekcí (povinné + volitelné)."""
    return [
        {
            "kategorie": kat,
            "nazev": meta["nazev"],
            "ig": meta["ig"],
            "ig_verze": meta["ig_verze"],
            "ig_url": meta["ig_url"],
            "legislativa": meta["legislativa"],
            "composition_profile": meta["composition_profile"],
            "bundle_profile": meta["bundle_profile"],
            "type_coding": meta["type_coding"],
            "du_typ_kod": meta["du_typ_kod"],
            "pozadavky": {
                "presentedForm": bool(meta.get("presented_form_required")),
                "encounter": bool(meta.get("encounter_required")),
                "language": bool(meta.get("language_required")),
                "identifier": bool(meta.get("identifier_required")),
                "confidentiality": bool(meta.get("confidentiality_required")),
                "diagnosticReport": bool(meta.get("diagnostic_report_required")),
                "min_sekci": meta.get("min_sections", 1),
            },
            "sekce": sekce_katalog(kat),
        }
        for kat, meta in EZD_KATEGORIE.items()
    ]


def _narrative(text: str) -> dict:
    return {"status": "generated",
            "div": f"<div xmlns=\"http://www.w3.org/1999/xhtml\"><p>{text}</p></div>"}


def _section(code: str, title: str, text: str = None) -> dict:
    return {
        "title": title,
        "code": {"coding": [{"system": LOINC, "code": code}]},
        "text": _narrative(text or title),
    }


def minimal_pdf_base64() -> str:
    """Base64 minimálního validního PDF (placeholder za PDF/A vizuál)."""
    return base64.b64encode(_MINIMAL_PDF).decode()


def build_ezd_bundle(kategorie: str, *, rid: str, autor_krzpid: str, ico: str,
                     pzs_nazev: str = "Testovací PZS",
                     pacient: dict = None,
                     pdf_base64: str = None,
                     title: str = None,
                     bundle_identifier: str = None,
                     sekce: dict = None,
                     autor: dict = None) -> dict:
    """Sestaví FHIR R4 document Bundle konformní s HL7 CZ IG (úroveň L1).

    ``kategorie`` je jeden z klíčů :data:`EZD_KATEGORIE`. Hlavička
    (Composition) obsahuje všechny povinné elementy a sekce dle profilu
    vč. presentedForm (PDF); tělo (klinické zdroje) není na L1 vyžadováno.

    ``sekce`` je volitelný slovník ``{slice: text | [text, ...]}`` s obsahem
    jednotlivých sekcí (pro interaktivní builder v GUI). Povinné sekce se
    doplní vždy – i bez textu, s poznámkou o nedostupnosti informace.
    Volitelné sekce se přidají jen tehdy, mají-li obsah.
    ``autor`` může nést ``{"jmeno", "prijmeni", "titul"}`` pro Practitioner.
    """
    meta = EZD_KATEGORIE.get(kategorie)
    if meta is None:
        raise ValueError(
            f"Neznámá kategorie eZD: {kategorie!r}. "
            f"Prioritní kategorie: {sorted(EZD_KATEGORIE)}")

    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    comp_uuid = f"urn:uuid:{uuid.uuid4()}"
    pat_uuid = f"urn:uuid:{uuid.uuid4()}"
    pract_uuid = f"urn:uuid:{uuid.uuid4()}"
    org_uuid = f"urn:uuid:{uuid.uuid4()}"
    enc_uuid = f"urn:uuid:{uuid.uuid4()}"
    dr_uuid = f"urn:uuid:{uuid.uuid4()}"

    pacient = pacient or {}

    patient_resource = {
        "resourceType": "Patient",
        "meta": {"profile": [CZ_PATIENT_PROFILE]},
        "identifier": [{"use": "official", "system": RID_SYSTEM, "value": rid}],
    }
    if pacient.get("jmeno") or pacient.get("prijmeni"):
        patient_resource["name"] = [{
            "use": "official",
            "family": pacient.get("prijmeni", ""),
            "given": [pacient.get("jmeno", "")] if pacient.get("jmeno") else [],
        }]
    if pacient.get("datum_narozeni"):
        patient_resource["birthDate"] = pacient["datum_narozeni"]

    practitioner_resource = {
        "resourceType": "Practitioner",
        "identifier": [{"system": KRZPID_SYSTEM, "value": autor_krzpid}],
    }
    autor = autor or {}
    if autor.get("jmeno") or autor.get("prijmeni"):
        jmeno_obj = {
            "use": "official",
            "family": autor.get("prijmeni", ""),
        }
        if autor.get("jmeno"):
            jmeno_obj["given"] = [autor["jmeno"]]
        if autor.get("titul"):
            jmeno_obj["prefix"] = [autor["titul"]]
        practitioner_resource["name"] = [jmeno_obj]
    organization_resource = {
        "resourceType": "Organization",
        "identifier": [{"system": ICO_SYSTEM, "value": ico}],
        "name": pzs_nazev,
    }

    # Sekce: povinné vždy, volitelné jen s obsahem (viz docstring)
    sekce = sekce or {}

    def _obsah(slice_name: str) -> str | None:
        val = sekce.get(slice_name)
        if val is None:
            return None
        if isinstance(val, (list, tuple)):
            items = [str(v).strip() for v in val if str(v).strip()]
            return " · ".join(items) if items else None
        text = str(val).strip()
        return text or None

    sekce_list = []
    for s in meta["required_sections"]:
        sekce_list.append(_section(
            s["code"], s["title"],
            _obsah(s["slice"]) or "Informace není k dispozici"))
    for s in meta.get("optional_sections", []):
        text = _obsah(s["slice"])
        if text:
            sekce_list.append(_section(s["code"], s["title"], text))

    composition = {
        "resourceType": "Composition",
        "meta": {"profile": [meta["composition_profile"]]},
        "status": "final",
        "type": {"coding": [dict(meta["type_coding"])]},
        "subject": {"reference": pat_uuid},
        "date": now_iso,
        "author": [{"reference": pract_uuid}],
        "custodian": {"reference": org_uuid},
        "title": title or f"{meta['nazev']} – testovací dokument (IROP/NPO)",
        "section": sekce_list,
    }
    if meta["category_codings"]:
        composition["category"] = [{"coding": [dict(c) for c in codings]}
                                    for codings in meta["category_codings"]]
    if meta.get("language_required"):
        composition["language"] = "cs"
    if meta.get("identifier_required"):
        composition["identifier"] = {"system": "urn:ietf:rfc:3986",
                                      "value": f"urn:uuid:{uuid.uuid4()}"}
    if meta.get("confidentiality_required"):
        composition["confidentiality"] = "N"

    # presentedForm – vizuální podoba (PDF/A) dle L1
    if meta.get("presented_form_required"):
        composition.setdefault("extension", []).append({
            "url": PRESENTED_FORM_EXT,
            "valueAttachment": {
                "contentType": "application/pdf",
                "data": pdf_base64 or minimal_pdf_base64(),
            },
        })

    entries = [
        {"fullUrl": comp_uuid, "resource": composition},
        {"fullUrl": pat_uuid, "resource": patient_resource},
        {"fullUrl": pract_uuid, "resource": practitioner_resource},
        {"fullUrl": org_uuid, "resource": organization_resource},
    ]

    if meta.get("encounter_required"):
        encounter_resource = {
            "resourceType": "Encounter",
            "status": "finished",
            "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                       "code": "IMP", "display": "inpatient encounter"},
            "subject": {"reference": pat_uuid},
            "serviceProvider": {"reference": org_uuid},
        }
        composition["encounter"] = {"reference": enc_uuid}
        entries.append({"fullUrl": enc_uuid, "resource": encounter_resource})

    if meta.get("diagnostic_report_required"):
        dr_resource = {
            "resourceType": "DiagnosticReport",
            "status": "final",
            "code": {"coding": [dict(meta["type_coding"])]},
            "subject": {"reference": pat_uuid},
            "issued": now_iso,
        }
        entries.append({"fullUrl": dr_uuid, "resource": dr_resource})

    return {
        "resourceType": "Bundle",
        "meta": {"profile": [meta["bundle_profile"]]},
        "identifier": {"system": "urn:ietf:rfc:3986",
                        "value": bundle_identifier or f"urn:uuid:{uuid.uuid4()}"},
        "type": "document",
        "timestamp": now_iso,
        "entry": entries,
    }


# ---------------------------------------------------------------------------
# Ukázková data pro interaktivní builder
# ---------------------------------------------------------------------------

# Demonstrační obsah sekcí pro každý typ zprávy – slouží jako „Vyplnit
# ukázková data" v GUI a jako příklad JSON v dokumentaci. Kódované položky
# (SNOMED/LOINC/ATC) patří v plné úrovni L3 do entry; na L1 jde o text.
UKAZKY = {
    "pacientsky-souhrn": {
        "title": "Pacientský souhrn – Mračena Mrakomorová",
        "sekce": {
            "sectionProblems": ["Diabetes mellitus 2. typu (E11)",
                                 "Arteriální hypertenze (I10)"],
            "sectionMedications": ["Metformin 1000 mg 2×denně",
                                    "Ramipril 5 mg 1×denně"],
            "sectionAllergies": ["Penicilin – exantém (2019)"],
            "sectionImmunizations": ["Tetanus (2021)", "COVID-19 mRNA (2023)"],
            "sectionVitalSigns": ["TK 138/86", "P 72", "Hmotnost 78 kg"],
            "sectionSocialHistory": ["Nekuřák", "Alkohol příležitostně"],
        },
    },
    "propousteci-zprava": {
        "title": "Propouštěcí zpráva – hospitalizace 12.–18. 7. 2026",
        "sekce": {
            "sectionHospitalCourse": [
                "Pacient přijat pro dekompenzaci diabetu s hyperglykemií 22 mmol/l.",
                "Zaveden inzulinový režim, stav se stabilizoval, glykemie 7–9 mmol/l.",
            ],
            "sectionProblemList": ["Dekompenzovaný diabetes mellitus 2. typu"],
            "sectionDiagnosticSummary": ["E11.9 – Diabetes mellitus 2. typu bez komplikací"],
            "sectionDischargeMedications": ["Metformin 1000 mg 2×denně",
                                             "Inzulin glargin 14 j. na noc"],
            "sectionDischargeInstructions": [
                "Kontrola u diabetologa do 14 dnů, měření glykemie 2× denně.",
            ],
            "sectionAllergies": ["Penicilin – exantém"],
            "sectionVitalSigns": ["TK 130/80 při propuštění"],
        },
    },
    "obrazove-vysetreni": {
        "title": "CT hrudníku – nález",
        "sekce": {
            "imagingstudy": ["CT hrudníku bez kontrastu, 18. 7. 2026, 120 kV"],
            "order": ["Žádanka č. Z-2026-4471, indikace: dušnost, susp. pneumonie"],
            "history": ["Kuřák 20 let, 3 dny febrilie a produktivní kašel"],
            "procedure": ["Nativní CT hrudníku, rozsah apex–bráníce"],
            "findings": [
                "V pravém dolním laloku splývavé konsolidace s air-bronchogramem.",
                "Bez pleurálního výpotku, mediastinum bez lymfadenopatie.",
            ],
            "impression": ["Pneumonie pravého dolního laloku."],
            "recommendation": ["Kontrolní snímek po 6 týdnech ATB terapie."],
        },
    },
    "vyjezd-zzs": {
        "title": "Záznam o výjezdu ZZS – náhlá zástava oběhu",
        "sekce": {
            "mission": ["Výzva 18:42, výjezd RLP, místo: Ústí nad Labem, Hrnčířská 12"],
            "dispatch": ["Priorita 1 – bezvědomí, nedýchá (dle volajícího)"],
            "timeline": ["18:42 výzva", "18:48 na místě", "19:15 předání na UP"],
            "findings": ["Pacient nereagující, bez dechu, GCS 3, komorová fibrilace"],
            "procedure": ["KPR 12 min, defibrilace 3×, intubace, adrenalin 3 mg i.v."],
            "diagnosticSummary": ["I46.9 – Zástava srdce, NS (ROSC v 19:02)"],
            "courseOfTreatment": ["Po ROSC transport za monitorace na urgentní příjem"],
        },
    },
    "laboratorni-vysetreni": {
        "title": "Laboratorní zpráva – biochemie a KO",
        "sekce": {
            "annotations": [
                "Glukóza 12,4 mmol/l (ref. 3,9–5,6) – zvýšeno",
                "HbA1c 68 mmol/mol (ref. do 42) – zvýšeno",
                "CRP 84 mg/l (ref. do 5) – zvýšeno",
                "Leukocyty 13,8 ×10⁹/l (ref. 4,0–10,0) – zvýšeno",
            ],
        },
    },
}


def ukazka_zpravy(kategorie: str, *, rid: str = "2667873559",
                   autor_krzpid: str = "102129137", ico: str = "25488627",
                   pzs_nazev: str = "Krajská zdravotní, a.s.") -> dict:
    """Vrátí kompletní ukázkový document Bundle dané kategorie – vhodný
    jako příklad JSON i jako výchozí obsah v GUI builderu."""
    u = UKAZKY.get(kategorie, {})
    return build_ezd_bundle(
        kategorie, rid=rid, autor_krzpid=autor_krzpid, ico=ico,
        pzs_nazev=pzs_nazev, title=u.get("title"), sekce=u.get("sekce"),
        pacient={"jmeno": "MRAČENA", "prijmeni": "MRAKOMOROVÁ",
                  "datum_narozeni": "1971-11-26"},
        autor={"jmeno": "Jan", "prijmeni": "Novák", "titul": "MUDr."},
    )


# ---------------------------------------------------------------------------
# Validace (L1)
# ---------------------------------------------------------------------------

def _coding_present(codeable, system: str, code: str) -> bool:
    if not isinstance(codeable, dict):
        return False
    for coding in codeable.get("coding", []) or []:
        if coding.get("system") == system and coding.get("code") == code:
            return True
    return False


def detect_kategorie(bundle: dict) -> str | None:
    """Určí kategorii eZD z Composition.type (LOINC), případně meta.profile."""
    comp = _first_resource(bundle, "Composition")
    if comp:
        for kat, meta in EZD_KATEGORIE.items():
            tc = meta["type_coding"]
            if _coding_present(comp.get("type"), tc["system"], tc["code"]):
                return kat
        profiles = (comp.get("meta") or {}).get("profile") or []
        for kat, meta in EZD_KATEGORIE.items():
            znama = [meta["composition_profile"],
                      *meta.get("composition_profile_aliasy", [])]
            if any(p in profiles for p in znama):
                return kat
    return None


def _first_resource(bundle: dict, resource_type: str) -> dict | None:
    for entry in bundle.get("entry", []) or []:
        res = entry.get("resource") or {}
        if res.get("resourceType") == resource_type:
            return res
    return None


def validate_ezd_bundle(bundle, kategorie: str = None) -> dict:
    """L1 validace document Bundle dle HL7 CZ IG a metodiky testování.

    Vrací ``{"valid", "errors", "warnings", "kategorie", "profil"}``.
    ``errors`` porušují kritéria shody (→ NEVYHOVUJE), ``warnings`` jsou
    nepodstatné odchylky (→ VYHOVUJE S VÝHRADAMI).
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(bundle, dict):
        return {"valid": False, "errors": ["Dokument není JSON objekt (FHIR JSON)"],
                "warnings": [], "kategorie": None, "profil": None}

    # -- syntaktická kontrola FHIR document Bundle --
    if bundle.get("resourceType") != "Bundle":
        errors.append("resourceType != Bundle")
    if bundle.get("type") != "document":
        errors.append("Bundle.type != document")
    if not bundle.get("identifier"):
        errors.append("Bundle.identifier chybí (dle IG povinný)")
    if not bundle.get("timestamp"):
        errors.append("Bundle.timestamp chybí (dle IG povinný)")

    entries = bundle.get("entry", []) or []
    if not entries:
        errors.append("Bundle.entry je prázdné")
    if entries and not all(e.get("fullUrl") for e in entries):
        errors.append("Některé Bundle.entry nemají fullUrl")
    if entries and entries[0].get("resource", {}).get("resourceType") != "Composition":
        errors.append("První entry musí být Composition (document Bundle)")

    comp = _first_resource(bundle, "Composition")
    patient = _first_resource(bundle, "Patient")
    if comp is None:
        errors.append("Chybí Composition")
    if patient is None:
        errors.append("Chybí Patient")

    kat = kategorie or detect_kategorie(bundle)
    meta = EZD_KATEGORIE.get(kat) if kat else None

    if comp is not None:
        # -- obecná hlavička --
        for field in ("status", "type", "date", "title"):
            if not comp.get(field):
                errors.append(f"Composition.{field} chybí")
        if not comp.get("subject"):
            errors.append("Composition.subject chybí (dle IG 1..1)")
        if not comp.get("author"):
            errors.append("Composition.author chybí")
        if not comp.get("section"):
            errors.append("Composition.section chybí")

        if meta:
            tc = meta["type_coding"]
            if not _coding_present(comp.get("type"), tc["system"], tc["code"]):
                errors.append(
                    f"Composition.type nemá kód {tc['code']} ({tc['system']}) "
                    f"dle profilu {meta['composition_profile']}")
            profiles = (comp.get("meta") or {}).get("profile") or []
            aliasy = meta.get("composition_profile_aliasy", [])
            if meta["composition_profile"] not in profiles:
                if any(a in profiles for a in aliasy):
                    warnings.append(
                        "Composition.meta.profile používá starší canonical "
                        f"{[a for a in aliasy if a in profiles][0]} – aktuální "
                        f"je {meta['composition_profile']} (přejmenováno "
                        "v CI buildu IG 10. 7. 2026)")
                else:
                    warnings.append(
                        f"Composition.meta.profile nedeklaruje {meta['composition_profile']}")

            for codings in meta["category_codings"]:
                expected = codings[0]
                cats = comp.get("category") or []
                if not any(_coding_present(c, expected["system"], expected["code"])
                            for c in cats):
                    errors.append(
                        f"Composition.category nemá povinný kód "
                        f"{expected['code']} ({expected['system']})")

            if meta.get("language_required") and not comp.get("language"):
                errors.append("Composition.language chybí (dle IG 1..1)")
            if meta.get("identifier_required") and not comp.get("identifier"):
                errors.append("Composition.identifier chybí (dle IG 1..1)")
            if meta.get("confidentiality_required") and not comp.get("confidentiality"):
                errors.append("Composition.confidentiality chybí (dle IG 1..1)")
            if meta.get("encounter_required") and not comp.get("encounter"):
                errors.append("Composition.encounter chybí (dle IG 1..1)")

            if meta.get("presented_form_required"):
                pf = [e for e in comp.get("extension", []) or []
                      if e.get("url") == PRESENTED_FORM_EXT]
                if not pf:
                    errors.append(
                        "Chybí povinná extension presentedForm "
                        f"({PRESENTED_FORM_EXT}) – vizuální podoba PDF/A")
                else:
                    att = pf[0].get("valueAttachment") or {}
                    if not (att.get("data") or att.get("url")):
                        errors.append("presentedForm nemá data ani url")
                    elif att.get("contentType") not in ("application/pdf", None):
                        warnings.append(
                            f"presentedForm.contentType={att.get('contentType')!r} "
                            "(očekáváno application/pdf – PDF/A)")

            sections = comp.get("section") or []
            if len(sections) < meta.get("min_sections", 1):
                errors.append(
                    f"Composition.section má {len(sections)} sekcí, "
                    f"dle IG minimálně {meta['min_sections']}")
            for req in meta["required_sections"]:
                found = any(_coding_present(s.get("code"), LOINC, req["code"])
                             for s in sections)
                if not found:
                    errors.append(
                        f"Chybí povinná sekce {req['slice']} "
                        f"(LOINC {req['code']} – {req['title']})")
            for s in sections:
                if not (s.get("text") or s.get("entry") or s.get("section")):
                    warnings.append(
                        f"Sekce '{s.get('title', '?')}' nemá text ani entry")

    if patient is not None:
        idents = patient.get("identifier") or []
        rid_ok = any(i.get("system") == RID_SYSTEM and i.get("value")
                      for i in idents)
        if not rid_ok:
            # starší OID zápis bereme jako výhradu, ne chybu
            legacy = any("2.16.840.1.113883.4.653" in str(i.get("system", ""))
                          for i in idents)
            if legacy:
                warnings.append(
                    f"Patient.identifier používá legacy OID; dle cz-core má být "
                    f"system {RID_SYSTEM}")
            else:
                errors.append(
                    f"Patient.identifier neobsahuje RID se system {RID_SYSTEM} "
                    "(cz-patient-core: identifier:RID 1..1)")

    if meta and meta.get("diagnostic_report_required"):
        if _first_resource(bundle, "DiagnosticReport") is None:
            errors.append(
                "Chybí DiagnosticReport (cz-bundle-imaging: "
                "entry:diagnosticReport 1..*)")

    if meta:
        bundle_profiles = (bundle.get("meta") or {}).get("profile") or []
        if meta["bundle_profile"] not in bundle_profiles:
            warnings.append(
                f"Bundle.meta.profile nedeklaruje {meta['bundle_profile']}")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "kategorie": kat,
        "profil": meta["composition_profile"] if meta else None,
    }
