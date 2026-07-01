"""
FHIR Imaging Order ⇔ NCEZ /eZadanky bridge.

Standard: HL7 Czech Imaging Order FHIR IG v0.1.0-ballot (FHIR R4 / 4.0.1)
   https://build.fhir.org/ig/HL7-cz/img-order/   (continuous CI build, draft)
   Kanonická báze IG: https://hl7.cz/fhir/img-order

Závislosti IG (ověřeno 2026-06-02 ze sushi-config.yaml):
   - hl7.fhir.cz.core            → 0.3.0  (STU1, trial-use, aktivní 2026-03-06)
   - hl7.fhir.cz.terminology     → 0.2.0  (release, aktivní 2026-02-02, tranzitivně přes core)
   - hl7.fhir.eu.base            → 2.0.0
   - hl7.fhir.eu.extensions.r4   → 1.3.0

Profil hlavního dokumentu:  cz-bundleImageOrder        (Bundle, type=document)
Profil Composition:         cz-compositionImageOrder
Profil ServiceRequest:      cz-imagingOrderInformation
Profil Condition (důvod):   cz-conditionImage          (MKN-10 / Mkn10_5, ORPHA)
Profil Observation:         cz-bodyHeight, cz-bodyWeight, cz-observationImage, cz-patientMobility
Profil Coverage:            cz-coverage (z cz-core)

ValueSety definované v IG: cz-modality(-vs), cz-imagingProcedureVs,
   cz-diagnosisConditionVs (Mkn10_5), cz-imaging-mobilityType/Value,
   cz-observation-unit-height/weight, cz-vzp-odbornost.
   POZN.: cz-bodySite a cz-bodySiteQualifier NEJSOU v IG samostatné ValueSety –
   bodySite se váže na základní FHIR ValueSet body-site + BodyStructureCz.
   V tomto modulu je vedeme jako *pomocné* (convenience) sety pro UI (ig=False).

Terminologický server (NTS / TermX, FHIR R4):
   - PROD read-only FHIR báze: https://apio.csez.gov.cz/terminologie
       (operace $lookup, $expand, $validate-code, $translate)
   - veřejný mirror (T2): termx-api-t2-pub.csez.cz  (používán pro live expand)

Cílový proprietární endpoint: NCEZ /eZadanky/api/v1/eZadanka/UlozZadanku
   (UlozZadankuExtRequest – viz sez_api/client.py: EZadanky.uloz_zadanku)

Tento modul poskytuje:
  - parsování a validaci CZ_BundleImageOrder Bundle (resourceType=Bundle, type=document)
  - extrakci klíčových údajů (RID pacienta, KRZP autora, IČO PZS,
    pojišťovna, ServiceRequest kódy, ICD-10 dg, modalita)
  - sestavení NCEZ UlozZadankuExtRequest těla z FHIR Bundle (FHIR → NCEZ)
  - zpětnou transformaci NactiZadanku odpovědi do FHIR Bundle (NCEZ → FHIR)
  - generování OperationOutcome odpovědí
  - lehkou strukturální validaci (povinná pole, identifier systems, kódy)
"""
from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Identifikační systémy (URI) podle CZ-core a img-order IG
# ---------------------------------------------------------------------------

SYS_RID = "https://ncez.mzcr.cz/fhir/sid/rid"            # NCEZ RID pacienta
SYS_CPOJ = "https://ncez.mzcr.cz/fhir/sid/cpoj"          # Číslo pojištěnce
SYS_KRZP = "https://ncez.mzcr.cz/fhir/sid/krzp"          # KRZP ID zdravotnického pracovníka
SYS_KP = "https://ncez.mzcr.cz/fhir/sid/kp"              # Kód pojišťovny (KP)
SYS_ICO = "https://ncez.mzcr.cz/fhir/sid/ico"            # IČO PZS

SYS_SNOMED = "http://snomed.info/sct"
SYS_LOINC = "http://loinc.org"
SYS_DICOM = "http://dicom.nema.org/resources/ontology/DCM"
SYS_MKN10_5 = "https://terminology.uzis.cz/CodeSystem/Mkn10_5"
SYS_ORPHA = "http://www.orpha.net"
SYS_UCUM = "http://unitsofmeasure.org"

# IG identita + závislosti (ověřeno 2026-06-02 ze sushi-config.yaml)
IG_VERSION = "0.1.0-ballot"
IG_FHIR_VERSION = "4.0.1"
IG_CANONICAL = "https://hl7.cz/fhir/img-order"
IG_DEPENDENCIES = {
    "hl7.fhir.cz.core": "0.3.0",
    "hl7.fhir.cz.terminology": "0.2.0",
    "hl7.fhir.eu.base": "2.0.0",
    "hl7.fhir.eu.extensions.r4": "1.3.0",
}

# Kanonická báze ValueSetů (NCEZ terminologie) a běhové TermX endpointy
TERMINOLOGY_VS_BASE = "https://ncez.mzcr.cz/terminology/ValueSet"
TERMX_FHIR_BASE_PROD = "https://apio.csez.gov.cz/terminologie"   # PROD read-only FHIR
TERMX_PUBLIC_MIRROR_T2 = "termx-api-t2-pub.csez.cz"               # T2 public mirror

PROFILE_BUNDLE = "https://hl7.cz/fhir/img-order/StructureDefinition/cz-bundleImageOrder"
PROFILE_COMPOSITION = "https://hl7.cz/fhir/img-order/StructureDefinition/cz-compositionImageOrder"
PROFILE_SR = "https://hl7.cz/fhir/img-order/StructureDefinition/cz-imagingOrderInformation"
PROFILE_CONDITION = "https://hl7.cz/fhir/img-order/StructureDefinition/cz-conditionImage"
PROFILE_PATIENT = "https://hl7.cz/fhir/core/StructureDefinition/cz-patient-core"
PROFILE_PRACTITIONER = "https://hl7.cz/fhir/core/StructureDefinition/cz-practitioner-core"
PROFILE_ORG = "https://hl7.cz/fhir/core/StructureDefinition/cz-organization-core"
PROFILE_COVERAGE = "https://hl7.cz/fhir/core/StructureDefinition/cz-coverage"

# Kódy známé z příkladů (referenční, ne autoritativní)
SCT_IMAGING_CATEGORY = "363679005"   # Imaging (ServiceRequest.category)
LOINC_REQUESTED_IMAGING_INFO = "55115-0"
LOINC_CLINICAL_QUESTION = "18785-6"
LOINC_DEVICES_IMPLANTS = "97813-0"
LOINC_SUPPORTING_INFO = "55752-0"
SCT_COMPOSITION_TYPE_IMG_ORDER = "721964003"  # Imaging order (record artifact)
LOINC_CATEGORY_IMG_ORDER = "57133-1"          # Imaging studies report (cat)

# NCEZ číselníky / verze
URGENTNOST_VERZE = "5.0.2"
FHIR_PRIORITY_TO_URGENTNOST = {
    "routine": "routine",
    "urgent": "urgent",
    "asap": "asap",
    "stat": "stat",
}
# default RAD (radiologie) jako metoda – img-order pokrývá modality DX/CR/CT/MR/US/PT/NM/XA
NCEZ_METODA_RAD = {"kod": "RAD", "verze": "1.0"}
NCEZ_ADRESAT_PZS = {"kod": "PZS", "verze": "1.0.0"}
NCEZ_STAV_NOVA = {"kod": "0", "verze": "1.0.0"}
ZASILKA_TYP_IMG_ORDER = {"kod": SCT_COMPOSITION_TYPE_IMG_ORDER, "verze": "1.0.0"}
ZASILKA_KLASIFIKACE_IMG_ORDER = {"kod": LOINC_CATEGORY_IMG_ORDER, "verze": "1.0.0"}

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "fhir_imgorder_examples")


# ---------------------------------------------------------------------------
# Taxonomy seed – ValueSets z img-order IG
# ---------------------------------------------------------------------------
# IG definuje:
#   - cz-modalityVs              (DICOM)
#   - cz-imagingProcedureVs      (SNOMED CT)
#   - cz-diagnosisConditionVs    (MKN-10 + ORPHA)
#   - cz-mobilityTypeVs          (SNOMED CT)
#   - cz-mobilityValueVs         (SNOMED CT)
#   - cz-bodySite (běžné použití) (SNOMED CT)
#   - cz-observationUnitsHeightVs / cz-observationUnitsWeightVs (UCUM)
#
# Tyto seedy obsahují nejčastější hodnoty pro UI dropdown / tabulku.
# Pro plný expand (zejména SNOMED, MKN-10) lze použít TermX přes
# /api/termx/valueset/{id}/expand.

VS_MODALITY = {
    "id": "cz-modalityVs",
    # Ověřená kanonická URL dle IG (CZ_ModalityVs, verze 1.0.0):
    "url": "https://ncez.mzcr.cz/terminology/ValueSet/cz-modality",
    "title": "Modalita zobrazovacího vyšetření (DICOM)",
    "system": SYS_DICOM,
    "ig": True,
    # Reálný TermX ValueSet (public mirror) s 41 modalitami a českými display:
    "termx_id": "cz-modality--1.0.0",
    "termx_public": True,
    "concept": [
        {"code": "DX",  "display": "Digital Radiography"},
        {"code": "CR",  "display": "Computed Radiography"},
        {"code": "CT",  "display": "Computed Tomography"},
        {"code": "MR",  "display": "Magnetic Resonance"},
        {"code": "US",  "display": "Ultrasound"},
        {"code": "PT",  "display": "Positron Emission Tomography (PET)"},
        {"code": "NM",  "display": "Nuclear Medicine"},
        {"code": "XA",  "display": "X-Ray Angiography"},
        {"code": "MG",  "display": "Mammography"},
        {"code": "RF",  "display": "Radio Fluoroscopy"},
        {"code": "OT",  "display": "Other"},
        {"code": "ES",  "display": "Endoscopy"},
        {"code": "BMD", "display": "Bone Mineral Densitometry"},
        {"code": "DG",  "display": "Diaphanography"},
        {"code": "PX",  "display": "Panoramic X-Ray"},
        {"code": "GM",  "display": "General Microscopy"},
        {"code": "IO",  "display": "Intra-Oral Radiography"},
        {"code": "OCT", "display": "Optical Coherence Tomography"},
        {"code": "OP",  "display": "Ophthalmic Photography"},
        {"code": "RG",  "display": "Radiographic Imaging"},
        {"code": "SM",  "display": "Slide Microscopy"},
        {"code": "SR",  "display": "SR Document"},
        {"code": "TG",  "display": "Thermography"},
        {"code": "XC",  "display": "External Camera Photography"},
    ],
}

VS_IMAGING_PROCEDURE = {
    "id": "cz-imagingProcedureVs",
    "url": "https://ncez.mzcr.cz/terminology/ValueSet/cz-imaging-procedure-vs",
    "title": "Procedura zobrazovacího vyšetření (SNOMED CT)",
    "system": SYS_SNOMED,
    "ig": True,
    # Reálný TermX VS (6751 SNOMED procedur img-order ballot 0.1.0):
    "termx_id": "cz-imaging-procedure-vs--0.1.0-ballot",
    "termx_public": True,
    # Praktická alternativa s LOINC kódy a českými display (56 položek):
    "termx_alt": [
        {"id": "imaging-document-types--1.0.0",
         "title": "Typy dokumentů obrazového komplementu (LOINC, česky)",
         "system": SYS_LOINC},
    ],
    "concept": [
        # Z příkladů Bundle Kralik RTG + běžné radiologické procedury
        {"code": "168537006",  "display": "Plain X-ray"},
        {"code": "169070004",  "display": "Plain X-ray of skull"},
        {"code": "168731009",  "display": "Plain chest X-ray"},
        {"code": "169068003",  "display": "Plain X-ray of pelvis"},
        {"code": "241541005",  "display": "Plain X-ray of cervical spine"},
        {"code": "241544002",  "display": "Plain X-ray of thoracic spine"},
        {"code": "241548004",  "display": "Plain X-ray of lumbar spine"},
        {"code": "241560004",  "display": "Plain X-ray of knee"},
        {"code": "241552004",  "display": "Plain X-ray of hip"},
        {"code": "241564008",  "display": "Plain X-ray of ankle"},
        {"code": "169040000",  "display": "Plain X-ray of abdomen"},
        # CT
        {"code": "77477000",   "display": "Computed tomography"},
        {"code": "303653007",  "display": "CT of head"},
        {"code": "169069006",  "display": "CT of chest"},
        {"code": "418023006",  "display": "CT of abdomen and pelvis"},
        {"code": "303722002",  "display": "CT of cervical spine"},
        {"code": "169037009",  "display": "CT of brain"},
        # MR
        {"code": "113091000",  "display": "Magnetic resonance imaging"},
        {"code": "241620003",  "display": "MRI of brain"},
        {"code": "432048007",  "display": "MRI of cervical spine"},
        {"code": "432050004",  "display": "MRI of lumbar spine"},
        {"code": "432104005",  "display": "MRI of knee"},
        {"code": "432105006",  "display": "MRI of shoulder"},
        # US
        {"code": "16310003",   "display": "Diagnostic ultrasound"},
        {"code": "78764006",   "display": "Echocardiography"},
        {"code": "419224008",  "display": "Ultrasound of abdomen"},
        {"code": "241341008",  "display": "Ultrasound of thyroid"},
        {"code": "241317008",  "display": "Pelvic ultrasound"},
        # MG
        {"code": "71651007",   "display": "Mammography"},
        # PT/NM
        {"code": "82918005",   "display": "Positron emission tomography"},
        {"code": "363680007",  "display": "Nuclear medicine procedure"},
    ],
}

VS_BODY_SITE = {
    "id": "cz-bodySite",
    # POZN.: NENÍ samostatný IG ValueSet – img-order váže ServiceRequest.bodySite
    # na základní FHIR VS http://hl7.org/fhir/ValueSet/body-site (+ BodyStructureCz).
    # Vedeme jako pomocný (convenience) set pro UI výběr nejčastějších oblastí.
    "url": "http://hl7.org/fhir/ValueSet/body-site",
    "title": "Oblast těla (SNOMED CT Body Structures) – pomocný výběr",
    "system": SYS_SNOMED,
    "ig": False,
    # Reálný TermX VS (37 111 SNOMED CT Body Structures, vyžaduje filter+count):
    "termx_id": "body-site--6.0.0",
    "termx_public": True,
    "termx_requires_filter": True,
    "concept": [
        # Z příkladů Bundle Kralik RTG + běžné body sites
        {"code": "6757004",    "display": "Right knee"},
        {"code": "82169009",   "display": "Left knee"},
        {"code": "62175007",   "display": "Right leg"},
        {"code": "32153003",   "display": "Left leg"},
        {"code": "287679003",  "display": "Right hip"},
        {"code": "287579007",  "display": "Left hip"},
        {"code": "12611008",   "display": "Pelvis"},
        {"code": "731788002",  "display": "Entire joint of lumbosacral junction of spine"},
        {"code": "33014001",   "display": "Lumbar spine"},
        {"code": "11378001",   "display": "Cervical spine"},
        {"code": "122494005",  "display": "Thoracic spine"},
        {"code": "69536005",   "display": "Head"},
        {"code": "12738006",   "display": "Brain"},
        {"code": "51185008",   "display": "Thoracic structure"},
        {"code": "302541006",  "display": "Heart"},
        {"code": "39607008",   "display": "Lung"},
        {"code": "76752008",   "display": "Breast"},
        {"code": "818983003",  "display": "Abdomen"},
        {"code": "10200004",   "display": "Liver"},
        {"code": "64033007",   "display": "Kidney"},
        {"code": "302521001",  "display": "Right talus bone"},  # 'Structure of right talus bone'
        {"code": "16982005",   "display": "Shoulder region"},
        {"code": "16953009",   "display": "Elbow region"},
        {"code": "8205005",    "display": "Wrist region"},
        {"code": "344001",     "display": "Ankle"},
        {"code": "302293008",  "display": "Foot"},
    ],
}

VS_MOBILITY_TYPE = {
    "id": "cz-mobilityTypeVs",
    "url": "https://ncez.mzcr.cz/terminology/ValueSet/cz-imaging-mobilityType",
    "title": "Typ omezení mobility (SNOMED CT)",
    "system": SYS_SNOMED,
    "ig": True,
    "concept": [
        {"code": "364832000",  "display": "Mobility / motor function finding"},
        {"code": "248280008",  "display": "Pacient mobility"},
        {"code": "364831007",  "display": "Mobility-related findings"},
    ],
}

VS_MOBILITY_VALUE = {
    "id": "cz-mobilityValueVs",
    "url": "https://ncez.mzcr.cz/terminology/ValueSet/cz-imaging-mobilityValue",
    "title": "Hodnota mobility / im/mobility (SNOMED CT)",
    "system": SYS_SNOMED,
    "ig": True,
    "concept": [
        {"code": "713511005",  "display": "Mobile"},
        {"code": "289003007",  "display": "Limited mobility"},
        {"code": "8510008",    "display": "Reduced mobility"},
        {"code": "371151008",  "display": "Immobile"},
        {"code": "165245003",  "display": "Wheelchair user"},
        {"code": "439681000124106", "display": "Bedbound (finding)"},
    ],
}

VS_DIAGNOSIS_CONDITION = {
    "id": "cz-diagnosisConditionVs",
    "url": "https://ncez.mzcr.cz/terminology/ValueSet/cz-diagnosis-condition",
    "title": "Diagnóza pro indikaci (MKN-10 / Mkn10_5)",
    "system": SYS_MKN10_5,
    "ig": True,
    # Reálný TermX VS (38 934 MKN-10 položek, vyžaduje filter+count):
    "termx_id": "mkn-10--0.1.2",
    "termx_public": True,
    "termx_requires_filter": True,
    # Pro $lookup používáme kanonickou WHO ICD-10 URL (TermX má v ní data),
    # ale i Mkn10_5 (CZ rozšíření) – lookup zkusíme oba pak fallback:
    "termx_lookup_systems": [
        "http://hl7.org/fhir/sid/icd-10",
        SYS_MKN10_5,
    ],
    "concept": [
        # Top běžné indikace pro radiologii
        {"code": "M54.5",  "display": "Bolesti dolní části zad"},
        {"code": "M51.1",  "display": "Onemocnění meziobratlové ploténky bederní s radikulopatií"},
        {"code": "M16.1",  "display": "Primární koxartróza, ostatní"},
        {"code": "M17.1",  "display": "Primární gonartróza, ostatní"},
        {"code": "M75.1",  "display": "Syndrom rotátorové manžety"},
        {"code": "S01.8",  "display": "Otevřená rána jiných částí hlavy"},
        {"code": "S06.0",  "display": "Otřes mozku"},
        {"code": "S22.3",  "display": "Zlomenina žebra"},
        {"code": "S52.5",  "display": "Zlomenina dolního konce kosti vřetenní"},
        {"code": "S72.0",  "display": "Zlomenina krčku stehenní kosti"},
        {"code": "S82.6",  "display": "Zlomenina kotníku"},
        {"code": "C50.9",  "display": "Zhoubný novotvar prsu, NS"},
        {"code": "C34.9",  "display": "Zhoubný novotvar průdušky a plíce, NS"},
        {"code": "C61",    "display": "Zhoubný novotvar prostaty"},
        {"code": "C18.9",  "display": "Zhoubný novotvar tlustého střeva, NS"},
        {"code": "I63.9",  "display": "Mozkový infarkt, NS"},
        {"code": "I25.1",  "display": "Aterosklerotická srdeční choroba"},
        {"code": "I50.0",  "display": "Městnavé selhání srdce"},
        {"code": "J18.9",  "display": "Zápal plic, NS"},
        {"code": "J44.9",  "display": "Chronická obstrukční plicní nemoc, NS"},
        {"code": "K80.5",  "display": "Kámen ve žlučovodu bez cholangitidy nebo cholecystitidy"},
        {"code": "N20.0",  "display": "Kámen v ledvině"},
        {"code": "R10.4",  "display": "Bolest břicha jiná a neurčená"},
        {"code": "R51",    "display": "Bolest hlavy"},
        {"code": "Z01.6",  "display": "Radiologické vyšetření, nezařazené jinde"},
    ],
}

VS_BODY_SITE_QUALIFIER = {
    "id": "cz-bodySiteQualifier",
    # POZN.: NENÍ samostatný IG ValueSet (lateralita se řeší přes BodyStructureCz
    # / bodySite extension). Pomocný (convenience) set pro UI výběr laterality.
    "url": "https://ncez.mzcr.cz/terminology/ValueSet/cz-sitequalifier-vs",
    "title": "Kvalifikátor lokality / lateralita (SNOMED CT) – pomocný výběr",
    "system": SYS_SNOMED,
    "ig": False,
    "termx_id": "cz-sitequalifier-vs--0.3.0-ballot",
    "termx_public": True,
    "concept": [
        {"code": "7771000",   "display": "Left"},
        {"code": "24028007",  "display": "Right"},
        {"code": "51440002",  "display": "Bilateral"},
        {"code": "46053002",  "display": "Distal"},
        {"code": "255554000", "display": "Dorsal"},
        {"code": "261183002", "display": "Upper"},
        {"code": "261122009", "display": "Lower"},
        {"code": "255561001", "display": "Medial"},
        {"code": "49370004",  "display": "Lateral"},
        {"code": "264217000", "display": "Superior"},
    ],
}

ALL_VALUE_SETS = [
    VS_MODALITY,
    VS_IMAGING_PROCEDURE,
    VS_BODY_SITE,
    VS_BODY_SITE_QUALIFIER,
    VS_DIAGNOSIS_CONDITION,
    VS_MOBILITY_TYPE,
    VS_MOBILITY_VALUE,
]

VS_BY_ID = {vs["id"]: vs for vs in ALL_VALUE_SETS}


def list_valuesets() -> list[dict]:
    """Vrátí seznam VS metadat pro UI navigátor."""
    return [{
        "id": vs["id"],
        "url": vs["url"],
        "title": vs["title"],
        "system": vs["system"],
        "ig": vs.get("ig", True),
        "count": len(vs["concept"]),
        "termx_id": vs.get("termx_id"),
        "termx_public": vs.get("termx_public", False),
        "termx_requires_filter": vs.get("termx_requires_filter", False),
        "termx_lookup_systems": vs.get("termx_lookup_systems") or [vs["system"]],
        "termx_alt": vs.get("termx_alt") or [],
    } for vs in ALL_VALUE_SETS]


def expand_valueset(vs_id: str, filter_text: str | None = None,
                    limit: int = 200) -> dict | None:
    """Vrátí FHIR ValueSet s expansion ze seedu (filtr podle text/code)."""
    vs = VS_BY_ID.get(vs_id)
    if not vs:
        return None
    needle = (filter_text or "").strip().lower()
    contains = []
    for c in vs["concept"]:
        if needle:
            if needle not in c["code"].lower() and needle not in c["display"].lower():
                continue
        contains.append({
            "system": vs["system"],
            "code": c["code"],
            "display": c["display"],
        })
        if len(contains) >= limit:
            break
    return {
        "resourceType": "ValueSet",
        "id": vs["id"],
        "url": vs["url"],
        "title": vs["title"],
        "status": "active",
        "expansion": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "total": len(contains),
            "contains": contains,
        },
    }


# ---------------------------------------------------------------------------
# Helper – výpis chyb / OperationOutcome
# ---------------------------------------------------------------------------

class FhirValidationError(Exception):
    """Strukturální nebo sémantická chyba CZ_BundleImageOrder."""

    def __init__(self, issues: list[dict]):
        super().__init__(f"FHIR validation failed: {len(issues)} issue(s)")
        self.issues = issues


def operation_outcome(issues: list[dict]) -> dict:
    """Sestaví FHIR OperationOutcome resource z issue listu."""
    return {
        "resourceType": "OperationOutcome",
        "issue": issues or [{
            "severity": "information",
            "code": "informational",
            "diagnostics": "OK",
        }],
    }


def issue(severity: str, code: str, diagnostics: str, location: str | None = None) -> dict:
    out = {"severity": severity, "code": code, "diagnostics": diagnostics}
    if location:
        out["expression"] = [location]
    return out


# ---------------------------------------------------------------------------
# Bundle parser – validace + extrakce klíčových polí
# ---------------------------------------------------------------------------

class ImagingOrderBundleParser:
    """Načte CZ_BundleImageOrder a vystaví indexovaný pohled na resources.

    Použití:
        parser = ImagingOrderBundleParser(fhir_bundle_dict)
        parser.validate()  # vyhodí FhirValidationError nebo vrátí []
        data = parser.extract()  # dict s klíči patient/practitioner/...
    """

    def __init__(self, bundle: dict):
        if not isinstance(bundle, dict):
            raise FhirValidationError([issue("error", "structure", "Bundle musí být JSON object")])
        self.bundle = bundle
        self.entries: list[dict] = bundle.get("entry") or []
        # index podle resourceType i podle fullUrl (urn:uuid:...)
        self._by_type: dict[str, list[dict]] = {}
        self._by_ref: dict[str, dict] = {}
        for e in self.entries:
            r = e.get("resource") or {}
            rt = r.get("resourceType")
            if not rt:
                continue
            self._by_type.setdefault(rt, []).append(r)
            full_url = e.get("fullUrl")
            rid = r.get("id")
            if full_url:
                self._by_ref[full_url] = r
            if rid:
                # forma "ResourceType/id" – běžné v reference
                self._by_ref[f"{rt}/{rid}"] = r
                self._by_ref[f"urn:uuid:{rid}"] = r

    # --- Validation ------------------------------------------------------

    def validate(self, strict: bool = False) -> list[dict]:
        """Vrátí list FHIR Issues. strict=True → vyhodí výjimku při errorech."""
        out: list[dict] = []
        b = self.bundle
        if b.get("resourceType") != "Bundle":
            out.append(issue("error", "structure", "resourceType musí být 'Bundle'", "Bundle.resourceType"))
        if b.get("type") != "document":
            out.append(issue("error", "value", "Bundle.type musí být 'document' (CZ_BundleImageOrder)", "Bundle.type"))
        profiles = (b.get("meta") or {}).get("profile") or []
        if PROFILE_BUNDLE not in profiles:
            out.append(issue("warning", "informational",
                             f"Bundle.meta.profile by měl obsahovat {PROFILE_BUNDLE}",
                             "Bundle.meta.profile"))
        if not self.entries:
            out.append(issue("error", "required", "Bundle.entry je prázdný", "Bundle.entry"))
        # Composition jako první entry (FHIR document pravidlo)
        first = (self.entries[0].get("resource") if self.entries else {}) or {}
        if first.get("resourceType") != "Composition":
            out.append(issue("error", "structure",
                             "První Bundle.entry musí být Composition (FHIR document)",
                             "Bundle.entry[0].resource"))
        # Povinné resources
        if not self._by_type.get("Patient"):
            out.append(issue("error", "required", "V Bundle chybí Patient resource", "Bundle.entry"))
        if not self._by_type.get("ServiceRequest"):
            out.append(issue("error", "required", "V Bundle chybí ServiceRequest resource", "Bundle.entry"))
        # ServiceRequest profil
        for sr in self._by_type.get("ServiceRequest", []):
            srprofs = (sr.get("meta") or {}).get("profile") or []
            if PROFILE_SR not in srprofs:
                out.append(issue("warning", "informational",
                                 f"ServiceRequest/{sr.get('id')} by měl mít profile {PROFILE_SR}",
                                 "ServiceRequest.meta.profile"))
            if sr.get("intent") != "order":
                out.append(issue("error", "value",
                                 f"ServiceRequest/{sr.get('id')}: intent musí být 'order'",
                                 "ServiceRequest.intent"))
            if not sr.get("status"):
                out.append(issue("error", "required",
                                 f"ServiceRequest/{sr.get('id')}: status je povinný",
                                 "ServiceRequest.status"))
            if not sr.get("subject"):
                out.append(issue("error", "required",
                                 f"ServiceRequest/{sr.get('id')}: subject je povinný",
                                 "ServiceRequest.subject"))
        # Patient identifier RID
        for p in self._by_type.get("Patient", []):
            ids = p.get("identifier") or []
            has_rid = any(i.get("system") == SYS_RID for i in ids)
            if not has_rid:
                out.append(issue("warning", "informational",
                                 f"Patient/{p.get('id')}: chybí identifier(system={SYS_RID}) – RID je doporučen",
                                 "Patient.identifier"))
        # Practitioner KRZP
        for pr in self._by_type.get("Practitioner", []):
            ids = pr.get("identifier") or []
            has_krzp = any(i.get("system") == SYS_KRZP for i in ids)
            if not has_krzp:
                out.append(issue("warning", "informational",
                                 f"Practitioner/{pr.get('id')}: chybí identifier(system={SYS_KRZP})",
                                 "Practitioner.identifier"))
        if strict and any(i["severity"] == "error" for i in out):
            raise FhirValidationError(out)
        return out

    # --- Lookup helpers --------------------------------------------------

    def resolve(self, ref: dict | str | None) -> dict | None:
        """Z FHIR Reference dict (s .reference) najde resource v Bundle."""
        if not ref:
            return None
        if isinstance(ref, dict):
            ref = ref.get("reference")
        if not isinstance(ref, str):
            return None
        return self._by_ref.get(ref)

    def first(self, rt: str) -> dict | None:
        lst = self._by_type.get(rt) or []
        return lst[0] if lst else None

    def all(self, rt: str) -> list[dict]:
        return self._by_type.get(rt) or []

    # --- Extraction ------------------------------------------------------

    def extract(self) -> dict:
        """Vytáhne ploché klíčové údaje pro UI a další zpracování."""
        comp = self.first("Composition") or {}
        patient = self.first("Patient") or {}
        practitioner = self.first("Practitioner") or {}
        practitioner_role = self.first("PractitionerRole") or {}
        org = self.first("Organization") or {}
        coverage = self.first("Coverage") or {}
        condition = self.first("Condition") or {}
        srs = self.all("ServiceRequest")

        # IDs
        rid = _identifier_value(patient, SYS_RID)
        cpoj = _identifier_value(patient, SYS_CPOJ)
        krzp = _identifier_value(practitioner, SYS_KRZP)
        ico = _identifier_value(org, SYS_ICO)
        # Pojišťovna – přes Coverage.payor → Organization s identifier(system=KP)
        kp_kod = None
        for payor in coverage.get("payor") or []:
            payor_org = self.resolve(payor)
            if payor_org and payor_org.get("resourceType") == "Organization":
                k = _identifier_value(payor_org, SYS_KP)
                if k:
                    kp_kod = k
                    break

        # ServiceRequests – ploché summary + first ServiceRequest dominantní
        sr_summary = []
        for sr in srs:
            code = _coding_first(sr.get("code"), SYS_SNOMED)
            modality = _coding_first(_first(sr.get("orderDetail")), SYS_DICOM)
            body_site = _coding_first(_first(sr.get("bodySite")), SYS_SNOMED)
            sr_summary.append({
                "id": sr.get("id"),
                "status": sr.get("status"),
                "intent": sr.get("intent"),
                "priority": sr.get("priority", "routine"),
                "code": code,                   # SNOMED procedure
                "modality": modality,           # DICOM (DX/CR/CT/MR/...)
                "body_site": body_site,         # SNOMED body site
                "authored_on": sr.get("authoredOn"),
                "identifier": _first(sr.get("identifier")),
            })

        # ICD-10 z první Condition (důvod žádanky)
        icd10 = _coding_first(condition.get("code"), SYS_MKN10_5)
        icd10_text = (condition.get("code") or {}).get("text")

        # Patient name
        nm = _first(patient.get("name")) or {}
        patient_name = " ".join([
            *(nm.get("prefix") or []),
            *(nm.get("given") or []),
            nm.get("family") or "",
            *(nm.get("suffix") or []),
        ]).strip()

        # Org name (PZS)
        org_name = org.get("name")

        # Practitioner name
        pname = _first(practitioner.get("name")) or {}
        practitioner_name = " ".join([
            *(pname.get("prefix") or []),
            *(pname.get("given") or []),
            pname.get("family") or "",
            *(pname.get("suffix") or []),
        ]).strip()

        return {
            "bundle_id": self.bundle.get("id"),
            "bundle_identifier": self.bundle.get("identifier"),
            "timestamp": self.bundle.get("timestamp"),
            "composition": {
                "id": comp.get("id"),
                "title": comp.get("title"),
                "date": comp.get("date"),
                "status": comp.get("status"),
                "type_code": _coding_first(comp.get("type"), SYS_SNOMED),
            },
            "patient": {
                "id": patient.get("id"),
                "rid": rid,
                "cpoj": cpoj,
                "name": patient_name,
                "gender": patient.get("gender"),
                "birth_date": patient.get("birthDate"),
            },
            "practitioner": {
                "id": practitioner.get("id"),
                "krzp": krzp,
                "name": practitioner_name,
            },
            "practitioner_role": {
                "id": practitioner_role.get("id"),
                "specialty": _coding_first(_first(practitioner_role.get("specialty")), SYS_SNOMED),
            },
            "organization": {
                "id": org.get("id"),
                "ico": ico,
                "name": org_name,
            },
            "coverage": {
                "id": coverage.get("id"),
                "kp": kp_kod,
            },
            "condition": {
                "id": condition.get("id"),
                "icd10": icd10,
                "text": icd10_text,
            },
            "service_requests": sr_summary,
            "service_requests_count": len(sr_summary),
            "validation_issues": self.validate(strict=False),
        }


# ---------------------------------------------------------------------------
# FHIR Bundle → NCEZ UlozZadankuExtRequest (mapping)
# ---------------------------------------------------------------------------

class ImagingOrderToEZadanka:
    """Konvertuje validní CZ_BundleImageOrder na NCEZ UlozZadankuExtRequest.

    Je to lossy mapping – FHIR Bundle obsahuje víc detailů než NCEZ schéma
    (např. Encounter, body site, modalita) – ty se uloží do `instrukceProPacienta`
    nebo do volných polí. Klíčové údaje (RID, KRZP, IČO, pojišťovna, urgentnost,
    ICD-10) jsou bez ztráty.
    """

    def __init__(self, bundle: dict, *, ispzs: str = "FHIR-IMG-ORDER"):
        self.parser = ImagingOrderBundleParser(bundle)
        self.parser.validate(strict=True)  # vyhodí FhirValidationError při errorech
        self.data = self.parser.extract()
        self.ispzs = ispzs

    def to_ncez(self) -> dict:
        d = self.data
        # ServiceRequest – první (dominantní) je hlavní; ostatní → instrukce
        srs = d["service_requests"]
        if not srs:
            raise FhirValidationError([issue("error", "required", "Žádný ServiceRequest v Bundle")])
        primary = srs[0]
        priority = (primary.get("priority") or "routine").lower()
        urgent_kod = FHIR_PRIORITY_TO_URGENTNOST.get(priority, "routine")

        # Sestavit instrukce – kombinace ICD-10 textu, SR.code displays, modalit
        notes_lines = []
        if d["condition"]["icd10"]:
            notes_lines.append(f"Dg.: {d['condition']['icd10']['code']} – {d['condition']['icd10'].get('display','')}")
        if d["condition"]["text"]:
            notes_lines.append(f"Klinický popis: {d['condition']['text']}")
        for sr in srs:
            parts = []
            if sr.get("code"):
                parts.append(f"{sr['code']['code']} – {sr['code'].get('display','')}")
            if sr.get("modality"):
                parts.append(f"modalita {sr['modality']['code']}")
            if sr.get("body_site"):
                parts.append(f"oblast {sr['body_site'].get('display') or sr['body_site']['code']}")
            if parts:
                notes_lines.append("• " + "; ".join(parts))
        instrukce = "\n".join(notes_lines)[:2000] or None

        # Hlavní SR.code → SNOMED procedure → mapping na MKN-10 řešen samostatně
        # (img-order používá SNOMED pro proceduru; ICD-10 jen pro diagnózu reasonReference)

        zadanka: dict[str, Any] = {
            "stav": NCEZ_STAV_NOVA,
            "urgentnost": {"kod": urgent_kod, "verze": URGENTNOST_VERZE},
            "icpZadatele": d["practitioner"]["krzp"] or "",  # NCEZ vyžaduje IČP – fallback na KRZP
            "samoplatce": False,
            "prilozenVzorek": False,
            "omezeniMobility": _has_mobility_limitation(self.parser),
            "pacientImplantat": _has_device_use(self.parser),
            "metodaData": [NCEZ_METODA_RAD],
            "zasilka": {
                "nazev": (d["composition"]["title"] or "Žádanka obrazové vyšetření")[:100],
                "typ": ZASILKA_TYP_IMG_ORDER,
                "klasifikace": ZASILKA_KLASIFIKACE_IMG_ORDER,
                "autor": d["practitioner"]["krzp"] or "",
                "zdravotnickyPracovnik": d["practitioner"]["krzp"] or "",
                "poskytovatel": d["organization"]["ico"] or "",
                "pacient": d["patient"]["rid"] or "",
                "ispzs": self.ispzs,
                "adresat": d["organization"]["ico"] or "",
                "adresatTyp": NCEZ_ADRESAT_PZS,
                "dokument": [],  # FHIR Bundle samotný se může vložit jako příloha (viz to_ncez_with_bundle_attachment)
            },
        }
        if d["coverage"]["kp"]:
            zadanka["pacientPojistovna"] = {"kod": d["coverage"]["kp"], "verze": "1.0"}
        if instrukce:
            zadanka["instrukceProPacienta"] = instrukce

        # zadankaK (konziliární) – pokud máme ICD-10 dg, vyplníme do duvodZadanky
        zadanka_k = None
        if d["condition"]["icd10"]:
            zadanka_k = {
                "duvodZadanky": {
                    "hlavniDiagnoza": {
                        "coding": [{
                            "system": SYS_MKN10_5,
                            "code": d["condition"]["icd10"]["code"],
                            "display": d["condition"]["icd10"].get("display") or "",
                        }],
                        "text": d["condition"]["text"] or d["condition"]["icd10"].get("display") or "",
                    },
                },
                "pozadovanaVysetreni": [
                    {"kod": sr["code"]["code"], "verze": "1.0.0", "system": SYS_SNOMED}
                    for sr in srs if sr.get("code")
                ],
            }

        body = {"zadanka": zadanka}
        if zadanka_k:
            body["zadankaK"] = zadanka_k
        return body

    def to_ncez_with_bundle_attachment(self) -> dict:
        """Stejné jako to_ncez(), ale připojí původní FHIR Bundle jako příloha."""
        body = self.to_ncez()
        bundle_b64 = _b64(json.dumps(self.parser.bundle, ensure_ascii=False))
        body["zadanka"]["zasilka"]["dokument"] = [{
            "nazev": "FHIR CZ_BundleImageOrder",
            "typ": ZASILKA_TYP_IMG_ORDER,
            "pacient": self.data["patient"]["rid"] or "",
            "autor": self.data["practitioner"]["krzp"] or "",
            "poskytovatel": self.data["organization"]["ico"] or "",
            "format": {"kod": "application/fhir+json", "verze": "R4"},
            "mime": "application/fhir+json",
            "jazyk": {"kod": "cs", "verze": "1.0"},
            "velikost": len(bundle_b64),
            "dostupnost": {"kod": "current", "verze": "1.0"},
            "soubor": {"soubor": bundle_b64},
        }]
        return body


# ---------------------------------------------------------------------------
# NCEZ NactiZadanku → FHIR CZ_BundleImageOrder (lossy reverse)
# ---------------------------------------------------------------------------

class EZadankaToImagingOrder:
    """Sestaví minimální FHIR CZ_BundleImageOrder z NCEZ NactiZadanku odpovědi.

    Toto NENÍ kompletní reverzní mapping – doplňuje jen co je v NCEZ
    odpovědi přítomno (RID, KRZP, IČO, urgentnost, ICD-10 z duvodZadanky).
    """

    def __init__(self, ncez_response: dict):
        # NCEZ odpověď je obvykle obalená v {"data": {...}} – přijmeme oboje
        if isinstance(ncez_response, dict) and "zadanka" not in ncez_response:
            ncez_response = ncez_response.get("data", ncez_response)
        self.zad = (ncez_response or {}).get("zadanka") or ncez_response or {}

    def to_bundle(self) -> dict:
        z = self.zad
        zasilka = z.get("zasilka") or {}
        pacient_rid = zasilka.get("pacient") or (zasilka.get("pacientData") or {}).get("rid")
        autor_krzp = zasilka.get("autor") or (zasilka.get("autorData") or {}).get("krzpId")
        ico = zasilka.get("poskytovatel") or (zasilka.get("poskytovatelData") or {}).get("ico")
        urgent_kod = (z.get("urgentnost") or {}).get("kod") or "routine"
        kp = (z.get("pacientPojistovna") or {}).get("kod")
        bundle_id = str(uuid.uuid4())
        comp_id = str(uuid.uuid4())
        patient_id = str(uuid.uuid4())
        practitioner_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())
        coverage_id = str(uuid.uuid4())
        condition_id = str(uuid.uuid4())
        sr_id = str(uuid.uuid4())

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        title = (zasilka.get("nazev") or "Žádanka obrazové vyšetření")[:100]

        # Vytáhnout MKN-10 dg z zadankaK (pokud je v odpovědi)
        zad_k = z.get("zadankaK") or {}
        duvod = (zad_k.get("duvodZadanky") or {}).get("hlavniDiagnoza") or {}
        codings = duvod.get("coding") or []

        condition_resource = None
        if codings:
            condition_resource = {
                "resourceType": "Condition",
                "id": condition_id,
                "meta": {"profile": [PROFILE_CONDITION]},
                "code": {
                    "coding": codings,
                    "text": duvod.get("text") or "",
                },
                "subject": {"reference": f"urn:uuid:{patient_id}"},
            }

        sr_resource = {
            "resourceType": "ServiceRequest",
            "id": sr_id,
            "meta": {"profile": [PROFILE_SR]},
            "status": "active",
            "intent": "order",
            "priority": urgent_kod if urgent_kod in FHIR_PRIORITY_TO_URGENTNOST else "routine",
            "category": [{"coding": [{"system": SYS_SNOMED, "code": SCT_IMAGING_CATEGORY, "display": "Imaging"}]}],
            "subject": {"reference": f"urn:uuid:{patient_id}"},
            "authoredOn": z.get("datumVytvoreni") or now,
            "requester": {"reference": f"urn:uuid:{practitioner_id}"},
        }
        if condition_resource:
            sr_resource["reasonReference"] = [{"reference": f"urn:uuid:{condition_id}"}]
        # Pokud je v zadankaK pozadovanaVysetreni, vytáhneme první kód
        pv = (zad_k.get("pozadovanaVysetreni") or [])
        if pv and isinstance(pv[0], dict):
            sr_resource["code"] = {
                "coding": [{
                    "system": pv[0].get("system") or SYS_SNOMED,
                    "code": pv[0].get("kod"),
                    "display": pv[0].get("display") or "",
                }]
            }

        composition = {
            "resourceType": "Composition",
            "id": comp_id,
            "meta": {"profile": [PROFILE_COMPOSITION]},
            "status": "final",
            "type": {"coding": [{"system": SYS_SNOMED, "code": SCT_COMPOSITION_TYPE_IMG_ORDER}]},
            "category": [{"coding": [{"system": SYS_LOINC, "code": LOINC_CATEGORY_IMG_ORDER}]}],
            "subject": {"reference": f"urn:uuid:{patient_id}"},
            "date": z.get("datumVytvoreni") or now,
            "author": [{"reference": f"urn:uuid:{practitioner_id}"}],
            "title": title,
            "section": [{
                "title": "Requested imaging studies information Document",
                "code": {"coding": [{"system": SYS_LOINC, "code": LOINC_REQUESTED_IMAGING_INFO}]},
                "entry": [{"reference": f"urn:uuid:{sr_id}"}],
            }],
        }

        patient = {
            "resourceType": "Patient",
            "id": patient_id,
            "meta": {"profile": [PROFILE_PATIENT]},
            "identifier": [{"system": SYS_RID, "value": pacient_rid}] if pacient_rid else [],
        }
        practitioner = {
            "resourceType": "Practitioner",
            "id": practitioner_id,
            "meta": {"profile": [PROFILE_PRACTITIONER]},
            "identifier": [{"system": SYS_KRZP, "value": autor_krzp}] if autor_krzp else [],
        }
        organization = {
            "resourceType": "Organization",
            "id": org_id,
            "meta": {"profile": [PROFILE_ORG]},
            "identifier": [{"system": SYS_ICO, "value": ico}] if ico else [],
            "name": (zasilka.get("poskytovatelData") or {}).get("nazev"),
        }

        entries = [
            {"fullUrl": f"urn:uuid:{comp_id}", "resource": composition},
            {"fullUrl": f"urn:uuid:{patient_id}", "resource": patient},
            {"fullUrl": f"urn:uuid:{sr_id}", "resource": sr_resource},
            {"fullUrl": f"urn:uuid:{practitioner_id}", "resource": practitioner},
            {"fullUrl": f"urn:uuid:{org_id}", "resource": organization},
        ]
        if kp:
            payor_org_id = str(uuid.uuid4())
            entries.append({
                "fullUrl": f"urn:uuid:{payor_org_id}",
                "resource": {
                    "resourceType": "Organization",
                    "id": payor_org_id,
                    "meta": {"profile": [PROFILE_ORG]},
                    "identifier": [{"system": SYS_KP, "value": kp}],
                    "name": "Pojišťovna",
                },
            })
            entries.append({
                "fullUrl": f"urn:uuid:{coverage_id}",
                "resource": {
                    "resourceType": "Coverage",
                    "id": coverage_id,
                    "meta": {"profile": [PROFILE_COVERAGE]},
                    "status": "active",
                    "beneficiary": {"reference": f"urn:uuid:{patient_id}"},
                    "payor": [{"reference": f"urn:uuid:{payor_org_id}"}],
                },
            })
            sr_resource["insurance"] = [{"reference": f"urn:uuid:{coverage_id}"}]
        if condition_resource:
            entries.append({"fullUrl": f"urn:uuid:{condition_id}", "resource": condition_resource})

        return {
            "resourceType": "Bundle",
            "id": bundle_id,
            "meta": {"profile": [PROFILE_BUNDLE]},
            "identifier": {"system": "urn:ietf:rfc:3986", "value": f"urn:uuid:{bundle_id}"},
            "type": "document",
            "timestamp": now,
            "entry": entries,
        }


# ---------------------------------------------------------------------------
# Examples loader (pro UI „Příklady")
# ---------------------------------------------------------------------------

def list_examples() -> list[dict]:
    """Seznam dostupných FHIR příkladů pro UI."""
    if not os.path.isdir(EXAMPLES_DIR):
        return []
    out = []
    for fname in sorted(os.listdir(EXAMPLES_DIR)):
        if not fname.endswith(".json"):
            continue
        # macOS AppleDouble resource forks – ignorovat
        if fname.startswith("._") or fname.startswith("."):
            continue
        path = os.path.join(EXAMPLES_DIR, fname)
        try:
            sz = os.path.getsize(path)
        except OSError:
            sz = 0
        # Heuristika title – z názvu souboru
        kind = "ServiceRequest" if "ServiceRequest" in fname else \
               "Bundle" if "Bundle" in fname else \
               "Composition" if "Composition" in fname else "Other"
        out.append({"name": fname, "kind": kind, "size": sz})
    return out


def load_example(name: str) -> dict | None:
    if not re.match(r"^[A-Za-z0-9._-]+\.json$", name or ""):
        return None
    path = os.path.join(EXAMPLES_DIR, name)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CapabilityStatement (jednoduchý, pro /api/img-order/CapabilityStatement)
# ---------------------------------------------------------------------------

def capability_statement(version: str = "0.1.0") -> dict:
    return {
        "resourceType": "CapabilityStatement",
        "status": "draft",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "kind": "instance",
        "software": {
            "name": "SEZ API – Imaging Order adapter",
            "version": version,
        },
        "implementation": {
            "description": (
                "SEZ API – HL7 Czech Imaging Order FHIR adapter "
                f"(IG {IG_VERSION}; cz-core {IG_DEPENDENCIES['hl7.fhir.cz.core']}, "
                f"cz-terminology {IG_DEPENDENCIES['hl7.fhir.cz.terminology']})"
            ),
        },
        "fhirVersion": IG_FHIR_VERSION,
        "format": ["application/fhir+json"],
        "implementationGuide": [
            f"{IG_CANONICAL}/ImplementationGuide/hl7.fhir.cz.img-order|{IG_VERSION}",
        ],
        "rest": [{
            "mode": "server",
            "resource": [{
                "type": "Bundle",
                "supportedProfile": [PROFILE_BUNDLE],
                "interaction": [{"code": "create"}, {"code": "read"}],
                "operation": [
                    {"name": "validate", "definition": "http://hl7.org/fhir/OperationDefinition/Resource-validate"},
                    {"name": "cancel", "definition": "https://hl7.cz/fhir/img-order/OperationDefinition/Bundle-cancel"},
                    {"name": "accept", "definition": "https://hl7.cz/fhir/img-order/OperationDefinition/Bundle-accept"},
                    {"name": "fulfill", "definition": "https://hl7.cz/fhir/img-order/OperationDefinition/Bundle-fulfill"},
                ],
            }],
        }],
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _identifier_value(resource: dict, system: str) -> str | None:
    for i in resource.get("identifier") or []:
        if i.get("system") == system and i.get("value"):
            return str(i["value"])
    return None


def _coding_first(codeable: dict | None, prefer_system: str | None = None) -> dict | None:
    """Z CodeableConcept vytáhne první coding (preferuje konkrétní system)."""
    if not codeable:
        return None
    codings = codeable.get("coding") or []
    if prefer_system:
        for c in codings:
            if c.get("system") == prefer_system:
                return {"system": c["system"], "code": c.get("code"), "display": c.get("display")}
    if codings:
        c = codings[0]
        return {"system": c.get("system"), "code": c.get("code"), "display": c.get("display")}
    return None


def _first(seq: Iterable | None) -> Any:
    if not seq:
        return None
    for x in seq:
        return x
    return None


def _has_mobility_limitation(parser: ImagingOrderBundleParser) -> bool:
    for obs in parser.all("Observation"):
        profs = (obs.get("meta") or {}).get("profile") or []
        if any("patientMobility" in p.lower() for p in profs):
            val = obs.get("valueCodeableConcept") or {}
            for c in val.get("coding") or []:
                disp = (c.get("display") or "").lower()
                code = (c.get("code") or "").lower()
                if "imobil" in disp or "limit" in disp or code in ("immobile", "limited"):
                    return True
    return False


def _has_device_use(parser: ImagingOrderBundleParser) -> bool:
    return bool(parser.all("DeviceUseStatement"))


def _b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode("utf-8")).decode("ascii")
