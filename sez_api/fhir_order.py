"""
HL7 CZ Order IG (hl7.fhir.cz.order 1.0.0) – žádanky typu **K** (konziliární)
a **FT** (fyzioterapie a ergoterapie) pro eŽádanky API v2 + společné nástroje
pro FHIR Bundle **všech tří typů** eŽádanky (Z / K / FT).

Zdroje (revize NCEZ 13. 10. 2026):

* Manuál EZ pro PZS → eŽádanky: podporované typy K, Z, FT; dokumentace platná
  od 1. 10. 2026 (Standard 2.0, funkční specifikace K 7.0 / Z 2.0 / FT 7.0);
  „Implementační specifikace (IG) – pro typy K a FT společná, pro typ Z
  samostatná“.
* IG K/FT: HL7 Czech Order IG, kanonické URL https://hl7.cz/fhir/order
  (CI build https://build.fhir.org/ig/HL7-cz/k-order/, repo HL7-cz/k-order) –
  profily BundleOrderCz, k-order-composition-cz, ft-order-composition-cz,
  KOrderServiceRequestCz, FTServiceRequestCz, cz-coverage-order,
  cz-clinicalQuestion; příklady Bundle-BundleKOrderExample, …FTExample atd.
* IG Z: HL7 CZ img-order (viz ``fhir_imgorder``).

Serverová pravidla brány (eŽádanky v2.0.0, ověřeno živě na T2 13. 10. 2026
pro všechny tři typy – uložení 201 → načtení → storno):

1. Reference v Bundle brána řeší **jen přesnou shodou s ``entry.fullUrl``** –
   relativní reference (``Patient/123``) při absolutním fullUrl
   (``https://…/Patient/123``, jak mají příklady IG) server nenajde
   (``"bundle": null`` → E00024). Řešení: ``normalizuj_reference`` převede
   fullUrl i reference na ``urn:uuid:``.
2. ``hlavicka.pacient`` = RID Patient (``Composition.subject``).
3. ``hlavicka.zadatel.autor`` = KRZP Practitioner z ``Composition.author``
   (přímo nebo přes PractitionerRole.practitioner).
4. ``hlavicka.zadatel.poskytovatel`` = IČO Organization v
   ``Composition.custodian`` – **u všech typů**; PractitionerRole.organization
   autora server nepoužívá (příklady IG order custodian nemají → nutno doplnit).
5. custodian Organization musí mít IČP (``sid/icp``) – E01002.
6. ``hlavicka.adresat`` = IČO právě jedné provádějící Organization odkazované
   ze ``ServiceRequest.performer`` (přímo nebo přes PractitionerRole); bez
   adresáta jde o neadresnou žádanku a performer se neuvádí.
7. adresát ≠ poskytovatel (E01001).
"""

from __future__ import annotations

import copy
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .fhir_imgorder import (  # společné identifikační systémy a helpery
    SYS_RID, SYS_CPOJ, SYS_KRZP, SYS_KP, SYS_ICO, SYS_ICP, SYS_SNOMED, SYS_LOINC,
    SCT_CZ_EDITION, PROFILE_PATIENT, PROFILE_PRACTITIONER, PROFILE_ORG,
    PROFILE_PRACTITIONER_ROLE, _identifier_value,
)

# ---------------------------------------------------------------------------
# Konstanty IG order
# ---------------------------------------------------------------------------

CANONICAL_ORDER = "https://hl7.cz/fhir/order"
IG_ORDER_PACKAGE = "hl7.fhir.cz.order"
IG_ORDER_VERSION = "1.0.0"
IG_ORDER_URL = "https://build.fhir.org/ig/HL7-cz/k-order/"
IG_IMG_ORDER_URL = "https://build.fhir.org/ig/HL7-cz/img-order/"

PROFILE_BUNDLE_ORDER = f"{CANONICAL_ORDER}/StructureDefinition/BundleOrderCz"
PROFILE_COMPOSITION_K = f"{CANONICAL_ORDER}/StructureDefinition/k-order-composition-cz"
PROFILE_COMPOSITION_FT = f"{CANONICAL_ORDER}/StructureDefinition/ft-order-composition-cz"
PROFILE_SR_K = f"{CANONICAL_ORDER}/StructureDefinition/KOrderServiceRequestCz"
PROFILE_SR_FT = f"{CANONICAL_ORDER}/StructureDefinition/FTServiceRequestCz"
PROFILE_COVERAGE_ORDER = f"{CANONICAL_ORDER}/StructureDefinition/cz-coverage-order"
PROFILE_CLINICAL_QUESTION = f"{CANONICAL_ORDER}/StructureDefinition/cz-clinicalQuestion"
PROFILE_PRACTITIONER_ROLE_ORDER = f"{CANONICAL_ORDER}/StructureDefinition/practitionerrole-cz-order"

SYS_ICZ = "https://ncez.mzcr.cz/fhir/sid/icz"
SYS_KRPZS = "https://ncez.mzcr.cz/fhir/sid/krpzs"
SYS_MKN10 = "https://uzis.cz/terminology/CodeSystem/mkn-10"
SYS_V3_ACTCODE = "http://terminology.hl7.org/CodeSystem/v3-ActCode"

LOINC_TYP_K = "57133-1"        # žádanka o vyšetření (Composition.type i category u K a FT)
LOINC_TYP_FT = "57154-7"       # žádanka o fyzioterapii
SCT_TYP_Z = "721964003"        # img-order (SNOMED)

#: Kódy sekcí Composition dle k-order-composition-cz / ft-order-composition-cz
SEKCE = {
    "orderInformation_K": LOINC_TYP_K,
    "orderInformation_FT": LOINC_TYP_FT,
    "clinicalQuestion": "104720-8",
    "goals": "61146-7",            # jen FT
    "coverage": "87520-3",
    "appointment": "56446-8",
    "carePlan": "18776-5",
    "medicalDevices": "97813-0",
    "supportingInformation": "55752-0",
    "attachments": "55107-7",
}

#: Katalog typů eŽádanky (referralorder-types ↔ IG). Klíč = zkratka z Manuálu EZ.
TYPY: dict[str, dict[str, Any]] = {
    "Z": {
        "kod": SCT_TYP_Z, "system": SYS_SNOMED,
        "nazev": "Žádanka o zobrazovací vyšetření",
        "specifikace": "Funkční specifikace eŽádanky typu Z v2.0",
        "ig": "hl7.fhir.cz.img-order", "ig_url": IG_IMG_ORDER_URL,
        "bundle_profile": "https://hl7.cz/fhir/img-order/StructureDefinition/cz-bundleImageOrder",
        "composition_profile": "https://hl7.cz/fhir/img-order/StructureDefinition/cz-compositionImageOrder",
        "servicerequest_profile": "https://hl7.cz/fhir/img-order/StructureDefinition/cz-imagingOrderInformation",
        "vzory": ["Bundle-BundleKralikRTG.json"],
    },
    "K": {
        "kod": LOINC_TYP_K, "system": SYS_LOINC,
        "nazev": "Konziliární žádanka (žádanka o vyšetření)",
        "specifikace": "Funkční specifikace eŽádanky typu K v7.0",
        "ig": IG_ORDER_PACKAGE, "ig_url": IG_ORDER_URL,
        "bundle_profile": PROFILE_BUNDLE_ORDER,
        "composition_profile": PROFILE_COMPOSITION_K,
        "servicerequest_profile": PROFILE_SR_K,
        "vzory": ["Bundle-BundleKOrderExample.json", "Bundle-BundleDermatologyUrgentExample.json",
                  "Bundle-BundleNephrologyHandoverExample.json",
                  "Bundle-BundleHospitalAdmissionRecommendationExample.json"],
    },
    "FT": {
        "kod": LOINC_TYP_FT, "system": SYS_LOINC,
        "nazev": "Žádanka o fyzioterapii a ergoterapii",
        "specifikace": "Funkční specifikace eŽádanky typu FT v7.0",
        "ig": IG_ORDER_PACKAGE, "ig_url": IG_ORDER_URL,
        "bundle_profile": PROFILE_BUNDLE_ORDER,
        "composition_profile": PROFILE_COMPOSITION_FT,
        "servicerequest_profile": PROFILE_SR_FT,
        "vzory": ["Bundle-BundleFTExample.json", "Bundle-BundleFTHipRehabilitation.json",
                  "Bundle-BundleFTCopdHomeCare.json", "Bundle-BundleFTPediatricPosture.json"],
    },
}
KOD_NA_TYP = {v["kod"]: k for k, v in TYPY.items()}

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "fhir_order_examples")

#: Pravidla brány (pro katalog / GUI)
PRAVIDLA_BRANY = [
    {"kod": "E00024", "pole": "reference", "pravidlo": "Reference se řeší jen přesnou shodou s entry.fullUrl – používejte urn:uuid: (relativní 'Patient/1' při absolutním fullUrl server nenajde)."},
    {"kod": "E00024", "pole": "hlavicka.pacient", "pravidlo": "RID pacienta = identifier sid/rid Patient v Composition.subject."},
    {"kod": "E00024", "pole": "hlavicka.zadatel.autor", "pravidlo": "KRZP autora = identifier sid/krzp Practitioner z Composition.author (přímo či přes PractitionerRole)."},
    {"kod": "E00024", "pole": "hlavicka.zadatel.poskytovatel", "pravidlo": "IČO poskytovatele = identifier sid/ico Organization v Composition.custodian (u všech typů Z/K/FT)."},
    {"kod": "E01002", "pole": "fhirBundle", "pravidlo": "Organization v Composition.custodian musí mít IČP (identifier sid/icp)."},
    {"kod": "E00024", "pole": "hlavicka.adresat", "pravidlo": "IČO adresáta = právě jedna provádějící Organization odkazovaná ze ServiceRequest.performer."},
    {"kod": "E01001", "pole": "hlavicka.adresat", "pravidlo": "Adresát se nesmí rovnat poskytovateli žadatele (komunikace mezi různými PZS)."},
    {"kod": "E01001", "pole": "ServiceRequest.priority", "pravidlo": "Priorita jen 'routine' nebo 'stat' (ValueSet request-priority-cz); 'urgent'/'asap' z FHIR core brána odmítne."},
    {"kod": "E01001", "pole": "operace příjemce", "pravidlo": "Přijmout / vrátit do oběhu / neproveditelnost / vyřídit smí jen jiný PZS než žadatel – 'Systém není určen pro evidenci intramurálních žádanek'; s jedním certifikátem lze celý cyklus projít jen v simulátoru."},
]


# ---------------------------------------------------------------------------
# Pomocné funkce
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _uuid() -> str:
    return str(uuid.uuid4())


def _ref(rid: str) -> dict:
    return {"reference": f"urn:uuid:{rid}"}


def typ_z_bundle(bundle: dict) -> str | None:
    """Zkratka typu (Z/K/FT) podle Composition.type.coding (první entry)."""
    entries = (bundle or {}).get("entry") or []
    comp = (entries[0].get("resource") if entries else None) or {}
    if comp.get("resourceType") != "Composition":
        return None
    for c in (comp.get("type") or {}).get("coding") or []:
        t = KOD_NA_TYP.get(c.get("code"))
        if t:
            return t
    return None


class _Index:
    """Index resources podle fullUrl / Type/id / urn:uuid:id."""

    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.by_url: dict[str, dict] = {}
        self.by_id: dict[str, dict] = {}
        self.url_of: dict[int, str] = {}
        for e in bundle.get("entry") or []:
            r = e.get("resource") or {}
            if e.get("fullUrl"):
                self.by_url[e["fullUrl"]] = r
                self.url_of[id(r)] = e["fullUrl"]
            if r.get("resourceType") and r.get("id"):
                self.by_id[f"{r['resourceType']}/{r['id']}"] = r
                self.by_id[f"urn:uuid:{r['id']}"] = r

    def exact(self, ref) -> dict | None:
        """Jen přesná shoda s fullUrl – tak to dělá brána."""
        if isinstance(ref, dict):
            ref = ref.get("reference")
        return self.by_url.get(ref) if ref else None

    def resolve(self, ref) -> dict | None:
        if isinstance(ref, dict):
            ref = ref.get("reference")
        if not ref:
            return None
        r = self.by_url.get(ref) or self.by_id.get(ref)
        if r is None and "/" in ref:
            # relativní vůči absolutnímu fullUrl: https://x/fhir/Patient/1 ~ Patient/1
            tail = "/".join(ref.rstrip("/").split("/")[-2:])
            r = self.by_id.get(tail)
        return r

    def all(self, rt: str) -> list[dict]:
        return [e.get("resource") for e in self.bundle.get("entry") or []
                if (e.get("resource") or {}).get("resourceType") == rt]

    def url(self, resource: dict) -> str | None:
        return self.url_of.get(id(resource))


# ---------------------------------------------------------------------------
# Normalizace referencí (urn:uuid)
# ---------------------------------------------------------------------------

def normalizuj_reference(bundle: dict) -> tuple[dict, list[str]]:
    """Vrátí kopii Bundle, kde má každý entry ``fullUrl = urn:uuid:<id>`` a
    všechny reference (absolutní, relativní ``Type/id`` i ``urn:uuid:``) na něj
    ukazují přesně. Brána eŽádanek v2 řeší reference jen přesnou shodou
    s fullUrl, takže příklady IG s ``https://example.org/fhir/...`` jinak
    skončí chybou E00024 (``"bundle": null``)."""
    b = copy.deepcopy(bundle)
    zmeny: list[str] = []
    mapping: dict[str, str] = {}
    for e in b.get("entry") or []:
        r = e.get("resource") or {}
        rt, rid = r.get("resourceType"), r.get("id")
        old_url = e.get("fullUrl")
        # id musí být platné FHIR id i UUID → jinak nové UUID
        new_id = rid if (rid and re.fullmatch(r"[0-9a-fA-F-]{36}", rid)) else _uuid()
        new_url = f"urn:uuid:{new_id}"
        if old_url:
            mapping[old_url] = new_url
        if rt and rid:
            mapping[f"{rt}/{rid}"] = new_url
            mapping[f"urn:uuid:{rid}"] = new_url
            if old_url and "/" in old_url:
                mapping["/".join(old_url.rstrip("/").split("/")[-2:])] = new_url
        if old_url != new_url:
            zmeny.append(f"{rt}/{rid}: fullUrl {old_url!r} → {new_url}")
        if rid != new_id:
            zmeny.append(f"{rt}: id {rid!r} → {new_id}")
        e["fullUrl"] = new_url
        r["id"] = new_id

    def walk(o):
        if isinstance(o, dict):
            ref = o.get("reference")
            if isinstance(ref, str):
                tgt = mapping.get(ref)
                if tgt is None and "/" in ref:
                    tgt = mapping.get("/".join(ref.rstrip("/").split("/")[-2:]))
                if tgt and tgt != ref:
                    o["reference"] = tgt
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(b)
    return b, zmeny


# ---------------------------------------------------------------------------
# Analýza Bundle (společná pro Z/K/FT)
# ---------------------------------------------------------------------------

def analyzuj(bundle: dict) -> dict:
    """Ploché údaje potřebné pro hlavičku v2 a kontrolu konzistence:
    typ, pacient (RID), autor (KRZP), žadatel (IČO/IČP, custodian?),
    provádějící Organization, nevyřešené / nepřesné reference."""
    ix = _Index(bundle or {})
    entries = (bundle or {}).get("entry") or []
    comp = (entries[0].get("resource") if entries else None) or {}
    if comp.get("resourceType") != "Composition":
        comp = {}
    out: dict[str, Any] = {
        "typ": typ_z_bundle(bundle), "typ_kod": None,
        "pacient": None, "autor": None, "autor_pres_roli": False,
        "zadatel": {"ico": None, "icp": None, "nazev": None, "zdroj": None},
        "performer": {"ico": None, "nazev": None, "pocet": 0},
        "nepresne_reference": [], "nevyresene_reference": [],
        "pocet_service_request": len(ix.all("ServiceRequest")),
    }
    for c in (comp.get("type") or {}).get("coding") or []:
        if c.get("code") in KOD_NA_TYP:
            out["typ_kod"] = c["code"]

    def check(ref, kde):
        """Eviduje reference, které brána nenajde (nepřesná shoda s fullUrl)."""
        if not ref:
            return None
        r = ix.exact(ref)
        if r is None:
            r2 = ix.resolve(ref)
            s = ref.get("reference") if isinstance(ref, dict) else ref
            (out["nepresne_reference"] if r2 else out["nevyresene_reference"]).append(f"{kde}: {s}")
            return r2
        return r

    pat = check(comp.get("subject"), "Composition.subject") or (ix.all("Patient") or [None])[0]
    if pat and pat.get("resourceType") == "Patient":
        out["pacient"] = _identifier_value(pat, SYS_RID)

    # autor: Composition.author → PractitionerRole → Practitioner | Practitioner
    autor = check((comp.get("author") or [None])[0], "Composition.author[0]")
    if autor and autor.get("resourceType") == "PractitionerRole":
        out["autor_pres_roli"] = True
        role_org = check(autor.get("organization"), "PractitionerRole.organization")
        autor = check(autor.get("practitioner"), "PractitionerRole.practitioner")
    else:
        role_org = None
    if not autor:
        srs = ix.all("ServiceRequest")
        req = ix.resolve((srs[0] if srs else {}).get("requester"))
        if req and req.get("resourceType") == "PractitionerRole":
            role_org = role_org or ix.resolve(req.get("organization"))
            req = ix.resolve(req.get("practitioner"))
        autor = req or (ix.all("Practitioner") or [None])[0]
    if autor and autor.get("resourceType") == "Practitioner":
        out["autor"] = _identifier_value(autor, SYS_KRZP)

    # žadatel: custodian (brána) → PractitionerRole.organization (fallback)
    cust = check(comp.get("custodian"), "Composition.custodian")
    zad_org, zdroj = None, None
    if cust and cust.get("resourceType") == "Organization":
        zad_org, zdroj = cust, "Composition.custodian"
    elif role_org and role_org.get("resourceType") == "Organization":
        zad_org, zdroj = role_org, "PractitionerRole.organization (custodian chybí!)"
    else:
        for o in ix.all("Organization"):
            if _identifier_value(o, SYS_ICO) and not _identifier_value(o, SYS_KP):
                zad_org, zdroj = o, "první Organization s IČO (custodian chybí!)"
                break
    if zad_org:
        out["zadatel"] = {"ico": _identifier_value(zad_org, SYS_ICO), "icp": _identifier_value(zad_org, SYS_ICP),
                          "nazev": zad_org.get("name"), "zdroj": zdroj}

    perf: dict[str, dict] = {}
    for sr in ix.all("ServiceRequest"):
        for p in sr.get("performer") or []:
            r = check(p, "ServiceRequest.performer")
            if r and r.get("resourceType") == "PractitionerRole":
                r = ix.resolve(r.get("organization"))
            if r and r.get("resourceType") == "Organization":
                perf[_identifier_value(r, SYS_ICO) or str(id(r))] = r
    if perf:
        first = next(iter(perf.values()))
        out["performer"] = {"ico": _identifier_value(first, SYS_ICO), "nazev": first.get("name"), "pocet": len(perf)}
    return out


# ---------------------------------------------------------------------------
# Hlavička v2 z Bundle + příprava Bundle podle hlavičky
# ---------------------------------------------------------------------------

def sestav_hlavicku(bundle: dict, *, typ: str | None = None, pacient: str | None = None,
                    poskytovatel: str | None = None, autor: str | None = None,
                    zdravotnicky_pracovnik: str | None = None, adresat: str | None = None,
                    dodatecny_prijemce: list[str] | None = None,
                    nadrizena_zadanka_id: str | None = None) -> dict:
    """HlavickaVstup v2 odvozená z Bundle (explicitní parametry mají přednost)."""
    a = analyzuj(bundle)
    t = typ or a["typ"] or "K"
    kod = TYPY[t]["kod"] if t in TYPY else t
    krzp = autor or a["autor"] or ""
    hl: dict[str, Any] = {
        "typZadanky": {"kod": kod},
        "zadatel": {
            "poskytovatel": str(poskytovatel or a["zadatel"]["ico"] or ""),
            "autor": str(krzp),
            "zdravotnickyPracovnik": str(zdravotnicky_pracovnik or krzp),
        },
        "pacient": str(pacient or a["pacient"] or ""),
    }
    adresat = adresat or a["performer"]["ico"]
    if adresat:
        hl["adresat"] = str(adresat)
    if dodatecny_prijemce:
        hl["dodatecnyPrijemce"] = [str(x) for x in dodatecny_prijemce if x]
    if nadrizena_zadanka_id:
        hl["nadrizenaZadankaId"] = str(nadrizena_zadanka_id)
    return hl


def pripravit(bundle: dict, hlavicka: dict, *, icp: str | None = None,
              nazev_poskytovatele: str | None = None,
              nazev_adresata: str | None = None) -> tuple[dict, list[str]]:
    """Upraví kopii Bundle tak, aby odpovídal hlavičce a pravidlům brány:

    * reference → ``urn:uuid`` (přesná shoda s fullUrl),
    * Patient RID, Practitioner (autor) KRZP,
    * ``Composition.custodian`` → Organization žadatele s IČO (+ IČP),
      doplní se z PractitionerRole.organization autora nebo se vytvoří,
    * při ``adresat``: právě jedna provádějící Organization s IČO adresáta ve
      všech ``ServiceRequest.performer`` (vytvoří se, pokud chybí);
      bez adresáta se performer ponechá (neadresná žádanka).

    Vrací ``(bundle, seznam změn)``. Nic nemaže kromě přesměrování performer.
    """
    b, zmeny = normalizuj_reference(bundle)
    if b.get("type") != "document":
        b["type"] = "document"
        zmeny.append("Bundle.type → document")
    ix = _Index(b)
    entries = b.setdefault("entry", [])
    comp = (entries[0].get("resource") if entries else None) or {}
    if comp.get("resourceType") != "Composition":
        return b, zmeny + ["Bundle nemá Composition jako první entry – nelze připravit."]
    hl = hlavicka or {}
    zad = hl.get("zadatel") or {}

    def set_identifier(res, system, value, label):
        if not value:
            return
        for i in res.get("identifier") or []:
            if i.get("system") == system:
                if i.get("value") != str(value):
                    zmeny.append(f"{label}: {i.get('value')!r} → {value}")
                    i["value"] = str(value)
                return
        res.setdefault("identifier", []).append({"system": system, "value": str(value)})
        zmeny.append(f"{label}: doplněn identifier {system.rsplit('/', 1)[-1]} = {value}")

    # Pacient
    pat = ix.exact(comp.get("subject")) or (ix.all("Patient") or [None])[0]
    if pat is not None and hl.get("pacient"):
        set_identifier(pat, SYS_RID, hl["pacient"], "Patient")
        if not ix.exact(comp.get("subject")):
            comp["subject"] = {"reference": ix.url(pat)}
            zmeny.append("Composition.subject → Patient")

    # Autor
    autor = ix.exact((comp.get("author") or [None])[0])
    role = None
    if autor and autor.get("resourceType") == "PractitionerRole":
        role = autor
        autor = ix.exact(role.get("practitioner"))
    if autor is None:
        roles = ix.all("PractitionerRole")
        role = role or (roles[0] if roles else None)
        autor = ix.exact(role.get("practitioner")) if role else None
        autor = autor or (ix.all("Practitioner") or [None])[0]
    krzp = zad.get("zdravotnickyPracovnik") or zad.get("autor")
    if autor is not None and krzp:
        set_identifier(autor, SYS_KRZP, krzp, "Practitioner (autor)")

    # Žadatel / custodian
    cust = ix.exact(comp.get("custodian"))
    if not (cust and cust.get("resourceType") == "Organization"):
        cust = ix.exact(role.get("organization")) if role else None
        if not (cust and cust.get("resourceType") == "Organization"):
            cust = next((o for o in ix.all("Organization")
                         if _identifier_value(o, SYS_ICO) and not _identifier_value(o, SYS_KP)), None)
        if cust is None and zad.get("poskytovatel"):
            oid = _uuid()
            cust = {"resourceType": "Organization", "id": oid, "meta": {"profile": [PROFILE_ORG]},
                    "identifier": [], "name": nazev_poskytovatele or f"Poskytovatel {zad['poskytovatel']}"}
            entries.append({"fullUrl": f"urn:uuid:{oid}", "resource": cust})
            ix = _Index(b)
            zmeny.append("doplněna Organization žadatele")
        if cust is not None:
            comp["custodian"] = {"reference": ix.url(cust)}
            zmeny.append("Composition.custodian → Organization žadatele")
    if cust is not None:
        set_identifier(cust, SYS_ICO, zad.get("poskytovatel"), "Organization (custodian)")
        if icp:
            set_identifier(cust, SYS_ICP, icp, "Organization (custodian)")
        if nazev_poskytovatele and cust.get("name") != nazev_poskytovatele:
            cust["name"] = nazev_poskytovatele

    # Adresát / performer
    adresat = hl.get("adresat")
    if adresat:
        srs = ix.all("ServiceRequest")
        perf_org = None
        # Organizace žadatele i její nadřízený PZS (custodian.partOf) nemohou být
        # provádějícím – IG vzory FT mají performer = mateřský PZS žadatele.
        vlastni = {id(cust)} if cust is not None else set()
        parent = ix.exact((cust or {}).get("partOf"))
        if parent is not None:
            vlastni.add(id(parent))
        for sr in srs:
            for p in sr.get("performer") or []:
                r = ix.exact(p)
                if r and r.get("resourceType") == "PractitionerRole":
                    r = ix.exact(r.get("organization"))
                if r and r.get("resourceType") == "Organization" and id(r) not in vlastni:
                    perf_org = r
                    break
            if perf_org:
                break
        if perf_org is None:
            pid = _uuid()
            perf_org = {"resourceType": "Organization", "id": pid, "meta": {"profile": [PROFILE_ORG]},
                        "identifier": [{"system": SYS_ICO, "value": str(adresat)}],
                        "name": nazev_adresata or f"Provádějící PZS {adresat}"}
            entries.append({"fullUrl": f"urn:uuid:{pid}", "resource": perf_org})
            ix = _Index(b)
            zmeny.append(f"doplněna provádějící Organization (IČO {adresat})")
        else:
            set_identifier(perf_org, SYS_ICO, adresat, "Organization (performer)")
        url = ix.url(perf_org)
        for sr in srs:
            if [p.get("reference") for p in sr.get("performer") or []] != [url]:
                sr["performer"] = [{"reference": url}]
                zmeny.append(f"ServiceRequest/{sr.get('id')}: performer → provádějící Organization")
    return b, zmeny


def to_v2(bundle: dict, *, icp: str | None = None, **hlavicka_kw) -> dict:
    """Tělo ``POST /eZadanky/api/v2/zadanka`` pro libovolný typ (Z/K/FT):
    hlavička odvozená z Bundle (přepsatelná ``hlavicka_kw``) + Bundle
    připravený podle pravidel brány."""
    hl = sestav_hlavicku(bundle, **hlavicka_kw)
    b, _ = pripravit(bundle, hl, icp=icp)
    return {"hlavicka": hl, "fhirBundle": b}


# ---------------------------------------------------------------------------
# Kostra Bundle K / FT (minimální validní dokument dle IG order 1.0.0)
# ---------------------------------------------------------------------------

#: Výchozí SNOMED kódy požadavků (SNOMED CT CZ edice) – z příkladů IG
VYCHOZI_VYKONY = {
    "K": [{"code": "185387006", "display": "konzultace s novým pacientem"}],
    "FT": [{"code": "229065009", "display": "terapie cvičením"}],
}


PRIORITY_CZ = ("routine", "stat")  # ValueSet request-priority-cz (brána odmítá urgent/asap, E01001)


def _over_prioritu(priorita: str) -> None:
    if priorita not in PRIORITY_CZ:
        raise ValueError(f"priorita '{priorita}' není v číselníku request-priority-cz "
                         f"({' | '.join(PRIORITY_CZ)}) – brána vrátí E01001")


def kostra(typ: str, *, pacient: str, poskytovatel: str, autor: str, icp: str | None = None,
           adresat: str | None = None, zdravotnicky_pracovnik: str | None = None,
           nazev: str | None = None, nazev_poskytovatele: str | None = None,
           nazev_adresata: str | None = None, text_pozadavku: str | None = None,
           vykony: list[dict] | None = None, diagnoza: dict | None = None,
           klinicka_otazka: str | None = None, pojistovna: str | None = "111",
           cislo_pojistence: str | None = None, priorita: str = "routine",
           pacient_jmeno: dict | None = None, odbornost: str | None = None,
           pocet_procedur: int | None = None) -> dict:
    """Minimální FHIR Bundle (document) žádanky **K** nebo **FT** podle
    HL7 CZ Order IG 1.0.0, který splňuje pravidla brány (urn:uuid reference,
    custodian s IČO+IČP, autor přes PractitionerRole, Coverage, sekce
    orderInformation + coverage [+ clinicalQuestion]). Pro typ Z použijte
    ``fhir_imgorder.EZadankaToImagingOrder(...).to_bundle()`` /
    ``kostra_z``."""
    typ = (typ or "K").upper()
    if typ not in ("K", "FT"):
        raise ValueError("kostra(): typ musí být K nebo FT (Z viz kostra_z)")
    _over_prioritu(priorita)
    t = TYPY[typ]
    now = _now()
    ids = {k: _uuid() for k in ("bundle", "comp", "pat", "prac", "role", "org", "cov", "payor", "cond", "perf")}
    sr_ids = []
    vykony = vykony or VYCHOZI_VYKONY[typ]
    jm = pacient_jmeno or {"family": "Příjmení", "given": ["Jméno"]}
    title = nazev or ("Žádanka o fyzioterapii" if typ == "FT" else "Konziliární žádanka")

    composition: dict[str, Any] = {
        "resourceType": "Composition", "id": ids["comp"],
        "meta": {"profile": [t["composition_profile"]]},
        "language": "cs",
        "identifier": {"system": "urn:ietf:rfc:3986", "value": f"urn:uuid:{ids['comp']}"},
        "status": "final",
        "type": {"coding": [{"system": SYS_LOINC, "code": t["kod"]}],
                 "text": "žádanka o fyzioterapii" if typ == "FT" else "žádanka o vyšetření"},
        "category": [{"coding": [{"system": SYS_LOINC, "code": LOINC_TYP_K}]}],
        "subject": _ref(ids["pat"]),
        "date": now,
        "author": [_ref(ids["role"])],
        "custodian": _ref(ids["org"]),
        "title": title,
        "section": [],
    }
    entries = [{"fullUrl": f"urn:uuid:{ids['comp']}", "resource": composition}]

    patient = {"resourceType": "Patient", "id": ids["pat"], "meta": {"profile": [PROFILE_PATIENT]},
               "identifier": [{"use": "official", "system": SYS_RID, "value": str(pacient)}],
               "name": [jm]}
    if cislo_pojistence:
        patient["identifier"].append({"system": SYS_CPOJ, "value": str(cislo_pojistence)})
    entries.append({"fullUrl": f"urn:uuid:{ids['pat']}", "resource": patient})

    practitioner = {"resourceType": "Practitioner", "id": ids["prac"], "meta": {"profile": [PROFILE_PRACTITIONER]},
                    "identifier": [{"system": SYS_KRZP, "value": str(zdravotnicky_pracovnik or autor)}],
                    "name": [{"family": "Lékař", "given": ["Žádající"], "prefix": ["MUDr."]}]}
    entries.append({"fullUrl": f"urn:uuid:{ids['prac']}", "resource": practitioner})
    role: dict[str, Any] = {"resourceType": "PractitionerRole", "id": ids["role"],
                            "meta": {"profile": [PROFILE_PRACTITIONER_ROLE_ORDER]},
                            "practitioner": _ref(ids["prac"]), "organization": _ref(ids["org"])}
    if odbornost:
        role["specialty"] = [{"coding": [{"system": "https://ncez.mzcr.cz/terminology/CodeSystem/vzp-smluvni-odbornost",
                                          "code": str(odbornost)}]}]
    entries.append({"fullUrl": f"urn:uuid:{ids['role']}", "resource": role})

    org_ids = [{"system": SYS_ICO, "value": str(poskytovatel)}]
    if icp:
        org_ids.append({"system": SYS_ICP, "value": str(icp)})
    entries.append({"fullUrl": f"urn:uuid:{ids['org']}", "resource": {
        "resourceType": "Organization", "id": ids["org"], "meta": {"profile": [PROFILE_ORG]},
        "identifier": org_ids, "name": nazev_poskytovatele or f"Poskytovatel {poskytovatel}"}})

    if adresat:
        entries.append({"fullUrl": f"urn:uuid:{ids['perf']}", "resource": {
            "resourceType": "Organization", "id": ids["perf"], "meta": {"profile": [PROFILE_ORG]},
            "identifier": [{"system": SYS_ICO, "value": str(adresat)}],
            "name": nazev_adresata or f"Provádějící PZS {adresat}"}})

    # Coverage (sekce coverage je 1..1)
    coverage: dict[str, Any] = {"resourceType": "Coverage", "id": ids["cov"],
                                "meta": {"profile": [PROFILE_COVERAGE_ORDER]}, "status": "active",
                                "type": {"coding": [{"system": SYS_V3_ACTCODE, "code": "HIP" if pojistovna else "pay"}]},
                                "beneficiary": _ref(ids["pat"])}
    if cislo_pojistence:
        coverage["subscriberId"] = str(cislo_pojistence)
    if pojistovna:
        coverage["payor"] = [_ref(ids["payor"])]
        entries.append({"fullUrl": f"urn:uuid:{ids['payor']}", "resource": {
            "resourceType": "Organization", "id": ids["payor"], "meta": {"profile": [PROFILE_ORG]},
            "identifier": [{"system": SYS_KP, "value": str(pojistovna)}], "name": f"Zdravotní pojišťovna {pojistovna}"}})
    else:
        coverage["payor"] = [_ref(ids["pat"])]   # samoplátce
    entries.append({"fullUrl": f"urn:uuid:{ids['cov']}", "resource": coverage})

    # Klinická otázka / diagnóza (Condition, profil cz-clinicalQuestion)
    condition = None
    if diagnoza or klinicka_otazka:
        code: dict[str, Any] = {}
        if diagnoza:
            code["coding"] = [{"system": diagnoza.get("system") or SYS_MKN10, "code": diagnoza.get("code") or diagnoza.get("kod"),
                               **({"display": diagnoza["display"]} if diagnoza.get("display") else {})}]
        code["text"] = klinicka_otazka or (diagnoza or {}).get("display") or (diagnoza or {}).get("text") or "Klinická otázka"
        condition = {"resourceType": "Condition", "id": ids["cond"], "meta": {"profile": [PROFILE_CLINICAL_QUESTION]},
                     "code": code, "subject": _ref(ids["pat"])}
        entries.append({"fullUrl": f"urn:uuid:{ids['cond']}", "resource": condition})

    for v in vykony:
        sid = _uuid()
        sr_ids.append(sid)
        sr: dict[str, Any] = {
            "resourceType": "ServiceRequest", "id": sid, "meta": {"profile": [t["servicerequest_profile"]]},
            "identifier": [{"system": "urn:ietf:rfc:3986", "value": f"urn:uuid:{sid}"}],
            "status": "active", "intent": "order", "priority": priorita,
            "code": {"coding": [{"system": v.get("system") or SYS_SNOMED,
                                 **({"version": SCT_CZ_EDITION} if not v.get("system") or v.get("system") == SYS_SNOMED else {}),
                                 "code": v.get("code") or v.get("kod"),
                                 **({"display": v["display"]} if v.get("display") else {})}],
                     **({"text": v["text"]} if v.get("text") else {})},
            "subject": _ref(ids["pat"]), "authoredOn": now, "requester": _ref(ids["role"]),
            "insurance": [_ref(ids["cov"])],
        }
        if text_pozadavku:
            sr["note"] = [{"text": text_pozadavku}]
        if typ == "FT" and (pocet_procedur or v.get("pocet")):
            sr["quantityQuantity"] = {"value": int(pocet_procedur or v.get("pocet"))}
        if condition:
            sr["reasonReference"] = [_ref(ids["cond"])]
        if adresat:
            sr["performer"] = [_ref(ids["perf"])]
        entries.append({"fullUrl": f"urn:uuid:{sid}", "resource": sr})

    composition["section"].append({
        "title": "Požadovaná fyzioterapie" if typ == "FT" else "Požadovaná vyšetření",
        "code": {"coding": [{"system": SYS_LOINC, "code": t["kod"]}]},
        "text": {"status": "generated", "div": f'<div xmlns="http://www.w3.org/1999/xhtml">{text_pozadavku or title}</div>'},
        "entry": [_ref(s) for s in sr_ids],
    })
    if condition:
        composition["section"].append({
            "title": "Klinická indikace a otázka",
            "code": {"coding": [{"system": SYS_LOINC, "code": SEKCE["clinicalQuestion"]}]},
            "entry": [_ref(ids["cond"])],
        })
    composition["section"].append({
        "title": "Úhrada",
        "code": {"coding": [{"system": SYS_LOINC, "code": SEKCE["coverage"]}]},
        "entry": [_ref(ids["cov"])],
    })

    return {
        "resourceType": "Bundle", "id": ids["bundle"],
        "meta": {"profile": [PROFILE_BUNDLE_ORDER]},
        "identifier": {"system": "urn:ietf:rfc:3986", "value": f"urn:uuid:{ids['bundle']}"},
        "type": "document", "timestamp": now,
        "entry": entries,
    }


def kostra_z(*, pacient: str, poskytovatel: str, autor: str, icp: str | None = None,
             adresat: str | None = None, nazev: str | None = None,
             nazev_poskytovatele: str | None = None, pojistovna: str | None = "111",
             priorita: str = "routine", diagnoza: dict | None = None, vykon: dict | None = None) -> dict:
    """Kostra žádanky **Z** (img-order) – využívá generátor v ``fhir_imgorder``
    (stejný tvar prošel 13. 10. 2026 na T2)."""
    from .fhir_imgorder import EZadankaToImagingOrder
    _over_prioritu(priorita)
    rec: dict[str, Any] = {"zadanka": {
        "id": _uuid(), "urgentnost": {"kod": priorita}, "icpZadatele": icp,
        "pacientPojistovna": {"kod": pojistovna} if pojistovna else None,
        "zasilka": {"pacient": pacient, "autor": autor, "poskytovatel": poskytovatel,
                    "adresat": adresat, "nazev": nazev or "Žádanka o zobrazovací vyšetření",
                    "poskytovatelData": {"nazev": nazev_poskytovatele}},
        "zadankaK": {},
    }}
    if diagnoza:
        rec["zadanka"]["zadankaK"]["duvodZadanky"] = {"hlavniDiagnoza": {"coding": [{
            "system": diagnoza.get("system") or SYS_MKN10, "code": diagnoza.get("code") or diagnoza.get("kod"),
            "display": diagnoza.get("display", "")}]}}
    if vykon:
        rec["zadanka"]["zadankaK"]["pozadovanaVysetreni"] = [{"system": vykon.get("system") or SYS_SNOMED,
                                                              "kod": vykon.get("code") or vykon.get("kod"),
                                                              "display": vykon.get("display", "")}]
    return EZadankaToImagingOrder(rec).to_bundle()


# ---------------------------------------------------------------------------
# Vzory (příklady IG order) – soubory v fhir_order_examples
# ---------------------------------------------------------------------------

def list_examples() -> list[dict]:
    out = []
    if os.path.isdir(EXAMPLES_DIR):
        for fname in sorted(os.listdir(EXAMPLES_DIR)):
            if not fname.endswith(".json") or fname.startswith("."):
                continue
            path = os.path.join(EXAMPLES_DIR, fname)
            typ = None
            try:
                with open(path, encoding="utf-8") as f:
                    typ = typ_z_bundle(json.load(f))
            except Exception:
                pass
            out.append({"name": fname, "typ": typ, "ig": IG_ORDER_PACKAGE, "size": os.path.getsize(path)})
    return out


def load_example(name: str) -> dict | None:
    if not re.match(r"^[A-Za-z0-9._-]+\.json$", name or ""):
        return None
    path = os.path.join(EXAMPLES_DIR, name)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def katalog_typu() -> dict:
    """Přehled typů eŽádanky pro GUI / API: kódy, IG, profily, vzory, pravidla."""
    dostupne = {e["name"] for e in list_examples()}
    try:
        from sez_api import fhir_imgorder as _img
        dostupne |= {e["name"] for e in _img.list_examples()}
    except Exception:  # pragma: no cover - img-order modul je součástí balíčku
        pass
    out = {}
    for k, t in TYPY.items():
        out[k] = dict(t, vzory=[{"name": n, "dostupny": n in dostupne} for n in t["vzory"]])
    return {"typy": out, "pravidla_brany": PRAVIDLA_BRANY,
            "zdroje": {"manual": "https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/56000561",
                       "api": "https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/59670529",
                       "ig_order": IG_ORDER_URL, "ig_img_order": IG_IMG_ORDER_URL},
            "overeno_t2": "2026-10-13"}
