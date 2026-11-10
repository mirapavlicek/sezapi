/// Builder elektronických zdravotních dokumentů (eZD) ve FHIR R4 pro
/// InterSystems IRIS – prioritní kategorie dle standardů MZ ČR
/// (HL7 CZ Implementation Guides).
///
/// Podporované typy zpráv (parametr pKategorie) a ověřené verze IG
/// (revize 10. 11. 2026):
///   pacientsky-souhrn      hl7.fhir.cz.ps   0.0.1 (CI)             LOINC 60591-5
///   propousteci-zprava     hl7.fhir.cz.hdr  0.1.0 (CI 21. 9. 2026) LOINC 34105-7
///   obrazove-vysetreni     hl7.fhir.cz.img  1.0.0 (portál)         LOINC 18748-4
///   vyjezd-zzs             hl7.fhir.cz.ems  0.1.0 (CI 5. 11. 2026) LOINC 67796-3
///   laboratorni-vysetreni  hl7.fhir.cz.lab  1.0.0 (portál)         LOINC 11502-2
///
/// Portál https://ig.ezdravi.gov.cz/ je závazným místem publikace IG;
/// PS, HDR a EMS na něm nejsou, platí pro ně CI build (build.fhir.org).
///
/// Generuje document Bundle na úrovni L1 (hlavička dle IG profilu +
/// presentedForm PDF/A); tělo (klinické zdroje) není na L1 vyžadováno.
///
/// Použití:
///   Set sekce = ##class(%DynamicObject).%New()
///   Do sekce.%Set("sectionHospitalCourse", "Průběh hospitalizace bez komplikací.")
///   Set bundle = ##class(SEZ.EZD.Builder).Sestav("propousteci-zprava",
///       "2667873559", "102129137", "25488627", .sekce, .sc)
///   Write bundle.%ToJSON()
Class SEZ.EZD.Builder Extends %RegisteredObject
{

/// Systém identifikátoru pacienta (RID) dle cz-core
Parameter RIDSYSTEM = "https://ncez.mzcr.cz/fhir/sid/rid";

/// Systém identifikátoru zdravotnického pracovníka (KRZPID)
Parameter KRZPIDSYSTEM = "https://ncez.mzcr.cz/fhir/sid/krzpid";

/// Systém identifikátoru poskytovatele (IČO)
Parameter ICOSYSTEM = "https://ncez.mzcr.cz/fhir/sid/ico";

/// URL extension presentedForm (vizuální podoba dokumentu, PDF/A)
Parameter PRESENTEDFORM = "https://hl7.cz/fhir/core/StructureDefinition/presentedForm";

/// Profil pacienta dle cz-core
Parameter CZPATIENT = "https://hl7.cz/fhir/core/StructureDefinition/cz-patient-core";

Parameter LOINC = "http://loinc.org";

/// Kategorie eEHRxF pro obrazovou dokumentaci (cz-composition-imaging)
Parameter EEHRXFKATEGORIE = "http://hl7.eu/fhir/health-data-api/CodeSystem/eehrxf-document-priority-category-cs";

/// Číselník časových bodů výjezdu ZZS (cz-ems 0.1.0, A.2.2)
Parameter EMSCASOVYBOD = "https://ncez.mzcr.cz/terminology/CodeSystem/ems-mission-time-point-cs";

/// Povinné časové body výjezdu – invariant mission-time-required
Parameter EMSCASYPOVINNE = "02,03,04,05,07";

/// LOINC kód sekce časové osy výjezdu ZZS
Parameter EMSTIMELINE = "67667-6";

/// Profil Observation časového bodu výjezdu
Parameter EMSOBSERVATIONCAS = "https://hl7.cz/fhir/cz-ems/StructureDefinition/cz-observation-mission-time-ems";

/// Profil Encounter výjezdu ZZS
Parameter EMSENCOUNTER = "https://hl7.cz/fhir/cz-ems/StructureDefinition/cz-encounter-ems";

/// Vrátí metadata kategorie zprávy (profily, kód dokumentu, požadavky IG).
/// Prázdný objekt = neznámá kategorie.
ClassMethod Metadata(pKategorie As %String) As %DynamicObject
{
    If pKategorie = "pacientsky-souhrn" {
        Quit {
            "nazev": "Pacientský souhrn",
            "ig": "hl7.fhir.cz.ps",
            "bundleProfile": "https://hl7.cz/fhir/ps/StructureDefinition/cz-bundle-ps",
            "compositionProfile": "https://hl7.cz/fhir/ps/StructureDefinition/cz-composition-ps",
            "typKod": "60591-5",
            "typNazev": "Patient summary Document",
            "kategorieKod": "11503-0",
            "presentedForm": true,
            "encounter": false,
            "language": false,
            "identifier": false,
            "confidentiality": false,
            "diagnosticReport": false,
            "duTypKod": "60591-5"
        }
    }
    If pKategorie = "propousteci-zprava" {
        Quit {
            "nazev": "Propouštěcí zpráva",
            "ig": "hl7.fhir.cz.hdr",
            "bundleProfile": "https://hl7.cz/fhir/hdr/StructureDefinition/cz-bundle-hdr",
            "compositionProfile": "https://hl7.cz/fhir/hdr/StructureDefinition/composition-cz-hdr",
            "typKod": "34105-7",
            "typNazev": "Hospital Discharge summary",
            "kategorieKod": "11503-0",
            "presentedForm": true,
            "encounter": true,
            "language": false,
            "identifier": true,
            "confidentiality": false,
            "diagnosticReport": false,
            "duTypKod": "18842-5"
        }
    }
    If pKategorie = "obrazove-vysetreni" {
        Quit {
            "nazev": "Zpráva z obrazového vyšetření",
            "ig": "hl7.fhir.cz.img",
            "bundleProfile": "https://hl7.cz/fhir/img/StructureDefinition/cz-bundle-imaging",
            "compositionProfile": "https://hl7.cz/fhir/img/StructureDefinition/cz-composition-imaging",
            "typKod": "18748-4",
            "typNazev": "Diagnostic imaging study",
            "kategorieKod": "85430-7",
            "presentedForm": false,
            "encounter": false,
            "language": true,
            "identifier": true,
            "confidentiality": true,
            "diagnosticReport": true,
            "duTypKod": "18748-4"
        }
    }
    If pKategorie = "vyjezd-zzs" {
        Quit {
            "nazev": "Zpráva o výjezdu ZZS",
            "ig": "hl7.fhir.cz.ems",
            "bundleProfile": "https://hl7.cz/fhir/cz-ems/StructureDefinition/cz-bundle-ems",
            "compositionProfile": "https://hl7.cz/fhir/cz-ems/StructureDefinition/cz-composition-ems",
            "typKod": "67796-3",
            "typNazev": "EMS note",
            "kategorieKod": "18682-5",
            "presentedForm": true,
            "encounter": false,
            "language": false,
            "identifier": true,
            "confidentiality": false,
            "diagnosticReport": false,
            "casoveBody": true,
            "duTypKod": "67796-3"
        }
    }
    If pKategorie = "laboratorni-vysetreni" {
        Quit {
            "nazev": "Laboratorní zpráva",
            "ig": "hl7.fhir.cz.lab",
            "bundleProfile": "https://hl7.cz/fhir/lab/StructureDefinition/cz-bundle-lab",
            "compositionProfile": "https://hl7.cz/fhir/lab/StructureDefinition/composition-cz-lab",
            "typKod": "11502-2",
            "typNazev": "Laboratory report",
            "kategorieKod": "11502-2",
            "presentedForm": false,
            "encounter": false,
            "language": true,
            "identifier": true,
            "confidentiality": false,
            "diagnosticReport": true,
            "duTypKod": "11502-2"
        }
    }
    Quit {}
}

/// Vrátí povinné kódy Composition.category dané kategorie:
/// [{"system":..,"code":..}]. Obrazové vyšetření (IG 1.0.0) nese dva
/// (imaging-report 85430-7 a eEHRxF Medical-Imaging), ostatní jeden.
ClassMethod Kategorie(pKategorie As %String) As %DynamicArray
{
    If pKategorie = "obrazove-vysetreni" {
        Quit [
            {"system": (..#LOINC), "code": "85430-7"},
            {"system": (..#EEHRXFKATEGORIE), "code": "Medical-Imaging"}
        ]
    }
    Set meta = ..Metadata(pKategorie)
    If (meta.%Size() = 0) || (meta.kategorieKod = "") Quit []
    Quit [{"system": (..#LOINC), "code": (meta.kategorieKod)}]
}

/// Dřívější názvy sekcí (slice) a jejich aktuální cíl. Obsah předaný pod
/// starým názvem se sloučí do cílové sekce.
ClassMethod AliasySekci(pKategorie As %String) As %DynamicObject
{
    If pKategorie = "pacientsky-souhrn" {
        Quit {"sectionPastProblems": "sectionProblems", "sectionAlerts": "sectionAlert"}
    }
    If pKategorie = "vyjezd-zzs" Quit {"significantProcedures": "procedure"}
    If pKategorie = "laboratorni-vysetreni" Quit {"annotations": "laboratorniNalez"}
    Quit {}
}

/// Sekce, které aktuální verze IG už nepřipouští:
/// [{"kod":..,"nazev":..,"chyba":bool,"duvod":..}]. chyba = 1 znamená
/// porušení profilu (max 0), chyba = 0 jen výhradu.
ClassMethod ZruseneSekce(pKategorie As %String) As %DynamicArray
{
    If pKategorie = "vyjezd-zzs" {
        Quit [{"kod": "10185-7", "nazev": "Významné výkony", "chyba": false,
               "duvod": "v cz-ems 0.1.0 už není pojmenovaný slice – použijte Provedené výkony (29554-3)"}]
    }
    If pKategorie = "laboratorni-vysetreni" {
        Quit [
            {"kod": "48767-8", "nazev": "Komentář k výsledkům", "chyba": true,
             "duvod": "v cz-lab 1.0.0 má slice annotations max 0"},
            {"kod": "77599-9", "nazev": "Přílohy", "chyba": true,
             "duvod": "v cz-lab 1.0.0 má slice attachment max 0"}
        ]
    }
    Quit []
}

/// Vrátí pole povinných sekcí kategorie: [{"slice":..,"kod":..,"nazev":..}]
/// Povinné sekce musí být v dokumentu vždy (i bez obsahu). Položka může
/// nést "alternativy" – kódy, které validace přijme místo hlavního kódu.
ClassMethod PovinneSekce(pKategorie As %String) As %DynamicArray
{
    If pKategorie = "pacientsky-souhrn" {
        Quit [
            {"slice": "sectionMedications", "kod": "10160-0", "nazev": "Medikace"},
            {"slice": "sectionAllergies", "kod": "48765-2", "nazev": "Alergie a intolerance"},
            {"slice": "sectionProblems", "kod": "11450-4", "nazev": "Problémy"}
        ]
    }
    If pKategorie = "propousteci-zprava" {
        Quit [{"slice": "sectionHospitalCourse", "kod": "8648-8", "nazev": "Průběh hospitalizace"}]
    }
    If pKategorie = "obrazove-vysetreni" {
        Quit [
            {"slice": "imagingstudy", "kod": "18726-0", "nazev": "Obrazové vyšetření"},
            {"slice": "order", "kod": "55115-0", "nazev": "Žádanka"},
            {"slice": "history", "kod": "11329-0", "nazev": "Anamnéza"},
            {"slice": "procedure", "kod": "55111-9", "nazev": "Provedené výkony"}
        ]
    }
    If pKategorie = "vyjezd-zzs" {
        Quit [{"slice": "mission", "kod": "67664-3", "nazev": "Výjezd"}]
    }
    If pKategorie = "laboratorni-vysetreni" {
        Quit [{"slice": "laboratorniNalez", "kod": "26436-6", "nazev": "Laboratorní nález",
               "alternativy": ["18719-5", "18723-7", "18725-2", "18717-9", "18722-9", "18728-6"]}]
    }
    Quit []
}

/// Mapa volitelných sekcí kategorie (slice -> {kod, nazev}). Volitelná
/// sekce se do dokumentu přidá pouze tehdy, má-li obsah.
ClassMethod VolitelneSekce(pKategorie As %String) As %DynamicObject
{
    If pKategorie = "pacientsky-souhrn" {
        Quit {
            "sectionImmunizations": {"kod": "11369-6", "nazev": "Očkování"},
            "sectionResults": {"kod": "30954-2", "nazev": "Výsledky vyšetření"},
            "sectionProceduresHx": {"kod": "47519-4", "nazev": "Historie výkonů"},
            "sectionMedicalDevices": {"kod": "46264-8", "nazev": "Zdravotnické prostředky"},
            "sectionAdvanceDirectives": {"kod": "42348-3", "nazev": "Dříve vyslovená přání"},
            "sectionAlert": {"kod": "104605-1", "nazev": "Upozornění"},
            "sectionFunctionalStatus": {"kod": "47420-5", "nazev": "Funkční stav"},
            "sectionPregnancyHx": {"kod": "10162-6", "nazev": "Anamnéza gravidity"},
            "sectionPatientStory": {"kod": "10164-2", "nazev": "Anamnéza dle pacienta"},
            "sectionPlanOfCare": {"kod": "18776-5", "nazev": "Plán péče"},
            "sectionSocialHistory": {"kod": "29762-2", "nazev": "Sociální anamnéza"},
            "sectionVitalSigns": {"kod": "8716-3", "nazev": "Vitální funkce"},
            "sectionTravelHx": {"kod": "10182-4", "nazev": "Cestovní anamnéza"},
            "sectionPatientHx": {"kod": "11329-0", "nazev": "Anamnéza"},
            "sectionAttachments": {"kod": "77599-9", "nazev": "Přílohy"}
        }
    }
    If pKategorie = "propousteci-zprava" {
        Quit {
            "sectionAdmissionEvaluation": {"kod": "67851-6", "nazev": "Vyhodnocení při příjmu"},
            "sectionPatientHx": {"kod": "35090-0", "nazev": "Anamnéza"},
            "sectionAllergies": {"kod": "48765-2", "nazev": "Alergie a intolerance"},
            "sectionAlert": {"kod": "104605-1", "nazev": "Upozornění"},
            "sectionProblemList": {"kod": "11450-4", "nazev": "Seznam problémů"},
            "sectionDiagnosticSummary": {"kod": "11535-2", "nazev": "Souhrn diagnóz"},
            "sectionSignificantProcedures": {"kod": "10185-7", "nazev": "Významné výkony"},
            "sectionSignificantResults": {"kod": "30954-2", "nazev": "Významné výsledky"},
            "sectionPhysicalFindings": {"kod": "29545-1", "nazev": "Fyzikální nález"},
            "sectionVitalSigns": {"kod": "8716-3", "nazev": "Vitální funkce"},
            "sectionFunctionalStatus": {"kod": "47420-5", "nazev": "Funkční stav"},
            "sectionMedicalDevices": {"kod": "57080-4", "nazev": "Zdravotnické prostředky"},
            "sectionPharmacotherapy": {"kod": "87232-5", "nazev": "Farmakoterapie"},
            "sectionDischargeMedications": {"kod": "75311-1", "nazev": "Medikace při propuštění"},
            "sectionDischargeDetails": {"kod": "8650-4", "nazev": "Podrobnosti propuštění"},
            "sectionDischargeInstructions": {"kod": "8653-8", "nazev": "Instrukce při propuštění"},
            "sectionSynthesis": {"kod": "67781-5", "nazev": "Souhrnná zpráva"},
            "sectionCareTeam": {"kod": "85847-2", "nazev": "Tým péče"},
            "sectionPlanOfCare": {"kod": "18776-5", "nazev": "Plán péče"},
            "sectionAdvanceDirectives": {"kod": "42348-3", "nazev": "Dříve vyslovená přání"},
            "sectionPayers": {"kod": "48768-6", "nazev": "Plátci"},
            "sectionAttachments": {"kod": "77599-9", "nazev": "Přílohy"}
        }
    }
    If pKategorie = "obrazove-vysetreni" {
        Quit {
            "clinicalQuestion": {"kod": "18785-6", "nazev": "Klinická otázka"},
            "comparison": {"kod": "18834-2", "nazev": "Srovnání s předchozími"},
            "findings": {"kod": "59776-5", "nazev": "Nález"},
            "impression": {"kod": "19005-8", "nazev": "Závěr / hodnocení"},
            "recommendation": {"kod": "18783-1", "nazev": "Doporučení"},
            "communication": {"kod": "73568-8", "nazev": "Komunikace s ošetřujícím"},
            "report": {"kod": "LP173421-1", "nazev": "Text zprávy"}
        }
    }
    If pKategorie = "vyjezd-zzs" {
        Quit {
            "dispatch": {"kod": "67660-1", "nazev": "Výzva / dispečink"},
            "timeline": {"kod": "67667-6", "nazev": "Časová osa výjezdu"},
            "patientHx": {"kod": "11329-0", "nazev": "Anamnéza"},
            "presentIllness": {"kod": "10164-2", "nazev": "Nynější onemocnění"},
            "allergies": {"kod": "48765-2", "nazev": "Alergie a intolerance"},
            "alert": {"kod": "75310-3", "nazev": "Upozornění"},
            "findings": {"kod": "29545-1", "nazev": "Nález na místě"},
            "procedure": {"kod": "29554-3", "nazev": "Provedené výkony"},
            "medicalDevices": {"kod": "57080-4", "nazev": "Zdravotnické prostředky"},
            "diagnosticSummary": {"kod": "11450-4", "nazev": "Diagnostický souhrn"},
            "courseOfTreatment": {"kod": "18682-5", "nazev": "Průběh ošetření"},
            "recommendations": {"kod": "18776-5", "nazev": "Doporučení"},
            "payers": {"kod": "48768-6", "nazev": "Plátci"},
            "attachments": {"kod": "34109-9", "nazev": "Přílohy"}
        }
    }
    If pKategorie = "laboratorni-vysetreni" {
        Quit {
            "biochemie": {"kod": "18719-5", "nazev": "Biochemie"},
            "hematologie": {"kod": "18723-7", "nazev": "Hematologie"},
            "mikrobiologie": {"kod": "18725-2", "nazev": "Mikrobiologie"},
            "transfuzni": {"kod": "18717-9", "nazev": "Transfuzní vyšetření"},
            "reprodukcni": {"kod": "18722-9", "nazev": "Reprodukční vyšetření"},
            "toxikologie": {"kod": "18728-6", "nazev": "Toxikologie"}
        }
    }
    Quit {}
}

/// Sestaví FHIR document Bundle dané kategorie.
/// pSekce: %DynamicObject {slice: "text" | ["text1","text2"]}
/// pPacient: volitelné {"jmeno","prijmeni","datumNarozeni"}
/// pAutorData: volitelné {"titul","jmeno","prijmeni"}
/// pCisloVyjezdu: číslo výjezdu ZZS pro Encounter (jen vyjezd-zzs s časy)
///
/// Výjezd ZZS (cz-ems 0.1.0): řádky sekce "timeline" ve tvaru
/// "<kód 01–08> <čas ISO 8601>" (např. "02 2026-07-18T18:42:00+02:00")
/// se převedou na Observation časových bodů a sekce na ně odkáže.
ClassMethod Sestav(pKategorie As %String, pRid As %String, pAutorKrzpId As %String, pIco As %String, pSekce As %DynamicObject = "", Output pSC As %Status, pNazevPZS As %String = "Testovací PZS", pTitulek As %String = "", pPdfBase64 As %String = "", pPacient As %DynamicObject = "", pAutorData As %DynamicObject = "", pCisloVyjezdu As %String = "") As %DynamicObject
{
    Set pSC = $$$OK
    Set bundle = ""
    Try {
        Set meta = ..Metadata(pKategorie)
        If meta.%Size() = 0 {
            Set pSC = $$$ERROR($$$GeneralError, "Neznámá kategorie eZD: " _ pKategorie)
            Quit
        }
        Set casISO = ..CasISO()
        Set sekceVstup = ..SlucAliasy(pKategorie, pSekce)
        Set compUuid = "urn:uuid:" _ ..NoveUUID()
        Set patUuid = "urn:uuid:" _ ..NoveUUID()
        Set pracUuid = "urn:uuid:" _ ..NoveUUID()
        Set orgUuid = "urn:uuid:" _ ..NoveUUID()

        // --- Composition (hlavička dokumentu) ---
        Set loinc = ..#LOINC
        Set comp = {
            "resourceType": "Composition",
            "meta": {"profile": [(meta.compositionProfile)]},
            "status": "final",
            "type": {"coding": [{"system": (loinc), "code": (meta.typKod), "display": (meta.typNazev)}]},
            "subject": {"reference": (patUuid)},
            "date": (casISO),
            "author": [{"reference": (pracUuid)}],
            "custodian": {"reference": (orgUuid)},
            "title": ($Select(pTitulek '= "": pTitulek, 1: meta.nazev)),
            "section": []
        }
        Set kody = ..Kategorie(pKategorie)
        If kody.%Size() > 0 {
            Set comp.category = []
            Set itk = kody.%GetIterator()
            While itk.%GetNext(.ik, .kodKat) {
                Do comp.category.%Push({"coding": [{"system": (kodKat.system), "code": (kodKat.code)}]})
            }
        }
        If meta.language Set comp.language = "cs"
        If meta.identifier {
            Set comp.identifier = {"system": "urn:ietf:rfc:3986", "value": ("urn:uuid:" _ ..NoveUUID())}
        }
        If meta.confidentiality Set comp.confidentiality = "N"
        If meta.presentedForm {
            Set pdf = $Select(pPdfBase64 '= "": pPdfBase64, 1: ..MinimalniPdfBase64())
            Set comp.extension = [{
                "url": (..#PRESENTEDFORM),
                "valueAttachment": {"contentType": "application/pdf", "data": (pdf)}
            }]
        }

        // --- Sekce: povinné vždy, volitelné jen s obsahem ---
        Set povinne = ..PovinneSekce(pKategorie)
        Set iter = povinne.%GetIterator()
        While iter.%GetNext(.klic, .sekceDef) {
            Set text = ..ObsahSekce(sekceVstup, sekceDef.slice)
            If text = "" Set text = "Informace není k dispozici"
            Do comp.section.%Push(..Sekce(sekceDef.kod, sekceDef.nazev, text))
        }
        Set volitelne = ..VolitelneSekce(pKategorie)
        Set iter2 = volitelne.%GetIterator()
        Set sekceTimeline = ""
        While iter2.%GetNext(.slice, .def) {
            Set text = ..ObsahSekce(sekceVstup, slice)
            If text '= "" {
                Set sekceObj = ..Sekce(def.kod, def.nazev, text)
                Do comp.section.%Push(sekceObj)
                If def.kod = ..#EMSTIMELINE Set sekceTimeline = sekceObj
            }
        }

        // --- Pacient (cz-patient-core, RID) ---
        Set patient = {
            "resourceType": "Patient",
            "meta": {"profile": [(..#CZPATIENT)]},
            "identifier": [{"use": "official", "system": (..#RIDSYSTEM), "value": (pRid)}]
        }
        If $IsObject(pPacient) {
            If (pPacient.jmeno '= "") || (pPacient.prijmeni '= "") {
                Set jmenoObj = {"use": "official", "family": (pPacient.prijmeni)}
                If pPacient.jmeno '= "" Set jmenoObj.given = [(pPacient.jmeno)]
                Set patient.name = [(jmenoObj)]
            }
            If pPacient.datumNarozeni '= "" Set patient.birthDate = pPacient.datumNarozeni
        }

        // --- Zdravotnický pracovník + poskytovatel ---
        Set prac = {
            "resourceType": "Practitioner",
            "identifier": [{"system": (..#KRZPIDSYSTEM), "value": (pAutorKrzpId)}]
        }
        If $IsObject(pAutorData), (pAutorData.jmeno '= "") || (pAutorData.prijmeni '= "") {
            Set jm = {"use": "official", "family": (pAutorData.prijmeni)}
            If pAutorData.jmeno '= "" Set jm.given = [(pAutorData.jmeno)]
            If pAutorData.titul '= "" Set jm.prefix = [(pAutorData.titul)]
            Set prac.name = [(jm)]
        }
        Set org = {
            "resourceType": "Organization",
            "identifier": [{"system": (..#ICOSYSTEM), "value": (pIco)}],
            "name": (pNazevPZS)
        }

        Set entries = [
            {"fullUrl": (compUuid), "resource": (comp)},
            {"fullUrl": (patUuid), "resource": (patient)},
            {"fullUrl": (pracUuid), "resource": (prac)},
            {"fullUrl": (orgUuid), "resource": (org)}
        ]

        // --- Encounter (propouštěcí zpráva: 1..1) ---
        If meta.encounter {
            Set encUuid = "urn:uuid:" _ ..NoveUUID()
            Set comp.encounter = {"reference": (encUuid)}
            Do entries.%Push({
                "fullUrl": (encUuid),
                "resource": {
                    "resourceType": "Encounter",
                    "status": "finished",
                    "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                               "code": "IMP", "display": "inpatient encounter"},
                    "subject": {"reference": (patUuid)},
                    "serviceProvider": {"reference": (orgUuid)}
                }
            })
        }

        // --- Časové body výjezdu ZZS (cz-ems 0.1.0, mission-time-required) ---
        If meta.casoveBody, $IsObject(sekceTimeline) {
            Set body = ..CasoveBody(sekceVstup.%Get("timeline"))
            If body.%Size() > 0 {
                Set encUuid = "urn:uuid:" _ ..NoveUUID()
                Set cislo = pCisloVyjezdu
                If cislo = "" Set cislo = "VYJEZD-" _ $ZDate($Horolog, 8) _ "-" _ $Extract(..NoveUUID(), 1, 8)
                Set comp.encounter = {"reference": (encUuid)}
                Do entries.%Push({
                    "fullUrl": (encUuid),
                    "resource": {
                        "resourceType": "Encounter",
                        "meta": {"profile": [(..#EMSENCOUNTER)]},
                        "identifier": [{"use": "official", "value": (cislo)}],
                        "status": "finished",
                        "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                                   "code": "EMER", "display": "emergency"},
                        "subject": {"reference": (patUuid)},
                        "serviceProvider": {"reference": (orgUuid)}
                    }
                })
                Set sekceTimeline.entry = []
                Set itb = body.%GetIterator()
                While itb.%GetNext(.kodBodu, .casBodu) {
                    Set obsUuid = "urn:uuid:" _ ..NoveUUID()
                    Do sekceTimeline.entry.%Push({"reference": (obsUuid)})
                    Do entries.%Push({
                        "fullUrl": (obsUuid),
                        "resource": {
                            "resourceType": "Observation",
                            "meta": {"profile": [(..#EMSOBSERVATIONCAS)]},
                            "status": "final",
                            "code": {"coding": [{"system": (..#EMSCASOVYBOD), "code": (kodBodu),
                                                 "display": (..NazevCasovehoBodu(kodBodu))}]},
                            "subject": {"reference": (patUuid)},
                            "encounter": {"reference": (encUuid)},
                            "valueDateTime": (casBodu)
                        }
                    })
                }
            }
        }

        // --- DiagnosticReport (obrazové vyšetření, laboratorní zpráva) ---
        If meta.diagnosticReport {
            Set drUuid = "urn:uuid:" _ ..NoveUUID()
            Do entries.%Push({
                "fullUrl": (drUuid),
                "resource": {
                    "resourceType": "DiagnosticReport",
                    "status": "final",
                    "code": {"coding": [{"system": (..#LOINC), "code": (meta.typKod), "display": (meta.typNazev)}]},
                    "subject": {"reference": (patUuid)},
                    "issued": (casISO)
                }
            })
        }

        Set bundle = {
            "resourceType": "Bundle",
            "meta": {"profile": [(meta.bundleProfile)]},
            "identifier": {"system": "urn:ietf:rfc:3986", "value": ("urn:uuid:" _ ..NoveUUID())},
            "type": "document",
            "timestamp": (casISO),
            "entry": (entries)
        }
    }
    Catch ex {
        Set pSC = ex.AsStatus()
    }
    Quit bundle
}

/// Vytvoří jednu sekci Composition s LOINC kódem a narativním textem.
ClassMethod Sekce(pKod As %String, pNazev As %String, pText As %String) As %DynamicObject
{
    Quit {
        "title": (pNazev),
        "code": {"coding": [{"system": (..#LOINC), "code": (pKod)}]},
        "text": {
            "status": "generated",
            "div": ("<div xmlns=""http://www.w3.org/1999/xhtml""><p>" _ ..XmlEscape(pText) _ "</p></div>")
        }
    }
}

/// Vrátí kopii obsahu sekcí, v níž jsou dřívější názvy sekcí (viz
/// AliasySekci) převedeny na aktuální; obsah se do cílové sekce přidá.
ClassMethod SlucAliasy(pKategorie As %String, pSekce As %DynamicObject) As %DynamicObject
{
    Set vysledek = {}
    If '$IsObject(pSekce) Quit vysledek
    Set aliasy = ..AliasySekci(pKategorie)
    Set it = pSekce.%GetIterator()
    While it.%GetNext(.slice, .hodnota) {
        Set cil = slice
        If aliasy.%IsDefined(slice) Set cil = aliasy.%Get(slice)
        If 'vysledek.%IsDefined(cil) Do vysledek.%Set(cil, [])
        Set pole = vysledek.%Get(cil)
        If $IsObject(hodnota), hodnota.%IsA("%DynamicArray") {
            Set itp = hodnota.%GetIterator()
            While itp.%GetNext(.i, .polozka) {
                Do pole.%Push(polozka)
            }
        }
        ElseIf hodnota '= "" {
            Do pole.%Push(hodnota)
        }
    }
    Quit vysledek
}

/// Český název časového bodu výjezdu ZZS (číselník ems-mission-time-point-cs).
ClassMethod NazevCasovehoBodu(pKod As %String) As %String
{
    Quit $Case(pKod,
        "01": "Oznámení události",
        "02": "Výzva",
        "03": "Výjezd",
        "04": "Příjezd na místo události",
        "05": "Odjezd z místa události",
        "06": "Příjezd do místa předání",
        "07": "Předání pacienta",
        "08": "Ukončení výjezdu",
        : "")
}

/// Vyčte z obsahu sekce časové osy časové body výjezdu: {kód: dateTime}.
/// Řádek má tvar "<kód 01–08> <datum a čas ISO 8601> [popis]". Čas bez
/// časové zóny se bere jako místní čas serveru IRIS.
ClassMethod CasoveBody(pHodnota) As %DynamicObject
{
    Set body = {}
    If pHodnota = "" Quit body
    Set radky = pHodnota
    If '$IsObject(pHodnota) {
        Set radky = []
        For i = 1:1:$Length(pHodnota, $Char(10)) {
            Do radky.%Push($Piece(pHodnota, $Char(10), i))
        }
    }
    // kódy v pevném pořadí, aby byly Observation v dokumentu seřazené
    Kill nalezene
    Set it = radky.%GetIterator()
    While it.%GetNext(.i, .radek) {
        Set radek = $ZStrip(radek, "<>W")
        If '$Match(radek, "0[1-8]\s*[:=\-]?\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}.*") Continue
        Set cas = ..NormalizujCas($Extract(radek, 3, *))
        If cas '= "" Set nalezene($Extract(radek, 1, 2)) = cas
    }
    Set kod = ""
    For {
        Set kod = $Order(nalezene(kod), 1, cas)
        If kod = "" Quit
        Do body.%Set(kod, cas)
    }
    Quit body
}

/// Najde v textu první datum a čas a vrátí jej jako FHIR dateTime
/// (YYYY-MM-DDThh:mm:ss+hh:mm). Prázdný řetězec = čas nelze přečíst.
ClassMethod NormalizujCas(pText As %String) As %String
{
    Set vzor = "\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"
    If '$Locate(pText, vzor, 1, konec, hodnota) Quit ""
    Set datum = $Extract(hodnota, 1, 10), zbytek = $Extract(hodnota, 12, *)
    Set zona = ""
    If $Extract(zbytek, *) = "Z" {
        Set zona = "+00:00", zbytek = $Extract(zbytek, 1, *-1)
    }
    ElseIf $Locate(zbytek, "[+-]\d{2}:?\d{2}$", 1, konecZony, zonaText) {
        Set zbytek = $Extract(zbytek, 1, $Length(zbytek) - $Length(zonaText))
        Set cislice = $Translate(zonaText, ":")
        Set zona = $Extract(cislice, 1, 3) _ ":" _ $Extract(cislice, 4, 5)
    }
    Set cas = $Piece(zbytek, ".", 1)
    If $Length(cas, ":") = 2 Set cas = cas _ ":00"
    If zona '= "" Quit datum _ "T" _ cas _ zona
    // bez zóny: místní čas serveru vč. letního času pro dané datum
    Set h = $ZDateTimeH(datum _ " " _ cas, 3, 1, , , , , , , "")
    If h = "" Quit ""
    Quit $ZDateTime(h, 3, 5)
}

/// Vrátí obsah sekce jako text. Pole hodnot spojí oddělovačem " · ".
ClassMethod ObsahSekce(pSekce As %DynamicObject, pSlice As %String) As %String
{
    If '$IsObject(pSekce) Quit ""
    Set hodnota = pSekce.%Get(pSlice)
    If hodnota = "" Quit ""
    If $IsObject(hodnota), hodnota.%IsA("%DynamicArray") {
        Set text = "", it = hodnota.%GetIterator()
        While it.%GetNext(.i, .polozka) {
            Set polozka = $ZStrip(polozka, "<>W")
            If polozka '= "" {
                Set text = text _ $Select(text = "": "", 1: " · ") _ polozka
            }
        }
        Quit text
    }
    Quit $ZStrip(hodnota, "<>W")
}

/// Lokální kontrola dokumentu na úrovni L1 (povinné prvky a sekce dle IG).
/// Vrací {"valid":bool,"chyby":[...],"varovani":[...]}.
/// Plnou strukturální validaci provádí https://validator.fhir.org/
ClassMethod Validuj(pBundle As %DynamicObject, pKategorie As %String = "") As %DynamicObject
{
    Set chyby = [], varovani = []
    Try {
        If '$IsObject(pBundle) {
            Do chyby.%Push("Dokument není objekt")
            Quit
        }
        If pBundle.resourceType '= "Bundle" Do chyby.%Push("resourceType != Bundle")
        If pBundle.type '= "document" Do chyby.%Push("Bundle.type != document")
        If '$IsObject(pBundle.identifier) Do chyby.%Push("Bundle.identifier chybí")
        If pBundle.timestamp = "" Do chyby.%Push("Bundle.timestamp chybí")
        If '$IsObject(pBundle.entry) || (pBundle.entry.%Size() = 0) {
            Do chyby.%Push("Bundle.entry je prázdné")
            Quit
        }

        Set comp = "", patient = "", maDR = 0
        Kill zdroje
        Set it = pBundle.entry.%GetIterator()
        While it.%GetNext(.i, .e) {
            If e.fullUrl = "" Do chyby.%Push("Bundle.entry bez fullUrl")
            Set r = e.resource
            If '$IsObject(r) Continue
            If e.fullUrl '= "" Set zdroje(e.fullUrl) = r
            If (r.resourceType = "Composition"), '$IsObject(comp) Set comp = r
            If (r.resourceType = "Patient"), '$IsObject(patient) Set patient = r
            If r.resourceType = "DiagnosticReport" Set maDR = 1
        }
        If '$IsObject(comp) Do chyby.%Push("Chybí Composition")
        If '$IsObject(patient) Do chyby.%Push("Chybí Patient")
        If '$IsObject(comp) Quit

        If comp.status = "" Do chyby.%Push("Composition.status chybí")
        If '$IsObject(comp.subject) Do chyby.%Push("Composition.subject chybí")
        If '$IsObject(comp.author) Do chyby.%Push("Composition.author chybí")
        If comp.date = "" Do chyby.%Push("Composition.date chybí")
        If comp.title = "" Do chyby.%Push("Composition.title chybí")
        If '$IsObject(comp.section) || (comp.section.%Size() = 0) {
            Do chyby.%Push("Composition.section chybí")
        }

        // Kategorie: z parametru, jinak dle kódu dokumentu
        Set kat = pKategorie
        If kat = "" Set kat = ..DetekujKategorii(comp)
        Set meta = ..Metadata(kat)
        If meta.%Size() = 0 {
            Do varovani.%Push("Kategorii dokumentu nelze určit – kontrola dle IG přeskočena")
            Quit
        }

        If '..MaKod(comp.type, meta.typKod) {
            Do chyby.%Push("Composition.type nemá kód " _ meta.typKod _ " dle profilu " _ meta.compositionProfile)
        }
        If '..MaProfil(comp, meta.compositionProfile) {
            Do varovani.%Push("Composition.meta.profile nedeklaruje " _ meta.compositionProfile)
        }
        // language a confidentiality jsou v aktuálních IG 0..1 – jen výhrada
        If meta.language, comp.language = "" Do varovani.%Push("Composition.language chybí (IG 0..1, doporučeno)")
        If meta.identifier, '$IsObject(comp.identifier) Do chyby.%Push("Composition.identifier chybí (IG 1..1)")
        If meta.confidentiality, comp.confidentiality = "" Do varovani.%Push("Composition.confidentiality chybí (IG 0..1, doporučeno)")
        Set kody = ..Kategorie(kat), itk = kody.%GetIterator()
        While itk.%GetNext(.ik, .kodKat) {
            If '..MaKategorii(comp, kodKat.system, kodKat.code) {
                Do chyby.%Push("Composition.category nemá povinný kód " _ kodKat.code _ " (" _ kodKat.system _ ")")
            }
        }
        If meta.encounter, '$IsObject(comp.encounter) Do chyby.%Push("Composition.encounter chybí (IG 1..1)")
        If meta.diagnosticReport, 'maDR Do chyby.%Push("Chybí DiagnosticReport v Bundle (IG 1..*)")
        If meta.presentedForm, '..MaPresentedForm(comp) {
            Do chyby.%Push("Chybí extension presentedForm (vizuální podoba PDF/A)")
        }

        // Povinné sekce dle IG
        Set povinne = ..PovinneSekce(kat), itp = povinne.%GetIterator()
        While itp.%GetNext(.j, .def) {
            Set maSekci = ..MaSekci(comp, def.kod)
            If 'maSekci, $IsObject(def.alternativy) {
                Set ita = def.alternativy.%GetIterator()
                While ita.%GetNext(.ia, .alt) {
                    If ..MaSekci(comp, alt) Set maSekci = 1
                }
            }
            If 'maSekci {
                Do chyby.%Push("Chybí povinná sekce " _ def.nazev _ " (LOINC " _ def.kod _ ")")
            }
        }

        // Sekce, které aktuální verze IG nepřipouští
        Set zrusene = ..ZruseneSekce(kat), itz = zrusene.%GetIterator()
        While itz.%GetNext(.iz, .zr) {
            If '..MaSekci(comp, zr.kod) Continue
            Set zprava = "Sekce " _ zr.nazev _ " (LOINC " _ zr.kod _ "): " _ zr.duvod
            If zr.chyba {
                Do chyby.%Push(zprava)
            }
            Else {
                Do varovani.%Push(zprava)
            }
        }

        // cz-ems 0.1.0: invariant mission-time-required
        If meta.casoveBody, (comp.status = "final") || (comp.status = "amended"), $IsObject(comp.section) {
            Set its = comp.section.%GetIterator()
            While its.%GetNext(.is, .sekce) {
                If '$IsObject(sekce) || '..MaKod(sekce.code, ..#EMSTIMELINE) Continue
                Kill maBod
                If $IsObject(sekce.entry) {
                    Set ite = sekce.entry.%GetIterator()
                    While ite.%GetNext(.ie, .odkaz) {
                        If '$IsObject(odkaz) || (odkaz.reference = "") Continue
                        Set obs = $Get(zdroje(odkaz.reference))
                        If '$IsObject(obs) || (obs.resourceType '= "Observation") || (obs.valueDateTime = "") Continue
                        Set kodBodu = ..KodCasovehoBodu(obs)
                        If kodBodu '= "" Set maBod(kodBodu) = 1
                    }
                }
                Set chybi = ""
                For ib = 1:1:$Length(..#EMSCASYPOVINNE, ",") {
                    Set bod = $Piece(..#EMSCASYPOVINNE, ",", ib)
                    If '$Data(maBod(bod)) Set chybi = chybi _ $Select(chybi = "": "", 1: ", ") _ bod _ " " _ ..NazevCasovehoBodu(bod)
                }
                If chybi '= "" {
                    Do chyby.%Push("Sekce časové osy výjezdu (LOINC 67667-6) neodkazuje Observation s časem pro povinné body: " _ chybi _ " (invariant mission-time-required, cz-ems 0.1.0)")
                }
            }
        }

        // RID pacienta dle cz-core
        If $IsObject(patient), '..MaRid(patient) {
            Do chyby.%Push("Patient.identifier neobsahuje RID se system " _ ..#RIDSYSTEM)
        }
    }
    Catch ex {
        Do chyby.%Push("Chyba validace: " _ ex.DisplayString())
    }
    Quit {"valid": ($Select(chyby.%Size() = 0: 1, 1: 0)), "chyby": (chyby), "varovani": (varovani)}
}

/// Určí kategorii dokumentu podle LOINC kódu v Composition.type.
/// Vrací prázdný řetězec, pokud kód neodpovídá žádné kategorii.
ClassMethod DetekujKategorii(pComp As %DynamicObject) As %String
{
    Set kategorie = $ListBuild("pacientsky-souhrn", "propousteci-zprava",
        "obrazove-vysetreni", "vyjezd-zzs", "laboratorni-vysetreni")
    Set nalezena = ""
    For i = 1:1:$ListLength(kategorie) {
        Set kat = $List(kategorie, i)
        Set meta = ..Metadata(kat)
        If ..MaKod(pComp.type, meta.typKod) {
            Set nalezena = kat
            Quit
        }
    }
    Quit nalezena
}

/// Ověří, že CodeableConcept obsahuje daný LOINC kód.
ClassMethod MaKod(pCodeable As %DynamicObject, pKod As %String) As %Boolean
{
    If '$IsObject(pCodeable) || '$IsObject(pCodeable.coding) Quit 0
    Set nalezeno = 0, it = pCodeable.coding.%GetIterator()
    While it.%GetNext(.i, .c) {
        If $IsObject(c), c.code = pKod {
            Set nalezeno = 1
            Quit
        }
    }
    Quit nalezeno
}

/// Ověří, že Composition deklaruje daný profil v meta.profile.
ClassMethod MaProfil(pComp As %DynamicObject, pProfil As %String) As %Boolean
{
    If '$IsObject(pComp.meta) || '$IsObject(pComp.meta.profile) Quit 0
    Set nalezeno = 0, it = pComp.meta.profile.%GetIterator()
    While it.%GetNext(.i, .profil) {
        If profil = pProfil Set nalezeno = 1
    }
    Quit nalezeno
}

/// Ověří, že Composition.category obsahuje kód z daného systému.
ClassMethod MaKategorii(pComp As %DynamicObject, pSystem As %String, pKod As %String) As %Boolean
{
    If '$IsObject(pComp.category) Quit 0
    Set nalezeno = 0, it = pComp.category.%GetIterator()
    While it.%GetNext(.i, .kategorie) {
        If '$IsObject(kategorie) || '$IsObject(kategorie.coding) Continue
        Set itc = kategorie.coding.%GetIterator()
        While itc.%GetNext(.j, .c) {
            If $IsObject(c), c.system = pSystem, c.code = pKod Set nalezeno = 1
        }
    }
    Quit nalezeno
}

/// Vrátí kód časového bodu výjezdu z Observation.code, nese-li právě
/// jeden kód číselníku ems-mission-time-point-cs; jinak prázdný řetězec.
ClassMethod KodCasovehoBodu(pObservation As %DynamicObject) As %String
{
    If '$IsObject(pObservation.code) || '$IsObject(pObservation.code.coding) Quit ""
    Set pocet = 0, kod = "", it = pObservation.code.coding.%GetIterator()
    While it.%GetNext(.i, .c) {
        If $IsObject(c), c.system = ..#EMSCASOVYBOD {
            Set pocet = pocet + 1, kod = c.code
        }
    }
    Quit $Select(pocet = 1: kod, 1: "")
}

/// Ověří přítomnost sekce s daným LOINC kódem.
ClassMethod MaSekci(pComp As %DynamicObject, pKod As %String) As %Boolean
{
    If '$IsObject(pComp.section) Quit 0
    Set nalezeno = 0, it = pComp.section.%GetIterator()
    While it.%GetNext(.i, .s) {
        If $IsObject(s), ..MaKod(s.code, pKod) Set nalezeno = 1 Quit
    }
    Quit nalezeno
}

/// Ověří přítomnost extension presentedForm s daty nebo url.
ClassMethod MaPresentedForm(pComp As %DynamicObject) As %Boolean
{
    If '$IsObject(pComp.extension) Quit 0
    Set nalezeno = 0, it = pComp.extension.%GetIterator()
    While it.%GetNext(.i, .e) {
        If $IsObject(e), e.url = ..#PRESENTEDFORM, $IsObject(e.valueAttachment) {
            If (e.valueAttachment.data '= "") || (e.valueAttachment.url '= "") Set nalezeno = 1 Quit
        }
    }
    Quit nalezeno
}

/// Ověří, že pacient má identifikátor RID dle cz-core.
ClassMethod MaRid(pPatient As %DynamicObject) As %Boolean
{
    If '$IsObject(pPatient.identifier) Quit 0
    Set nalezeno = 0, it = pPatient.identifier.%GetIterator()
    While it.%GetNext(.i, .id) {
        If $IsObject(id), id.system = ..#RIDSYSTEM, id.value '= "" Set nalezeno = 1 Quit
    }
    Quit nalezeno
}

/// Sestaví zásilku Dočasného úložiště s dokumentem eZD (base64 + SHA-256).
/// pIcoAdresat MUSÍ být jiné PZS než tvůrce (DÚ validace E01001).
ClassMethod ZasilkaProDU(pKategorie As %String, pBundle As %DynamicObject, pRid As %String, pAutorKrzpId As %String, pIco As %String, pIcoAdresat As %String, pNazev As %String = "") As %DynamicObject
{
    Set meta = ..Metadata(pKategorie)
    Set json = pBundle.%ToJSON()
    Set b64 = ..Base64(json)
    Set hashHex = $ZConvert(##class(%xsd.hexBinary).LogicalToXSD($System.Encryption.SHAHash(256, json)), "l")
    Set nazev = $Select(pNazev '= "": pNazev, 1: meta.nazev)
    Set zasilka = {
        "nazev": (nazev),
        "popis": ("eZD dle " _ meta.ig),
        "typ": {"ciselnikKod": "medical-document-type", "kod": (meta.duTypKod), "verze": "1.0.0"},
        "klasifikace": {"ciselnikKod": "document-category", "kod": "11503-0", "verze": ""},
        "autor": (pAutorKrzpId),
        "zdravotnickyPracovnik": (pAutorKrzpId),
        "poskytovatel": (pIco),
        "pacient": (pRid),
        "ispzs": "IRIS SEZ.EZD.Builder",
        "adresat": (pIcoAdresat),
        "adresatTyp": {"ciselnikKod": "typ-adresata", "kod": "PZS", "verze": "1.0.0"},
        "dostupnost": true,
        "dokument": [{
            "nazev": (nazev),
            "jazyk": {"ciselnikKod": "languages", "kod": "cs", "verze": "5.0.0"},
            "typ": {"ciselnikKod": "medical-document-type", "kod": (meta.duTypKod), "verze": "1.0.0"},
            "klasifikace": {"ciselnikKod": "document-category", "kod": "11503-0", "verze": ""},
            "autor": (pAutorKrzpId),
            "poskytovatel": (pIco),
            "pacient": (pRid),
            "dostupnost": true,
            "duvernost": {"ciselnikKod": "v3-Confidentiality", "kod": "N", "verze": "2.0.0"},
            "format": {"ciselnikKod": "format-code", "kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient", "verze": "1.0.0"},
            "mime": {"ciselnikKod": "media-type", "kod": "application/fhir+json", "verze": "1.0.0"},
            "hash": (hashHex),
            "velikost": ($Length(json)),
            "soubor": {"soubor": (b64)}
        }]
    }
    Quit zasilka
}

/// Sestaví dokument a rovnou ho uloží do Dočasného úložiště.
/// Vyžaduje nakonfigurovaný SEZ.API.Config (mTLS + JWT).
ClassMethod SestavAOdesli(pConfig As SEZ.API.Config, pKategorie As %String, pRid As %String, pAutorKrzpId As %String, pIco As %String, pIcoAdresat As %String, pSekce As %DynamicObject = "", Output pResponse As %DynamicObject) As %Status
{
    Set sc = $$$OK
    Try {
        Set bundle = ..Sestav(pKategorie, pRid, pAutorKrzpId, pIco, .pSekce, .sc)
        $$$ThrowOnError(sc)
        Set validace = ..Validuj(bundle, pKategorie)
        If 'validace.valid {
            Set sc = $$$ERROR($$$GeneralError, "Dokument nesplňuje L1 kritéria: " _ validace.chyby.%ToJSON())
            Quit
        }
        Set zasilka = ..ZasilkaProDU(pKategorie, bundle, pRid, pAutorKrzpId, pIco, pIcoAdresat)
        Set du = ##class(SEZ.API.DocasneUloziste).%New(pConfig)
        Set sc = du.UlozZasilku(zasilka, .pResponse)
    }
    Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Aktuální čas v ISO 8601 (UTC) pro FHIR instant.
ClassMethod CasISO() As %String
{
    Quit $ZDateTime($ZTimeStamp, 3, 7, 0) _ "+00:00"
}

/// Nové UUID v4 (malými písmeny).
ClassMethod NoveUUID() As %String
{
    Quit $ZConvert($System.Util.CreateGUID(), "l")
}

/// Base64 kódování bez zalomení řádků.
ClassMethod Base64(pText As %String) As %String
{
    Quit $Translate($System.Encryption.Base64Encode(pText, 1), $Char(13, 10))
}

/// Escapuje znaky, které nesmí být v XHTML narativu.
ClassMethod XmlEscape(pText As %String) As %String
{
    Set text = $Replace(pText, "&", "&amp;")
    Set text = $Replace(text, "<", "&lt;")
    Set text = $Replace(text, ">", "&gt;")
    Quit text
}

/// Minimální validní PDF v Base64 (placeholder za vizuální podobu PDF/A).
ClassMethod MinimalniPdfBase64() As %String
{
    Set pdf = "%PDF-1.4" _ $Char(10)
        _ "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj" _ $Char(10)
        _ "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj" _ $Char(10)
        _ "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Resources<<>>>>endobj" _ $Char(10)
        _ "trailer<</Size 4/Root 1 0 R>>" _ $Char(10) _ "%%EOF" _ $Char(10)
    Quit ..Base64(pdf)
}

}
