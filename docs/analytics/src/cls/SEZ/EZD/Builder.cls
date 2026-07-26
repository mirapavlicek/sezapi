/// Builder elektronických zdravotních dokumentů (eZD) ve FHIR R4 pro
/// InterSystems IRIS – prioritní kategorie dle standardů MZ ČR
/// (HL7 CZ Implementation Guides).
///
/// Podporované typy zpráv (parametr pKategorie):
///   pacientsky-souhrn      hl7.fhir.cz.ps     LOINC 60591-5
///   propousteci-zprava     hl7.fhir.cz.hdr    LOINC 34105-7
///   obrazove-vysetreni     hl7.fhir.cz.img    LOINC 18748-4
///   vyjezd-zzs             hl7.fhir.cz.ems    LOINC 67796-3
///   laboratorni-vysetreni  hl7.fhir.cz.lab    LOINC 11502-2
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
            "kategorieKod": "",
            "presentedForm": true,
            "encounter": true,
            "language": false,
            "identifier": false,
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
            "kategorieKod": "",
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
            "identifier": false,
            "confidentiality": false,
            "diagnosticReport": false,
            "duTypKod": "67796-3"
        }
    }
    If pKategorie = "laboratorni-vysetreni" {
        Quit {
            "nazev": "Laboratorní zpráva",
            "ig": "hl7.fhir.cz.lab",
            "bundleProfile": "https://hl7.cz/fhir/lab/StructureDefinition/cz-bundle-lab",
            "compositionProfile": "https://hl7.cz/fhir/lab/StructureDefinition/cz-composition-lab-report",
            "typKod": "11502-2",
            "typNazev": "Laboratory report",
            "kategorieKod": "",
            "presentedForm": false,
            "encounter": false,
            "language": true,
            "identifier": false,
            "confidentiality": false,
            "diagnosticReport": true,
            "duTypKod": "11502-2"
        }
    }
    Quit {}
}

/// Vrátí pole povinných sekcí kategorie: [{"slice":..,"kod":..,"nazev":..}]
/// Povinné sekce musí být v dokumentu vždy (i bez obsahu).
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
        Quit [{"slice": "annotations", "kod": "48767-8", "nazev": "Komentář k výsledkům"}]
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
            "sectionAlerts": {"kod": "104605-1", "nazev": "Upozornění"},
            "sectionFunctionalStatus": {"kod": "47420-5", "nazev": "Funkční stav"},
            "sectionPregnancyHx": {"kod": "10162-6", "nazev": "Anamnéza gravidity"},
            "sectionPatientStory": {"kod": "10164-2", "nazev": "Anamnéza dle pacienta"},
            "sectionPlanOfCare": {"kod": "18776-5", "nazev": "Plán péče"},
            "sectionSocialHistory": {"kod": "29762-2", "nazev": "Sociální anamnéza"},
            "sectionVitalSigns": {"kod": "8716-3", "nazev": "Vitální funkce"},
            "sectionTravelHx": {"kod": "10182-4", "nazev": "Cestovní anamnéza"},
            "sectionPatientHx": {"kod": "11329-0", "nazev": "Anamnéza"},
            "sectionPastProblems": {"kod": "11348-0", "nazev": "Dřívější problémy"},
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
            "allergies": {"kod": "48765-2", "nazev": "Alergie a intolerance"},
            "alert": {"kod": "75310-3", "nazev": "Upozornění"},
            "findings": {"kod": "29545-1", "nazev": "Nález na místě"},
            "procedure": {"kod": "29554-3", "nazev": "Provedené výkony"},
            "significantProcedures": {"kod": "10185-7", "nazev": "Významné výkony"},
            "medicalDevices": {"kod": "57080-4", "nazev": "Zdravotnické prostředky"},
            "diagnosticSummary": {"kod": "11450-4", "nazev": "Diagnostický souhrn"},
            "courseOfTreatment": {"kod": "18682-5", "nazev": "Průběh ošetření"},
            "recommendations": {"kod": "18776-5", "nazev": "Doporučení"},
            "payers": {"kod": "48768-6", "nazev": "Plátci"},
            "attachments": {"kod": "34109-9", "nazev": "Přílohy"}
        }
    }
    If pKategorie = "laboratorni-vysetreni" {
        Quit {"attachment": {"kod": "77599-9", "nazev": "Přílohy"}}
    }
    Quit {}
}

/// Sestaví FHIR document Bundle dané kategorie.
/// pSekce: %DynamicObject {slice: "text" | ["text1","text2"]}
/// pPacient: volitelné {"jmeno","prijmeni","datumNarozeni"}
/// pAutorData: volitelné {"titul","jmeno","prijmeni"}
ClassMethod Sestav(pKategorie As %String, pRid As %String, pAutorKrzpId As %String, pIco As %String, pSekce As %DynamicObject = "", Output pSC As %Status, pNazevPZS As %String = "Testovací PZS", pTitulek As %String = "", pPdfBase64 As %String = "", pPacient As %DynamicObject = "", pAutorData As %DynamicObject = "") As %DynamicObject
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
        If meta.kategorieKod '= "" {
            Set comp.category = [{"coding": [{"system": (..#LOINC), "code": (meta.kategorieKod)}]}]
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
            Set text = ..ObsahSekce(pSekce, sekceDef.slice)
            If text = "" Set text = "Informace není k dispozici"
            Do comp.section.%Push(..Sekce(sekceDef.kod, sekceDef.nazev, text))
        }
        Set volitelne = ..VolitelneSekce(pKategorie)
        Set iter2 = volitelne.%GetIterator()
        While iter2.%GetNext(.slice, .def) {
            Set text = ..ObsahSekce(pSekce, slice)
            If text '= "" {
                Do comp.section.%Push(..Sekce(def.kod, def.nazev, text))
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
        Set it = pBundle.entry.%GetIterator()
        While it.%GetNext(.i, .e) {
            If e.fullUrl = "" Do chyby.%Push("Bundle.entry bez fullUrl")
            Set r = e.resource
            If '$IsObject(r) Continue
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
        If meta.language, comp.language = "" Do chyby.%Push("Composition.language chybí (IG 1..1)")
        If meta.identifier, '$IsObject(comp.identifier) Do chyby.%Push("Composition.identifier chybí (IG 1..1)")
        If meta.confidentiality, comp.confidentiality = "" Do chyby.%Push("Composition.confidentiality chybí (IG 1..1)")
        If meta.encounter, '$IsObject(comp.encounter) Do chyby.%Push("Composition.encounter chybí (IG 1..1)")
        If meta.diagnosticReport, 'maDR Do chyby.%Push("Chybí DiagnosticReport v Bundle (IG 1..*)")
        If meta.presentedForm, '..MaPresentedForm(comp) {
            Do chyby.%Push("Chybí extension presentedForm (vizuální podoba PDF/A)")
        }

        // Povinné sekce dle IG
        Set povinne = ..PovinneSekce(kat), itp = povinne.%GetIterator()
        While itp.%GetNext(.j, .def) {
            If '..MaSekci(comp, def.kod) {
                Do chyby.%Push("Chybí povinná sekce " _ def.nazev _ " (LOINC " _ def.kod _ ")")
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
