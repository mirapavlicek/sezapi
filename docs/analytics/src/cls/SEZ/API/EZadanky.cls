/// E-žádanky SEZ API – v2.0.0 (aktuální od 1. 10. 2026) + v1 (deprecated)
/// Base URL: /eZadanky
///
/// Revize NCEZ zdrojů 13. 10. 2026 (Manuál EZ pro PZS → API eŽádanky):
///  - v2: datová věta = systémová hlavička (hlavicka) + FHIR Bundle typu "document"
///    (fhirBundle) dle HL7 CZ IG (img-order / k-order); strukturované DTO zmizely
///  - v2: zdrojové cesty /api/v2/zadanka[/{id}/<operace>], id žádanky v cestě
///  - v2: procesní operace předávají verzeZaznamu v hlavičce If-Match (409 při
///    nesouladu); uložení vrací 201 + hlavička (id, kod, verzeZaznamu)
///  - v2: UpravZadanku neexistuje (náhradou storno + nová žádanka), vyřízení
///    vyžaduje zásilku s >= 1 dokumentem, stránkování od 0, User-Agent povinný
///  - metody V2* používají ETag parametr HttpClient.Patch pro If-Match
Class SEZ.API.EZadanky Extends %RegisteredObject
{

/// Kódy typů žádanky (číselník referralorder-types, TermX 13. 10. 2026)
Parameter TYPZ = "721964003";

Parameter TYPK = "57133-1";

Parameter TYPFT = "57154-7";

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/eZadanky";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}


// ---------------------------------------------------------------------------
// API v2.0.0 – hlavicka + FHIR Bundle, If-Match
// ---------------------------------------------------------------------------

/// Sestaví systémovou hlavičku (HlavickaVstup). pTyp: "Z" | "K" | "FT" nebo kód
/// z číselníku referralorder-types. pZP (podepsal) se bez zadání rovná pAutor.
/// Brána kontroluje konzistenci s FHIR Bundle (ověřeno na T2 13. 10. 2026):
/// pPoskytovatel = IČO Organization v Composition.custodian (E00024), tato
/// Organization musí mít identifier IČP (sid/icp, E01002), pAdresat = IČO právě
/// jedné provádějící Organization ze ServiceRequest.performer (E00024) a
/// adresát se nesmí rovnat poskytovateli (E01001). Dále: pPacient = RID Patient
/// v Composition.subject, pAutor = KRZP Practitioner z Composition.author (přímo
/// nebo přes PractitionerRole), reference se párují jen přesnou shodou
/// s entry.fullUrl (používejte urn:uuid:), ServiceRequest.priority jen
/// routine | stat a operace příjemce (prijmout, vratitDoObehu, neproveditelnost,
/// vyridit) smí volat jen jiný PZS než žadatel. Platí shodně pro všechny typy:
/// Z (img-order), K a FT (společný HL7 CZ Order IG hl7.fhir.cz.order 1.0.0).
ClassMethod V2Hlavicka(pTyp As %String, pPacient As %String, pPoskytovatel As %String, pAutor As %String, pZP As %String = "", pAdresat As %String = "", pDodatecniPrijemci As %DynamicArray = "", pNadrizenaZadankaId As %String = "") As %DynamicObject
{
    Set typ = $ZConvert(pTyp, "U")
    If typ = "Z" Set typ = ..#TYPZ
    If typ = "K" Set typ = ..#TYPK
    If typ = "FT" Set typ = ..#TYPFT
    Set hl = {
        "typZadanky": {"kod": (typ)},
        "zadatel": {
            "poskytovatel": (pPoskytovatel),
            "autor": (pAutor),
            "zdravotnickyPracovnik": ($Select(pZP '= "": pZP, 1: pAutor))
        },
        "pacient": (pPacient)
    }
    If pAdresat '= "" Set hl.adresat = pAdresat
    If $IsObject(pDodatecniPrijemci), pDodatecniPrijemci.%Size() > 0 Set hl.dodatecnyPrijemce = pDodatecniPrijemci
    If pNadrizenaZadankaId '= "" Set hl.nadrizenaZadankaId = pNadrizenaZadankaId
    Quit hl
}

/// POST /api/v2/zadanka – uloží žádanku (HTTP 201). pFhirBundle: FHIR Bundle
/// typu "document" (první entry Composition). Odpověď: {"hlavicka": {id, kod, verzeZaznamu, ...}}
Method V2UlozZadanku(pHlavicka As %DynamicObject, pFhirBundle As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set body = {"hlavicka": (pHlavicka), "fhirBundle": (pFhirBundle)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/zadanka", body, .pResponse)
}

/// POST /api/v2/zadanka/vyhledat – stránky číslované od 0.
/// pFiltr: pacient, autor, prijemce, poskytovatel, datumOd, datumDo, kod, id, stav,
/// typZadanky, priorita, metoda[], uzavrena (viz VyhledejZadankuRequest)
Method V2VyhledejZadanku(pFiltr As %DynamicObject = "", pPage As %Integer = 0, pSize As %Integer = 25, Output pResponse As %DynamicObject) As %Status
{
    Set body = $Select($IsObject(pFiltr): pFiltr, 1: {})
    Set body.strankovani = {"page": (pPage), "size": (pSize)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/zadanka/vyhledat", body, .pResponse)
}

/// POST /api/v2/zadanka/vyhledatAktivni – žádanky ve stavu Nová dle id / rid / kodZadanky
Method V2VyhledejAktivniZadanku(pId As %String = "", pRid As %String = "", pKodZadanky As %String = "", pPage As %Integer = 0, pSize As %Integer = 25, Output pResponse As %DynamicObject) As %Status
{
    Set body = {"strankovani": {"page": (pPage), "size": (pSize)}}
    If pId '= "" Set body.id = pId
    If pRid '= "" Set body.rid = pRid
    If pKodZadanky '= "" Set body.kodZadanky = pKodZadanky
    Quit ..Client.Post(..#BASEPATH_"/api/v2/zadanka/vyhledatAktivni", body, .pResponse)
}

/// POST /api/v2/zadanka/{id}/nacist – hlavička + FHIR Bundle. Kód žádanky nebo
/// číslo dokladu zpřístupní Bundle i ne-žadateli / ne-příjemci.
Method V2NactiZadanku(pId As %String, pKodZadanky As %String = "", pCisloDokladu As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {}
    If pKodZadanky '= "" Set body.kodZadanky = pKodZadanky
    If pCisloDokladu '= "" Set body.cisloDokladu = pCisloDokladu
    Quit ..Client.Post(..#BASEPATH_"/api/v2/zadanka/"_pId_"/nacist", body, .pResponse)
}

/// verzeZaznamu z poslední odpovědi (hlavicka.verzeZaznamu) pro další If-Match
ClassMethod V2VerzeZaznamu(pResponse As %DynamicObject) As %String
{
    If '$IsObject(pResponse) Quit ""
    If $IsObject(pResponse.hlavicka) Quit pResponse.hlavicka.verzeZaznamu
    Quit pResponse.verzeZaznamu
}

/// PATCH /api/v2/zadanka/{id}/prijmout (If-Match = pVerzeZaznamu)
Method V2PrijmiZadanku(pId As %String, pVerzeZaznamu As %String, pKodZadanky As %String = "", pCisloDokladu As %String = "", pDatumPlan As %String = "", Output pResponse As %DynamicObject) As %Status
{
    If pVerzeZaznamu = "" Quit $$$ERROR($$$GeneralError, "v2: verzeZaznamu (If-Match) je povinná")
    Set body = {}
    If pKodZadanky '= "" Set body.kodZadanky = pKodZadanky
    If pCisloDokladu '= "" Set body.cisloDokladu = pCisloDokladu
    If pDatumPlan '= "" Set body.datumPlanovanehoVysetreni = pDatumPlan
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v2/zadanka/"_pId_"/prijmout", body, .params, .pResponse, pVerzeZaznamu)
}

/// PATCH /api/v2/zadanka/{id}/vyridit – pVysledek: zásilka s >= 1 dokumentem (povinná
/// u všech způsobů vyřízení). pZpusobVyrizeni: kód z číselníku zpusob-vyrizeni.
Method V2VyridZadanku(pId As %String, pVerzeZaznamu As %String, pZpusobVyrizeni As %String, pVysledek As %DynamicObject, pDatumRealizace As %String, pUpresneni As %String = "", pZaslatPacientovi As %Boolean = 0, pZaslatPraktikovi As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    If pVerzeZaznamu = "" Quit $$$ERROR($$$GeneralError, "v2: verzeZaznamu (If-Match) je povinná")
    If '$IsObject(pVysledek) || '$IsObject(pVysledek.dokument) || (pVysledek.dokument.%Size() = 0) {
        Quit $$$ERROR($$$GeneralError, "v2: vysledek musí být zásilka s nejméně jedním dokumentem")
    }
    Set body = {
        "zpusobVyrizeniZadanky": {"kod": (pZpusobVyrizeni)},
        "vysledek": (pVysledek),
        "datumSkutecneRealizaceVysetreni": (pDatumRealizace)
    }
    // JSON boolean (ne 0/1 ani řetězec) – vyžaduje schéma VyridZadankuV2Request
    Do body.%Set("zaslatVysledekPacientovi", ''pZaslatPacientovi, "boolean")
    Do body.%Set("zaslatVysledekPraktikovi", ''pZaslatPraktikovi, "boolean")
    If pUpresneni '= "" Set body.zpusobVyrizeniUpresneni = $Extract(pUpresneni, 1, 250)
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v2/zadanka/"_pId_"/vyridit", body, .params, .pResponse, pVerzeZaznamu)
}

/// PATCH /api/v2/zadanka/{id}/stornovat – pDuvod: kód z číselníku duvod-storna
Method V2StornujZadanku(pId As %String, pVerzeZaznamu As %String, pDuvod As %String, pUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    If pVerzeZaznamu = "" Quit $$$ERROR($$$GeneralError, "v2: verzeZaznamu (If-Match) je povinná")
    Set body = {"duvodStornaZadanky": {"kod": (pDuvod)}}
    If pUpresneni '= "" Set body.duvodStornaUpresneni = $Extract(pUpresneni, 1, 250)
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v2/zadanka/"_pId_"/stornovat", body, .params, .pResponse, pVerzeZaznamu)
}

/// PATCH /api/v2/zadanka/{id}/zaznacitNeproveditelnost – pDuvod: kód z duvod-odmitnuti
Method V2ZaznacNeproveditelnost(pId As %String, pVerzeZaznamu As %String, pDuvod As %String, pUpresneni As %String = "", pKodZadanky As %String = "", Output pResponse As %DynamicObject) As %Status
{
    If pVerzeZaznamu = "" Quit $$$ERROR($$$GeneralError, "v2: verzeZaznamu (If-Match) je povinná")
    Set body = {"duvodNeproveditelnostiZadanky": {"kod": (pDuvod)}}
    If pUpresneni '= "" Set body.duvodNeproveditelnostiUpresneni = $Extract(pUpresneni, 1, 250)
    If pKodZadanky '= "" Set body.kodZadanky = pKodZadanky
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v2/zadanka/"_pId_"/zaznacitNeproveditelnost", body, .params, .pResponse, pVerzeZaznamu)
}

/// PATCH /api/v2/zadanka/{id}/vratitDoObehu – pDuvod: kód z číselníku duvod-vraceni
Method V2VratDoObehu(pId As %String, pVerzeZaznamu As %String, pDuvod As %String, pUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    If pVerzeZaznamu = "" Quit $$$ERROR($$$GeneralError, "v2: verzeZaznamu (If-Match) je povinná")
    Set body = {"duvodVraceniZadanky": {"kod": (pDuvod)}}
    If pUpresneni '= "" Set body.duvodVraceniUpresneni = $Extract(pUpresneni, 1, 250)
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v2/zadanka/"_pId_"/vratitDoObehu", body, .params, .pResponse, pVerzeZaznamu)
}

/// Ve v2 neexistuje – vždy vrátí chybu (náhradou je V2StornujZadanku + V2UlozZadanku)
Method V2UpravZadanku(pId As %String, pVerzeZaznamu As %String, pUpravy As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pResponse = ""
    Quit $$$ERROR($$$GeneralError, "UpravZadanku ve verzi 2 neexistuje – vystavenou eŽádanku nelze upravit; stornujte ji a vystavte novou")
}

// ---------------------------------------------------------------------------
// API v1 (deprecated od 1. 10. 2026) – ponecháno pro přechodné období
// ---------------------------------------------------------------------------

/// Získá token pro eŽádanky
Method DejToken(Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/DejToken", , .pResponse)
}

/// Uloží novou žádanku
/// pRequest: {"zadanka": {...}, "zadankaZ": {...}} nebo "zadankaFt"/"zadankaK"
Method UlozZadanku(pRequest As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/eZadanka/UlozZadanku", pRequest, .pResponse)
}

/// Vyhledá žádanky
Method VyhledejZadanku(pDatumOd As %String, pDatumDo As %String, pPacient As %String = "", pPage As %Integer = 1, pSize As %Integer = 25, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "datumOd": (pDatumOd),
        "datumDo": (pDatumDo),
        "strankovani": {"page": (pPage), "size": (pSize)}
    }
    If pPacient '= "" Set body.pacient = pPacient
    Quit ..Client.Post(..#BASEPATH_"/api/v1/eZadanka/VyhledejZadanku", body, .pResponse)
}

/// Vyhledá aktivní žádanky
Method VyhledejAktivniZadanku(pKriteria As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/eZadanka/VyhledejAktivniZadanku", pKriteria, .pResponse)
}

/// Načte žádanku podle ID
Method NactiZadanku(pId As %String, pKodZadanky As %String = "", pKodVzorku As %String = "", pCisloDokladu As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set params = ""
    If pKodZadanky '= "" Set params("KodZadanky") = pKodZadanky
    If pKodVzorku '= "" Set params("KodVzorku") = pKodVzorku
    If pCisloDokladu '= "" Set params("CisloDokladu") = pCisloDokladu
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/NactiZadanku/"_pId, .params, .pResponse)
}

/// Přijme žádanku
Method PrijmiZadanku(pId As %String, pVerzeRadku As %String, pKodZadanky As %String = "", pDatumPlan As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku)
    }
    If pKodZadanky '= "" Set body.kodZadanky = pKodZadanky
    If pDatumPlan '= "" Set body.datumPlanovanehoVysetreni = pDatumPlan
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/PrijmiZadanku", body, .params, .pResponse)
}

/// Vyřídí žádanku
Method VyridZadanku(pId As %String, pVerzeRadku As %String, pZpusobVyrizeni As %DynamicObject, pVysledek As %DynamicObject = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "zpusobVyrizeniZadanky": (pZpusobVyrizeni)
    }
    If $IsObject(pVysledek) Set body.vysledek = pVysledek
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/VyridZadanku", body, .params, .pResponse)
}

/// Stornuje žádanku
Method StornujZadanku(pId As %String, pVerzeRadku As %String, pDuvodStorna As %DynamicObject, pDuvodUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "duvodStornaZadanky": (pDuvodStorna)
    }
    If pDuvodUpresneni '= "" Set body.duvodStornaUpresneni = pDuvodUpresneni
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/StornujZadanku", body, .params, .pResponse)
}

/// Zaznamená neproveditelnost žádanky
Method ZaznacNeproveditelnost(pId As %String, pVerzeRadku As %String, pDuvod As %DynamicObject, pDuvodUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "duvodNeproveditelnostiZadanky": (pDuvod)
    }
    If pDuvodUpresneni '= "" Set body.duvodNeproveditelnostiUpresneni = pDuvodUpresneni
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/ZaznacNeproveditelnostZadanky", body, .params, .pResponse)
}

/// Vrátí žádanku do oběhu
Method VratDoObehu(pId As %String, pVerzeRadku As %String, pDuvod As %DynamicObject, pDuvodUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "duvodVraceniZadanky": (pDuvod)
    }
    If pDuvodUpresneni '= "" Set body.duvodVraceniUpresneni = pDuvodUpresneni
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/VratZadankuDoObehu", body, .params, .pResponse)
}

/// Stáhne vizualizaci žádanky (HTML/PDF)
Method DejVizualZadanky(pId As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/DejVizualZadanky/"_pId, , .pResponse)
}

/// Stáhne přílohy žádanky
Method DejPrilohyZadanky(pId As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/DejPrilohyZadanky/"_pId, , .pResponse)
}

/// Upraví žádanku
Method UpravZadanku(pId As %String, pVerzeRadku As %String, pUpravy As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pUpravy.id = pId
    Set pUpravy.verzeRadku = pVerzeRadku
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/UpravZadanku", pUpravy, .params, .pResponse)
}

/// Pomocná metoda: vytvoří laboratorní žádanku
ClassMethod NovaLaboratorniZadanka(pAutor As %String, pPacient As %String, pPoskytovatel As %String, pZP As %String, pIspzs As %String, pIcp As %String, pAdresat As %String) As %DynamicObject
{
    Quit {
        "zadanka": {
            "stav": {"kod": "Nova"},
            "urgentnost": {"kod": "Rutinni"},
            "samoplatce": false,
            "prilozenVzorek": false,
            "omezeniMobility": false,
            "pacientImplantat": false,
            "icpZadatele": (pIcp),
            "zasilka": {
                "nazev": "Laboratorní žádanka",
                "autor": (pAutor),
                "pacient": (pPacient),
                "poskytovatel": (pPoskytovatel),
                "zdravotnickyPracovnik": (pZP),
                "ispzs": (pIspzs),
                "typ": {"kod": "Zadanka"},
                "klasifikace": {"kod": "Laboratorni"}
            },
            "vzorekData": [],
            "metodaData": []
        },
        "zadankaZ": {
            "autorId": (pAutor),
            "zadatelId": (pPoskytovatel),
            "pacient": (pPacient),
            "adresatId": (pAdresat),
            "typZadanky": "LABORATORNI",
            "icp": (pIcp),
            "pozadovanaVysetreni": []
        }
    }
}

}
