/// Kmenový registr pacientů – KRP PZS API v2.0.0
/// Base URL: /krp
Class SEZ.API.KRP Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/krp";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

// ==========================================================================
// VYHLEDÁVÁNÍ PACIENTŮ
// ==========================================================================

/// Vyhledání pacienta podle RID
Method HledatPodleRID(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/rid", body, .pResponse)
}

/// Univerzální vyhledání pacienta
Method HledatUni(pData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pData
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/uni", body, .pResponse)
}

/// Vyhledání podle jména, příjmení a rodného čísla
Method HledatJmenoPrijmeniRC(pJmeno As %String, pPrijmeni As %String, pRC As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"jmeno": (pJmeno), "prijmeni": (pPrijmeni), "rodneCislo": (pRC)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/jmeno_prijmeni_rc", body, .pResponse)
}

/// Vyhledání podle jména, příjmení a data narození
Method HledatJmenoPrijmeniDN(pJmeno As %String, pPrijmeni As %String, pDatumNarozeni As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"jmeno": (pJmeno), "prijmeni": (pPrijmeni), "datumNarozeni": (pDatumNarozeni)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/jmeno_prijmeni_datum_narozeni", body, .pResponse)
}

/// Vyhledání podle dokladu
Method HledatPodleDokladu(pCisloDokladu As %String, pTypDokladu As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"doklad": {"cislo": (pCisloDokladu), "typDokladu": (pTypDokladu)}}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/doklady", body, .pResponse)
}

/// Vyhledání cizince podle čísla pojištěnce
Method HledatCizinecCP(pCisloPojistence As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"cisloPojistence": (pCisloPojistence)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/cizinec_cp", body, .pResponse)
}

/// Vyhledání podle NIA BSI
Method HledatNiaBsi(pNiaBsi As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"niaBsi": (pNiaBsi)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/niabsi", body, .pResponse)
}

/// Historie pojištění pacienta
Method HledatHistoriePojisteni(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/historie_pojisteni", body, .pResponse)
}

/// Historie registrujících lékařů
Method HledatHistorieRegistrujicichLekaru(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/historie_registrujicich_lekaru", body, .pResponse)
}

/// Mapování RID
Method HledatMapovaniRID(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/hledat/mapovani_rid", body, .pResponse)
}

// ==========================================================================
// SPRÁVA PACIENTŮ
// ==========================================================================

/// Založení nového pacienta
Method ZalozitPacienta(pPacientData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pPacientData
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/zalozit/pacient", body, .pResponse)
}

/// Změna údajů pacienta
Method ZmenitPacienta(pRid As %String, pZmeny As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set zmenyData = pZmeny.%FromJSON(pZmeny.%ToJSON())
    Set zmenyData.rid = pRid
    Set body.zadostData = zmenyData
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/zmenit/pacient", body, .pResponse)
}

/// Generování dočasného RID
Method GenerujDocasnyRID(pPacientData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pPacientData
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/generovat/docasny_rid", body, .pResponse)
}

/// Přiřazení dočasného RID
Method PriraditDocasnyRID(pDocasnyRid As %String, pSkutecnyRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"docasnyRid": (pDocasnyRid), "skutecnyRid": (pSkutecnyRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/priradit/docasny_rid", body, .pResponse)
}

/// Reklamace údajů
Method ReklamujUdaj(pReklamaceData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pReklamaceData
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/reklamuj/udaj", body, .pResponse)
}

/// Sloučení pacientů
Method SlouceniPacientu(pNavrhSlouceni As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pNavrhSlouceni
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/slouceni/zadost", body, .pResponse)
}

/// Rozdělení pacienta
Method RozdeleniPacienta(pNavrhRozdeleni As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pNavrhRozdeleni
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/rozdeleni/zadost", body, .pResponse)
}

/// Žádost o zrušení záznamu
Method ZruseniZadost(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pacient/zruseni/zadost", body, .pResponse)
}

// ==========================================================================
// NOTIFIKACE
// ==========================================================================

/// Založení odběru notifikací o změnách pacienta
Method ZalozitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/notifikace/zalozit/odber", pOdber, .pResponse)
}

/// Zrušení odběru notifikací
Method ZrusitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Delete(..#BASEPATH_"/api/v2/notifikace/zrusit/odber", pOdber, .pResponse)
}

/// Vyhledání odběrů notifikací
Method VyhledatOdberyNotifikaci(pKriteria As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/notifikace/vyhledat/odber", pKriteria, .pResponse)
}

// ==========================================================================
// ČÍSELNÍKY
// ==========================================================================

/// Vyhledání v číselníku
Method Ciselnik(pZadostId As %String, pTyp As %String, pKriteria As %DynamicObject = "", Output pResponse As %DynamicObject) As %Status
{
    If '$IsObject(pKriteria) {
        Set pKriteria = {"zadostInfo": {"datum": ($ZDATETIME($ZTIMESTAMP,3,1)), "ucel": "CISELNIK", "zadostId": (pZadostId)}}
    }
    Quit ..Client.Post(..#BASEPATH_"/api/v1/ciselnik/"_pZadostId_"/"_pTyp, pKriteria, .pResponse)
}

// ==========================================================================
// POMOCNÉ METODY
// ==========================================================================

/// Sestaví základní obálku požadavku KRP.
/// Datum musí být ve formátu YYYY-MM-DD (bez času), jinak KRP vrací 400.
Method BuildRequest(pUcel As %String = "LECBA") As %DynamicObject [ Private ]
{
    Set body = {}
    Set body.zadostInfo = {
        "datum": ($ZDATE(+$HOROLOG, 3)),
        "ucel": (pUcel),
        "zadostId": (##class(SEZ.API.Config).NewUUID())
    }
    Quit body
}

}
