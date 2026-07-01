/// Sdílený zdravotní záznam API v1.0.6
/// Base URL: /sdilenyZdravotniZaznam
Class SEZ.API.SZZ Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/sdilenyZdravotniZaznam";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

// ==========================================================================
// EMERGENTNÍ ZÁZNAM
// ==========================================================================

/// Načte kompletní emergentní záznam pacienta
Method NactiEmergentniZaznam(pRid As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/emergentniZaznam/"_pRid, , .pResponse)
}

/// Stáhne emergentní záznam jako PDF
Method EmergentniZaznamPDF(pRid As %String, Output pStream As %Stream.TmpBinary) As %Status
{
    Set ct = ""
    Quit ..Client.GetBinary(..#BASEPATH_"/api/v1/emergentniZaznam/"_pRid_"/pdf", .pStream, .ct)
}

// ==========================================================================
// ALERGIE
// ==========================================================================

/// Načte alergie pacienta
Method NactiAlergie(pRid As %String, pJenPlatne As %Boolean = 1, Output pResponse As %DynamicAbstractObject) As %Status
{
    Set params("jenPlatne") = $Select(pJenPlatne:"true", 1:"false")
    Quit ..Client.Get(..#BASEPATH_"/api/v1/emergentniZaznam/alergie/"_pRid, .params, .pResponse)
}

/// Vytvoří záznam alergie
Method VytvorAlergii(pRid As %String, pAlergie As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pAlergie.rid = pRid
    Set pAlergie.ico = ..Config.ICO
    Set pAlergie.krzpId = ..Config.KrzpId
    Quit ..Client.Post(..#BASEPATH_"/api/v1/emergentniZaznam/alergie", pAlergie, .pResponse)
}

/// Upraví alergii
Method UpravAlergii(pId As %String, pAlergie As %DynamicObject, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Put(..#BASEPATH_"/api/v1/emergentniZaznam/alergie/"_pId, pAlergie, .pResponse, pETag)
}

/// Zneplatní/zpochybní/obnoví alergii
Method ZmenStavAlergie(pId As %String, pAkce As %String, pDuvod As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..ZmenStav("alergie", pId, pAkce, pDuvod, pETag, .pResponse)
}

// ==========================================================================
// KREVNÍ SKUPINA
// ==========================================================================

/// Načte krevní skupinu pacienta
Method NactiKrevniSkupinu(pRid As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/emergentniZaznam/krevniSkupina/"_pRid, , .pResponse)
}

/// Vytvoří záznam krevní skupiny
Method VytvorKrevniSkupinu(pRid As %String, pKod As %String, pVerze As %String = "1.0", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "rid": (pRid),
        "ico": (..Config.ICO),
        "krzpId": (..Config.KrzpId),
        "krevniSkupina": {"kod": (pKod), "verze": (pVerze)}
    }
    Quit ..Client.Post(..#BASEPATH_"/api/v1/emergentniZaznam/krevniSkupina", body, .pResponse)
}

/// Změní stav krevní skupiny
Method ZmenStavKrevniSkupiny(pId As %String, pAkce As %String, pDuvod As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..ZmenStav("krevniSkupina", pId, pAkce, pDuvod, pETag, .pResponse)
}

// ==========================================================================
// NEŽÁDOUCÍ PŘÍHODY / REAKCE / ÚČINKY / UDÁLOSTI
// ==========================================================================

/// Načte nežádoucí záznamy daného typu
/// pTyp: nezadouciPrihody | nezadouciReakce | nezadouciUcinky | nezadouciUdalosti
Method NactiNezadouci(pTyp As %String, pRid As %String, pJenPlatne As %Boolean = 1, Output pResponse As %DynamicAbstractObject) As %Status
{
    Set params("jenPlatne") = $Select(pJenPlatne:"true", 1:"false")
    Quit ..Client.Get(..#BASEPATH_"/api/v1/emergentniZaznam/"_pTyp_"/"_pRid, .params, .pResponse)
}

/// Vytvoří nežádoucí záznam
Method VytvorNezadouci(pTyp As %String, pRid As %String, pData As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pData.rid = pRid
    Set pData.ico = ..Config.ICO
    Set pData.krzpId = ..Config.KrzpId
    Quit ..Client.Post(..#BASEPATH_"/api/v1/emergentniZaznam/"_pTyp, pData, .pResponse)
}

/// Upraví nežádoucí záznam
Method UpravNezadouci(pTyp As %String, pId As %String, pData As %DynamicObject, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Put(..#BASEPATH_"/api/v1/emergentniZaznam/"_pTyp_"/"_pId, pData, .pResponse, pETag)
}

/// Změní stav nežádoucího záznamu
Method ZmenStavNezadouci(pTyp As %String, pId As %String, pAkce As %String, pDuvod As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..ZmenStav(pTyp, pId, pAkce, pDuvod, pETag, .pResponse)
}

// ==========================================================================
// LÉČIVÉ PŘÍPRAVKY
// ==========================================================================

/// Načte léčivé přípravky pacienta
Method NactiLeciva(pRid As %String, Output pResponse As %DynamicAbstractObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/lecivePripravky/"_pRid, , .pResponse)
}

/// Vytvoří záznam léčivého přípravku
Method VytvorLecivo(pRid As %String, pData As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pData.rid = pRid
    Set pData.ico = ..Config.ICO
    Set pData.krzpId = ..Config.KrzpId
    Quit ..Client.Post(..#BASEPATH_"/api/v1/lecivePripravky", pData, .pResponse)
}

/// Upraví léčivý přípravek
Method UpravLecivo(pId As %String, pData As %DynamicObject, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Put(..#BASEPATH_"/api/v1/lecivePripravky/"_pId, pData, .pResponse, pETag)
}

/// Změní stav léčivého přípravku
Method ZmenStavLeciva(pId As %String, pAkce As %String, pDuvod As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "duvod": (pDuvod),
        "ico": (..Config.ICO),
        "krzpId": (..Config.KrzpId)
    }
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/lecivePripravky/"_pId_"/"_pAkce, body, .params, .pResponse, pETag)
}

// ==========================================================================
// ZDRAVOTNÍ ZÁZNAMY
// ==========================================================================

/// Vyhledá zdravotní záznamy
Method VyhledatZdravotniZaznamy(pRid As %String, pJenPlatne As %Boolean = 1, pPage As %Integer = 0, pSize As %Integer = 25, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "rid": (pRid),
        "jenPlatne": (pJenPlatne),
        "page": (pPage),
        "size": (pSize)
    }
    Quit ..Client.Post(..#BASEPATH_"/api/v1/zdravotniZaznamy/vyhledat", body, .pResponse)
}

/// Vytvoří zdravotní záznam
Method VytvorZdravotniZaznam(pRid As %String, pData As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pData.rid = pRid
    Set pData.ico = ..Config.ICO
    Set pData.krzpId = ..Config.KrzpId
    Quit ..Client.Post(..#BASEPATH_"/api/v1/zdravotniZaznamy", pData, .pResponse)
}

/// Upraví zdravotní záznam
Method UpravZdravotniZaznam(pId As %String, pData As %DynamicObject, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Put(..#BASEPATH_"/api/v1/zdravotniZaznamy/"_pId, pData, .pResponse, pETag)
}

/// Změní stav zdravotního záznamu
Method ZmenStavZdravotnihoZaznamu(pId As %String, pAkce As %String, pDuvod As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "duvod": (pDuvod),
        "ico": (..Config.ICO),
        "krzpId": (..Config.KrzpId)
    }
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/zdravotniZaznamy/"_pId_"/"_pAkce, body, .params, .pResponse, pETag)
}

// ==========================================================================
// ČÍSELNÍKY
// ==========================================================================

/// Seznam číselníků SZZ
Method SeznamCiselniku(Output pResponse As %DynamicAbstractObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/ciselniky", , .pResponse)
}

/// Položky číselníku
Method PolozkyCiselniku(pKod As %String, pDotaz As %String = "", pLimit As %Integer = 100, Output pResponse As %DynamicAbstractObject) As %Status
{
    Set params("limit") = pLimit
    If pDotaz '= "" Set params("dotaz") = pDotaz
    Quit ..Client.Get(..#BASEPATH_"/api/v1/ciselniky/"_pKod_"/polozky", .params, .pResponse)
}

// ==========================================================================
// INTERNÍ HELPER
// ==========================================================================

/// Univerzální změna stavu záznamu (zneplatnit/zpochybnit/obnovit)
Method ZmenStav(pEntita As %String, pId As %String, pAkce As %String, pDuvod As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status [ Private ]
{
    Set body = {
        "duvod": (pDuvod),
        "ico": (..Config.ICO),
        "krzpId": (..Config.KrzpId)
    }
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/emergentniZaznam/"_pEntita_"/"_pId_"/"_pAkce, body, .params, .pResponse, pETag)
}

}
