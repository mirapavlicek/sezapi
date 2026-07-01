/// Elektronické lékařské posudky API v1.0.6
/// Base URL: /elektronickePosudky
Class SEZ.API.ELP Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/elektronickePosudky";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Vytvoří nový posudek řidičského oprávnění
Method VytvorPosudek(pPosudek As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni", pPosudek, .pResponse)
}

/// Vyhledá posudky
Method VyhledatPosudky(pKriteria As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni/vyhledat", pKriteria, .pResponse)
}

/// Načte detail posudku
Method DetailPosudku(pId As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni/"_pId, , .pResponse)
}

/// Zneplatní posudek (vyžaduje ETag v hlavičce If-Match)
Method ZneplatnitPosudek(pId As %String, pETag As %String, Output pResponse As %DynamicObject) As %Status
{
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni/"_pId_"/zneplatnit", "", .params, .pResponse, pETag)
}

/// Stáhne PDF posudku
Method StahniPDF(pId As %String, Output pStream As %Stream.TmpBinary) As %Status
{
    Set ct = ""
    Quit ..Client.GetBinary(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni/"_pId_"/pdf", .pStream, .ct)
}

/// Stáhne testovací PDF
Method StahniTestPDF(pId As %String, Output pStream As %Stream.TmpBinary) As %Status
{
    Set ct = ""
    Quit ..Client.GetBinary(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni/"_pId_"/pdftest", .pStream, .ct)
}

/// Historie změn posudku
Method HistoriePosudku(pId As %String, Output pResponse As %DynamicAbstractObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/posudky/ridicskeOpravneni/"_pId_"/historie", , .pResponse)
}

/// Seznam číselníků
Method SeznamCiselniku(Output pResponse As %DynamicAbstractObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/ciselniky", , .pResponse)
}

/// Položky číselníku
Method PolozkyCiselniku(pKod As %String, Output pResponse As %DynamicAbstractObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/ciselniky/"_pKod_"/polozky", , .pResponse)
}

/// Pomocná metoda: vytvoří nový posudek řidičského oprávnění
ClassMethod NovyPosudek(pRid As %String, pKrzpId As %String, pICO As %String, pICP As %String) As %DynamicObject
{
    Quit {
        "rid": (pRid),
        "krzpId": (pKrzpId),
        "ico": (pICO),
        "icp": (pICP),
        "druhPosudku": {"kod": "", "verze": "1.0"},
        "druhProhlidky": {"kod": "", "verze": "1.0"},
        "odbornostLekare": {"kod": "", "verze": "1.0"},
        "stavPosudku": {"kod": "PLATNY", "verze": "1.0"},
        "typAkce": {"kod": "NOVY", "verze": "1.0"},
        "vysledek": {"kod": "", "verze": "1.0"},
        "skupinaZadatelRidic": {"kod": "", "verze": "1.0"},
        "datumVysetreni": "",
        "datumVystaveni": "",
        "skupinyRidicskehoOpravneni": [],
        "odbornaVysetreni": [],
        "harmonizovaneKody": [],
        "narodniKody": [],
        "prilohy": []
    }
}

}
