/// Notifikace CSSN API v1.0.0
/// Base URL: /notifikace
Class SEZ.API.Notifikace Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Parameter BASEPATH = "/notifikace";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Ping – kontrola dostupnosti
Method Ping(Output pResponse As %String) As %Status
{
    Set sc = ..Client.Get(..#BASEPATH_"/api/v1/notifikace/ping", , .resp)
    Set pResponse = ..Client.LastRawResponse
    Quit sc
}

/// Odešle notifikaci
Method Odeslat(pNotifikace As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/notifikace/odeslat", pNotifikace, .pResponse)
}

/// Vyhledá notifikace
Method Vyhledat(pIdPrijemce As %String, pOdData As %String = "", pLimit As %Integer = 50, Output pResponse As %DynamicObject) As %Status
{
    Set params("idPrijemce") = pIdPrijemce
    If pOdData '= "" Set params("odData") = pOdData
    Set params("limit") = pLimit
    Quit ..Client.Get(..#BASEPATH_"/api/v1/notifikace/vyhledat", .params, .pResponse)
}

/// Katalog kanálů
Method KatalogKanalu(pPage As %Integer = 0, pSize As %Integer = 50, Output pResponse As %DynamicObject) As %Status
{
    Set params("page") = pPage
    Set params("size") = pSize
    Quit ..Client.Get(..#BASEPATH_"/api/v1/kanaly/katalog", .params, .pResponse)
}

/// Katalog šablon
Method KatalogSablon(pPage As %Integer = 0, pSize As %Integer = 50, Output pResponse As %DynamicObject) As %Status
{
    Set params("page") = pPage
    Set params("size") = pSize
    Quit ..Client.Get(..#BASEPATH_"/api/v1/sablony/katalog", .params, .pResponse)
}

/// Katalog zdrojů
Method KatalogZdroju(pPage As %Integer = 0, pSize As %Integer = 50, Output pResponse As %DynamicObject) As %Status
{
    Set params("page") = pPage
    Set params("size") = pSize
    Quit ..Client.Get(..#BASEPATH_"/api/v1/zdroje/katalog", .params, .pResponse)
}

/// Pomocná metoda: sestaví notifikaci
ClassMethod NovaNotifikace(pZdrojovySystem As %String, pTyp As %String, pKanal As %String, pSablona As %String, pPrioritaNormal As %Boolean = 1) As %DynamicObject
{
    Quit {
        "idKorelace": (##class(SEZ.API.Config).NewUUID()),
        "zdrojovySystem": (pZdrojovySystem),
        "typ": (pTyp),
        "kanal": (pKanal),
        "sablona": (pSablona),
        "casovaZnacka": ($ZDATETIME($ZTIMESTAMP, 3, 1)),
        "prijemce": [],
        "doruceni": {
            "priorita": ($Select(pPrioritaNormal:"NORMAL", 1:"URGENT"))
        },
        "dataNotifikace": {
            "hlavicka": "",
            "obsah": "",
            "pushText": "",
            "dataSablony": []
        }
    }
}

}
