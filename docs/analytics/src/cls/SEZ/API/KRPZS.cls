/// Kmenový registr poskytovatelů zdravotních služeb – KRPZS PZS API v2.0.0
/// Base URL: /krpzs
Class SEZ.API.KRPZS Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/krpzs";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Vyhledání poskytovatele podle IČO
Method HledatPodleICO(pICO As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.ico = pICO
    Quit ..Client.Post(..#BASEPATH_"/api/v2/Poskytovatel/hledat/ico", body, .pResponse)
}

/// Vyhledání poskytovatele podle názvu
Method HledatPodleNazvu(pNazev As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.nazev = pNazev
    Quit ..Client.Post(..#BASEPATH_"/api/v2/Poskytovatel/hledat/nazev", body, .pResponse)
}

/// Vyhledání poskytovatele podle místa poskytování
Method HledatPodleMista(pMisto As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.misto = pMisto
    Quit ..Client.Post(..#BASEPATH_"/api/v2/Poskytovatel/hledat/misto", body, .pResponse)
}

/// Reklamace údajů PZS
Method ReklamujUdaj(pReklamace As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/Poskytovatel/reklamuj/udaj", pReklamace, .pResponse)
}

/// Nastavení URL pro notifikace PZS
Method NastavitURLNotifikace(pUrl As %String, Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest("NOTIFIKACE")
    Set body.url = pUrl
    Quit ..Client.Post(..#BASEPATH_"/api/v2/Poskytovatel/nastavit/urlpronotifikace", body, .pResponse)
}

/// Založení odběru notifikací
Method ZalozitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/notifikace/zalozit/odber", pOdber, .pResponse)
}

/// Zrušení odběru notifikací
Method ZrusitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Delete(..#BASEPATH_"/api/v2/notifikace/zrusit/odber", pOdber, .pResponse)
}

/// Vyhledání v číselníku (druh_pece, kategorie_pristrojove_techniky, spravni_organ, typ_rozhodnuti, ...)
Method Ciselnik(pTyp As %String, pKriteria As %DynamicObject = "", Output pResponse As %DynamicObject) As %Status
{
    If '$IsObject(pKriteria) {
        Set pKriteria = {"zadostInfo": {"datum": ($ZDATETIME($ZTIMESTAMP,3,1)), "ucel": "CISELNIK", "zadostId": (##class(SEZ.API.Config).NewUUID())}}
    }
    Quit ..Client.Post(..#BASEPATH_"/api/v2/ciselnik/"_pTyp, pKriteria, .pResponse)
}

Method BuildRequest(pUcel As %String = "LECBA") As %DynamicObject [ Private ]
{
    Quit {
        "zadostInfo": {
            "datum": ($ZDATETIME($ZTIMESTAMP, 3, 1)),
            "ucel": (pUcel),
            "zadostId": (##class(SEZ.API.Config).NewUUID())
        }
    }
}

}
