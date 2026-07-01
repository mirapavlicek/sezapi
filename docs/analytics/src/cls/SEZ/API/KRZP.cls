/// Kmenový registr zdravotnických pracovníků – KRZP PZS API v2.0.0
/// Base URL: /krzp
Class SEZ.API.KRZP Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/krzp";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Vyhledání pracovníka podle KRZP ID
Method HledatPodleKrzpId(pKrzpId As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.krzpid = pKrzpId
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pracovnik/hledat/krzpid", body, .pResponse)
}

/// Vyhledání podle jména, příjmení a data narození
Method HledatJmenoDatumNarozeni(pJmeno As %String, pPrijmeni As %String, pDatumNarozeni As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.jmeno = pJmeno
    Set body.prijmeni = pPrijmeni
    Set body.datumNarozeni = pDatumNarozeni
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pracovnik/hledat/jmenoPrijmeniDatumNarozeni", body, .pResponse)
}

/// Vyhledání pro personalistiku
Method HledatProPersonalistiku(pKriteria As %DynamicObject, pUcel As %String = "PERSONALISTIKA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set iter = pKriteria.%GetIterator()
    While iter.%GetNext(.key, .val) { Do body.%Set(key, val) }
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pracovnik/hledat/personalistika", body, .pResponse)
}

/// Vyhledání podle zaměstnavatele
Method HledatPodleZamestnavatele(pICO As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.ico = pICO
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pracovnik/hledat/zamestnavatel", body, .pResponse)
}

/// Reklamace údajů ZP
Method ReklamujUdaj(pReklamace As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/pracovnik/reklamuj/udaj", pReklamace, .pResponse)
}

/// Založení odběru notifikací
Method ZalozitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/notifikace/zalozit", pOdber, .pResponse)
}

/// Zrušení odběru
Method ZrusitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/notifikace/zrusit", pOdber, .pResponse)
}

/// Stav odběru notifikací
Method StavOdberuNotifikaci(pKriteria As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v2/notifikace/stav", pKriteria, .pResponse)
}

/// Vyhledání v číselníku (certifikovany_kurz, komory, obor, specializace, ...)
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
