/// Registr oprávnění API v1.0.0
/// Base URL: /registrOpravneni
Class SEZ.API.RegistrOpravneni Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Parameter BASEPATH = "/registrOpravneni";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Ověří oprávnění osoby k přístupu ke službě
/// pRoleOpravnujici / pRoleOpravnena: Interni | Pacient | PoskytovatelZdravotnickychSluzeb | ZdravotniPracovnik | PravnickaOsoba | Zastupce | FyzickaOsoba
Method Over(pIdSluzbyEZ As %Integer, pIdTypuDokumentace As %Integer, pRoleOpravnujici As %String, pHodnotaOpravnujici As %String, pRoleOpravnena As %String, pHodnotaOpravnena As %String, Output pOpravnen As %Boolean) As %Status
{
    Set pOpravnen = 0
    Set params("IdSluzbyEZ") = pIdSluzbyEZ
    Set params("IdTypuDokumentace") = pIdTypuDokumentace
    Set params("OpravnujiciOsoba.Role") = pRoleOpravnujici
    Set params("OpravnujiciOsoba.Hodnota") = pHodnotaOpravnujici
    Set params("OpravnenaOsoba.Role") = pRoleOpravnena
    Set params("OpravnenaOsoba.Hodnota") = pHodnotaOpravnena
    Set sc = ..Client.Get(..#BASEPATH_"/api/v1/Opravneni/Over", .params, .resp)
    If $$$ISOK(sc) {
        Set raw = ..Client.LastRawResponse
        Set pOpravnen = ($ZCONVERT(raw, "l") = "true")
    }
    Quit sc
}

}
