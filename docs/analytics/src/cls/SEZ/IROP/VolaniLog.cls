/// Debug log volání SEZ API z IROP/NPO testovacích scénářů.
/// Pro každý krok testu ukládá CO SE POSÍLÁ (metoda, URL, query, tělo)
/// a NÁVRATOVÉ HODNOTY (HTTP status, tělo odpovědi) vč. trvání.
///
/// Odpovídá požadavku Metodiky testování EHR fáze I na dokumentaci
/// průběhu testu (logy volání a odpovědí testovaného systému).
///
/// Dotazy: SELECT * FROM SEZ_IROP.VolaniLog WHERE Scenar = 'TS-TECH-4'
Class SEZ.IROP.VolaniLog Extends %Persistent
{

/// ID testovacího scénáře (např. TS-TECH-1, TS-OBS-2)
Property Scenar As %String(MAXLEN = 32) [ Required ];

/// Název kroku scénáře
Property Krok As %String(MAXLEN = 250) [ Required ];

/// HTTP metoda volání (GET/POST/PUT/PATCH)
Property Metoda As %String(MAXLEN = 10);

/// Cesta/URL volané služby (bez hostu brány)
Property Url As %String(MAXLEN = 2000);

/// Query parametry volání (JSON)
Property QueryParametry As %String(MAXLEN = 4000);

/// Tělo požadavku (JSON) – co se posílá
Property RequestBody As %String(MAXLEN = "");

/// HTTP status odpovědi
Property HttpStatus As %Integer;

/// Tělo odpovědi (JSON/raw) – návratová hodnota pro debug
Property ResponseBody As %String(MAXLEN = "");

/// Trvání volání v milisekundách
Property TrvaniMs As %Integer;

/// Úspěch kroku (HTTP 2xx/3xx a bez chyby)
Property Uspech As %Boolean [ InitialExpression = 0 ];

/// Chybový text (%Status / výjimka), pokud volání selhalo
Property Chyba As %String(MAXLEN = 2000);

/// Čas záznamu (UTC)
Property Vytvoreno As %TimeStamp [ InitialExpression = {$ZDateTime($ZTimestamp, 3, 1, 3)} ];

Index ScenarIdx On Scenar;

Index VytvorenoIdx On Vytvoreno;

/// Zapíše jeden záznam volání. Chyby ukládání se vrací jako %Status –
/// selhání logu nesmí shodit běžící test, volající je může jen vypsat.
ClassMethod Zapis(pScenar As %String, pKrok As %String, pMetoda As %String, pUrl As %String, pQuery As %String = "", pRequestBody As %String = "", pHttpStatus As %Integer = 0, pResponseBody As %String = "", pTrvaniMs As %Integer = 0, pUspech As %Boolean = 0, pChyba As %String = "") As %Status
{
    Set sc = $$$OK
    Try {
        Set log = ..%New()
        Set log.Scenar = pScenar
        Set log.Krok = pKrok
        Set log.Metoda = pMetoda
        Set log.Url = pUrl
        Set log.QueryParametry = pQuery
        Set log.RequestBody = pRequestBody
        Set log.HttpStatus = pHttpStatus
        Set log.ResponseBody = pResponseBody
        Set log.TrvaniMs = pTrvaniMs
        Set log.Uspech = pUspech
        Set log.Chyba = pChyba
        Set sc = log.%Save()
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Vypíše na terminál záznamy volání daného scénáře (poslední běh nahoře).
/// pMaxBody omezuje délku vypisovaných těl (0 = celá).
ClassMethod Vypis(pScenar As %String = "", pMaxBody As %Integer = 500) As %Status
{
    Set sc = $$$OK
    Try {
        Set sql = "SELECT ID, Scenar, Krok, Metoda, Url, QueryParametry, "
                _ "RequestBody, HttpStatus, ResponseBody, TrvaniMs, Uspech, Chyba, Vytvoreno "
                _ "FROM SEZ_IROP.VolaniLog"
        If pScenar '= "" {
            Set sql = sql _ " WHERE Scenar = ?"
        }
        Set sql = sql _ " ORDER BY ID DESC"
        Set stmt = ##class(%SQL.Statement).%New()
        $$$ThrowOnError(stmt.%Prepare(sql))
        If pScenar '= "" {
            Set rs = stmt.%Execute(pScenar)
        } Else {
            Set rs = stmt.%Execute()
        }
        While rs.%Next() {
            Write !, "[", rs.%Get("Vytvoreno"), "] ", rs.%Get("Scenar"), " – ", rs.%Get("Krok")
            Write !, "  ", $Select(rs.%Get("Uspech"): "PASS", 1: "FAIL"),
                " · HTTP ", rs.%Get("HttpStatus"), " · ", rs.%Get("TrvaniMs"), " ms"
            Write !, "  → ", rs.%Get("Metoda"), " ", rs.%Get("Url")
            If rs.%Get("QueryParametry") '= "" {
                Write !, "    query: ", ..Zkrat(rs.%Get("QueryParametry"), pMaxBody)
            }
            If rs.%Get("RequestBody") '= "" {
                Write !, "    body:  ", ..Zkrat(rs.%Get("RequestBody"), pMaxBody)
            }
            Write !, "  ← ", ..Zkrat(rs.%Get("ResponseBody"), pMaxBody)
            If rs.%Get("Chyba") '= "" {
                Write !, "  ! ", rs.%Get("Chyba")
            }
            Write !
        }
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Zkrátí text na pMax znaků (0 = bez zkracování).
ClassMethod Zkrat(pText As %String, pMax As %Integer = 500) As %String
{
    If (pMax <= 0) || ($Length(pText) <= pMax) Quit pText
    Quit $Extract(pText, 1, pMax) _ "… (" _ $Length(pText) _ " znaků)"
}

/// Smaže záznamy (všechny, nebo jen daného scénáře).
ClassMethod Smazat(pScenar As %String = "") As %Status
{
    Set sc = $$$OK
    Try {
        If pScenar = "" {
            &sql(DELETE FROM SEZ_IROP.VolaniLog)
        } Else {
            &sql(DELETE FROM SEZ_IROP.VolaniLog WHERE Scenar = :pScenar)
        }
        If (SQLCODE '= 0) && (SQLCODE '= 100) {
            Set sc = $$$ERROR($$$GeneralError, "DELETE selhal, SQLCODE=" _ SQLCODE)
        }
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

}
