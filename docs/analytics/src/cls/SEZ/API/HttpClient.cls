/// HTTP klient pro komunikaci se SEZ API
/// Zajišťuje mTLS, JWT autentizaci a společné hlavičky
Class SEZ.API.HttpClient Extends %RegisteredObject
{

Property Config As SEZ.API.Config [ Required ];

/// Poslední HTTP status kód
Property LastStatusCode As %Integer;

/// Poslední tělo odpovědi jako JSON objekt
Property LastResponse As %DynamicObject;

/// Poslední surová odpověď
Property LastRawResponse As %String(MAXLEN = "");

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Quit $$$OK
}

/// Provede HTTP GET požadavek
Method Get(pPath As %String, ByRef pQueryParams, Output pResponse As %DynamicAbstractObject) As %Status
{
    Quit ..Execute("GET", pPath, .pQueryParams, "", .pResponse)
}

/// Provede HTTP POST požadavek
Method Post(pPath As %String, pBody As %DynamicAbstractObject = "", Output pResponse As %DynamicAbstractObject) As %Status
{
    Set queryParams = ""
    Quit ..Execute("POST", pPath, .queryParams, pBody, .pResponse)
}

/// Provede HTTP PUT požadavek
Method Put(pPath As %String, pBody As %DynamicAbstractObject = "", Output pResponse As %DynamicAbstractObject, pETag As %String = "") As %Status
{
    Set queryParams = ""
    Quit ..Execute("PUT", pPath, .queryParams, pBody, .pResponse, pETag)
}

/// Provede HTTP PATCH požadavek
Method Patch(pPath As %String, pBody As %DynamicAbstractObject = "", ByRef pQueryParams, Output pResponse As %DynamicAbstractObject, pETag As %String = "") As %Status
{
    Quit ..Execute("PATCH", pPath, .pQueryParams, pBody, .pResponse, pETag)
}

/// Provede HTTP DELETE požadavek
Method Delete(pPath As %String, pBody As %DynamicAbstractObject = "", Output pResponse As %DynamicAbstractObject) As %Status
{
    Set queryParams = ""
    Quit ..Execute("DELETE", pPath, .queryParams, pBody, .pResponse)
}

/// Hlavní metoda pro vykonání HTTP požadavku (s automatickým retry při 401)
Method Execute(pMethod As %String, pPath As %String, ByRef pQueryParams, pBody As %DynamicAbstractObject = "", Output pResponse As %DynamicAbstractObject, pETag As %String = "") As %Status
{
    Set sc = ..ExecuteInternal(pMethod, pPath, .pQueryParams, pBody, .pResponse, pETag, 0)

    If (..LastStatusCode = 401) {
        Set ..Config.Token = ""
        Set sc = ..ExecuteInternal(pMethod, pPath, .pQueryParams, pBody, .pResponse, pETag, 1)
    }

    Quit sc
}

/// Interní provedení HTTP požadavku
Method ExecuteInternal(pMethod As %String, pPath As %String, ByRef pQueryParams, pBody As %DynamicAbstractObject = "", Output pResponse As %DynamicAbstractObject, pETag As %String = "", pRetry As %Integer = 0) As %Status [ Private ]
{
    Set sc = $$$OK
    Set pResponse = ""
    Set ..LastStatusCode = 0
    Set ..LastResponse = ""
    Set ..LastRawResponse = ""

    Try {
        Set token = ""
        Set sc = ..Config.GetToken(.token)
        If $$$ISERR(sc) Quit

        Set req = ##class(%Net.HttpRequest).%New()
        Set req.Server = ..Config.#GATEWAY
        Set req.Port = ..Config.#PORT
        Set req.Https = 1
        Set req.SSLConfiguration = ..Config.#SSLCONFIG
        Set req.Timeout = ..Config.#TIMEOUT
        Set req.ContentType = "application/json"

        Do req.SetHeader("Authorization", "Bearer "_token)
        Do req.SetHeader("Accept", "application/json")
        Do req.SetHeader("Accept-Language", ..Config.#DEFAULTLANG)
        Do req.SetHeader("User-Agent", ##class(SEZ.API.Config).UserAgent())
        Do req.SetHeader("X-Correlation-Id", ##class(SEZ.API.Config).NewUUID())
        Do req.SetHeader("X-Trace-Id", ##class(SEZ.API.Config).NewUUID())

        If pETag '= "" {
            Do req.SetHeader("If-Match", pETag)
        }

        If $Data(pQueryParams) {
            Set key = ""
            For {
                Set key = $Order(pQueryParams(key))
                Quit:key=""
                Do req.SetParam(key, pQueryParams(key))
            }
        }

        If $IsObject(pBody) {
            Set bodyStr = pBody.%ToJSON()
            Do req.EntityBody.Write(bodyStr)
        }

        If pMethod = "GET" {
            Set sc = req.Get(pPath)
        } ElseIf pMethod = "POST" {
            Set sc = req.Post(pPath)
        } ElseIf pMethod = "PUT" {
            Set sc = req.Put(pPath)
        } ElseIf pMethod = "PATCH" {
            Set sc = req.Patch(pPath)
        } ElseIf pMethod = "DELETE" {
            Set sc = req.Delete(pPath)
        }
        If $$$ISERR(sc) Quit

        Set ..LastStatusCode = req.HttpResponse.StatusCode
        Set ..LastRawResponse = req.HttpResponse.Data.Read($$$MaxStringLength)

        If ..LastRawResponse '= "" {
            Try {
                Set pResponse = {}.%FromJSON(..LastRawResponse)
                Set ..LastResponse = pResponse
            } Catch {
                Set pResponse = ""
            }
        }

        If (..LastStatusCode >= 400) {
            Set errMsg = "HTTP "_..LastStatusCode
            If pRetry Set errMsg = errMsg_" (po retry)"
            If $IsObject(pResponse) {
                If pResponse.%IsDefined("Errors") {
                    Set errArr = pResponse.%Get("Errors")
                    If $IsObject(errArr) && (errArr.%Size() > 0) {
                        Set errMsg = errMsg_": "_errArr.%Get(0).%Get("Message")_" ["_errArr.%Get(0).%Get("Error")_"]"
                    }
                }
                ElseIf pResponse.%Get("detail") '= "" Set errMsg = errMsg_": "_pResponse.%Get("detail")
                ElseIf pResponse.%Get("error") '= "" {
                    If $IsObject(pResponse.%Get("error")) {
                        Set errMsg = errMsg_": "_pResponse.%Get("error").%Get("message")
                    } Else {
                        Set errMsg = errMsg_": "_pResponse.%Get("error")
                    }
                }
                ElseIf pResponse.%IsDefined("errors") {
                    Set errArr = pResponse.%Get("errors")
                    If $IsObject(errArr) && (errArr.%Size() > 0) {
                        Set errMsg = errMsg_": "_errArr.%Get(0).%Get("message")_" ["_errArr.%Get(0).%Get("error")_"]"
                    }
                }
            }
            Set sc = $$$ERROR($$$GeneralError, errMsg)
        }

    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Stáhne binární obsah (PDF apod.) s automatickým retry při 401
Method GetBinary(pPath As %String, Output pStream As %Stream.TmpBinary, Output pContentType As %String) As %Status
{
    Set sc = ..GetBinaryInternal(pPath, .pStream, .pContentType)
    If ..LastStatusCode = 401 {
        Set ..Config.Token = ""
        Set sc = ..GetBinaryInternal(pPath, .pStream, .pContentType)
    }
    Quit sc
}

Method GetBinaryInternal(pPath As %String, Output pStream As %Stream.TmpBinary, Output pContentType As %String) As %Status [ Private ]
{
    Set sc = $$$OK
    Set pStream = ##class(%Stream.TmpBinary).%New()
    Set pContentType = ""

    Try {
        Set token = ""
        Set sc = ..Config.GetToken(.token)
        If $$$ISERR(sc) Quit

        Set req = ##class(%Net.HttpRequest).%New()
        Set req.Server = ..Config.#GATEWAY
        Set req.Port = ..Config.#PORT
        Set req.Https = 1
        Set req.SSLConfiguration = ..Config.#SSLCONFIG
        Set req.Timeout = ..Config.#TIMEOUT

        Do req.SetHeader("Authorization", "Bearer "_token)
        Do req.SetHeader("Accept-Language", ..Config.#DEFAULTLANG)
        Do req.SetHeader("User-Agent", ##class(SEZ.API.Config).UserAgent())
        Do req.SetHeader("X-Correlation-Id", ##class(SEZ.API.Config).NewUUID())

        Set sc = req.Get(pPath)
        If $$$ISERR(sc) Quit

        Set ..LastStatusCode = req.HttpResponse.StatusCode
        Set pContentType = req.HttpResponse.GetHeader("Content-Type")

        If ..LastStatusCode '= 200 {
            Set errBody = ""
            Try { Set errBody = req.HttpResponse.Data.Read(2000) } Catch {}
            Set sc = $$$ERROR($$$GeneralError, "HTTP "_..LastStatusCode_$Select(errBody'="":": "_errBody, 1:""))
            Quit
        }

        Do pStream.CopyFrom(req.HttpResponse.Data)

    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

}
