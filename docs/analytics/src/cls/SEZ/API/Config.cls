/// Konfigurace připojení k SEZ API gateway
/// Podporuje dva režimy autentizace:
///   1) client_secret – ClientSecret neprázdný → client_credentials s client_secret_post (volá JSU přímo)
///   2) private_key_jwt – ClientSecret prázdný → JWT assertion podepsaný privátním klíčem EZCA II
///      certifikátu se posílá PŘÍMO jako Bearer token na API Gateway.
///      Gateway interně provede výměnu za access token vůči JSU.
///      Vyžaduje CertUID (= kid v JWT headeru) = UID certifikátu z EZCA.
Class SEZ.API.Config Extends %RegisteredObject
{

/// Hostname SEZ API gateway
Parameter GATEWAY = "gwy-ext-sec-t2.csez.cz";

/// Port
Parameter PORT = 443;

/// Token endpoint server (interní JSU – použito pouze v režimu client_secret)
Parameter TOKENSERVER = "jsuint-auth-t2.csez.cz";

/// Token endpoint path
Parameter TOKENPATH = "/connect/token";

/// Audience pro client assertion JWT
Parameter TOKENAUDIENCE = "https://jsuint-auth-t2.csez.cz/connect/token";

/// SSL konfigurace v IRIS pro mTLS
Parameter SSLCONFIG = "SEZ_API_T2";

/// Výchozí jazyk
Parameter DEFAULTLANG = "cs";

/// Timeout v sekundách
Parameter TIMEOUT = 30;

/// Platnost JWT assertion v sekundách (dle MZČR doporučení max 60s)
Parameter ASSERTIONVALIDITY = 55;

/// Client ID (formát: "ICO_nazev", např. "25488627_KrajskaZdravotniVerejnyTest")
Property ClientId As %String;

/// Client Secret – pokud prázdný, použije se private_key_jwt s přímou assertion
Property ClientSecret As %String;

/// Cesta k .p12 certifikátu EZCA II (jeden certifikát pro mTLS i JWT signing)
Property P12CertFile As %String;

/// Heslo k .p12 certifikátu
Property P12CertPassword As %String;

/// UID certifikátu z EZCA – použije se jako "kid" v JWT header
/// Povinný pro režim private_key_jwt
Property CertUID As %String;

/// Scope pro OAuth2 (relevantní pouze v režimu client_secret)
Property Scope As %String [ InitialExpression = "openid" ];

/// Aktuální access token / assertion (cachovaný)
Property Token As %String(MAXLEN = 32000);

/// Expirace tokenu / assertion
Property TokenExpiry As %TimeStamp [ Private ];

/// IČO poskytovatele
Property ICO As %String;

/// KRZP ID zdravotnického pracovníka
Property KrzpId As %String;

/// IČP
Property ICP As %String;

Method %OnNew(pClientId As %String = "", pClientSecret As %String = "", pICO As %String = "") As %Status
{
    Set ..ClientId = pClientId
    Set ..ClientSecret = pClientSecret
    Set ..ICO = pICO
    Quit $$$OK
}

/// Vrací platný Bearer token.
/// V režimu private_key_jwt vrací přímo JWT assertion (Gateway provede výměnu za access token).
/// V režimu client_secret vrací access token získaný z JSU.
Method GetToken(Output pToken As %String) As %Status
{
    If ..ClientSecret = "" {
        Quit ..GetDirectAssertion(.pToken)
    }

    If (..Token '= "") && ($SYSTEM.SQL.DATEDIFF("ss", ..TokenExpiry, $ZDATETIME($ZTIMESTAMP, 3, 1)) < -30) {
        Set pToken = ..Token
        Quit $$$OK
    }
    Quit ..RefreshToken(.pToken)
}

/// Sestaví JWT assertion a vrátí ji přímo jako Bearer token.
/// Assertion se cachuje s 10s bufferem před expirací.
Method GetDirectAssertion(Output pToken As %String) As %Status [ Private ]
{
    Set pToken = ""

    If (..Token '= "") && ($SYSTEM.SQL.DATEDIFF("ss", ..TokenExpiry, $ZDATETIME($ZTIMESTAMP, 3, 1)) < -10) {
        Set pToken = ..Token
        Quit $$$OK
    }

    Set assertion = ..BuildClientAssertion()
    If assertion = "" {
        Quit $$$ERROR($$$GeneralError, "Nelze vytvorit JWT assertion – zkontrolujte P12CertFile, P12CertPassword a CertUID")
    }

    Set ..Token = assertion
    Set ..TokenExpiry = $SYSTEM.SQL.DATEADD("ss", ..#ASSERTIONVALIDITY, $ZDATETIME($ZTIMESTAMP, 3, 1))
    Set pToken = assertion
    Quit $$$OK
}

/// Získá nový access token z JSU token endpointu (režim client_secret)
Method RefreshToken(Output pToken As %String) As %Status
{
    Set sc = $$$OK
    Set pToken = ""

    Try {
        Set req = ##class(%Net.HttpRequest).%New()
        Set req.Server = ..#TOKENSERVER
        Set req.Port = 443
        Set req.Https = 1
        Set req.SSLConfiguration = ..#SSLCONFIG
        Set req.ContentType = "application/x-www-form-urlencoded"
        Set req.Timeout = ..#TIMEOUT

        Do req.InsertFormData("grant_type", "client_credentials")
        Do req.InsertFormData("client_id", ..ClientId)
        Do req.InsertFormData("scope", ..Scope)
        Do req.InsertFormData("client_secret", ..ClientSecret)

        Set sc = req.Post(..#TOKENPATH)
        If $$$ISERR(sc) {
            Set sc = $$$ERROR($$$GeneralError, "Token HTTP pozadavek selhal: "_$System.Status.GetErrorText(sc))
            Quit
        }

        Set respBody = req.HttpResponse.Data.Read($$$MaxStringLength)

        If req.HttpResponse.StatusCode '= 200 {
            Set sc = $$$ERROR($$$GeneralError, "Token request selhal: HTTP "_req.HttpResponse.StatusCode_" | "_respBody)
            Quit
        }

        Set json = {}.%FromJSON(respBody)
        Set ..Token = json.%Get("access_token")

        If ..Token = "" {
            Set sc = $$$ERROR($$$GeneralError, "Token response neobsahuje access_token: "_respBody)
            Quit
        }

        Set ..TokenExpiry = $ZDATETIME($ZTIMESTAMP, 3, 1)
        Set expiresIn = json.%Get("expires_in")
        If expiresIn {
            Set ..TokenExpiry = $SYSTEM.SQL.DATEADD("ss", expiresIn, ..TokenExpiry)
        }

        Set pToken = ..Token

    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Sestaví a podepíše JWT assertion pro private_key_jwt autentizaci.
/// Header obsahuje "kid" = CertUID (UID certifikátu z EZCA).
/// Payload: iss, sub = ClientId, aud = JSU token endpoint, jti, iat, exp (55s).
Method BuildClientAssertion() As %String [ Private ]
{
    Set result = ""
    Try {
        Set certFile = ..P12CertFile
        Set certPwd = ..P12CertPassword

        If certFile = "" {
            Try {
                Set ssl = ##class(Security.SSLConfigs).%OpenId(..#SSLCONFIG)
                If $IsObject(ssl) {
                    Set certFile = ssl.PrivateKeyFile
                    Set certPwd = ssl.PrivateKeyPassword
                }
            } Catch {}
        }

        If certFile = "" Quit

        Set epoch = ..GetUnixTimestamp()

        If ..CertUID '= "" {
            Set headerJson = "{""alg"":""RS256"",""typ"":""JWT"",""kid"":"""_..CertUID_"""}"
        } Else {
            Set headerJson = "{""alg"":""RS256"",""typ"":""JWT""}"
        }
        Set payloadJson = "{""iss"":"""_..ClientId_""",""sub"":"""_..ClientId_""",""aud"":"""_..#TOKENAUDIENCE_""",""jti"":"""_..NewUUID()_""",""iat"":"_epoch_",""exp"":"_(epoch + ..#ASSERTIONVALIDITY)_"}"

        Set headerB64 = ..Base64UrlEncode(headerJson)
        Set payloadB64 = ..Base64UrlEncode(payloadJson)
        Set signingInput = headerB64_"."_payloadB64

        Set sigB64 = ..SignWithOpenSSL(signingInput, certFile, certPwd)
        If sigB64 = "" Quit

        Set result = signingInput_"."_sigB64

    } Catch ex {
    }
    Quit result
}

/// Podepíše data privátním klíčem z .p12 souboru pomocí openssl
ClassMethod SignWithOpenSSL(pData As %String, pP12File As %String, pPassword As %String) As %String
{
    Set result = ""
    Try {
        Set tmpDir = $System.Util.GetEnviron("TEMP")
        If tmpDir = "" Set tmpDir = "/tmp"
        Set keyFile = tmpDir_"/_sez_jwt_key_"_$Job_".pem"
        Set dataFile = tmpDir_"/_sez_jwt_data_"_$Job_".bin"
        Set sigFile = tmpDir_"/_sez_jwt_sig_"_$Job_".bin"

        Set extractCmd = "openssl pkcs12 -in """_pP12File_""" -nocerts -nodes -passin pass:"_pPassword
        If $ZF(-1, extractCmd_" -legacy > """_keyFile_""" 2>/dev/null") '= 0 {
            Set void = $ZF(-1, extractCmd_" > """_keyFile_""" 2>/dev/null")
        }

        Set dataStream = ##class(%Stream.FileCharacter).%New()
        Set dataStream.Filename = dataFile
        Do dataStream.Write(pData)
        Do dataStream.%Save()

        Set signCmd = "openssl dgst -sha256 -sign """_keyFile_""" -out """_sigFile_""" """_dataFile_""""
        If $ZF(-1, signCmd) '= 0 Quit

        Set sigStream = ##class(%Stream.FileBinary).%New()
        Set sigStream.Filename = sigFile
        Set sigBytes = sigStream.Read(sigStream.Size)

        Set b64 = $System.Encryption.Base64Encode(sigBytes, 1)
        Set b64 = $Translate(b64, "+/", "-_")
        Set result = $ZStrip(b64, ">", "=")

    } Catch ex {
    }

    Do ##class(%File).Delete(keyFile)
    Do ##class(%File).Delete(dataFile)
    Do ##class(%File).Delete(sigFile)

    Quit result
}

/// Vrátí aktuální Unix timestamp (sekundy od 1970-01-01)
ClassMethod GetUnixTimestamp() As %Integer
{
    Set h = $ZTimestamp
    Set days = $Piece(h, ",", 1) - 47117
    Set secs = $Piece(h, ",", 2)
    Quit (days * 86400) + secs
}

/// Base64url encoding
ClassMethod Base64UrlEncode(pString As %String) As %String
{
    Set b64 = $System.Encryption.Base64Encode(pString, 1)
    Set b64 = $Translate(b64, "+/", "-_")
    Quit $ZStrip(b64, ">", "=")
}

/// Diagnostika: ověří celý autentizační řetězec
Method DiagToken() As %Status
{
    Set sc = $$$OK
    Try {
        Write "=== SEZ API Token Diagnostika ===",!
        Write "Gateway: ",..#GATEWAY,!
        Write "SSL konfigurace: ",..#SSLCONFIG,!
        Write "Client ID: ",..ClientId,!
        Write "Auth rezim: ",$Select(..ClientSecret'="":"client_secret (volani JSU)", 1:"private_key_jwt (prima assertion na GW)"),!

        If ..ClientSecret = "" {
            Write "Cert UID (kid): ",$Select(..CertUID'="":..CertUID, 1:"(nenastaveno!)"),!
            Write "P12 soubor: ",$Select(..P12CertFile'="":..P12CertFile, 1:"(ze SSL konfigurace)"),!
            Write "Assertion platnost: ",..#ASSERTIONVALIDITY,"s",!
            Write "Audience: ",..#TOKENAUDIENCE,!
            Write !

            Set assertion = ..BuildClientAssertion()
            If assertion '= "" {
                Write "Client assertion OK (delka: ",$Length(assertion),")",!

                Set parts = $ListFromString(assertion, ".")
                If $ListLength(parts) >= 2 {
                    Set hdr = $ListGet(parts, 1)
                    Set pad = 4 - ($Length(hdr) # 4) If pad < 4 { For i=1:1:pad { Set hdr = hdr_"=" } }
                    Set hdr = $Translate(hdr, "-_", "+/")
                    Write "Header: ",$System.Encryption.Base64Decode(hdr),!

                    Set p = $ListGet(parts, 2)
                    Set pad = 4 - ($Length(p) # 4) If pad < 4 { For i=1:1:pad { Set p = p_"=" } }
                    Set p = $Translate(p, "-_", "+/")
                    Write "Payload: ",$System.Encryption.Base64Decode(p),!
                }
            } Else {
                Write "!!! CHYBA: Client assertion se nepodarilo vytvorit !!!",!
                Write "    Zkontrolujte:",!
                Write "    - P12CertFile a P12CertPassword",!
                Write "    - CertUID (povinne pro kid v JWT headeru)",!
                Quit
            }
        } Else {
            Write "Token server: ",..#TOKENSERVER,!
            Write "Scope: ",..Scope,!
        }

        Write !,"--- Ziskavam Bearer token ---",!
        Set ..Token = ""
        Set sc = ..GetToken(.token)

        If $$$ISERR(sc) {
            Write "CHYBA: ",$System.Status.GetErrorText(sc),!
            Quit
        }

        Write "Token ziskan!",!
        Write "Delka: ",$Length(token)," znaku",!
        Write "Expirace: ",..TokenExpiry,!

        If ..ClientSecret '= "" {
            Set parts = $ListFromString(token, ".")
            If $ListLength(parts) >= 2 {
                Set p = $ListGet(parts, 2)
                Set pad = 4 - ($Length(p) # 4) If pad < 4 { For i=1:1:pad { Set p = p_"=" } }
                Set p = $Translate(p, "-_", "+/")
                Set decoded = $System.Encryption.Base64Decode(p)
                Write !,"Access token claims:",!
                Write decoded,!
            }
        }

        Write !,"--- Testuji gateway ---",!
        Set req = ##class(%Net.HttpRequest).%New()
        Set req.Server = ..#GATEWAY
        Set req.Port = ..#PORT
        Set req.Https = 1
        Set req.SSLConfiguration = ..#SSLCONFIG
        Set req.Timeout = 10
        Do req.SetHeader("Authorization", "Bearer "_token)
        Do req.SetHeader("Accept", "application/json")
        Do req.SetHeader("Accept-Language", "cs")
        Set sc2 = req.Get("/notifikace/api/v1/notifikace/ping")
        If $$$ISERR(sc2) {
            Write "Gateway chyba: ",$System.Status.GetErrorText(sc2),!
        } Else {
            Write "Gateway HTTP: ",req.HttpResponse.StatusCode,!
            Set resp = req.HttpResponse.Data.Read(1000)
            Write "Odpoved: ",resp,!
            If req.HttpResponse.StatusCode = 401 {
                Write !,">>> TOKEN ODMITNUT GATEWAY <<<",!
                Write "    Mozne priciny:",!
                Write "    - Chybny/chybejici kid (CertUID) v JWT headeru",!
                Write "    - Jiny certifikat pro mTLS vs JWT signing",!
                Write "    - Expirovany assertion",!
            } ElseIf req.HttpResponse.StatusCode < 400 {
                Write !,">>> VSE OK – AUTENTIZACE FUNGUJE <<<",!
            }
        }

    } Catch ex {
        Set sc = ex.AsStatus()
        Write "Vyjimka: ",$System.Status.GetErrorText(sc),!
    }
    Quit sc
}

ClassMethod NewUUID() As %String
{
    Quit $SYSTEM.Util.CreateGUID()
}

}
