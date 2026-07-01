/// Instalační a konfigurační utilita
/// Nastaví SSL konfiguraci a ověří připojení
Class SEZ.API.Installer Extends %RegisteredObject
{

/// Vytvoří SSL konfiguraci v IRIS pro SEZ API gateway.
/// Jeden certifikát EZCA II se používá pro mTLS i JWT signing.
/// Spusťte jednou po instalaci: Do ##class(SEZ.API.Installer).SetupSSL("/cesta/k/certifikatu.pfx", "heslo")
ClassMethod SetupSSL(pCertPath As %String, pCertPassword As %String, pConfigName As %String = "SEZ_API_T2") As %Status
{
    Set sc = $$$OK
    Try {
        Set ssl = ##class(Security.SSLConfigs).%New()
        Set ssl.Name = pConfigName
        Set ssl.Type = 0
        Set ssl.Enabled = 1
        Set ssl.VerifyPeer = 1
        Set ssl.VerifyDepth = 9

        If $ZCONVERT($Piece(pCertPath, ".", *), "l") = "p12" || ($ZCONVERT($Piece(pCertPath, ".", *), "l") = "pfx") {
            Set ssl.CertificateFile = pCertPath
            Set ssl.PrivateKeyFile = pCertPath
            Set ssl.PrivateKeyPassword = pCertPassword
            Set ssl.PrivateKeyType = "PKCS12"
        } Else {
            Set ssl.CertificateFile = pCertPath
        }

        Set ssl.Protocols = "TLSv1.2,TLSv1.3"
        Set sc = ssl.%Save()

        If $$$ISOK(sc) {
            Write "SSL konfigurace '"_pConfigName_"' vytvorena.",!
        }

    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Otestuje připojení k SEZ API gateway.
/// V režimu private_key_jwt (ClientSecret prázdný) se JWT assertion posílá přímo na Gateway.
ClassMethod TestConnection(pClientId As %String, pClientSecret As %String = "", pP12File As %String = "", pP12Password As %String = "", pCertUID As %String = "") As %Status
{
    Set sc = $$$OK
    Try {
        Write "=== Test pripojeni k SEZ API ===",!,!

        Set config = ##class(SEZ.API.Config).%New(pClientId, pClientSecret)
        If pP12File '= "" Set config.P12CertFile = pP12File
        If pP12Password '= "" Set config.P12CertPassword = pP12Password
        If pCertUID '= "" Set config.CertUID = pCertUID

        Write "Rezim: ",$Select(pClientSecret'="":"client_secret (JSU)", 1:"private_key_jwt (prima assertion)"),!
        If pClientSecret = "" Write "Cert UID (kid): ",pCertUID,!

        Write !,"1. Ziskavani Bearer tokenu...",!
        Set sc = config.GetToken(.token)
        If $$$ISERR(sc) {
            Write "   CHYBA: "_$System.Status.GetErrorText(sc),!
            Quit
        }
        Write "   OK - token ziskan (delka: "_$Length(token)_")",!,!

        Write "2. Test Notifikace ping...",!
        Set notif = ##class(SEZ.API.Notifikace).%New(config)
        Set sc2 = notif.Ping(.resp)
        If $$$ISERR(sc2) {
            Write "   CHYBA: "_$System.Status.GetErrorText(sc2),!
        } Else {
            Write "   OK - odpoved: "_resp,!
        }
        Write !

        Write "3. Test EZCA health check...",!
        Set ezca = ##class(SEZ.API.EZCA).%New(config)
        Set sc3 = ezca.HealthCheck(.ok)
        If $$$ISERR(sc3) {
            Write "   CHYBA: "_$System.Status.GetErrorText(sc3),!
        } Else {
            Write "   "_$Select(ok:"OK", 1:"FAIL"),!
        }
        Write !

        Write "4. Test SZZ ciselniky...",!
        Set szz = ##class(SEZ.API.SZZ).%New(config)
        Set sc4 = szz.SeznamCiselniku(.ciselniky)
        If $$$ISERR(sc4) {
            Write "   CHYBA: "_$System.Status.GetErrorText(sc4),!
        } ElseIf $IsObject(ciselniky) {
            If ciselniky.%IsA("%DynamicArray") {
                Write "   OK - nalezeno "_ciselniky.%Size()_" ciselniku",!
            } Else {
                Write "   OK - odpoved prijata",!
            }
        }

        Write !,"=== Test dokoncen ===",!

    } Catch ex {
        Set sc = ex.AsStatus()
        Write "FATALNI CHYBA: "_$System.Status.GetErrorText(sc),!
    }
    Quit sc
}

}
