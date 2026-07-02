/// Runner testovacích scénářů IROP/NPO (Metodika testování EHR fáze I)
/// pro InterSystems IRIS. Provádí stejná volání jako webová aplikace
/// sez-api (sekce IROP/NPO Testy) a KAŽDÉ volání loguje do
/// SEZ.IROP.VolaniLog: co se posílá (metoda, URL, query, tělo) a co se
/// vrací (HTTP status, tělo odpovědi) – pro debug a dokumentaci testu.
///
/// Použití (terminál):
///   Set config = ##class(SEZ.API.Config).%New("25488627_KrajskaZdravotniVerejnyTest")
///   Set config.P12CertFile = "/opt/certs/krajska_zdravotni.pfx"
///   Set config.P12CertPassword = "…"
///   Set runner = ##class(SEZ.IROP.TestRunner).%New(config)
///   Do runner.RunAll()
///   Do ##class(SEZ.IROP.VolaniLog).Vypis("TS-TECH-4")
Class SEZ.IROP.TestRunner Extends %RegisteredObject
{

/// Konfigurace SEZ API (certifikát, client_id, brána)
Property Config As SEZ.API.Config [ Required ];

/// Sdílený HTTP klient (mTLS + JWT assertion)
Property Client As SEZ.API.HttpClient [ Required ];

/// RID testovacího pacienta
Property Rid As %String [ InitialExpression = "2667873559" ];

/// KRZPID testovacího zdravotnického pracovníka
Property KrzpId As %String [ InitialExpression = "102129137" ];

/// IČO testovaného PZS (tvůrce zásilek)
Property ICO As %String [ InitialExpression = "25488627" ];

/// IČO adresáta zásilek DÚ – MUSÍ být jiné PZS než tvůrce,
/// jinak DÚ vrací validaci E01001 (výchozí: VFN Praha)
Property ICOAdresat As %String [ InitialExpression = "00064165" ];

/// Počet splněných kroků posledního běhu
Property KrokuSplneno As %Integer [ InitialExpression = 0 ];

/// Počet kroků posledního běhu celkem
Property KrokuCelkem As %Integer [ InitialExpression = 0 ];

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set sc = $$$OK
    Try {
        Set ..Config = pConfig
        Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Provede jeden krok scénáře: HTTP volání přes SEZ.API.HttpClient,
/// zaloguje request i response do SEZ.IROP.VolaniLog a vypíše souhrn.
/// Vrací 1 při úspěchu (HTTP 2xx/3xx), jinak 0.
Method Krok(pScenar As %String, pNazev As %String, pMetoda As %String, pPath As %String, pBody As %DynamicAbstractObject = "", ByRef pQuery, Output pResponse As %DynamicAbstractObject) As %Boolean
{
    Set uspech = 0, chyba = "", t0 = $ZHorolog
    Set pResponse = ""
    Try {
        If pMetoda = "GET" {
            Set sc = ..Client.Get(pPath, .pQuery, .pResponse)
        } ElseIf pMetoda = "POST" {
            Set sc = ..Client.Post(pPath, pBody, .pResponse)
        } ElseIf pMetoda = "PUT" {
            Set sc = ..Client.Put(pPath, pBody, .pResponse)
        } ElseIf pMetoda = "PATCH" {
            Set sc = ..Client.Patch(pPath, pBody, .pQuery, .pResponse)
        } Else {
            Set sc = $$$ERROR($$$GeneralError, "Nepodporovaná metoda: " _ pMetoda)
        }
        If $$$ISERR(sc) {
            Set chyba = $System.Status.GetErrorText(sc)
        }
    } Catch ex {
        Set chyba = ex.DisplayString()
    }
    Set trvani = ((($ZHorolog - t0) * 1000) \ 1)
    Set httpStatus = +..Client.LastStatusCode
    Set uspech = (chyba = "") && (httpStatus >= 200) && (httpStatus < 400)

    // Serializace requestu/query pro log
    Set bodyJson = ""
    If $IsObject(pBody) Set bodyJson = pBody.%ToJSON()
    Set queryJson = ..QueryDoJson(.pQuery)

    Set scLog = ##class(SEZ.IROP.VolaniLog).Zapis(pScenar, pNazev, pMetoda, pPath,
        queryJson, bodyJson, httpStatus, ..Client.LastRawResponse, trvani, uspech, chyba)
    If $$$ISERR(scLog) {
        Write !, "  ! log se nepodařilo uložit: ", $System.Status.GetErrorText(scLog)
    }

    Set ..KrokuCelkem = ..KrokuCelkem + 1
    If uspech Set ..KrokuSplneno = ..KrokuSplneno + 1

    Write !, "  ", $Select(uspech: "✓", 1: "✗"), " [", pScenar, "] ", pNazev,
        " → ", pMetoda, " ", pPath, " (HTTP ", httpStatus, ", ", trvani, " ms)"
    If chyba '= "" Write !, "    ! ", chyba
    Quit uspech
}

/// Serializuje pole query parametrů do JSON řetězce pro log.
ClassMethod QueryDoJson(ByRef pQuery) As %String
{
    Set json = ##class(%DynamicObject).%New()
    Set klic = ""
    For {
        Set klic = $Order(pQuery(klic))
        Quit:klic=""
        Do json.%Set(klic, pQuery(klic))
    }
    Quit $Select(json.%Size() > 0: json.%ToJSON(), 1: "")
}

/// TS-TECH-1: Připojení ke KRP – všech 6 metod vyhledání dle metodiky.
Method RunTech1() As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-TECH-1: Připojení ke KRP ==="
        Set body = ..KrpZadost({"rid": (..Rid)})
        Do ..Krok("TS-TECH-1", "Vyhledání dle RID", "POST",
            "/krp/api/v2/pacient/hledat/rid", body, , .resp)

        Set jmeno = "MRAKOMOROVÁ", prijmeni = "MRAČENA", rc = "7161264528"
        Do ..Krok("TS-TECH-1", "Vyhledání dle jméno + RC", "POST",
            "/krp/api/v2/pacient/hledat/jmeno_prijmeni_rc",
            ..KrpZadost({"jmeno": (jmeno), "prijmeni": (prijmeni), "rodneCislo": (rc)}), , .resp)
        Do ..Krok("TS-TECH-1", "Vyhledání dle jméno + datum narození", "POST",
            "/krp/api/v2/pacient/hledat/jmeno_prijmeni_datum_narozeni",
            ..KrpZadost({"jmeno": (jmeno), "prijmeni": (prijmeni),
                          "datumNarozeni": "1971-11-26", "statniObcanstvi": "CZ"}), , .resp)
        Do ..Krok("TS-TECH-1", "Vyhledání dle jméno + číslo pojištěnce", "POST",
            "/krp/api/v2/pacient/hledat/jmeno_prijmeni_cp",
            ..KrpZadost({"jmeno": (jmeno), "prijmeni": (prijmeni), "cisloPojistence": (rc)}), , .resp)
        Do ..Krok("TS-TECH-1", "Vyhledání cizince dle ČP", "POST",
            "/krp/api/v2/pacient/hledat/cizinec_cp",
            ..KrpZadost({"cisloPojistence": (rc), "statniObcanstvi": "CZ"}), , .resp)
        Do ..Krok("TS-TECH-1", "Vyhledání dle dokladu", "POST",
            "/krp/api/v2/pacient/hledat/doklady",
            ..KrpZadost({"cislo": "123456789", "typDokladu": "ID", "stat": "CZ"}), , .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-TECH-2A: Připojení ke KRPZS – IČO, název, místo.
/// Název a krajKod se přebírají z odpovědi na hledání dle IČO (PZSDetail),
/// protože hledání dle názvu vyžaduje přesný název (jinak 404) a hledání
/// dle místa má dle kontraktu jediný POVINNÝ parametr krajKod (jinak 400).
Method RunTech2A() As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-TECH-2A: Připojení ke KRPZS ==="
        Do ..Krok("TS-TECH-2A", "Vyhledání dle IČO", "POST",
            "/krpzs/api/v2/Poskytovatel/hledat/ico",
            ..KrpZadost({"ico": (..ICO)}, "OVERENI"), , .icoResp)

        // Oficiální název + krajKod sídla z PZSDetail
        Set nazev = "Krajská zdravotní, a.s.", krajKod = "CZ042"
        If $IsObject(icoResp) && $IsObject(icoResp.%Get("odpovedData"))
            && (icoResp.%Get("odpovedData").%Size() > 0) {
            Set detail = icoResp.%Get("odpovedData").%Get(0)
            If detail.%Get("poskytovatelNazev") '= "" {
                Set nazev = detail.%Get("poskytovatelNazev")
            }
            If $IsObject(detail.%Get("adresaSidla"))
                && (detail.%Get("adresaSidla").%Get("krajKod") '= "") {
                Set krajKod = detail.%Get("adresaSidla").%Get("krajKod")
            }
        }

        Do ..Krok("TS-TECH-2A", "Vyhledání dle názvu (" _ nazev _ ")", "POST",
            "/krpzs/api/v2/Poskytovatel/hledat/nazev",
            ..KrpZadost({"nazev": (nazev)}, "OVERENI"), , .resp)
        Do ..Krok("TS-TECH-2A", "Vyhledání dle místa (krajKod=" _ krajKod _ ")", "POST",
            "/krpzs/api/v2/Poskytovatel/hledat/misto",
            ..KrpZadost({"krajKod": (krajKod)}, "OVERENI"), , .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-TECH-2B: Připojení ke KRZP – KRZPID + vazba na zaměstnavatele.
Method RunTech2B() As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-TECH-2B: Připojení ke KRZP ==="
        Do ..Krok("TS-TECH-2B", "Vyhledání ZP dle KRZPID", "POST",
            "/krzp/api/v2/pracovnik/hledat/krzpid",
            ..KrpZadost({"krzpid": (..KrzpId)}), , .resp)
        Set zam = {"data": {"ico": (..ICO), "vcetneNeplatnych": false}}
        Do ..PridejZadostInfo(zam, "LECBA")
        Do ..Krok("TS-TECH-2B", "Vyhledání ZP dle zaměstnavatele", "POST",
            "/krzp/api/v2/pracovnik/hledat/zamestnavatel", zam, , .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-TECH-4: Registr oprávnění – číselníky a Over s reálnými ID.
/// POZOR: Over s neexistujícími ID číselníků (např. natvrdo 1/5) vrací
/// na T2 HTTP 500 z backendu RO – proto se ID berou z číselníků.
Method RunTech4() As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-TECH-4: Registr oprávnění ==="
        Kill query
        Do ..Krok("TS-TECH-4", "Číselník SluzbyEZ", "GET",
            "/registrOpravneni/api/v1/Ciselniky/SluzbyEZ", , .query, .sluzby)
        Kill query
        Do ..Krok("TS-TECH-4", "Číselník TypyDokumentaci", "GET",
            "/registrOpravneni/api/v1/Ciselniky/TypyDokumentaci", , .query, .typy)

        Set idSluzby = "", idTypu = ""
        If $IsObject(sluzby) && $IsObject(sluzby.%Get("page")) && (sluzby.%Get("page").%Size() > 0) {
            Set idSluzby = sluzby.%Get("page").%Get(0).%Get("id")
        }
        If $IsObject(typy) && $IsObject(typy.%Get("page")) && (typy.%Get("page").%Size() > 0) {
            Set idTypu = typy.%Get("page").%Get(0).%Get("id")
        }
        If (idSluzby = "") || (idTypu = "") {
            Write !, "  ✗ Nelze určit ID služby/typu z číselníků – Over se přeskakuje"
            Quit
        }

        // Opravňující je dle metodiky vždy Pacient (přístup k dokumentaci
        // pacienta). Kombinace PZS→ZP na T2 shazuje backend RO (Abp 500).
        Kill query
        Set query("IdSluzbyEZ") = idSluzby
        Set query("IdTypuDokumentace") = idTypu
        Set query("OpravnujiciOsoba.Role") = "Pacient"
        Set query("OpravnujiciOsoba.Hodnota") = ..Rid
        Set query("OpravnenaOsoba.Role") = "PoskytovatelZdravotnickychSluzeb"
        Set query("OpravnenaOsoba.Hodnota") = ..ICO
        Do ..Krok("TS-TECH-4", "Over: Pacient→PZS (přístup k dokumentaci)", "GET",
            "/registrOpravneni/api/v1/Opravneni/Over", , .query, .resp)

        Kill query
        Set query("IdSluzbyEZ") = idSluzby
        Set query("IdTypuDokumentace") = idTypu
        Set query("OpravnujiciOsoba.Role") = "Pacient"
        Set query("OpravnujiciOsoba.Hodnota") = ..Rid
        Set query("OpravnenaOsoba.Role") = "ZdravotnickyPracovnik"
        Set query("OpravnenaOsoba.Hodnota") = ..KrzpId
        Do ..Krok("TS-TECH-4", "Over: Pacient→ZP (přístup k dokumentaci)", "GET",
            "/registrOpravneni/api/v1/Opravneni/Over", , .query, .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-TECH-5: Terminologický server – povinné kroky metodiky:
/// ValueSet/?url= (definice) a ValueSet/$expand (položky).
/// POZOR: cesty jsou dle swaggeru (v1.0.5 i v1.1.0) přímo pod
/// /terminologie BEZ mezisegmentu /fhir – legacy /terminologie/fhir
/// po upgrade TermX na T2 vrací HTTP 406 „could not find matching
/// enabled interaction".
Method RunTech5(pValueSetUrl As %String = "https://ncez.mzcr.cz/terminology/ValueSet/medical-document-type") As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-TECH-5: Terminologický server (TermX) ==="
        Kill query
        Set query("url") = pValueSetUrl
        Set query("_count") = 5
        Do ..Krok("TS-TECH-5", "ValueSet search dle url (metodika krok 1)", "GET",
            "/terminologie/ValueSet", , .query, .resp)
        Kill query
        Set query("url") = pValueSetUrl
        Do ..Krok("TS-TECH-5", "ValueSet/$expand (metodika krok 2)", "GET",
            "/terminologie/ValueSet/$expand", , .query, .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-TECH-6: Uložení dokumentace do DÚ. Adresát je jiné PZS než tvůrce
/// (DÚ validace E01001 nedovolí shodné IČO).
Method RunTech6() As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-TECH-6: Uložení dokumentace do DÚ ==="
        Set obsah = "IROP test document (IRIS TestRunner) " _ $ZDateTime($ZTimestamp, 3, 1, 3)
        Set b64 = ..Base64(obsah)
        Set hashHex = $ZConvert(##class(%xsd.hexBinary).LogicalToXSD(
            $System.Encryption.SHAHash(256, obsah)), "l")

        Set zasilka = ##class(SEZ.API.DocasneUloziste).NovaZasilka(
            "IROP TS-TECH-6 (IRIS)", ..KrzpId, ..Rid, ..ICO, ..KrzpId, "IRIS TestRunner")
        Set zasilka.adresat = ..ICOAdresat
        Set zasilka.adresatTyp = {"kod": "PZS", "verze": "1.0.0"}
        $$$ThrowOnError(##class(SEZ.API.DocasneUloziste).PridejDokument(
            zasilka, "IROP testovací dokument", ..Rid, hashHex, $Length(obsah),
            b64, , "text/plain", ..KrzpId, ..ICO))

        Do ..Krok("TS-TECH-6", "UlozZasilku", "POST",
            "/docasneUloziste/api/v1/Zasilka/UlozZasilku", zasilka, , .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-TECH-8/9: Vyhledání zásilky + změna/zneplatnění.
/// pAkce: "zmen" (PUT ZmenZasilku) nebo "zneplatni" (PATCH ZneplatniZasilku).
Method RunTech89(pAkce As %String = "zneplatni") As %Status
{
    Set sc = $$$OK
    Try {
        Set scenar = $Select(pAkce = "zmen": "TS-TECH-8", 1: "TS-TECH-9")
        Write !!, "=== ", scenar, ": ", $Select(pAkce = "zmen": "Změna", 1: "Zneplatnění"),
            " dokumentace v DÚ ==="
        Set od = $ZDate($Horolog - 90, 3) _ "T00:00:00+00:00"
        Set datumDo = $ZDate($Horolog + 1, 3) _ "T23:59:59+00:00"
        Set hledani = {"datumOd": (od), "datumDo": (datumDo), "pacient": (..Rid),
                        "strankovani": {"page": 1, "size": 5}}
        Do ..Krok(scenar, "VyhledejZasilku", "POST",
            "/docasneUloziste/api/v1/Zasilka/VyhledejZasilku", hledani, , .nalez)

        Set id = "", verze = ""
        If $IsObject(nalez) && $IsObject(nalez.%Get("zasilka")) && (nalez.%Get("zasilka").%Size() > 0) {
            Set prvni = nalez.%Get("zasilka").%Get(0)
            Set id = prvni.%Get("id")
            Set verze = prvni.%Get("verzeRadku")
        }
        If id = "" {
            Write !, "  ✗ Žádná zásilka k ", $Select(pAkce = "zmen": "změně", 1: "zneplatnění")
            Quit
        }

        Kill query
        Set query("Id") = id
        Set query("VerzeRadku") = verze
        If pAkce = "zmen" {
            Set zmena = {"nazev": ("Změněno IRIS TestRunner " _ $ZDateTime($ZTimestamp, 3))}
            Do ..Krok(scenar, "ZmenZasilku", "PUT",
                "/docasneUloziste/api/v1/Zasilka/ZmenZasilku?Id=" _ id _ "&VerzeRadku=" _ verze,
                zmena, , .resp)
        } Else {
            Do ..Krok(scenar, "ZneplatniZasilku", "PATCH",
                "/docasneUloziste/api/v1/Zasilka/ZneplatniZasilku", "", .query, .resp)
        }
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// TS-OBS-1: Příjem eZD – vyhledání a stažení zásilky z DÚ.
Method RunObs1() As %Status
{
    Set sc = $$$OK
    Try {
        Write !!, "=== TS-OBS-1: Příjem, uložení a zobrazení eZD ==="
        Set od = $ZDate($Horolog - 90, 3) _ "T00:00:00+00:00"
        Set datumDo = $ZDate($Horolog + 1, 3) _ "T23:59:59+00:00"
        Set hledani = {"datumOd": (od), "datumDo": (datumDo), "pacient": (..Rid),
                        "strankovani": {"page": 1, "size": 5}}
        Do ..Krok("TS-OBS-1", "VyhledejZasilku", "POST",
            "/docasneUloziste/api/v1/Zasilka/VyhledejZasilku", hledani, , .nalez)

        Set id = ""
        If $IsObject(nalez) && $IsObject(nalez.%Get("zasilka")) && (nalez.%Get("zasilka").%Size() > 0) {
            Set id = nalez.%Get("zasilka").%Get(0).%Get("id")
        }
        If id = "" {
            Write !, "  ✗ Žádná zásilka ke stažení"
            Quit
        }
        Kill query
        Do ..Krok("TS-OBS-1", "DejZasilku (stažení dokumentu)", "GET",
            "/docasneUloziste/api/v1/Zasilka/DejZasilku/" _ id, , .query, .resp)
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Spustí všechny implementované scénáře a vypíše souhrn.
Method RunAll() As %Status
{
    Set sc = $$$OK
    Try {
        Set ..KrokuSplneno = 0, ..KrokuCelkem = 0
        $$$ThrowOnError(..RunTech1())
        $$$ThrowOnError(..RunTech2A())
        $$$ThrowOnError(..RunTech2B())
        $$$ThrowOnError(..RunTech4())
        $$$ThrowOnError(..RunTech5())
        $$$ThrowOnError(..RunTech6())
        $$$ThrowOnError(..RunTech89("zmen"))
        $$$ThrowOnError(..RunTech89("zneplatni"))
        $$$ThrowOnError(..RunObs1())
        Write !!, "=== SOUHRN: ", ..KrokuSplneno, "/", ..KrokuCelkem, " kroků splněno ==="
        Write !, "Detailní log volání: Do ##class(SEZ.IROP.VolaniLog).Vypis()", !
    } Catch ex {
        Set sc = ex.AsStatus()
    }
    Quit sc
}

/// Sestaví standardní obálku žádosti KZR (zadostInfo + zadostData).
Method KrpZadost(pData As %DynamicObject, pUcel As %String = "LECBA") As %DynamicObject
{
    Set zadost = {"zadostData": (pData)}
    Do ..PridejZadostInfo(zadost, pUcel)
    Quit zadost
}

/// Doplní zadostInfo (datum, účel, zadostId) do obálky žádosti.
Method PridejZadostInfo(pZadost As %DynamicObject, pUcel As %String = "LECBA") As %Status
{
    Set pZadost.zadostInfo = {
        "datum": ($ZDate($Horolog, 3)),
        "ucel": (pUcel),
        "zadostId": (##class(SEZ.API.Config).NewUUID())
    }
    Quit $$$OK
}

/// Base64 kódování textu (bez zalomení řádků).
ClassMethod Base64(pText As %String) As %String
{
    Set b64 = $System.Encryption.Base64Encode(pText, 1)
    Quit $Translate(b64, $Char(13, 10))
}

}
