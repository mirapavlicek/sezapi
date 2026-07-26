/// Generátor hlavičky <b>User-Agent</b> pro volání SEZ API (NCEZ).
///
/// Formát dle stránky "API endpointy" (aktualizace 21. 7. 2026):
/// <pre>&lt;název-aplikace&gt;/&lt;verze&gt; (Test|Prod; výrobceSW[; poznámka])</pre>
/// Hlavička je POVINNÁ od 1. 9. 2026 (RFC 9110, sekce 10.1.5) – volání bez ní
/// brána odmítne. Pozor: %Net.HttpRequest bez explicitního nastavení pošle
/// vlastní "Mozilla/4.0 (compatible; InterSystems IRIS;)", které formátu
/// nevyhovuje.
///
/// Konfigurace se drží v globálu ^SEZ.API.UserAgent, takže se mění za běhu
/// bez rekompilace:
/// <example>
/// Do ##class(SEZ.API.UserAgent).Nastav("nis-kz", "3.4.1", "Krajská zdravotní, a.s.")
/// Write ##class(SEZ.API.UserAgent).Dej("gwy-ext-sec-t2.csez.cz")
/// nis-kz/3.4.1 (Test; Krajska zdravotni a.s.)
/// </example>
Class SEZ.API.UserAgent Extends %RegisteredObject
{

/// Výchozí název aplikace, dokud se nezavolá Nastav().
Parameter APPNAME = "sez-api-iris";

/// Výchozí verze aplikace.
Parameter APPVERSION = "1.0.0";

/// Výchozí výrobce SW.
Parameter VENDOR = "Neznamy vyrobce";

/// Znaky povolené v product tokenu (název i verze) dle RFC 9110.
Parameter TOKENCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";

/// Kontrolní vzor hotové hlavičky. Poznámka za výrobcem je volitelná.
Parameter PATTERN = "^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+ \((Test|Prod); [^();]+(; [^();]+)?\)$";

/// Pojistka proti nesmyslně dlouhé hlavičce. RFC 9110 délku nelimituje,
/// servery běžně přijímají jednotky kB; 200 znaků je pro identifikaci SW dost.
Parameter MAXLEN = 200;

/// Vrátí hlavičku User-Agent z aktuální konfigurace.
///
/// pGateway je hostname brány, ze kterého se odvodí prostředí (Test/Prod) –
/// předává ho SEZ.API.Config jako ..#GATEWAY. Je-li prázdný, použije se
/// prostředí uložené v konfiguraci, jinak "Test".
ClassMethod Dej(pGateway As %String = "") As %String
{
    Set nazev = $Get(^SEZ.API.UserAgent("appName"), ..#APPNAME)
    Set verze = $Get(^SEZ.API.UserAgent("appVersion"), ..#APPVERSION)
    Set vyrobce = $Get(^SEZ.API.UserAgent("vendor"), ..#VENDOR)
    Set poznamka = $Get(^SEZ.API.UserAgent("note"), "")
    If pGateway '= "" {
        Set prostredi = ..Prostredi(pGateway)
    } Else {
        Set prostredi = $Get(^SEZ.API.UserAgent("environment"), "Test")
    }
    Set sc = $$$OK
    Set ua = ..Sestav(nazev, verze, prostredi, vyrobce, poznamka, .sc)
    // Sestav() sanitizuje vstupy, takže chybu vrátí jen u prázdné konfigurace;
    // v takovém případě se vrátí alespoň zaručeně platná výchozí hodnota.
    If $$$ISERR(sc) {
        Set ua = ..#APPNAME _ "/" _ ..#APPVERSION _ " (" _ prostredi _ "; " _ ..#VENDOR _ ")"
    }
    Quit ua
}

/// Sestaví hlavičku z explicitních hodnot. Vstupy sanitizuje (diakritika,
/// mezery, znaky zakázané v tokenu i v komentáři) a výsledek zvaliduje.
/// pSC vrací chybu, pokud po sanitizaci nezbyl platný název nebo verze.
ClassMethod Sestav(pNazev As %String, pVerze As %String, pProstredi As %String = "Test", pVyrobce As %String = "", pPoznamka As %String = "", Output pSC As %Status) As %String
{
    Set pSC = $$$OK
    Set nazev = ..Token(pNazev)
    Set verze = ..Token(pVerze)
    Set vyrobce = ..Komentar($Select(pVyrobce = "": ..#VENDOR, 1: pVyrobce))
    Set poznamka = ..Komentar(pPoznamka)
    Set prostredi = $Select($ZConvert(pProstredi, "L") = "prod": "Prod", 1: "Test")

    If nazev = "" {
        Set pSC = $$$ERROR($$$GeneralError, "Název aplikace pro User-Agent je prázdný.")
        Quit ""
    }
    If verze = "" {
        Set pSC = $$$ERROR($$$GeneralError, "Verze aplikace pro User-Agent je prázdná.")
        Quit ""
    }

    Set detail = prostredi _ "; " _ vyrobce
    If poznamka '= "" {
        Set detail = detail _ "; " _ poznamka
    }
    Set ua = nazev _ "/" _ verze _ " (" _ detail _ ")"

    // Přes limit se nejdřív vypustí volitelná poznámka, teprve pak se zkrátí
    // výrobce – hlavička si tak zachová platnou strukturu.
    If ($Length(ua) > ..#MAXLEN) && (poznamka '= "") {
        Set poznamka = ""
        Set ua = nazev _ "/" _ verze _ " (" _ prostredi _ "; " _ vyrobce _ ")"
    }
    If $Length(ua) > ..#MAXLEN {
        Set volno = ..#MAXLEN - $Length(nazev _ "/" _ verze _ " (" _ prostredi _ "; )")
        Set vyrobce = $Extract(vyrobce, 1, $Select(volno > 0: volno, 1: 1))
        Set ua = nazev _ "/" _ verze _ " (" _ prostredi _ "; " _ vyrobce _ ")"
    }
    If '..Validuj(ua, .chyby) {
        Set pSC = $$$ERROR($$$GeneralError, "Sestavená hlavička je neplatná: " _ chyby.%ToJSON())
    }
    Quit ua
}

/// Uloží konfiguraci do globálu ^SEZ.API.UserAgent. Prostředí je volitelné –
/// běžně se odvozuje z hostname brány při každém volání Dej().
ClassMethod Nastav(pNazev As %String, pVerze As %String, pVyrobce As %String, pPoznamka As %String = "", pProstredi As %String = "") As %Status
{
    Set sc = $$$OK
    Set ua = ..Sestav(pNazev, pVerze, $Select(pProstredi = "": "Test", 1: pProstredi), pVyrobce, pPoznamka, .sc)
    If $$$ISERR(sc) {
        Quit sc
    }
    Set ^SEZ.API.UserAgent("appName") = ..Token(pNazev)
    Set ^SEZ.API.UserAgent("appVersion") = ..Token(pVerze)
    Set ^SEZ.API.UserAgent("vendor") = ..Komentar(pVyrobce)
    Set ^SEZ.API.UserAgent("note") = ..Komentar(pPoznamka)
    If pProstredi '= "" {
        Set ^SEZ.API.UserAgent("environment") = $Select($ZConvert(pProstredi, "L") = "prod": "Prod", 1: "Test")
    }
    Quit sc
}

/// Nastaví hlavičku do připraveného %Net.HttpRequest. Volá se u každého
/// requestu – hlavička není součástí spojení, ale jednotlivého volání.
ClassMethod Aplikuj(pRequest As %Net.HttpRequest, pGateway As %String = "") As %Status
{
    If '$IsObject(pRequest) {
        Quit $$$ERROR($$$GeneralError, "pRequest není objekt %Net.HttpRequest.")
    }
    Quit pRequest.SetHeader("User-Agent", ..Dej($Select(pGateway = "": pRequest.Server, 1: pGateway)))
}

/// Odvodí prostředí z hostname brány: testovací brány obsahují "-t2"
/// (gwy-ext-sec-t2.csez.cz), produkce je api.csez.gov.cz.
ClassMethod Prostredi(pGateway As %String) As %String
{
    Set host = $ZConvert(pGateway, "L")
    If (host [ "-t2") || (host [ "test") || (host [ "jsuint") {
        Quit "Test"
    }
    Quit "Prod"
}

/// Sanitizuje product token (název nebo verze): odstraní diakritiku, mezery
/// a lomítka nahradí pomlčkou, ostatní nepovolené znaky zahodí.
ClassMethod Token(pText As %String) As %String
{
    Set text = ..BezDiakritiky($ZStrip(pText, "<>W"))
    Set out = ""
    For i = 1:1:$Length(text) {
        Set znak = $Extract(text, i)
        If ..#TOKENCHARS [ znak {
            Set out = out _ znak
        } ElseIf (znak = " ") || (znak = "/") || (znak = "\") {
            Set out = out _ "-"
        }
    }
    While out [ "--" {
        Set out = $Replace(out, "--", "-")
    }
    Quit $ZStrip(out, "<>", "-")
}

/// Sanitizuje komentářovou část (výrobce, poznámka): znaky "()" a ";"
/// oddělují strukturu hlavičky, proto se v hodnotě nesmí vyskytnout.
ClassMethod Komentar(pText As %String) As %String
{
    Set text = ..BezDiakritiky($ZStrip(pText, "*C"))
    Set text = $Translate(text, "();\", "    ")
    While text [ "  " {
        Set text = $Replace(text, "  ", " ")
    }
    Quit $ZStrip(text, "<>W")
}

/// Odstraní českou a slovenskou diakritiku – hodnoty HTTP hlaviček mají být
/// dle RFC 9110 v US-ASCII, jinak se na druhé straně zobrazí poškozené.
ClassMethod BezDiakritiky(pText As %String) As %String
{
    Set dia = "áäčďéěëíľĺňóöřŕšťúůüýžÁÄČĎÉĚËÍĽĹŇÓÖŘŔŠŤÚŮÜÝŽ"
    Set ascii = "aacdeeeillnoorrstuuuyzAACDEEEILLNOORRSTUUUYZ"
    Quit $Translate(pText, dia, ascii)
}

/// Zkontroluje hotovou hlavičku. Chyby vrací v pChyby jako %DynamicArray.
ClassMethod Validuj(pUserAgent As %String, Output pChyby As %DynamicArray) As %Boolean
{
    Set pChyby = []
    If $Length(pUserAgent) = 0 {
        Do pChyby.%Push("Hlavička je prázdná.")
        Quit 0
    }
    Set matcher = ##class(%Regex.Matcher).%New(..#PATTERN, pUserAgent)
    If 'matcher.Locate() {
        Do pChyby.%Push("Nevyhovuje formátu <aplikace>/<verze> (Test|Prod; výrobceSW).")
    }
    If $ZConvert(pUserAgent, "L") [ "mozilla" {
        Do pChyby.%Push("Obsahuje výchozí hodnotu %Net.HttpRequest – hlavička nebyla nastavena.")
    }
    If $Length(pUserAgent) > ..#MAXLEN {
        Do pChyby.%Push("Delší než " _ ..#MAXLEN _ " znaků.")
    }
    For i = 1:1:$Length(pUserAgent) {
        If $Ascii(pUserAgent, i) > 126 {
            Do pChyby.%Push("Obsahuje znak mimo ASCII na pozici " _ i _ ".")
            Quit
        }
    }
    Quit pChyby.%Size() = 0
}

/// Vypíše aktuální konfiguraci a hlavičku pro obě prostředí.
ClassMethod Zobraz() As %Status
{
    Write !, "Konfigurace ^SEZ.API.UserAgent:"
    Write !, "  název aplikace : ", $Get(^SEZ.API.UserAgent("appName"), ..#APPNAME _ " (výchozí)")
    Write !, "  verze          : ", $Get(^SEZ.API.UserAgent("appVersion"), ..#APPVERSION _ " (výchozí)")
    Write !, "  výrobce        : ", $Get(^SEZ.API.UserAgent("vendor"), ..#VENDOR _ " (výchozí)")
    Write !, "  poznámka       : ", $Get(^SEZ.API.UserAgent("note"), "-")
    Write !!, "Odesílaná hlavička:"
    Write !, "  T2  : ", ..Dej("gwy-ext-sec-t2.csez.cz")
    Write !, "  Prod: ", ..Dej("api.csez.gov.cz")
    Write !
    Quit $$$OK
}

/// Samotest generátoru – ověří sanitizaci, detekci prostředí i validaci.
/// <example>Do ##class(SEZ.API.UserAgent).Test()</example>
ClassMethod Test() As %Status
{
    Set chyb = 0

    // Sanitizace: diakritika a mezery v názvu, závorky ve výrobci.
    Set ua = ..Sestav("NIS Krajské zdravotní", "3.4.1", "Test", "Krajská zdravotní, a.s. (KZ)", , .sc)
    Set ocekavano = "NIS-Krajske-zdravotni/3.4.1 (Test; Krajska zdravotni, a.s. KZ)"
    If ($$$ISERR(sc)) || (ua '= ocekavano) {
        Write !, "CHYBA sanitizace: ", ua, " != ", ocekavano
        Set chyb = chyb + 1
    }

    // Detekce prostředí z hostname.
    If ..Prostredi("gwy-ext-sec-t2.csez.cz") '= "Test" {
        Write !, "CHYBA detekce prostředí T2"
        Set chyb = chyb + 1
    }
    If ..Prostredi("api.csez.gov.cz") '= "Prod" {
        Write !, "CHYBA detekce prostředí Prod"
        Set chyb = chyb + 1
    }

    // Validace odmítne výchozí hodnotu %Net.HttpRequest a prázdnou hlavičku.
    If ..Validuj("Mozilla/4.0 (compatible; InterSystems IRIS;)", .chyby) {
        Write !, "CHYBA: výchozí Mozilla hlavička prošla validací"
        Set chyb = chyb + 1
    }
    If ..Validuj("nis-kz/1.0 (T2; KZ)", .chyby) {
        Write !, "CHYBA: prostředí T2 místo Test prošlo validací"
        Set chyb = chyb + 1
    }
    If '..Validuj("nis-kz/3.4.1 (Prod; Krajska zdravotni a.s.)", .chyby) {
        Write !, "CHYBA: platná hlavička neprošla: ", chyby.%ToJSON()
        Set chyb = chyb + 1
    }

    // Prázdný název je chyba, ne tichý fallback.
    Do ..Sestav("", "1.0", "Test", "KZ", , .sc)
    If $$$ISOK(sc) {
        Write !, "CHYBA: prázdný název aplikace neohlásil chybu"
        Set chyb = chyb + 1
    }

    Write !, $Select(chyb = 0: "Samotest OK", 1: "Samotest: " _ chyb _ " chyb"), !
    Quit $Select(chyb = 0: $$$OK, 1: $$$ERROR($$$GeneralError, chyb _ " chyb v samotestu"))
}

}
