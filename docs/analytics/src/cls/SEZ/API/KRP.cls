/// Kmenový registr pacientů – KRP PZS API v3 (cesty i tělo shodné s v2, jen prefix /api/v3)
/// Base URL: /krp
/// Výchozí verze je v3 – viz Parameter APIVERZE. Stav starších verzí (revize
/// 10. 11. 2026) není jednoznačný: Novinky EZ z 27. 8. 2026 oznámily vypnutí
/// v1 i v2 k 15. 9. 2026, plány MZ ČR z 3. 11. 2026 uvádějí "do konce roku
/// vypnout v1, zůstane v2 a v3". v3 zůstává podle obou zdrojů.
///
/// Pravidla Standardu EZ Kmenové registry 1.3 (platnost 3. 11. 2026):
/// DRID = "D" + devítimístné číslo dělitelné 13 a nedělitelné 11, zásoba 50 ks,
/// neslouží k založení novorozence; hromadné ztotožnění nejvýše 10 000
/// pacientů v dávce (zpracování cca 30 minut); univerzální hledání vždy jméno
/// + příjmení + další údaj; ve jméně a příjmení jen písmena, spojovník,
/// apostrof a mezera.
Class SEZ.API.KRP Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/krp";

/// Verze API KRP pro PZS (v3 zůstává podle oznámení z 27. 8. i plánů z 3. 11. 2026)
Parameter APIVERZE = "v3";

/// Zásoba předgenerovaných DRID dle Standardu KZR 1.3, kap. 4.4.3.
Parameter DRIDZASOBA = 50;

/// Nejvyšší počet pacientů v jedné dávce hromadného ztotožnění (kap. 4.4.5).
Parameter DAVKAMAXPACIENTU = 10000;

/// Zástupné hodnoty, které MZ ČR (3. 11. 2026) uvádí jako zjevně chybná jména.
/// Porovnává se celé slovo bez diakritiky malými písmeny.
Parameter ZAKAZANAJMENA = "test,testovaci,pacient,pokusnicek,nerekl,nevi,neuvedeno";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

// ==========================================================================
// VYHLEDÁVÁNÍ PACIENTŮ
// ==========================================================================

/// Vyhledání pacienta podle RID
Method HledatPodleRID(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/rid", body, .pResponse)
}

/// Univerzální vyhledání pacienta
Method HledatUni(pData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pData
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/uni", body, .pResponse)
}

/// Vyhledání podle jména, příjmení a rodného čísla
Method HledatJmenoPrijmeniRC(pJmeno As %String, pPrijmeni As %String, pRC As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"jmeno": (pJmeno), "prijmeni": (pPrijmeni), "rodneCislo": (pRC)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/jmeno_prijmeni_rc", body, .pResponse)
}

/// Vyhledání podle jména, příjmení a data narození
Method HledatJmenoPrijmeniDN(pJmeno As %String, pPrijmeni As %String, pDatumNarozeni As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"jmeno": (pJmeno), "prijmeni": (pPrijmeni), "datumNarozeni": (pDatumNarozeni)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/jmeno_prijmeni_datum_narozeni", body, .pResponse)
}

/// Vyhledání podle dokladu
Method HledatPodleDokladu(pCisloDokladu As %String, pTypDokladu As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"doklad": {"cislo": (pCisloDokladu), "typDokladu": (pTypDokladu)}}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/doklady", body, .pResponse)
}

/// Vyhledání cizince podle čísla pojištěnce
Method HledatCizinecCP(pCisloPojistence As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"cisloPojistence": (pCisloPojistence)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/cizinec_cp", body, .pResponse)
}

/// Vyhledání podle NIA BSI
Method HledatNiaBsi(pNiaBsi As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"niaBsi": (pNiaBsi)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/niabsi", body, .pResponse)
}

/// Historie pojištění pacienta
Method HledatHistoriePojisteni(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/historie_pojisteni", body, .pResponse)
}

/// Historie registrujících lékařů
Method HledatHistorieRegistrujicichLekaru(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/historie_registrujicich_lekaru", body, .pResponse)
}

/// Mapování RID
Method HledatMapovaniRID(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/hledat/mapovani_rid", body, .pResponse)
}

// ==========================================================================
// SPRÁVA PACIENTŮ
// ==========================================================================

/// Založení nového pacienta
Method ZalozitPacienta(pPacientData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pPacientData
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/zalozit/pacient", body, .pResponse)
}

/// Změna údajů pacienta
Method ZmenitPacienta(pRid As %String, pZmeny As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set zmenyData = pZmeny.%FromJSON(pZmeny.%ToJSON())
    Set zmenyData.rid = pRid
    Set body.zadostData = zmenyData
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/zmenit/pacient", body, .pResponse)
}

/// Generování dočasného RID (DRID). Standard KZR 1.3, kap. 4.4.3: DRID je pro
/// pacienta s neznámou totožností, výpadek sítě nebo traumaplán – NESLOUŽÍ
/// k založení novorozence (ten se zakládá metodou ZalozitPacienta). Každý DRID
/// smí být použit jen jednou; zásoba předgenerovaných DRID je 50 ks.
/// pPacientData = {"pocet": n}
Method GenerujDocasnyRID(pPacientData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pPacientData
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/generovat/docasny_rid", body, .pResponse)
}

/// Přiřazení použitého dočasného RID k trvalému RID (kap. 4.4.4).
/// Tělo dle swaggeru KRP 3.0.6: docasnyRID a rid. DRID se špatným tvarem
/// (jiným než "D" + 9 číslic) se na bránu neposílá; kontrolní pravidlo verze
/// 1.3 se nevynucuje, protože DRID vydané před 3. 11. 2026 ho splňovat nemusí.
Method PriraditDocasnyRID(pDocasnyRid As %String, pSkutecnyRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set pResponse = ""
    Set drid = $ZConvert($ZStrip(pDocasnyRid, "<>W"), "U")
    If '..DRIDTvar(drid) {
        Quit $$$ERROR($$$GeneralError, "Dočasný RID musí mít tvar D + 9 číslic: " _ drid)
    }
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"docasnyRID": (drid), "rid": ($ZStrip(pSkutecnyRid, "<>W"))}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/priradit/docasny_rid", body, .pResponse)
}

/// Reklamace údajů
Method ReklamujUdaj(pReklamaceData As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pReklamaceData
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/reklamuj/udaj", body, .pResponse)
}

/// Sloučení pacientů
Method SlouceniPacientu(pNavrhSlouceni As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pNavrhSlouceni
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/slouceni/zadost", body, .pResponse)
}

/// Rozdělení pacienta
Method RozdeleniPacienta(pNavrhRozdeleni As %DynamicObject, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = pNavrhRozdeleni
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/rozdeleni/zadost", body, .pResponse)
}

/// Žádost o zrušení záznamu
Method ZruseniZadost(pRid As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"rid": (pRid)}
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/pacient/zruseni/zadost", body, .pResponse)
}

// ==========================================================================
// NOTIFIKACE
// ==========================================================================

/// Založí odběr notifikací pro jeden RID (Standard KZR 1.3, kap. 4.5.3.1).
/// pUrl je nepovinná adresa listeneru – bez ní použije KRP výchozí URL
/// poskytovatele z KRPZS; pSubjektId je nepovinné IČO subjektu. Odpověď nese
/// odpovedData.zalozeneNotifikace[].idSubskripce a predmetId.
Method ZalozOdber(pRid As %String, pUrl As %String = "", pSubjektId As %String = "", pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set pResponse = ""
    If $ZStrip(pRid, "<>W") = "" {
        Quit $$$ERROR($$$GeneralError, "Pro založení odběru notifikací zadejte RID.")
    }
    Set data = {"predmet": [{"rid": ($ZStrip(pRid, "<>W"))}]}
    If pUrl '= "" {
        Set data.prijemci = {"url": (pUrl)}
    }
    If pSubjektId '= "" {
        Set data.subjektId = pSubjektId
    }
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = data
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/notifikace/zalozit/odber", body, .pResponse)
}

/// Zruší odběr podle idSubskripce (GUID vrácený při založení) – kap. 4.5.3.2.
Method ZrusOdber(pIdSubskripce As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set pResponse = ""
    If pIdSubskripce = "" {
        Quit $$$ERROR($$$GeneralError, "Pro zrušení odběru notifikací zadejte idSubskripce.")
    }
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = {"idSubskripce": (pIdSubskripce)}
    Quit ..Client.Delete(..#BASEPATH_"/api/"_..#APIVERZE_"/notifikace/zrusit/odber", body, .pResponse)
}

/// Vyhledá odběry podle idSubskripce a/nebo IČO subjektu – kap. 4.5.3.3;
/// alespoň jeden z parametrů musí být zadán.
Method VyhledejOdbery(pIdSubskripce As %String = "", pSubjektId As %String = "", pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set pResponse = ""
    If (pIdSubskripce = "") && (pSubjektId = "") {
        Quit $$$ERROR($$$GeneralError, "Zadejte idSubskripce nebo subjektId (IČO).")
    }
    Set data = {}
    If pIdSubskripce '= "" {
        Set data.idSubskripce = pIdSubskripce
    }
    If pSubjektId '= "" {
        Set data.subjektId = pSubjektId
    }
    Set body = ..BuildRequest(pUcel)
    Set body.zadostData = data
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/notifikace/vyhledat/odber", body, .pResponse)
}

/// Založení odběru notifikací o změnách pacienta – hotové tělo včetně obálky.
/// zadostData dle swaggeru 3.0.6: predmet[].rid, prijemci.url, subjektId
/// (schéma má additionalProperties: false). Pohodlnější je ZalozOdber().
Method ZalozitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/notifikace/zalozit/odber", pOdber, .pResponse)
}

/// Zrušení odběru notifikací
Method ZrusitOdberNotifikaci(pOdber As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Delete(..#BASEPATH_"/api/"_..#APIVERZE_"/notifikace/zrusit/odber", pOdber, .pResponse)
}

/// Vyhledání odběrů notifikací
Method VyhledatOdberyNotifikaci(pKriteria As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/notifikace/vyhledat/odber", pKriteria, .pResponse)
}

// ==========================================================================
// ČÍSELNÍKY
// ==========================================================================

/// Načtení číselníku KRP: POST /api/v3/ciselnik/{nazev} (swagger 3.0.6).
/// Názvy: pohlavi, stat, druh_dokladu, zdravotni_pojistovna, country_service_context.
/// (Dřívější cesta /api/v1/ciselnik/{zadostId}/{typ} ve v3 neexistuje.)
Method Ciselnik(pNazev As %String, pUcel As %String = "LECBA", Output pResponse As %DynamicObject) As %Status
{
    Set body = ..BuildRequest(pUcel)
    Quit ..Client.Post(..#BASEPATH_"/api/"_..#APIVERZE_"/ciselnik/"_pNazev, body, .pResponse)
}

// ==========================================================================
// PRAVIDLA STANDARDU KZR 1.3
// ==========================================================================

/// Tvar DRID platný ve verzi 1.2 i 1.3: "D" a 9 číslic.
ClassMethod DRIDTvar(pDrid As %String) As %Boolean
{
    Quit $Match(pDrid, "^D[0-9]{9}$")
}

/// DRID dle Standardu KZR 1.3: číslo za "D" je dělitelné 13 a není dělitelné 11.
ClassMethod DRIDPlatny(pDrid As %String) As %Boolean
{
    If '..DRIDTvar(pDrid) {
        Quit 0
    }
    Set cislo = +$Extract(pDrid, 2, 10)
    Quit ((cislo # 13) = 0) && ((cislo # 11) '= 0)
}

/// Trvalý RID: 10 číslic, nezačíná nulou, dělitelný 13 a nedělitelný 11.
ClassMethod RIDPlatny(pRid As %String) As %Boolean
{
    If '$Match(pRid, "^[1-9][0-9]{9}$") {
        Quit 0
    }
    Quit ((pRid # 13) = 0) && ((pRid # 11) '= 0)
}

/// Vrátí důvod, proč hodnota nesmí jít do KRP jako jméno nebo příjmení, nebo
/// prázdný řetězec. MZ ČR (3. 11. 2026): ve jméně ani příjmení nesmí být jiné
/// znaky než písmena, spojovník, apostrof a mezera; zástupné hodnoty ("Test",
/// "Neuvedeno", …) zatěžují KRP a ISZR. Volat před každým vyhledáním
/// a před zařazením pacienta do dávky hromadného ztotožnění.
ClassMethod JmenoChyba(pText As %String, pPole As %String = "jméno") As %String
{
    Set text = $ZStrip(pText, "<>W")
    If text = "" {
        Quit ""
    }
    If '$Match(text, "^[\p{L}\p{M} '\x{2019}-]+$") {
        Quit "Pole " _ pPole _ " obsahuje nepovolené znaky; povolena jsou jen písmena, spojovník, apostrof a mezera."
    }
    Set bez = $ZConvert(##class(SEZ.API.UserAgent).BezDiakritiky(text), "L")
    Set slova = $Translate(bez, "-'" _ $Char(8217), "   ")
    For i = 1:1:$Length(slova, " ") {
        Set slovo = $Piece(slova, " ", i)
        Continue:slovo=""
        If ("," _ ..#ZAKAZANAJMENA _ ",") [ ("," _ slovo _ ",") {
            Return "Pole " _ pPole _ " obsahuje zástupnou hodnotu (" _ text _ "), ne jméno skutečné osoby."
        }
    }
    Quit ""
}

// ==========================================================================
// POMOCNÉ METODY
// ==========================================================================

/// Sestaví základní obálku požadavku KRP.
/// Datum musí být ve formátu YYYY-MM-DD (bez času), jinak KRP vrací 400.
Method BuildRequest(pUcel As %String = "LECBA") As %DynamicObject [ Private ]
{
    Set body = {}
    Set body.zadostInfo = {
        "datum": ($ZDATE(+$HOROLOG, 3)),
        "ucel": (pUcel),
        "zadostId": (##class(SEZ.API.Config).NewUUID())
    }
    Quit body
}

}
