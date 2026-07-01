/// Dočasné úložiště SEZ API v1.0.0
/// Base URL: /docasneUloziste
///
/// Autorizační model (dle use case MZČR – Stažení zásilky):
///   VyhledejZasilku a UlozZasilku – fungují na úrovni PZS.
///   DejZasilku – vyžaduje identitu konkrétního zdravotnického pracovníka:
///     1) Autentizace a autorizace PZS + ZP vůči JSU
///     2) Ověření existence ZP v KZR
///     3) Oprávnění ZP na ZD pacienta z Registru práv a mandátů
///   Systémový PZS uživatel bez vazby na ZP → 400 "Pracovník nemá oprávnění".
///   Zdroj: https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58949648
Class SEZ.API.DocasneUloziste Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/docasneUloziste";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Uloží novou zásilku
/// pZasilka - dynamický objekt dle schématu UlozZasilkuCommand
Method UlozZasilku(pZasilka As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/Zasilka/UlozZasilku", pZasilka, .pResponse)
}

/// Načte zásilku podle ID (vyžaduje oprávnění pracovníka v JSU)
Method DejZasilku(pId As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/Zasilka/DejZasilku/"_pId, , .pResponse)
}

/// Vyhledá zásilky dle kritérií.
/// pPrijemce – IČO příjemce, pPoskytovatel – IČO poskytovatele, pAutor – ID autora
Method VyhledejZasilku(pDatumOd As %String, pDatumDo As %String, pPacient As %String = "", pPrijemce As %String = "", pPoskytovatel As %String = "", pAutor As %String = "", pIdZasilky As %String = "", pPage As %Integer = 1, pSize As %Integer = 25, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "datumOd": (pDatumOd),
        "datumDo": (pDatumDo),
        "strankovani": {
            "page": (pPage),
            "size": (pSize)
        }
    }
    If pPacient '= "" Set body.pacient = pPacient
    If pPrijemce '= "" Set body.prijemce = pPrijemce
    If pPoskytovatel '= "" Set body.poskytovatel = pPoskytovatel
    If pAutor '= "" Set body.autor = pAutor
    If pIdZasilky '= "" Set body.idZasilky = pIdZasilky
    Quit ..Client.Post(..#BASEPATH_"/api/v1/Zasilka/VyhledejZasilku", body, .pResponse)
}

/// Zneplatní zásilku
Method ZneplatniZasilku(pId As %String, pVerzeRadku As %String, Output pResponse As %DynamicObject) As %Status
{
    Set params("Id") = pId
    Set params("VerzeRadku") = pVerzeRadku
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/Zasilka/ZneplatniZasilku", "", .params, .pResponse)
}

/// Změní zásilku
Method ZmenZasilku(pId As %String, pVerzeRadku As %String, pZasilka As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set params("Id") = pId
    Set params("VerzeRadku") = pVerzeRadku
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/Zasilka/ZmenZasilku", pZasilka, .params, .pResponse)
}

/// Vytvoří objekt zásilky s povinnými poli.
/// Kódy typ a klasifikace: viz TermX číselníky "medical-document-type" a "document-category".
ClassMethod NovaZasilka(pNazev As %String, pAutor As %String, pPacient As %String, pPoskytovatel As %String, pZP As %String, pIspzs As %String, pTypKod As %String = "11506-3", pKlasifikaceKod As %String = "11503-0") As %DynamicObject
{
    Quit {
        "nazev": (pNazev),
        "autor": (pAutor),
        "pacient": (pPacient),
        "poskytovatel": (pPoskytovatel),
        "zdravotnickyPracovnik": (pZP),
        "ispzs": (pIspzs),
        "typ": {"kod": (pTypKod), "verze": "1.0.0"},
        "klasifikace": {"kod": (pKlasifikaceKod), "verze": "1.0.0"},
        "dostupnost": true,
        "dokument": []
    }
}

/// Přidá dokument do zásilky.
/// pMime: např. "application/fhir+json", "application/pdf"
/// pFormat: "urn:ihe:iti:xds:2017:mimeTypeSufficient"
ClassMethod PridejDokument(pZasilka As %DynamicObject, pNazev As %String, pPacient As %String, pHash As %String, pVelikost As %Integer = 0, pBase64 As %String = "", pCesta As %String = "", pMime As %String = "application/fhir+json", pAutor As %String = "", pPoskytovatel As %String = "") As %Status
{
    Set dok = {
        "nazev": (pNazev),
        "pacient": (pPacient),
        "dostupnost": true,
        "hash": (pHash),
        "velikost": (pVelikost),
        "jazyk": {"kod": "cs", "verze": "5.0.0"},
        "typ": {"kod": "11506-3", "verze": "1.0.0"},
        "klasifikace": {"kod": "11503-0", "verze": "1.0.0"},
        "duvernost": {"kod": "N", "verze": "2.0.0"},
        "format": {"kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient", "verze": "1.0.0"},
        "mime": {"kod": (pMime), "verze": "1.0.0"}
    }
    If pAutor '= "" Set dok.autor = pAutor
    If pPoskytovatel '= "" Set dok.poskytovatel = pPoskytovatel
    If pBase64 '= "" {
        Set dok.soubor = {"soubor": (pBase64)}
    } ElseIf pCesta '= "" {
        Set dok.soubor = {"cesta": (pCesta)}
    }
    Do pZasilka.%Get("dokument").%Push(dok)
    Quit $$$OK
}

}
