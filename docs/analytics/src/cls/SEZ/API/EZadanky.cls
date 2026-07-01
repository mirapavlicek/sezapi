/// E-žádanky SEZ API v1.0.0
/// Base URL: /eZadanky
Class SEZ.API.EZadanky Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Property Config As SEZ.API.Config [ Required ];

Parameter BASEPATH = "/eZadanky";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Config = pConfig
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

/// Získá token pro eŽádanky
Method DejToken(Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/DejToken", , .pResponse)
}

/// Uloží novou žádanku
/// pRequest: {"zadanka": {...}, "zadankaZ": {...}} nebo "zadankaFt"/"zadankaK"
Method UlozZadanku(pRequest As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/eZadanka/UlozZadanku", pRequest, .pResponse)
}

/// Vyhledá žádanky
Method VyhledejZadanku(pDatumOd As %String, pDatumDo As %String, pPacient As %String = "", pPage As %Integer = 1, pSize As %Integer = 25, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "datumOd": (pDatumOd),
        "datumDo": (pDatumDo),
        "strankovani": {"page": (pPage), "size": (pSize)}
    }
    If pPacient '= "" Set body.pacient = pPacient
    Quit ..Client.Post(..#BASEPATH_"/api/v1/eZadanka/VyhledejZadanku", body, .pResponse)
}

/// Vyhledá aktivní žádanky
Method VyhledejAktivniZadanku(pKriteria As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Post(..#BASEPATH_"/api/v1/eZadanka/VyhledejAktivniZadanku", pKriteria, .pResponse)
}

/// Načte žádanku podle ID
Method NactiZadanku(pId As %String, pKodZadanky As %String = "", pKodVzorku As %String = "", pCisloDokladu As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set params = ""
    If pKodZadanky '= "" Set params("KodZadanky") = pKodZadanky
    If pKodVzorku '= "" Set params("KodVzorku") = pKodVzorku
    If pCisloDokladu '= "" Set params("CisloDokladu") = pCisloDokladu
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/NactiZadanku/"_pId, .params, .pResponse)
}

/// Přijme žádanku
Method PrijmiZadanku(pId As %String, pVerzeRadku As %String, pKodZadanky As %String = "", pDatumPlan As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku)
    }
    If pKodZadanky '= "" Set body.kodZadanky = pKodZadanky
    If pDatumPlan '= "" Set body.datumPlanovanehoVysetreni = pDatumPlan
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/PrijmiZadanku", body, .params, .pResponse)
}

/// Vyřídí žádanku
Method VyridZadanku(pId As %String, pVerzeRadku As %String, pZpusobVyrizeni As %DynamicObject, pVysledek As %DynamicObject = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "zpusobVyrizeniZadanky": (pZpusobVyrizeni)
    }
    If $IsObject(pVysledek) Set body.vysledek = pVysledek
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/VyridZadanku", body, .params, .pResponse)
}

/// Stornuje žádanku
Method StornujZadanku(pId As %String, pVerzeRadku As %String, pDuvodStorna As %DynamicObject, pDuvodUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "duvodStornaZadanky": (pDuvodStorna)
    }
    If pDuvodUpresneni '= "" Set body.duvodStornaUpresneni = pDuvodUpresneni
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/StornujZadanku", body, .params, .pResponse)
}

/// Zaznamená neproveditelnost žádanky
Method ZaznacNeproveditelnost(pId As %String, pVerzeRadku As %String, pDuvod As %DynamicObject, pDuvodUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "duvodNeproveditelnostiZadanky": (pDuvod)
    }
    If pDuvodUpresneni '= "" Set body.duvodNeproveditelnostiUpresneni = pDuvodUpresneni
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/ZaznacNeproveditelnostZadanky", body, .params, .pResponse)
}

/// Vrátí žádanku do oběhu
Method VratDoObehu(pId As %String, pVerzeRadku As %String, pDuvod As %DynamicObject, pDuvodUpresneni As %String = "", Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "id": (pId),
        "verzeRadku": (pVerzeRadku),
        "duvodVraceniZadanky": (pDuvod)
    }
    If pDuvodUpresneni '= "" Set body.duvodVraceniUpresneni = pDuvodUpresneni
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/VratZadankuDoObehu", body, .params, .pResponse)
}

/// Stáhne vizualizaci žádanky (HTML/PDF)
Method DejVizualZadanky(pId As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/DejVizualZadanky/"_pId, , .pResponse)
}

/// Stáhne přílohy žádanky
Method DejPrilohyZadanky(pId As %String, Output pResponse As %DynamicObject) As %Status
{
    Quit ..Client.Get(..#BASEPATH_"/api/v1/eZadanka/DejPrilohyZadanky/"_pId, , .pResponse)
}

/// Upraví žádanku
Method UpravZadanku(pId As %String, pVerzeRadku As %String, pUpravy As %DynamicObject, Output pResponse As %DynamicObject) As %Status
{
    Set pUpravy.id = pId
    Set pUpravy.verzeRadku = pVerzeRadku
    Set params = ""
    Quit ..Client.Patch(..#BASEPATH_"/api/v1/eZadanka/UpravZadanku", pUpravy, .params, .pResponse)
}

/// Pomocná metoda: vytvoří laboratorní žádanku
ClassMethod NovaLaboratorniZadanka(pAutor As %String, pPacient As %String, pPoskytovatel As %String, pZP As %String, pIspzs As %String, pIcp As %String, pAdresat As %String) As %DynamicObject
{
    Quit {
        "zadanka": {
            "stav": {"kod": "Nova"},
            "urgentnost": {"kod": "Rutinni"},
            "samoplatce": false,
            "prilozenVzorek": false,
            "omezeniMobility": false,
            "pacientImplantat": false,
            "icpZadatele": (pIcp),
            "zasilka": {
                "nazev": "Laboratorní žádanka",
                "autor": (pAutor),
                "pacient": (pPacient),
                "poskytovatel": (pPoskytovatel),
                "zdravotnickyPracovnik": (pZP),
                "ispzs": (pIspzs),
                "typ": {"kod": "Zadanka"},
                "klasifikace": {"kod": "Laboratorni"}
            },
            "vzorekData": [],
            "metodaData": []
        },
        "zadankaZ": {
            "autorId": (pAutor),
            "zadatelId": (pPoskytovatel),
            "pacient": (pPacient),
            "adresatId": (pAdresat),
            "typZadanky": "LABORATORNI",
            "icp": (pIcp),
            "pozadovanaVysetreni": []
        }
    }
}

}
