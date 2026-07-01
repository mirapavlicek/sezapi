# SEZ API klient pro InterSystems IRIS – Instalace

## Struktura projektu

```
src/
├── cls/SEZ/API/
│   ├── Config.cls           – Konfigurace (SSL, JWT tokeny, parametry připojení)
│   ├── HttpClient.cls       – HTTP klient s mTLS a Bearer autentizací
│   ├── Installer.cls        – Nastavení SSL a test připojení
│   ├── KRP.cls              – Kmenový registr pacientů (24 endpointů)
│   ├── KRPZS.cls            – Kmenový registr poskytovatelů ZS (17 endpointů)
│   ├── KRZP.cls             – Kmenový registr zdravotnických pracovníků (18 endpointů)
│   ├── DocasneUloziste.cls  – Dočasné úložiště zásilek (5 endpointů)
│   ├── EZadanky.cls         – E-žádanky – lab/FT/konziliární (10 endpointů)
│   ├── ELP.cls              – Elektronické lékařské posudky (10 endpointů)
│   ├── SZZ.cls              – Sdílený zdravotní záznam (40 endpointů)
│   ├── Notifikace.cls       – Notifikace CSSN (7 endpointů)
│   ├── EZCA.cls             – Certifikační autorita, podpisy (30 endpointů)
│   └── RegistrOpravneni.cls – Ověření oprávnění (1 endpoint)
├── csp/
│   └── SEZAPI.csp           – Webová konzole pro testování
swagger_specs/               – Stažené Swagger specifikace (JSON)
SEZ_API_Dokumentace.md       – Kompletní dokumentace API
```

## 1. Nahrání tříd do IRIS

V IRIS Terminal nebo Management Portal importujte všechny `.cls` soubory:

```objectscript
Do $System.OBJ.LoadDir("/cesta/k/src/cls/", "ck", .errors, 1)
```

Nebo jednotlivě:

```objectscript
Do $System.OBJ.Load("/cesta/k/src/cls/SEZ/API/Config.cls", "ck")
Do $System.OBJ.Load("/cesta/k/src/cls/SEZ/API/HttpClient.cls", "ck")
// ... atd.
```

## 2. Nastavení SSL konfigurace

**Důležité:** Jeden certifikát EZCA II se používá pro mTLS i podepisování JWT assertion.

### Varianta A – Přes kód (doporučeno)

```objectscript
Do ##class(SEZ.API.Installer).SetupSSL("/cesta/k/krajska_zdravotni.pfx", "heslo-k-pfx", "SEZ_API_T2")
```

### Varianta B – Přes Management Portal

1. Otevřete **System Administration → Security → SSL/TLS Configurations**
2. Vytvořte novou konfiguraci:
   - **Name:** `SEZ_API_T2`
   - **Type:** Client
   - **Certificate file:** `/cesta/k/krajska_zdravotni.pfx`
   - **Private key file:** `/cesta/k/krajska_zdravotni.pfx`
   - **Private key password:** heslo k certifikátu
   - **Private key type:** PKCS12
   - **Protocols:** TLSv1.2, TLSv1.3

## 3. Nasazení CSP stránky

1. Zkopírujte `src/csp/SEZAPI.csp` do CSP adresáře vaší webové aplikace
   (typicky `/opt/irisapp/csp/` nebo příslušný CSP adresář namespace)
2. Otevřete v prohlížeči: `http://vasiris:57772/csp/namespace/SEZAPI.csp`

## 4. Test připojení

### Režim private_key_jwt (doporučený)

JWT assertion se posílá přímo jako Bearer token na API Gateway.
Gateway interně provede výměnu za access token vůči JSU.

```objectscript
// V IRIS Terminal:
Do ##class(SEZ.API.Installer).TestConnection("25488627_KrajskaZdravotniVerejnyTest", , "/certs/krajska_zdravotni.pfx", "heslo", "85cf28c4-c190-406f-bc96-f92ad25b3202")
```

### Režim client_secret (starší, méně doporučený)

```objectscript
Do ##class(SEZ.API.Installer).TestConnection("VAS_CLIENT_ID", "VAS_CLIENT_SECRET")
```

## 5. Příklady použití z ObjectScript

### Konfigurace (private_key_jwt)

```objectscript
Set config = ##class(SEZ.API.Config).%New("25488627_KrajskaZdravotniVerejnyTest", , "25488627")
Set config.P12CertFile = "/certs/krajska_zdravotni.pfx"
Set config.P12CertPassword = "heslo-k-pfx"
Set config.CertUID = "85cf28c4-c190-406f-bc96-f92ad25b3202"
```

### Vyhledání pacienta podle RID

```objectscript
Set krp = ##class(SEZ.API.KRP).%New(config)
Set sc = krp.HledatPodleRID("7653800856", "LECBA", .response)
If $$$ISOK(sc) {
    Write response.%ToJSON()
}
```

Odešle JSON (datum ve formátu YYYY-MM-DD):
```json
{
  "zadostInfo": {"datum": "2026-02-19", "ucel": "LECBA", "zadostId": "..."},
  "zadostData": {"rid": "7653800856"}
}
```

### Vyhledání pacienta podle jména a RČ

```objectscript
Set sc = krp.HledatJmenoPrijmeniRC("Jan", "Novak", "8506151234", "LECBA", .response)
```

### Založení nového pacienta (cizinec)

```objectscript
Set novyPacient = {
    "jmeno": "Hans",
    "prijmeni": "Mueller",
    "datumNarozeni": "1985-03-22T00:00:00+01:00",
    "pohlavi": "M",
    "statniObcanstvi": ["DE"],
    "adresaPobytu": {"stat": "CZ", "obec": "Praha", "psc": 11000, "ulice": "Vinohradska", "cisloPopisne": 48},
    "doklady": [{"typ": "PAS", "cislo": "C01X00T47", "platnostDo": "2030-05-15"}]
}
Set sc = krp.ZalozitPacienta(novyPacient, "Zalozeni cizince", .response)
```

### Vytvoření záznamu alergie (SZZ)

```objectscript
Set szz = ##class(SEZ.API.SZZ).%New(config)

Set alergie = {
    "nazev": "Alergie na penicilin",
    "alergen": {"kod": "91936005", "verze": "1.0.0"},
    "kategorieAlergenu": {"kod": "medication", "verze": "1.0.0"},
    "kriticnost": {"kod": "high", "verze": "1.0.0"},
    "typReakce": {"kod": "allergy", "verze": "1.0.0"},
    "zavaznostReakce": {"kod": "severe", "verze": "1.0.0"},
    "manifestaceReakce": [{"kod": "39579001", "verze": "1.0.0"}],
    "datumZjisteni": "2024-06-15T00:00:00+02:00",
    "poznamka": "Anafylakticka reakce po Amoxicilinu"
}
Set sc = szz.VytvorAlergii("6653225891", alergie, .response)
```

### Odeslání notifikace

```objectscript
Set notif = ##class(SEZ.API.Notifikace).%New(config)
Set msg = ##class(SEZ.API.Notifikace).NovaNotifikace("EZadanky", "ZADANKA_NOVA", "PUSH_PZS", "TMPL_ZADANKA_PRIJEM")
Do msg.%Get("prijemce").%Push({"id": "177550538", "typ": "KRZP"})
Set msg.dataNotifikace.hlavicka = "Nova zadanka k vyrizeni"
Set msg.dataNotifikace.obsah = "Pacient Jan Novak - zadanka na krevni obraz"
Set sc = notif.Odeslat(msg, .response)
```

### Podpis dokumentu (EZCA)

DocumentType enum: ARCHIVATION=0, CADES=1, **PADES=2**, XADES=3, ASIC_S=4, ...

```objectscript
Set ezca = ##class(SEZ.API.EZCA).%New(config)
Set sc = ezca.PodpisDokumentu(
    base64Content,
    2,
    "posudek_ridicske_opravneni.pdf",
    "ElektronickePosudky",
    "d4e5f6a7-b8c9-0123-d4e5-f6a7b8c90123",
    "U2FsdGVkX1+abc123...",
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    1,
    0,
    .response
)
```

### Ověření oprávnění

```objectscript
Set opr = ##class(SEZ.API.RegistrOpravneni).%New(config)
Set sc = opr.Over(1, 5, "PoskytovatelZdravotnickychSluzeb", "00064203", "ZdravotniPracovnik", "177550538", .opravnen)
Write "Opravnen: ", opravnen
```
