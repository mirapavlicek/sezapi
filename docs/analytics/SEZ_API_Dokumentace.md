# SEZ API – Komplexní dokumentace

**Zdroj:** https://gwy-ext-sec-t2.csez.cz/apidoc/
**Datum zpracování:** 2026-02-19
**Prostředí:** T2 (testovací)

---

## Obsah

1. [Přehled API služeb](#1-přehled-api-služeb)
2. [Autentizace a zabezpečení](#2-autentizace-a-zabezpečení)
3. [Dočasné úložiště (SEZ)](#3-dočasné-úložiště-sez)
4. [Elektronické posudky (ELP)](#4-elektronické-posudky-elp)
5. [E-žádanky (SEZ)](#5-e-žádanky-sez)
6. [EZCA 2 – Elektronická certifikační autorita](#6-ezca-2--elektronická-certifikační-autorita)
7. [KRP PZS – Kmenový registr pacientů](#7-krp-pzs--kmenový-registr-pacientů)
8. [KRPZS PZS – Kmenový registr PZS](#8-krpzs-pzs--kmenový-registr-pzs)
9. [KRZP PZS – Kmenový registr ZP](#9-krzp-pzs--kmenový-registr-zp)
10. [Notifikace CSSN](#10-notifikace-cssn)
11. [Registr oprávnění](#11-registr-oprávnění)
12. [Sdílený zdravotní záznam (SZZ)](#12-sdílený-zdravotní-záznam-szz)
13. [TermX Terminologie (FHIR)](#13-termx-terminologie-fhir)
14. [Návrhy JSON zpráv dle specifikace](#14-návrhy-json-zpráv-dle-specifikace)
15. [Přehled chybových formátů](#15-přehled-chybových-formátů)

---

## 1. Přehled API služeb

| # | API | Verze | Base URL | Endpointů | Účel |
|---|-----|-------|----------|-----------|------|
| 1 | Dočasné úložiště SEZ | v1.0.0 | `/docasneUloziste` | 5 | Dočasné ukládání zásilek/dokumentů |
| 2 | Elektronické posudky | v1.0.6 | `/elektronickePosudky` | 10 | Lékařské posudky (řidičské oprávnění) |
| 3 | E-žádanky SEZ | v1.0.0 | `/eZadanky` | 10 | Životní cyklus elektronických žádanek |
| 4 | EZCA 2 | v1.0.0 | `/ezca2` | 30 | Podepisování, razítkování, validace dokumentů |
| 5 | KRP PZS | v2.0.0 | `/krp` | 24 | Kmenový registr pacientů |
| 6 | KRPZS PZS | v2.0.0 | `/krpzs` | 17 | Kmenový registr poskytovatelů ZS |
| 7 | KRZP PZS | v2.0.0 | `/krzp` | 18 | Kmenový registr zdravotnických pracovníků |
| 8 | Notifikace CSSN | v1.0.0 | `/notifikace` | 7 | Odesílání a správa notifikací |
| 9 | Registr oprávnění | v1.0.0 | `/registrOpravneni` | 1 | Ověření oprávnění přístupu |
| 10 | Sdílený zdravotní záznam | v1.0.6 | `/sdilenyZdravotniZaznam` | 40 | Emergentní záznamy, alergie, léčiva, ZZ |
| 11 | TermX Terminologie | v1.0.5 | `/terminologie` | 57 | FHIR terminologický server |

---

## 2. Autentizace a zabezpečení

> **Zdroj:** [Autentizace k API gateway – MZČR Confluence](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/160530443)

### Princip autentizace

**Jeden certifikát EZCA II** slouží pro obojí: mTLS i podepisování JWT assertion.

1. Aplikace vytvoří **JWT assertion** podepsanou privátním klíčem certifikátu EZCA II
2. Tentýž certifikát se použije jako **klientský certifikát** pro mTLS (TLS handshake)
3. JWT assertion se pošle **přímo na API Gateway** v hlavičce `Authorization: Bearer <JWT_assertion>`
4. API Gateway si **sama vyřídí** access token ze systému JSU (interně)
5. API Gateway vrátí aplikaci odpověď

> **Pozor:** Nelze použít jiný certifikát pro mTLS a jiný pro JWT signing.
> Gateway ověřuje, že certifikát v TLS odpovídá klíči v JWT assertion.

### Potřebný certifikát

Certifikát musí být registrován v EZCA II. Pro testovací prostředí:

| Parametr | Hodnota |
|----------|---------|
| Název | krajska zdravotni verejny test |
| client_id | `25488627_KrajskaZdravotniVerejnyTest` |
| UID (kid) | `85cf28c4-c190-406f-bc96-f92ad25b3202` |
| IČO | 25488627 |
| PZS | Krajská zdravotní, a.s. |

### JWT assertion – hlavička (header)

```json
{
  "alg": "RS256",
  "kid": "85cf28c4-c190-406f-bc96-f92ad25b3202",
  "typ": "JWT"
}
```

- `alg` – RS256 (RSA + SHA-256)
- `kid` – **UID certifikátu** z EZCA II (GUID)

### JWT assertion – payload (claims)

```json
{
  "iss": "25488627_KrajskaZdravotniVerejnyTest",
  "sub": "25488627_KrajskaZdravotniVerejnyTest",
  "aud": "https://jsuint-auth-t2.csez.cz/connect/token",
  "jti": "3f91f203-3b2c-4c8e-bb7e-2e9326c4dd87",
  "iat": 1771522256,
  "exp": 1771522311
}
```

- `iss`, `sub` – `client_id` (formát: `<IČO>_<CN>`)
- `aud` – token endpoint JSU: testovací `https://jsuint-auth-t2.csez.cz/connect/token`, produkční `https://jsuint-auth-ez.csez.cz/connect/token`
- `jti` – unikátní UUID (ochrana proti replay)
- `iat` – Unix timestamp vydání
- `exp` – expirace (do 60 sekund od `iat`)

### JWT assertion – podpis

Assertion se podepisuje **privátním klíčem** z certifikátu EZCA II (formát PFX/P12) algoritmem RS256.

### Společné hlavičky

| Hlavička | Typ | Popis |
|----------|-----|-------|
| `Authorization` | string | `Bearer <JWT_assertion>` |
| `Content-Type` | string | `application/json` |
| `Accept-Language` | string | Jazyk odpovědi (`cs`, `en`, `de`), výchozí `cs` |
| `User-Agent` | string | `<název-aplikace>/<verze> (Test\|Prod; výrobceSW)` – **povinná od 1. 9. 2026** |
| `X-Correlation-Id` | uuid | ID korelace pro trasování |
| `X-Trace-Id` | uuid | ID trasování |
| `If-Match` | string | ETag pro optimistickou souběžnost (SZZ, ELP) |

#### User-Agent v IRIS / CSP

`%Net.HttpRequest` si bez explicitního nastavení doplní vlastní
`User-Agent: Mozilla/4.0 (compatible; ...)`, které formátu SEZ nevyhovuje –
hlavičku je proto nutné nastavit u **každého** requestu. Hodnotu sestavuje
`SEZ.API.Config:UserAgent()` (prostředí se odvodí z hostname brány, výrobce
a název aplikace jsou parametry `VENDOR`, `APPNAME`, `APPVERSION`):

```objectscript
Set req = ##class(%Net.HttpRequest).%New()
Do req.SetHeader("User-Agent", ##class(SEZ.API.Config).UserAgent())
Do req.SetHeader("X-Correlation-Id", ##class(SEZ.API.Config).NewUUID())
```

V CSP stránce (`SEZAPI.csp`, záložka *Konfigurace*) se efektivní hodnota
zobrazuje přes výraz `#(##class(SEZ.API.Config).UserAgent())#`. Pro příchozí
volání (např. `%CSP.REST` endpoint pro notifikace) se hlavička naopak jen čte:
`%request.GetCgiEnv("HTTP_USER_AGENT")`.

---

## 3. Dočasné úložiště (SEZ)

> **Zdroj:** [API Dočasného úložiště – MZČR Confluence](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58916867)

**Base URL:** `/docasneUloziste`
**OpenAPI:** 3.1.0 | **Verze:** v1.0.0

Dočasné úložiště (DÚ) umožňuje bezpečné dočasné ukládání zdravotnických záznamů a jejich zpřístupnění autorizovaným subjektům. Maximální doba uložení je **30 dní** (eŽádanky 3 roky). DÚ validuje odesílatele i příjemce vůči KZR a ověřuje oprávnění přes Registr práv a mandátů.

### Endpointy

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v1/Zasilka/UlozZasilku` | Uložení nové zásilky (SubmissionSet) |
| `GET` | `/api/v1/Zasilka/DejZasilku/{id}` | Stažení zásilky (vyžaduje identitu ZP – viz níže) |
| `POST` | `/api/v1/Zasilka/VyhledejZasilku` | Vyhledání zásilek dle kritérií |
| `PATCH` | `/api/v1/Zasilka/ZneplatniZasilku` | Zneplatnění zásilky (pouze odesílatel) |
| `PUT` | `/api/v1/Zasilka/ZmenZasilku` | Změna zásilky (před stažením) |

### Autorizace DÚ

> **Zdroj:** [Případ užití: Stažení zásilky](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58949648)

DÚ provádí při každém volání:
1. Autentizaci a autorizaci PZS a zdravotnického pracovníka vůči JSU
2. Ověření existence subjektů v KZR (pacient dle RID, PZS, ZP)
3. Kontrolu oprávnění v Registru práv a mandátů
4. Validaci integrity (hash, elektronický podpis via EZCA)

**Důležité pro `DejZasilku`:** Tato služba vyžaduje identitu konkrétního **zdravotnického pracovníka** (ZP):
- ZP musí existovat v KZR
- ZP musí mít oprávnění na zdravotnickou dokumentaci pacienta v Registru práv a mandátů
- Systémový PZS uživatel (bez vazby na ZP) obdrží chybu `400: "Pracovník nemá oprávnění získat detail této zásilky"`
- `VyhledejZasilku` a `UlozZasilku` fungují i na úrovni PZS (bez konkrétního ZP)

### Číselníky DÚ – kompletní přehled kódů

> Zdroj: [Terminologický server](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935117) + hodnoty ověřeny z reálných dat T2 prostředí.

#### `stav-zasilky` – stav zásilky

| Kód | Název | Verze |
|-----|-------|-------|
| `0` | Uložena | 1.0.0 |

#### `medical-document-type` – typ zásilky / dokumentu

| Kód | Název | Verze |
|-----|-------|-------|
| `11506-3` | Průběžná zpráva | 1.0.0 |
| `67781-5` | Zpráva o vyšetření či ošetření | 1.0.0 |
| `34748-4` | Zpráva o telekonzultaci | 1.0.0 |
| `74207-2` | Souhrn pre-hospitalizační péče | 1.0.0 |

#### `document-category` – klasifikace zásilky / dokumentu

| Kód | Název | Verze |
|-----|-------|-------|
| `11503-0` | Lékařské záznamy | 1.0.0 |
| `26436-6` | Laboratorní nálezy | 1.0.0 |
| `18682-5` | Záznamy zdravotnické záchranné služby | 1.0.0 |
| `107904-5` | Administrativní záznamy | 1.0.0 |
| `57133-1` | Žádanky | 1.0.0 |

#### `typ-adresata` – typ adresáta

| Kód | Název | Verze |
|-----|-------|-------|
| `PZS` | Poskytovatel zdravotních služeb | 1.0.0 |
| `PAT` | Pacient | 1.0.0 |

#### `v3-Confidentiality` – důvěrnost dokumentu

| Kód | Název | Verze |
|-----|-------|-------|
| `N` | normální | 2.0.0 |
| `M` | střední | 2.0.0 |

#### `format-code` – formát dokumentu

| Kód | Název | Verze |
|-----|-------|-------|
| `urn:ihe:iti:xds:2017:mimeTypeSufficient` | MimeType specifikovaný | 1.0.0 |
| `urn:ihe:iti:xds-sd:pdf:2008` | XDS-SD naskenované PDF | 1.0.0 |
| `urn:ihe:rad:PDF` | XDS-I PDF (XDS-I) | 1.0.0 |
| `urn:cz-mzcr:ns:dasta:ds4:ds_dasta` | DASTA v.4 | 1.0.0 |

#### `media-type` – MIME typ dokumentu

| Kód | Název | Verze |
|-----|-------|-------|
| `application/pdf` | PDF | 1.0.0 |
| `application/fhir+json` | FHIR (JSON) | 1.0.0 |
| `text/plain` | Plain text | 1.0.0 |
| `image/gif` | GIF Graphics Interchange Format | 1.0.0 |

#### `languages` – jazyk dokumentu

| Kód | Název | Verze |
|-----|-------|-------|
| `cs` | čeština | 5.0.0 |
| `cs-CZ` | čeština (Česko) | 5.0.0 |

#### `event-code` – událost (volitelné)

| Kód | Název | Verze |
|-----|-------|-------|
| `US` | Ultrazvuk | 2.0.0 |
| `DX` | Digitální radiografie | 2.0.0 |
| `ES` | Endoskopie | 2.0.0 |
| `OP` | Oftalmologická fotografie | 2.0.0 |
| `OPT` | Oftalmologická tomografie | 2.0.0 |
| `IVOCT` | Intravaskulární optická koherenční tomografie | 2.0.0 |

#### `odbornosti-snomed-ct` – odbornost (volitelné)

| Kód | Název | Verze |
|-----|-------|-------|
| `24251000087109` | General pediatric specialty | 1.0.0 |

#### Formát položky číselníku (`PolozkaCiselniku`)

```json
{
  "ciselnikKod": "medical-document-type",
  "kod": "11506-3",
  "verze": "1.0.0",
  "nazev": "Průběžná zpráva",
  "popis": null
}
```

V **requestu** stačí posílat `ciselnikKod`, `kod`, `verze`. Pole `nazev` a `popis` doplňuje DÚ v response.

### Datový model – Zásilka

Povinná pole: `nazev`, `typ`, `klasifikace`, `datumOd`, `datumDo`, `autor`, `zdravotnickyPracovnik`, `poskytovatel`, `pacient`, `ispzs`, `adresat`, `adresatTyp`, `dostupnost`

```
Zásilka
├── id (string) – UUID, přiřadí DÚ (read-only)
├── verzeRadku (string) – concurrency control (read-only, potřeba pro ZmenZasilku/ZneplatniZasilku)
├── nazev (string) * – název zásilky
├── popis (string) – podrobný popis
├── stav (PolozkaCiselniku) – stav-zasilky (read-only, přiřadí DÚ)
├── typ (PolozkaCiselniku) * – medical-document-type
├── klasifikace (PolozkaCiselniku) * – document-category
├── odbornost (PolozkaCiselniku) – odbornosti-snomed-ct
├── datumOd (string) * – datum zpřístupnění (ISO 8601)
├── datumDo (string) * – datum ukončení dostupnosti (ISO 8601)
├── datumVytvoreni (string) – přiřadí DÚ (read-only)
├── autor (string) * – NRZP autora (vazba na KRZP)
├── zdravotnickyPracovnik (string) * – NRZP pracovníka (vazba na KRZP)
├── poskytovatel (string) * – IČO poskytovatele (vazba na KRPZS)
├── pacient (string) * – RID pacienta (vazba na KRP)
├── ispzs (string) * – název informačního systému PZS
├── adresat (string) * – IČO/RID příjemce
├── adresatTyp (PolozkaCiselniku) * – typ-adresata (PZS/PAT)
├── adresatData (object) – rozšířená data adresáta (read-only)
├── dostupnost (boolean) * – status dostupnosti
├── rodic (string) – ID nadřazené zásilky
├── udalost (PolozkaCiselniku) – event-code
├── datumUkonceniPublikovani (string) – read-only
└── dokument[] (Dokument)
    ├── id (string) – UUID, přiřadí DÚ (read-only)
    ├── verzeRadku (string) – read-only
    ├── nazev (string) * – název dokumentu
    ├── popis (string) – popis dokumentu
    ├── jazyk (PolozkaCiselniku) * – languages
    ├── typ (PolozkaCiselniku) * – medical-document-type
    ├── klasifikace (PolozkaCiselniku) * – document-category
    ├── kod (string) – interní kód dokumentu
    ├── autor (string) * – NRZP autora
    ├── poskytovatel (string) * – IČO poskytovatele
    ├── pacient (string) * – RID pacienta
    ├── dostupnost (boolean) * – dostupnost dokumentu
    ├── duvernost (PolozkaCiselniku) * – v3-Confidentiality
    ├── format (PolozkaCiselniku) – format-code
    ├── mime (PolozkaCiselniku) – media-type
    ├── hash (string) * – SHA-256 kontrolní součet (64 hex znaků)
    ├── velikost (number) * – velikost obsahu v bajtech (před base64)
    ├── vazanyDokument (string) – ID vazaného dokumentu
    ├── soubor (Soubor) * – { id, soubor: base64, cesta: string }
    └── slozka (Slozka) – { id, verzeRadku, nazev, autor, datumVytvoreni }
```

### Příklady request/response pro všechny operace DÚ

#### 3.1 VyhledejZasilku – request

`POST /docasneUloziste/api/v1/Zasilka/VyhledejZasilku`

```json
{
  "datumOd": "2026-01-01T00:00:00+01:00",
  "datumDo": "2026-12-31T23:59:59+01:00",
  "pacient": "2667873559",
  "strankovani": {
    "page": 1,
    "size": 25
  }
}
```

Volitelné filtry: `pacient`, `prijemce`, `poskytovatel`, `autor`, `idZasilky`

#### 3.2 VyhledejZasilku – response

```json
{
  "zasilka": [
    {
      "id": "cac1aef9-0bb4-4a8b-868f-d54136733461",
      "verzeRadku": "AAAAAAABDXU=",
      "nazev": "Laboratorní zpráva",
      "popis": null,
      "stav": {
        "ciselnikKod": "stav-zasilky",
        "kod": "0",
        "verze": "1.0.0",
        "nazev": "Uložena",
        "popis": "Uložena"
      },
      "typ": {
        "ciselnikKod": "medical-document-type",
        "kod": "11506-3",
        "verze": "1.0.0",
        "nazev": "Průběžná zpráva",
        "popis": null
      },
      "klasifikace": {
        "ciselnikKod": "document-category",
        "kod": "11503-0",
        "verze": "1.0.0",
        "nazev": "Lékařské záznamy",
        "popis": null
      },
      "odbornost": null,
      "datumOd": "2026-02-19T16:03:58.8819895",
      "datumDo": "2026-03-22T16:03:58.8819895",
      "datumVytvoreni": "2026-02-19T16:03:58.8933333",
      "autor": "175702010",
      "autorData": null,
      "zdravotnickyPracovnik": "175702010",
      "zdravotnickyPracovnikData": null,
      "poskytovatel": "28821599",
      "poskytovatelData": null,
      "pacient": "8011194950",
      "pacientData": null,
      "ispzs": "Stapro OpenLIMS",
      "adresat": "28821599",
      "adresatData": {
        "zdravotnickyPracovnik": null,
        "pacient": null,
        "poskytovatel": null
      },
      "adresatTyp": {
        "ciselnikKod": "typ-adresata",
        "kod": "PZS",
        "verze": "1.0.0",
        "nazev": "Poskytovatel zdravotních služeb",
        "popis": "Poskytovatel zdravotních služeb"
      },
      "dostupnost": true,
      "rodic": null,
      "udalost": null,
      "datumUkonceniPublikovani": "2026-03-22T16:03:58.8819895",
      "dokument": [
        {
          "id": "3c943e0d-6435-4b6d-9782-dc8d30262c65",
          "verzeRadku": "AAAAAAABDXc=",
          "nazev": "Laboratorní zpráva",
          "popis": null,
          "jazyk": {
            "ciselnikKod": "languages",
            "kod": "cs",
            "verze": "5.0.0",
            "nazev": "čeština",
            "popis": null
          },
          "typ": {
            "ciselnikKod": "medical-document-type",
            "kod": "67781-5",
            "verze": "1.0.0",
            "nazev": "Zpráva o vyšetření či ošetření",
            "popis": null
          },
          "klasifikace": {
            "ciselnikKod": "document-category",
            "kod": "11503-0",
            "verze": "1.0.0",
            "nazev": "Lékařské záznamy",
            "popis": null
          },
          "kod": null,
          "autor": "175702010",
          "poskytovatel": "28821599",
          "pacient": "8011194950",
          "dostupnost": true,
          "duvernost": {
            "ciselnikKod": "v3-Confidentiality",
            "kod": "N",
            "verze": "2.0.0",
            "nazev": "normální",
            "popis": null
          },
          "format": {
            "ciselnikKod": "format-code",
            "kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient",
            "verze": "1.0.0",
            "nazev": "MimeType specifikovaný",
            "popis": null
          },
          "mime": {
            "ciselnikKod": "media-type",
            "kod": "application/fhir+json",
            "verze": "1.0.0",
            "nazev": "FHIR (JSON)",
            "popis": null
          },
          "hash": "61d656b3b326cf1c2c749c740ba618c58de8865331bc31a9429f09a0278fa1a6",
          "velikost": 30152,
          "vazanyDokument": null,
          "soubor": {
            "id": "bf49d8f3-10d5-4b44-a5e0-666237a3d0cf",
            "soubor": null,
            "cesta": null
          },
          "slozka": null
        }
      ]
    }
  ]
}
```

> **Poznámka:** Při vyhledávání `soubor.soubor` je `null` – obsah se nestahuje. Pro stažení obsahu je nutné volat `DejZasilku/{id}`.

#### 3.3 DejZasilku – request / response

`GET /docasneUloziste/api/v1/Zasilka/DejZasilku/{id}`

Parametry: `id` (UUID zásilky z VyhledejZasilku)

Response: stejná struktura jako zásilka v 3.2, ale pole `soubor.soubor` obsahuje **base64-encoded obsah dokumentu**.

> **Vyžaduje identitu ZP:** Tato služba vrací `400 "Pracovník nemá oprávnění"` při použití systémového PZS certifikátu.
> Pro stažení je nutný **uživatelský certifikát EZCA II** s vazbou na konkrétního ZP registrovaného v KRZP.
> Viz [Případ užití: Stažení zásilky](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58949648).

#### 3.4 ZneplatniZasilku – request

`PUT /docasneUloziste/api/v1/Zasilka/ZneplatniZasilku`

> Pouze odesílatel může zneplatnit zásilku. Vyžaduje `id` a `verzeRadku` z VyhledejZasilku.

```json
{
  "id": "cac1aef9-0bb4-4a8b-868f-d54136733461",
  "verzeRadku": "AAAAAAABDXU="
}
```

#### 3.5 ZmenZasilku – request

`PUT /docasneUloziste/api/v1/Zasilka/ZmenZasilku/{id}`

> Změna je možná pouze před stažením zásilky adresátem. Struktura těla je stejná jako UlozZasilku, ale musí obsahovat `id` a `verzeRadku`.

```json
{
  "id": "cac1aef9-0bb4-4a8b-868f-d54136733461",
  "verzeRadku": "AAAAAAABDXU=",
  "nazev": "Laboratorní zpráva – opraveno",
  "popis": "Opravená verze zprávy",
  "typ": {
    "ciselnikKod": "medical-document-type",
    "kod": "11506-3",
    "verze": "1.0.0"
  },
  "klasifikace": {
    "ciselnikKod": "document-category",
    "kod": "11503-0",
    "verze": "1.0.0"
  },
  "datumOd": "2026-02-20T08:00:00+01:00",
  "datumDo": "2026-03-22T08:00:00+01:00",
  "autor": "102129137",
  "zdravotnickyPracovnik": "102129137",
  "poskytovatel": "25488627",
  "pacient": "2667873559",
  "ispzs": "NIS Krajska zdravotni",
  "adresat": "25488627",
  "adresatTyp": {
    "ciselnikKod": "typ-adresata",
    "kod": "PZS",
    "verze": "1.0.0"
  },
  "dostupnost": true,
  "dokument": []
}
```

---

## 4. Elektronické posudky (ELP)

**Base URL:** `/elektronickePosudky`
**OpenAPI:** 3.0.4 | **Verze:** v1.0.6
**Popis:** Externí API systému ELP – určeno pro PZS

### Endpointy

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v1/posudky/ridicskeOpravneni` | Vytvoření posudku |
| `POST` | `/api/v1/posudky/ridicskeOpravneni/vyhledat` | Vyhledání posudků |
| `GET` | `/api/v1/posudky/ridicskeOpravneni/{id}` | Detail posudku |
| `PATCH` | `/api/v1/posudky/ridicskeOpravneni/{id}/zneplatnit` | Zneplatnění posudku |
| `GET` | `/api/v1/posudky/ridicskeOpravneni/{id}/pdf` | Stažení PDF posudku |
| `GET` | `/api/v1/posudky/ridicskeOpravneni/{id}/historie` | Historie změn |
| `GET` | `/api/v1/ciselniky` | Seznam číselníků |
| `GET` | `/api/v1/ciselniky/{kod}/polozky` | Položky číselníku |

### Datový model – Posudek (řidičské oprávnění)

Povinná pole při vytvoření: `rid`, `datumVysetreni`, `datumVystaveni`, `druhPosudku`, `druhProhlidky`, `odbornostLekare`, `skupinaZadatelRidic`, `stavPosudku`, `typAkce`, `vysledek`

```
PosudekRoCreateDto
├── rid (string, 1–20) – identifikátor pacienta
├── krzpId (string, max 50) – identifikátor ZP
├── ico, icp (string)
├── druhPosudku, druhProhlidky, vysledek, ... (CiselnikPolozka)
├── datumVysetreni, datumVystaveni (date)
├── platnostDo (date, nullable)
├── zduvodneni (string)
├── skupinyRidicskehoOpravneni[] (skupina ŘO)
├── odbornaVysetreni[] (vyšetření + datum)
├── harmonizovaneKody[] (EU harmonizované kódy)
├── narodniKody[] (národní kódy)
└── prilohy[] (nazev, dataBase64, hashSha256 [64 hex znaků], mimeType, velikostB)
```

---

## 5. E-žádanky (SEZ)

**Base URL:** `/eZadanky`
**OpenAPI:** 3.0.4 | **Verze:** v1.0.0

### Endpointy – životní cyklus žádanky

| Metoda | Cesta | Popis | Stav žádanky |
|--------|-------|-------|-------------|
| `POST` | `.../UlozZadanku` | Vytvoření žádanky | → Nová |
| `POST` | `.../VyhledejZadanku` | Vyhledání | — |
| `POST` | `.../VyhledejAktivniZadanku` | Vyhledání aktivních | — |
| `GET` | `.../NactiZadanku/{id}` | Načtení detailu | — |
| `PATCH` | `.../PrijmiZadanku` | Přijetí žádanky | → Přijata |
| `PATCH` | `.../VyridZadanku` | Vyřízení žádanky | → Vyřízena |
| `PATCH` | `.../VratZadankuDoObehu` | Vrácení do oběhu | → V oběhu |
| `PATCH` | `.../ZaznacNeproveditelnostZadanky` | Neproveditelnost | → Neproveditelná |
| `PATCH` | `.../StornujZadanku` | Stornování | → Stornována |
| `PATCH` | `.../UpravZadanku` | Úprava žádanky | — |

### Typy žádanek

| Typ | DTO | Obsah |
|-----|-----|-------|
| **Laboratorní (Z)** | `SestavSouborZadankyRequestDto` | požadovaná vyšetření, biometrické údaje, urgentní informace, kontraindikace, implantáty |
| **Fyzioterapeutická (Ft)** | `SestavSouborFtZadankyRequestDto` | stav pacienta, cíl, část těla, druh péče, výkony FT |
| **Konziliární (K)** | `SestavSouborKonziliarniZadankyRequestDto` | typ vyšetření, doporučení, anamnéza, výsledky vyšetření, diferenciální rozvaha |

### Datový model žádanky

```
Zadanka
├── id (uuid), verzeRadku (binary)
├── stav, urgentnost (PolozkaCiselnikuDto)
├── kod (string, max 100)
├── samoplatce, prilozenVzorek, omezeniMobility, pacientImplantat (boolean)
├── datumExpirace, datumPlanovanehoVysetreni (date-time)
├── icpZadatele (string)
├── zasilka (Zasilka) – vazba na dočasné úložiště
├── vzorekData[] (Vzorek – materiál, datum odběru, pokyny)
├── dodatecnyPrijemce[] (adresát + typ)
├── metodaData[] (PolozkaCiselnikuDto)
└── [typově specifická data dle Z/Ft/K]
```

### FHIR vzory v žádankách

E-žádanky používají FHIR-inspirované datové typy:
- **CodeableConcept** – `coding[]` (system, code, display) + `text`
- **Coding** – `system`, `code`, `display`
- **IdentifikatorModel** – `use`, `system`, `value`, `type`

---

## 6. EZCA 2 – Elektronická certifikační autorita

**Base URL:** `/ezca2`
**OpenAPI:** 3.0.4 | **Verze:** v1.0.0

### Funkční oblasti

| Oblast | Endpointy (sync/async) | Popis |
|--------|----------------------|-------|
| **Certificate** | `POST /api/list/certificates` | Výpis podepsaných certifikátů |
| **Document** | `POST /api/create/document` | Vytvoření dokumentu v EZCA |
| **SignDocument** | `POST /api/sign/document` | Podepsání dokumentu |
| **SignHash** | `POST /api/sign/hash` | Podepsání hashe |
| **StampDocument** | `POST /api/stamp/document` | Časové razítko dokumentu |
| **StampHash** | `POST /api/stamp/hash` | Časové razítko hashe |
| **ValidateDocument** | `POST /api/validate/document` | Validace podpisu |
| **XADES** | `POST /api/create/xades` | Vytvoření XAdES obálky |
| **SpecificReport** | `POST /api/content/report` | Generování reportu |

Každý endpoint existuje i v async variantě (`/api/signasync/document` atd.).

### Podporované formáty dokumentů (DocumentTypeEnum)

`ARCHIVATION`, `CADES`, `PADES`, `XADES`, `ASIC_S`, `ASIC_E`, `CADES_ATTACHED`, `CADES_DETACHED`, `DOCX`, `XLSX`, `EML`, `MSG`, `JADES`

### Hash algoritmy (HashAlgorithmEnum)

`MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512` (+ Cng varianty)

---

## 7. KRP PZS – Kmenový registr pacientů

**Base URL:** `/krp`
**OpenAPI:** 3.0.1 | **Verze:** v2.0.0
**Kontakt:** SLE01 – Kmenové registry, `csez@mzd.gov.cz`

### Endpointy – Pacient (výběr)

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v2/pacient/hledat/rid` | Vyhledání podle RID |
| `POST` | `/api/v2/pacient/hledat/uni` | Univerzální vyhledání |
| `POST` | `/api/v2/pacient/hledat/jmeno_prijmeni_rc` | Podle jména a RČ |
| `POST` | `/api/v2/pacient/hledat/jmeno_prijmeni_datum_narozeni` | Podle jména a data narození |
| `POST` | `/api/v2/pacient/hledat/doklady` | Podle dokladů |
| `POST` | `/api/v2/pacient/hledat/cizinec_cp` | Cizinec podle č. pojištěnce |
| `POST` | `/api/v2/pacient/hledat/historie_pojisteni` | Historie pojištění |
| `POST` | `/api/v2/pacient/hledat/historie_registrujicich_lekaru` | Historie registrujících lékařů |
| `POST` | `/api/v2/pacient/zalozit/pacient` | Založení pacienta |
| `POST` | `/api/v2/pacient/zmenit/pacient` | Změna pacienta |
| `POST` | `/api/v2/pacient/generovat/docasny_rid` | Generování dočasného RID |
| `POST` | `/api/v2/pacient/slouceni/zadost` | Sloučení pacientů |
| `POST` | `/api/v2/pacient/rozdeleni/zadost` | Rozdělení pacientů |
| `POST` | `.../ztotoznihromadne/zadost` | Hromadné ztotožnění (multipart) |

### Datový model – Pacient

```
Pacient
├── stavZaznamu (StatusZaznamu: "Platny" | "Zruseny")
├── typZaznamuPacienta ("Kmenovy" | "Castecny" | "Docasny")
├── rid (string) – resortní identifikátor
├── jmeno, prijmeni, rodnePrijmeni (KZRString – hodnota + stav + zdroj)
├── datumNarozeni, datumUmrti (KZRDate)
├── pohlavi (KZRString)
├── adresaPobytu, adresaTrvalehoPobytu, adresaZasilaci (KZRAdresaDetail)
│   └── ruianId, stat, obec, psc, ulice, cisloPopisne, ...
├── doklady[] (KZRDoklad – cislo, typDokladu, stat)
├── prubehPojisteni[] (KZRPrubehPojisteni – pojistovna, platneOd/Do)
├── registrujiciLekar[] (KZRRegistrujiciLekar)
├── referencniOsoby[] (KZRReferencniOsoba)
├── statniObcanstvi[] (KZRString)
├── telefon, email (KZRString)
└── matkaNovorozence (MatkaNovorozence)
```

### KZR obálky (wrapper typy)

Všechny KZR registry sdílí metadatové obálky:
- **KZRDotaz** – `datum` (date-time), `ucel` (string), `zadostId` (uuid)
- **KZROdpoved** – `stav`, `zadostId`, `odpovedId`, `chybyZpracovani[]`
- **KZRString** / **KZRDate** / **KZRLong** – hodnota + `referencni` (bool) + `stav` + `zdroj`

---

## 8. KRPZS PZS – Kmenový registr PZS

**Base URL:** `/krpzs`
**OpenAPI:** 3.0.1 | **Verze:** v2.0.0

### Endpointy

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v2/Poskytovatel/hledat/ico` | Vyhledání PZS podle IČO |
| `POST` | `/api/v2/Poskytovatel/hledat/nazev` | Vyhledání PZS podle názvu |
| `POST` | `/api/v2/Poskytovatel/hledat/misto` | Vyhledání PZS podle místa |
| `POST` | `/api/v2/Poskytovatel/reklamuj/udaj` | Reklamace údajů |
| `POST` | `/api/v2/Poskytovatel/nastavit/urlpronotifikace` | Nastavení URL pro notifikace |

### Datový model – Poskytovatel zdravotních služeb

```
PZSDetail
├── stavZaznamu (string)
├── ico (KZRString)
├── poskytovatelNazev (KZRString)
├── adresaSidla (KZRAdresaDetail)
├── datovaSchranka, kontaktniEmail, kontaktniTelefon, kontaktniWeb (KZRString)
├── typPoskytovatele (KZRInt)
└── opravneni[] (Opravneni)
    ├── spravniOrgan (string)
    ├── rozhodnuti[] (Rozhodnuti)
    └── mistaPoskytovani[] (MistoPoskytovani)
        ├── adresa (KZRAdresaDetail)
        ├── sluzby[] (Sluzba – druh, forma, obor péče)
        └── zdravotnickeZarizeni[] (ZdravotnickeZarizeni)
            ├── oddeleni[] (lůžka, ordinační doba)
            ├── pristrojovaTechnika[]
            └── vymennaSit
```

---

## 9. KRZP PZS – Kmenový registr ZP

**Base URL:** `/krzp`
**OpenAPI:** 3.0.1 | **Verze:** v2.0.0

### Endpointy

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v2/pracovnik/hledat/krzpid` | Vyhledání podle KRZP ID |
| `POST` | `/api/v2/pracovnik/hledat/jmenoPrijmeniDatumNarozeni` | Podle jména a data narození |
| `POST` | `/api/v2/pracovnik/hledat/personalistika` | Pro personalistiku |
| `POST` | `/api/v2/pracovnik/hledat/zamestnavatel` | Podle zaměstnavatele |
| `POST` | `/api/v2/pracovnik/reklamuj/udaj` | Reklamace údajů |

### Datový model – Zdravotnický pracovník

```
ZdravotnickyPracovnik
├── stavZaznamu, krzpid
├── jmeno, prijmeni, rodnePrijmeni (KZRString)
├── datumNarozeni (KZRDate)
├── pohlavi, mistoNarozeni (KZRString)
├── titulPred, titulZa (KZRString)
├── email, telefon, dalsiKontakt (KZRString)
├── jeLekar (boolean)
├── ztotozenaOsoba (boolean)
├── adresaPobytu (KZRAdresaDetail)
├── doklady[] (Doklad)
├── statniObcanstvi[] (KZRString)
├── clenstviVKomorach[] (Komora)
├── kmen[] (KmenPracovnik – certifikát, instituce)
├── odbornaZpusobilost[] (OdbornaZpusobilost – obor, diplom, datum)
├── specializovanaZpusobilost[] (SpecializovanaZpusobilost)
├── zvlastniZpusobilost[] (ZvlastniOdbornaZpusobilost)
├── omezeniVykonuPovolani[] (OmezeniVykonuPovolani)
└── zamestnani[] (Zamestnani – ICO poskytovatele, druh/forma/obor péče)
```

---

## 10. Notifikace CSSN

**Base URL:** `/notifikace`
**OpenAPI:** 3.0.1 | **Verze:** v1.0.0

### Endpointy

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v1/notifikace/odeslat` | Odeslání notifikace |
| `GET` | `/api/v1/notifikace/vyhledat` | Vyhledání notifikací |
| `GET` | `/api/v1/notifikace/ping` | Kontrola dostupnosti |
| `POST` | `/api/v1/pzs/prijem/vzor` | Vzorová push notifikace pro PZS |
| `GET` | `/api/v1/kanaly/katalog` | Katalog kanálů |
| `GET` | `/api/v1/sablony/katalog` | Katalog šablon |
| `GET` | `/api/v1/zdroje/katalog` | Katalog zdrojů |

### Datový model – Odeslání notifikace

```
NotifikaceOdeslatRequestModel
├── idKorelace (string) – korelační ID
├── zdrojovySystem (string) – identifikátor zdroje
├── typ (string) – typ notifikace
├── kanal (string) – kanál doručení
├── sablona (string) – kód šablony
├── casovaZnacka (date-time)
├── planOdeslani (date-time, nullable) – plánované odeslání
├── prijemce[] (TypPrijemce)
│   ├── id, typ (string)
│   ├── email, telefon (string)
│   └── urlSluzby (string) – URL pro push
└── doruceni (TypDoruceni)
│   └── priorita ("NORMAL" | "URGENT")
└── dataNotifikace (TypDataNotifikace)
    ├── hlavicka, obsah, pushText (string)
    └── dataSablony[] (nazev, hodnota, popis)
```

---

## 11. Registr oprávnění

**Base URL:** `/registrOpravneni`
**OpenAPI:** 3.0.4 | **Verze:** v1.0.0

### Endpoint

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `GET` | `/api/v1/Opravneni/Over` | Ověření oprávnění osoby |

### Parametry dotazu

| Parametr | Typ | Popis |
|----------|-----|-------|
| `IdSluzbyEZ` | int32 | ID služby eZdravotnictví |
| `IdTypuDokumentace` | int32 | ID typu dokumentace |
| `OpravnujiciOsoba.Role` | enum | Role opravňující osoby |
| `OpravnujiciOsoba.Hodnota` | string | Hodnota identifikátoru |
| `OpravnenaOsoba.Role` | enum | Role oprávněné osoby |
| `OpravnenaOsoba.Hodnota` | string | Hodnota identifikátoru |

### TypExplicitniRoleOsoby (enum)

`Interni`, `Pacient`, `PoskytovatelZdravotnickychSluzeb`, `ZdravotniPracovnik`, `PravnickaOsoba`, `Zastupce`, `FyzickaOsoba`

**Odpověď:** `boolean` (true = oprávnění uděleno)

---

## 12. Sdílený zdravotní záznam (SZZ)

**Base URL:** `/sdilenyZdravotniZaznam`
**OpenAPI:** 3.0.4 | **Verze:** v1.0.6
**Popis:** Externí API systému SZZ – určeno pro PZS

> **Aktuální verze API je 3.0.0** (Standard EZ SZZ 3.0 s platností
> od 29. 7. 2026, swagger `gwy-ext-sec-t2.csez.cz/apidoc/Sdileny_zdravotni_zaznam_v3`).
> Verze v1 a v2 níže zůstávají dostupné. Přehled změn ve verzi 3 je
> v části 12.4.

### Endpointy – přehled oblastí

#### Emergentní záznam (29 endpointů)

Pro každý typ záznamu existuje kompletní CRUD + správa stavů:

| Typ záznamu | GET (seznam) | POST (vytvořit) | PUT (upravit) | PATCH (zneplatnit/zpochybnit/obnovit) |
|-------------|-------------|-----------------|----------------|---------------------------------------|
| **Alergie** | `/alergie/{rid}` | `/alergie` | `/alergie/{id}` | `/alergie/{id}/zneplatnit\|zpochybnit\|obnovit` |
| **Krevní skupina** | `/krevniSkupina/{rid}` | `/krevniSkupina` | `/krevniSkupina/{id}` | `/krevniSkupina/{id}/...` |
| **Nežádoucí příhody** | `/nezadouciPrihody/{rid}` | `/nezadouciPrihody` | `/nezadouciPrihody/{id}` | `/nezadouciPrihody/{id}/...` |
| **Nežádoucí reakce** | `/nezadouciReakce/{rid}` | `/nezadouciReakce` | `/nezadouciReakce/{id}` | `/nezadouciReakce/{id}/...` |
| **Nežádoucí účinky** | `/nezadouciUcinky/{rid}` | `/nezadouciUcinky` | `/nezadouciUcinky/{id}` | `/nezadouciUcinky/{id}/...` |
| **Nežádoucí události** | `/nezadouciUdalosti/{rid}` | `/nezadouciUdalosti` | `/nezadouciUdalosti/{id}` | `/nezadouciUdalosti/{id}/...` |

Kompletní emergentní záznam: `GET /api/v1/emergentniZaznam/{rid}`
PDF export: `GET /api/v1/emergentniZaznam/{rid}/pdf`

#### Léčivé přípravky (5 endpointů)

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `GET` | `/api/v1/lecivePripravky/{rid}` | Seznam léčiv pacienta |
| `POST` | `/api/v1/lecivePripravky` | Zápis léčivého přípravku |
| `PUT` | `/api/v1/lecivePripravky/{id}` | Úprava |
| `PATCH` | `.../zneplatnit\|zpochybnit\|obnovit` | Správa stavů |

#### Zdravotní záznamy (5 endpointů)

| Metoda | Cesta | Popis |
|--------|-------|-------|
| `POST` | `/api/v1/zdravotniZaznamy/vyhledat` | Vyhledání ZZ |
| `POST` | `/api/v1/zdravotniZaznamy` | Vytvoření ZZ |
| `PUT` | `/api/v1/zdravotniZaznamy/{id}` | Úprava ZZ |
| `PATCH` | `.../zneplatnit\|zpochybnit\|obnovit` | Správa stavů |

### Životní cyklus záznamu

```
[Platný] ──→ zneplatnit ──→ [Zneplatněný]
    │                            │
    ├──→ zpochybnit ──→ [Zpochybněný]
    │                            │
    └────────── obnovit ◄────────┘
```

Každá operace vyžaduje: `duvod` (důvod), `ico` (IČO poskytovatele), `krzpId` (ID pracovníka)

### Audit trail (AuditDto)

Každý záznam obsahuje kompletní audit: kdo a kdy vytvořil / změnil / zneplatnil / zpochybnil / obnovil (pracovník + poskytovatel + datum + důvod)

### 12.4 Verze 3.0.0 (Standard EZ SZZ 3.0, platnost od 29. 7. 2026)

Cesty se mění z `/api/v2/…` na `/api/v3/…`; moduly (`prevence`,
`screeningy`, `emergentniZaznam`, `lecivePripravky`, `ciselniky`) i sada
operací (POST / `vyhledat` / PUT / PATCH `zneplatnit`, `zpochybnit`,
`obnovit`) zůstávají. Klient: třída `SZZv3`, endpointy `/api/szz3/…`.

**Nové screeningy** (`POST /api/v3/screeningy/{typ}`):

| Typ | Vyšetření | Oprávněná odbornost |
|-----|-----------|---------------------|
| `kolorektalniKarcinomKoloskopie` | Kolorektální karcinom – koloskopie | L10 gastroenterologie |
| `karcinomProstatyVstupniPsa` | Karcinom prostaty – vstupní PSA | L42 urologie |
| `karcinomProstatyUrologickeVysetreni` | Karcinom prostaty – navazující urologické | L42 urologie |
| `karcinomProstatyBioptickeVysetreni` | Karcinom prostaty – navazující bioptické | L42 urologie |
| `karcinomPlicPneumologickeVysetreni` | Karcinom plic – pneumologické | L32 pneumologie a ftizeologie |

**Změněný název:** HPV screening děložního hrdla je nově
`karcinomDeloznihoHrdlaHpv` (verze v2 měla v cestě dvojité „D“ –
`karcinomDDeloznihoHrdlaHpv`; klient starý zápis přijímá jako alias).

**Nové položky:**

- `samoplatce` – boolean u všech preventivních i screeningových vyšetření,
  výchozí `false` (vyšetření hrazené ze zdravotního pojištění).
- `genotypyHpvTestu` – volitelný text u HPV screeningu, vyplňuje se při
  pozitivním výsledku.
- Preventivní prohlídka praktického lékaře: účast ve screeningu karcinomu
  plic, karcinomu prostaty a aneurysmatu abdominální aorty (číselníky
  `szz-ucast-karcinom-plic`, `szz-ucast-karcinom-prostaty`,
  `szz-ucast-ve-screeningu-aaa`) a `obvodPasu`.
- Souhrn `POST /api/v3/zdravotniZaznamy/vyhledat` – prevence i screeningy
  pacienta jedním dotazem.

**Rozsahy hodnot** (příloha Validace ve SZZ v3.0):

| Atribut | Rozsah | Desetinná místa |
|---------|--------|-----------------|
| `ntProbnp` | 0 – 100 000 pg/ml | celé číslo |
| `vyska` | 10 – 300 cm | 3 |
| `vaha` | 0 – 400 kg | 3 |
| `obvodPasu` | 10 – 400 cm | 3 |
| `hladinaToksUgG` | 0 – 500 µg/g (jen při vytvoření) | 2 |
| `vysledekBbps` | 0 – 9 (Boston Bowel Preparation Scale) | celé číslo |
| `hladinaPsa` | 1 000 – 12 000 µg/l | 2 |
| `objemProstaty` | 0 – 1 000 ml | 2 |
| `psaDenzita`, `psaVelocita` | 0 – 10 | 2 |

Volné texty (`poznamka`, `popis`, `davkovani`, `genotypyHpvTestu`) mají limit
300 znaků, datum zjištění lze zadat nejvýše 100 let zpětně. Kontrolu nad
tělem požadavku dělá `SZZv3.zkontroluj()` respektive
`POST /api/szz3/zkontrolovat`; závazná validace je na straně serveru.

**Nové číselníky:** `szz-ucast-karcinom-plic`, `szz-ucast-karcinom-prostaty`,
`szz-ucast-ve-screeningu-aaa`, `gastro-typ-koloskopie`,
`gastro-kompletnost-koloskopie`, `gastro-patologie-nalez`, `gastro-zaver`,
`urologie-klinicke-vysetreni`, `urologie-dalsi-vysetreni`,
`urologie-typ-biopsie`, `urologie-vysledek-biopt-vys`,
`pneumologie-koureni`, `pneumologie-fyzikalni-vysetreni`,
`pneumologie-rtg-plic`, `pneumologie-funkcni-vysetreni`.

> Screening chronického onemocnění ledvin (CKD) je ve standardu popsaný, ale
> označený jako **NEIMPLEMENTOVÁNO**, proto v klientovi není.

---

## 13. TermX Terminologie (FHIR)

**Base URL:** `/terminologie`
**OpenAPI:** 3.0.1 | **Verze:** v1.0.5
**Content-Type:** `application/fhir+json`

FHIR R4 terminologický server s podporou:

| Zdroj | Operace |
|-------|---------|
| **ValueSet** | read, search, create, update, `$expand`, `$validate-code`, `$sync` |
| **CodeSystem** | read, search, create, update, `$lookup`, `$validate-code`, `$subsumes`, `$find-matches`, `$compare`, `$sync` |
| **ConceptMap** | read, search, update, `$translate`, `$sync` |
| **StructureMap** | read, search, create, `$transform` |
| **Provenance** | search |

### Vyhledávací parametry (sdílené)

`_count`, `_page`, `_id`, `url`, `version`, `name`, `title`, `status`, `publisher`, `description`, `identifier`, `date`

---

## 14. Návrhy JSON zpráv dle specifikace

> Všechna SEZ API komunikují výhradně přes **JSON** (`application/json`).
> Následující příklady jsou sestaveny přesně podle OpenAPI schémat stažených ze Swagger endpointu.
> Povinná pole jsou označena `*`.

### 14.1 Uložení zásilky – `POST /docasneUloziste/api/v1/Zasilka/UlozZasilku`

Povinná pole: `nazev*`, `typ*`, `klasifikace*`, `autor*`, `zdravotnickyPracovnik*`, `poskytovatel*`, `pacient*`, `ispzs*`
Dokument povinná pole: `nazev*`, `typ*`, `klasifikace*`, `jazyk*`, `duvernost*`, `pacient*`, `dostupnost*`, `hash*`

> **Příklad s testovacími identitami** (viz [Testovací identity – MZČR](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/68616204)):
> - Poskytovatel: `25488627` (Krajská zdravotní, a.s.)
> - ZP/autor: `102129137` (MRAČENA MRAKOMOROVÁ, lékař – NRZP)
> - Pacient: `2667873559` (MRAČENA MRAKOMOROVÁ – RID)
>
> Číselníkové položky používají plný formát `{ "ciselnikKod", "kod", "verze" }` dle Terminologického serveru.

```json
{
  "nazev": "Lékařská zpráva z vyšetření",
  "popis": "Testovací zásilka – zpráva z vyšetření",
  "typ": {
    "ciselnikKod": "medical-document-type",
    "kod": "11506-3",
    "verze": "1.0.0"
  },
  "klasifikace": {
    "ciselnikKod": "document-category",
    "kod": "11503-0",
    "verze": "1.0.0"
  },
  "datumOd": "2026-02-20T08:00:00+01:00",
  "datumDo": "2026-03-22T08:00:00+01:00",
  "autor": "102129137",
  "zdravotnickyPracovnik": "102129137",
  "poskytovatel": "25488627",
  "pacient": "2667873559",
  "ispzs": "NIS Krajska zdravotni",
  "adresat": "25488627",
  "adresatTyp": {
    "ciselnikKod": "typ-adresata",
    "kod": "PZS",
    "verze": "1.0.0"
  },
  "dostupnost": true,
  "dokument": [
    {
      "nazev": "Zpráva z vyšetření",
      "popis": "Testovací dokument",
      "jazyk": {
        "ciselnikKod": "languages",
        "kod": "cs",
        "verze": "5.0.0"
      },
      "typ": {
        "ciselnikKod": "medical-document-type",
        "kod": "67781-5",
        "verze": "1.0.0"
      },
      "klasifikace": {
        "ciselnikKod": "document-category",
        "kod": "11503-0",
        "verze": "1.0.0"
      },
      "autor": "102129137",
      "poskytovatel": "25488627",
      "pacient": "2667873559",
      "dostupnost": true,
      "duvernost": {
        "ciselnikKod": "v3-Confidentiality",
        "kod": "N",
        "verze": "2.0.0"
      },
      "format": {
        "ciselnikKod": "format-code",
        "kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient",
        "verze": "1.0.0"
      },
      "mime": {
        "ciselnikKod": "media-type",
        "kod": "text/plain",
        "verze": "1.0.0"
      },
      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "velikost": 57,
      "soubor": {
        "soubor": "VGVzdG92YWPDrSBkb2t1bWVudCAtIHpwcsOhdmEgeiB2ecWhZXTFmWVuw60gcHJvIG92xJtFmWVuw60gQVBJLg=="
      }
    }
  ]
}
```

> **Poznámka:** Pole `soubor.soubor` obsahuje obsah dokumentu v **base64**. Pole `hash` je **SHA-256** hashe originálních dat (hex string, 64 znaků). DÚ ověřuje integritu dokumentu porovnáním hashe při uložení i stažení.

### 14.2 Vyhledání zásilek – `POST /docasneUloziste/api/v1/Zasilka/VyhledejZasilku`

Povinná pole: `datumOd*`, `datumDo*`, `strankovani.page*`, `strankovani.size*`

```json
{
  "pacient": "6653225891",
  "datumOd": "2025-01-01T00:00:00+01:00",
  "datumDo": "2026-12-31T23:59:59+01:00",
  "strankovani": { "page": 1, "size": 20 }
}
```

### 14.3 Posudek řidičského oprávnění – `POST /elektronickePosudky/api/v1/posudky/ridicskeOpravneni`

Povinná pole: `rid*`, `datumVysetreni*`, `datumVystaveni*`, `druhPosudku*`, `druhProhlidky*`, `odbornostLekare*`, `stavPosudku*`, `typAkce*`, `vysledek*`, `skupinaZadatelRidic*`
Příloha: `nazev*` (1–200), `dataBase64*`, `hashSha256*` (přesně 64 hex znaků, pattern `^[a-fA-F0-9]{64}$`)

```json
{
  "rid": "6259251557",
  "krzpId": "177550538",
  "ico": "27661989",
  "icp": "27661989",
  "typAkce": { "kod": "akce_ro_1", "verze": "1.0.0" },
  "odbornostLekare": { "kod": "PraktickyLekar", "verze": "1.0.0" },
  "stavPosudku": { "kod": "platny", "verze": "1.0.0" },
  "druhProhlidky": { "kod": "Pravidelna", "verze": "1.0.0" },
  "skupinaZadatelRidic": { "kod": "Skupina1", "verze": "1.0.0" },
  "druhPosudku": { "kod": "Prvoridic", "verze": "1.0.0" },
  "vysledek": { "kod": "ZpusobilySPodminkou", "verze": "1.0.0" },
  "datumVysetreni": "2026-02-15",
  "datumVystaveni": "2026-02-18",
  "platnostDo": "2028-02-15",
  "zduvodneni": "Zpusobily k rizeni s omezenim - nutne bryle.",
  "skupinyRidicskehoOpravneni": [
    { "skupinaRo": { "kod": "B", "verze": "1.0.0" } },
    { "skupinaRo": { "kod": "AM", "verze": "1.0.0" } }
  ],
  "harmonizovaneKody": [
    {
      "harmonizovanyKod": { "kod": "01.06", "verze": "1.0.0" },
      "skupinaRo": { "kod": "B", "verze": "1.0.0" },
      "upresneniText": "Bryle pro korekci zraku"
    }
  ],
  "narodniKody": [
    {
      "narodniKod": { "kod": "105", "verze": "1.0.0" },
      "skupinaRo": { "kod": "B", "verze": "1.0.0" },
      "upresneniText": "Omezeni jizdy v noci"
    }
  ],
  "odbornaVysetreni": [
    {
      "odborneVysetreni": { "kod": "Jine", "verze": "1.0.0" },
      "datumVysetreni": "2026-02-14T10:30:00+01:00"
    }
  ],
  "prilohy": [
    {
      "nazev": "vysledek_ocniho_vysetreni.pdf",
      "mimeType": "application/pdf",
      "dataBase64": "JVBERi0xLjMK...",
      "velikostB": 1619,
      "hashSha256": "1cdef036f218c8c19648fefc904122e458a1a7832c9db17eab0a60390aa0567e"
    }
  ]
}
```

### 14.4 Vyhledání posudků – `POST /elektronickePosudky/api/v1/posudky/ridicskeOpravneni/vyhledat`

```json
{
  "rid": "6259251557",
  "datumOd": "2025-01-01T00:00:00+01:00",
  "datumDo": "2026-12-31T23:59:59+01:00",
  "jenPlatne": true,
  "page": 0,
  "size": 25,
  "sort": "datumVystaveni",
  "order": "desc"
}
```

### 14.5 Uložení žádanky – `POST /eZadanky/api/v1/eZadanka/UlozZadanku`

Povinná pole Zadanka: `stav*`, `urgentnost*`, `samoplatce*`, `prilozenVzorek*`, `omezeniMobility*`, `pacientImplantat*`, `icpZadatele*`, `zasilka*`, `metodaData*`

```json
{
  "zadanka": {
    "kod": "EZ-2026-00158",
    "stav": { "kod": "0", "verze": "1.0.0" },
    "urgentnost": { "kod": "asap", "verze": "5.0.2" },
    "pacientPojistovna": { "kod": "111", "verze": "1.0" },
    "samoplatce": false,
    "prilozenVzorek": true,
    "omezeniMobility": false,
    "icpZadatele": "72090001",
    "pacientImplantat": false,
    "zpusobVyrizeni": { "kod": "1", "verze": "1.0.0" },
    "vzorekData": [
      {
        "materialVzorku": { "kod": "BAFTOX", "verze": "1.0.0" },
        "datumCasOdberu": "2026-02-19T09:15:00+01:00",
        "kodVzorku": "VZK-20260219-001"
      }
    ],
    "zasilka": {
      "nazev": "Zadanka na krevni obraz",
      "typ": { "kod": "07", "verze": "1.0.0" },
      "klasifikace": { "kod": "721963009", "verze": "1.0.0" },
      "autor": "5",
      "zdravotnickyPracovnik": "6",
      "poskytovatel": "1",
      "pacient": "6653225891",
      "ispzs": "NIS FN Motol",
      "dokument": []
    },
    "metodaData": [ { "kod": "LAB", "verze": "1.0" } ]
  }
}
```

### 14.6 Přijetí žádanky – `PATCH /eZadanky/api/v1/eZadanka/PrijmiZadanku`

Povinná pole: `id*`, `verzeRadku*`

```json
{
  "id": "383950be-cab2-484f-b9a2-72867d7dc0b9",
  "verzeRadku": "AAAAAAAAB+8=",
  "cisloDokladu": "OP-987654",
  "cisloVzorku": "VZK-20260219-001",
  "datumPlanovanehoVysetreni": "2026-02-25T10:00:00+01:00"
}
```

### 14.7 Storno žádanky – `PATCH /eZadanky/api/v1/eZadanka/StornujZadanku`

Povinná pole: `id*`, `verzeRadku*`, `duvodStornaZadanky*`

```json
{
  "id": "c2005f74-0e68-47b6-bbdd-69f85dc30b7c",
  "verzeRadku": "AAAAAAAAB+8=",
  "duvodStornaZadanky": { "kod": "1", "verze": "1.0.0" },
  "duvodStornaUpresneni": "Pacient odmitl vysetreni"
}
```

### 14.8 Vyřízení žádanky – `PATCH /eZadanky/api/v1/eZadanka/VyridZadanku`

Povinná pole: `id*`, `verzeRadku*`, `zpusobVyrizeniZadanky*`

```json
{
  "id": "ff959669-d4b5-4451-bee9-f160c194b8eb",
  "verzeRadku": "AAAAAAAAB+8=",
  "zpusobVyrizeniZadanky": { "kod": "1", "verze": "1.0.0" },
  "zpusobVyrizeniUpresneni": "Vysetreni provedeno standardne",
  "datumSkutecneRealizaceVysetreni": "2026-02-19T14:30:00+01:00",
  "zaslatVysledekPacientovi": true,
  "zaslatVysledekPraktikovi": true,
  "vysledek": {
    "nazev": "Vysledky krevniho obrazu",
    "typ": { "kod": "07", "verze": "1.0.0" },
    "klasifikace": { "kod": "721963009", "verze": "1.0.0" },
    "autor": "5",
    "zdravotnickyPracovnik": "6",
    "poskytovatel": "1",
    "pacient": "6653225891",
    "ispzs": "NIS FN Motol",
    "dokument": []
  }
}
```

### 14.9 Vyhledání pacienta podle RID – `POST /krp/api/v2/pacient/hledat/rid`

Struktura KRP: vždy obálka `{zadostInfo*, zadostData*}`

```json
{
  "zadostInfo": {
    "datum": "2026-02-19T10:00:00+01:00",
    "ucel": "Vyhledani pacienta pro ambulantni vysetreni",
    "zadostId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  },
  "zadostData": {
    "rid": "6653225891"
  }
}
```

### 14.10 Založení pacienta – `POST /krp/api/v2/pacient/zalozit/pacient`

Povinná pole NovyPacient: `prijmeni*` (max 50), `datumNarozeni*`

```json
{
  "zadostInfo": {
    "datum": "2026-02-19T11:00:00+01:00",
    "ucel": "Zalozeni noveho pacienta - cizinec bez RC",
    "zadostId": "b2c3d4e5-f6a7-8901-bcde-f12345678901"
  },
  "zadostData": {
    "jmeno": "Hans",
    "prijmeni": "Mueller",
    "datumNarozeni": "1985-03-22T00:00:00+01:00",
    "pohlavi": "M",
    "statniObcanstvi": ["DE"],
    "kontaktniEmail": "hans.mueller@example.de",
    "kontaktniTelefon": "+491701234567",
    "adresaPobytu": {
      "stat": "CZ",
      "obec": "Praha",
      "psc": 11000,
      "ulice": "Vinohradska",
      "cisloPopisne": 48
    },
    "doklady": [
      { "typ": "PAS", "cislo": "C01X00T47", "platnostDo": "2030-05-15" }
    ]
  }
}
```

### 14.11 Vytvoření alergie – `POST /sdilenyZdravotniZaznam/api/v1/emergentniZaznam/alergie`

```json
{
  "rid": "6653225891",
  "ico": "00064203",
  "krzpId": "177550538",
  "nazev": "Alergie na penicilin",
  "alergen": { "kod": "91936005", "verze": "1.0.0" },
  "kategorieAlergenu": { "kod": "medication", "verze": "1.0.0" },
  "kriticnost": { "kod": "high", "verze": "1.0.0" },
  "typReakce": { "kod": "allergy", "verze": "1.0.0" },
  "manifestaceReakce": [
    { "kod": "39579001", "verze": "1.0.0" }
  ],
  "zavaznostReakce": { "kod": "severe", "verze": "1.0.0" },
  "datumZjisteni": "2024-06-15T00:00:00+02:00",
  "poznamka": "Anafylakticka reakce po podani Amoxicilinu v roce 2024"
}
```

### 14.12 Krevní skupina – `POST /sdilenyZdravotniZaznam/api/v1/emergentniZaznam/krevniSkupina`

```json
{
  "rid": "6653225891",
  "ico": "00064203",
  "krzpId": "177550538",
  "krevniSkupina": { "kod": "A_POSITIVE", "verze": "1.0.0" }
}
```

### 14.13 Léčivý přípravek – `POST /sdilenyZdravotniZaznam/api/v1/lecivePripravky`

```json
{
  "rid": "6653225891",
  "ico": "00064203",
  "krzpId": "177550538",
  "identifikace": { "kod": "0001234", "verze": "1.0.0" },
  "davkovani": "500mg 2x denne",
  "datumPodani": "2026-02-19T08:00:00+01:00"
}
```

### 14.14 Zdravotní záznam (prevence) – `POST /sdilenyZdravotniZaznam/api/v1/zdravotniZaznamy`

```json
{
  "typZdravotnihoZaznamu": { "kod": "prevence", "verze": "1.0.0" },
  "rid": "6653225891",
  "ico": "00064203",
  "krzpId": "177550538",
  "datumProvedeni": "2026-02-19T10:00:00+01:00",
  "poznamka": "Preventivni prohlidka - bez nalezu",
  "prevence": {
    "vyska": 178,
    "vaha": 82.5,
    "obvodPasu": 94,
    "tlakSystolicky": 130,
    "tlakDiastolicky": 85
  }
}
```

### 14.15 Zneplatnění/zpochybnění/obnovení záznamu – `PATCH .../alergie/{id}/zneplatnit`

Povinná pole: `duvod*`, `krzpId*`, `ico*`

```json
{
  "duvod": "Chybne zadany udaj o alergii pacienta",
  "krzpId": "177550538",
  "ico": "00064203"
}
```

### 14.16 Odeslání notifikace – `POST /notifikace/api/v1/notifikace/odeslat`

Priorita: `"NORMAL"` | `"URGENT"`

```json
{
  "idKorelace": "corr-2026-02-19-001",
  "zdrojovySystem": "EZadanky",
  "typ": "ZADANKA_NOVA",
  "kanal": "PUSH_PZS",
  "sablona": "TMPL_ZADANKA_PRIJEM",
  "casovaZnacka": "2026-02-19T12:00:00+01:00",
  "prijemce": [
    {
      "id": "177550538",
      "typ": "KRZP",
      "email": "lekar@nemocnice.cz"
    }
  ],
  "doruceni": {
    "priorita": "NORMAL"
  },
  "dataNotifikace": {
    "hlavicka": "Nova zadanka k vyrizeni",
    "obsah": "Pacient Jan Novak (RID 6653225891) - zadanka na krevni obraz",
    "pushText": "Nova zadanka ke zpracovani",
    "dataSablony": [
      { "nazev": "pacientJmeno", "hodnota": "Jan Novak" },
      { "nazev": "typVysetreni", "hodnota": "Krevni obraz" }
    ]
  }
}
```

### 14.17 Push notifikace pro PZS – `POST /notifikace/api/v1/pzs/prijem/vzor`

```json
{
  "idKorelace": "push-2026-02-19-001",
  "id": "MSG-EZ-2026-0042",
  "typ": "ZADANKA_VYSLEDEK",
  "priorita": "URGENT",
  "hlavicka": "Vysledek zadanky - urgentni",
  "obsah": "Vysledky laboratorniho vysetreni jsou k dispozici pro pacienta RID 6653225891.",
  "zdrojovySystem": "Laboratore",
  "casovaZnacka": "2026-02-19T15:30:00+01:00",
  "prijemce": [
    { "id": "177550538", "typ": "KRZP" }
  ],
  "predmet": [
    { "id": "ff959669-d4b5-4451-bee9-f160c194b8eb", "typ": "ZADANKA" }
  ]
}
```

### 14.18 Podpis dokumentu – `POST /ezca2/api/sign/document`

DocumentType enum (int32): ARCHIVATION=0, CADES=1, **PADES=2**, XADES=3, ASIC_S=4, ASIC_E=5, CADES_ATTACHED=6, CADES_DETACHED=7, DOCX=8, XLSX=9, EML=10, MSG=11, JADES=12

```json
{
  "authentication": { "userLogin": "lekar.novak@fnmotol.cz" },
  "document": {
    "documentContent": "JVBERi0xLjMKJZOMi54gUmVwb3...",
    "documentType": 2,
    "fileName": "posudek_ridicske_opravneni.pdf",
    "isSignatureWithTimestamp": true,
    "sourceSystem": "ElektronickePosudky",
    "certificateId": "d4e5f6a7-b8c9-0123-d4e5-f6a7b8c90123",
    "cryptedPassword": "U2FsdGVkX1+abc123...",
    "storageId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
}
```

### 14.19 Časové razítko – `POST /ezca2/api/stamp/document`

```json
{
  "authentication": { "userLogin": "system@cssn.cz" },
  "document": {
    "documentContent": "JVBERi0xLjMK...",
    "documentType": 2,
    "fileName": "zdravotni_dokumentace.pdf",
    "sourceSystem": "DocasneUloziste",
    "tsaId": "c3d4e5f6-a7b8-9012-c3d4-e5f6a7b89012",
    "storageId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
}
```

### 14.20 Validace podpisu – `POST /ezca2/api/validate/document`

DocumentVerificationType enum (int32): ADES=0, DOCX=1, XLSX=2, EML=3, MSG=4

```json
{
  "authentication": { "userLogin": "admin@cssn.cz" },
  "document": {
    "signedDocumentContent": "MIIGfAYJKoZIhvcNAQcC...",
    "signedFileName": "posudek_signed.pdf",
    "originalDocumentContent": "JVBERi0xLjMK...",
    "originalFileName": "posudek_original.pdf",
    "documentValidationType": 0,
    "sourceSystem": "ElektronickePosudky",
    "storageId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
}
```

### 14.21 Ověření oprávnění – `GET /registrOpravneni/api/v1/Opravneni/Over`

TypExplicitniRoleOsoby: `Interni` | `Pacient` | `PoskytovatelZdravotnickychSluzeb` | `ZdravotniPracovnik` | `PravnickaOsoba` | `Zastupce` | `FyzickaOsoba`

```
GET /registrOpravneni/api/v1/Opravneni/Over
  ?IdSluzbyEZ=1
  &IdTypuDokumentace=5
  &OpravnujiciOsoba.Role=PoskytovatelZdravotnickychSluzeb
  &OpravnujiciOsoba.Hodnota=00064203
  &OpravnenaOsoba.Role=ZdravotniPracovnik
  &OpravnenaOsoba.Hodnota=177550538

Odpoved: true | false
```

---

## 15. Přehled chybových formátů

### 15.1 RFC 7807 Problem Details (SZZ, ELP)

**400 – validační chyba:**

```json
{
  "type": "https://httpstatuses.com/400",
  "title": "Chyba validace",
  "status": 400,
  "detail": "Pozadavek obsahuje neplatna data",
  "instance": "/api/v1/emergentniZaznam/alergie",
  "correlationId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "errors": [
    { "field": "rid", "message": "Pole rid je povinne" },
    { "field": "kriticnost.kod", "message": "Neplatny kod ciselniku" }
  ]
}
```

**404 – záznam neexistuje** (např. pacient nemá krevní skupinu):

```json
{
  "type": "https://api.szz.cz/errors/not-found",
  "title": "Záznam nebyl nalezen.",
  "status": 404,
  "detail": "Záznam s daným identifikátorem neexistuje.",
  "instance": "/api/v1/emergentniZaznam/krevniSkupina/7706120004",
  "correlationId": "00007a46-632d-7fbf-a7f0-dde0470e31c1"
}
```

> **Poznámka:** GET endpointy SZZ (`/alergie/{rid}`, `/krevniSkupina/{rid}` atd.) vrací 404,
> pokud pro daného pacienta záznam daného typu neexistuje. Jde o očekávané chování.

### 15.2 Custom ErrorsResponse (Dočasné úložiště, E-žádanky)

```json
{
  "errors": [
    {
      "error": "VALIDATION_ERROR",
      "scope": "nazev",
      "parameters": {},
      "message": "Nazev zasilky je povinny"
    }
  ]
}
```

### 15.3 ABP RemoteServiceErrorResponse (Registr oprávnění)

```json
{
  "error": {
    "code": "AUTH_001",
    "message": "Opravneni nebylo nalezeno",
    "details": "Pro danou kombinaci roli neexistuje opravneni",
    "validationErrors": [
      {
        "message": "IdSluzbyEZ musi byt kladne cislo",
        "members": ["IdSluzbyEZ"]
      }
    ]
  }
}
```

---

## Příloha A – EZCA 2 enum hodnoty

| Enum | Hodnota | Název |
|------|---------|-------|
| **DocumentTypeEnum** | 0 | ARCHIVATION |
| | 1 | CADES |
| | 2 | PADES |
| | 3 | XADES |
| | 4 | ASIC_S |
| | 5 | ASIC_E |
| | 6 | CADES_ATTACHED |
| | 7 | CADES_DETACHED |
| | 8 | DOCX |
| | 9 | XLSX |
| | 10 | EML |
| | 11 | MSG |
| | 12 | JADES |
| **DocumentVerificationTypeEnum** | 0 | ADES |
| | 1 | DOCX |
| | 2 | XLSX |
| | 3 | EML |
| | 4 | MSG |
| **HashAlgorithmEnum** | 0 | MD5 |
| | 3 | SHA1 |
| | 5 | SHA256 |
| | 7 | SHA384 |
| | 9 | SHA512 |
| **ReportFormatEnum** | 0 | PDF |
| | 1 | XML |

---

## Příloha A2 – Testovací identity (T2)

> **Zdroj:** [Testovací identity – MZČR Confluence](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/68616204)

### Certifikát (pro mTLS i JWT signing)

| Parametr | Hodnota |
|----------|---------|
| CN | krajska zdravotni verejny test |
| client_id | `25488627_KrajskaZdravotniVerejnyTest` |
| UID (kid) | `85cf28c4-c190-406f-bc96-f92ad25b3202` |
| IČO | 25488627 (Krajská zdravotní, a.s.) |

### Testovací pacienti (výběr)

| RID | Příjmení | Jméno | Datum narození |
|-----|----------|-------|---------------|
| 2667873559 | MRAKOMOROVÁ | MRAČENA | 26.11.1971 |
| 7653800856 | — | — | — |
| 7706120004 | — | — | — |
| 6653225891 | ROLNIČKA | MAREK | 11.01.1968 |
| 6259251557 | SVATÁ | ANNA | 03.03.2013 |

### Testovací zdravotničtí pracovníci (výběr)

| NRZP | Jméno | Příjmení | Povolání |
|------|-------|----------|----------|
| 102129137 | MRAČENA | MRAKOMOROVÁ | Lékař |
| 175702010 | PETRA | NOSKOVÁ | Lékař |
| 158350302 | NORBERT | NĚMEČEK | Zubní lékař |
| 191331954 | LUDMILA | LÉKAŘSKÁ | Lékař |
| 155348468 | PAVLA | DVOŘÁKOVÁ | Lékař |

### Typy certifikátů EZCA II

| Typ | Identifikátor | Použití |
|-----|---------------|---------|
| **Systémový** (PZS) | IČO v `organizationIdentifier` | VyhledejZasilku, UlozZasilku, KRP, SZZ, ELP, eŽádanky, Notifikace |
| **Uživatelský** (ZP) | KRZPID v `organizationIdentifier` | DejZasilku (vyžaduje identitu konkrétního ZP) |

> **Poznámka:** Pro testovací prostředí je k dispozici pouze systémový certifikát PZS.
> Uživatelské certifikáty ZP pro testovací pracovníky nejsou v manuálu publikovány.
> Pro `DejZasilku` je nutné požádat NCEZ (`csez@mzd.gov.cz`) o vydání testovacího uživatelského certifikátu.

---

## Příloha B – Společné HTTP hlavičky

| Hlavička | Směr | Typ | Popis |
|----------|------|-----|-------|
| `Authorization` | Request | string | `Bearer <JWT_assertion>` |
| `Content-Type` | Request | string | `application/json` |
| `Accept-Language` | Request | string | `cs` / `en` / `de` |
| `User-Agent` | Request | string | `<aplikace>/<verze> (Test\|Prod; výrobceSW)`, povinná od 1. 9. 2026 |
| `X-Correlation-Id` | Request | uuid | ID pro korelaci požadavků |
| `X-Trace-Id` | Request | uuid | ID pro trasování |
| `If-Match` | Request | string | ETag pro optimistickou souběžnost (SZZ, ELP) |
| `ETag` | Response | string | Verze záznamu |

---

## Příloha C – Přístup k API (curl + Python)

### curl

```bash
# 1. Vytvoreni JWT assertion pomoci openssl a jq
HEADER=$(echo -n '{"alg":"RS256","kid":"85cf28c4-c190-406f-bc96-f92ad25b3202","typ":"JWT"}' | \
  openssl base64 -e | tr -d '\n=' | tr '+/' '-_')
PAYLOAD=$(echo -n "{\"iss\":\"25488627_KrajskaZdravotniVerejnyTest\",\"sub\":\"25488627_KrajskaZdravotniVerejnyTest\",\"aud\":\"https://jsuint-auth-t2.csez.cz/connect/token\",\"jti\":\"$(uuidgen)\",\"iat\":$(date +%s),\"exp\":$(($(date +%s)+55))}" | \
  openssl base64 -e | tr -d '\n=' | tr '+/' '-_')
SIG=$(echo -n "${HEADER}.${PAYLOAD}" | \
  openssl dgst -sha256 -sign <(openssl pkcs12 -in krajska_zdravotni.pfx -passin pass:'Tre-987set*krajzdra321/' -nocerts -nodes 2>/dev/null) | \
  openssl base64 -e | tr -d '\n=' | tr '+/' '-_')
ASSERTION="${HEADER}.${PAYLOAD}.${SIG}"

# 2. Vyhledani pacienta podle RID (tentyz certifikat pro mTLS i assertion)
curl -s -X POST \
  "https://gwy-ext-sec-t2.csez.cz/krp/api/v2/pacient/hledat/rid" \
  --cert-type P12 --cert "krajska_zdravotni.pfx:Tre-987set*krajzdra321/" \
  -H "Authorization: Bearer $ASSERTION" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: cs" \
  -H "User-Agent: sez-api-iris/1.0.0 (Test; Krajska zdravotni a.s.)" \
  -H "X-Correlation-Id: $(uuidgen)" \
  -d '{
    "zadostInfo": {
      "datum": "2026-02-19",
      "ucel": "LECBA",
      "zadostId": "'$(uuidgen)'"
    },
    "zadostData": {
      "rid": "7706120004"
    }
  }' | jq .
```

### Python

```python
from sez_client import SEZAuth, SEZClient, KRP, DocasneUloziste, SZZ, ELP, Notifikace

# Jeden certifikát EZCA II pro mTLS i JWT signing
auth = SEZAuth(
    client_id="25488627_KrajskaZdravotniVerejnyTest",
    p12_path="krajska_zdravotni.pfx",
    p12_password="Tre-987set*krajzdra321/",
)
client = SEZClient(auth)

# KRP – hledání pacienta
krp = KRP(client)
resp = krp.hledat_rid("7653800856")
print(resp.json())  # {"odpovedInfo": {"stav": "OK"}, "odpovedData": [...]}

# DU – vyhledání zásilek
du = DocasneUloziste(client)
resp = du.vyhledej_zasilku("2025-01-01T00:00:00+01:00", "2026-12-31T23:59:59+01:00")
print(resp.json())  # {"zasilka": [...]}

# SZZ – alergie pacienta
szz = SZZ(client)
resp = szz.alergie("7653800856")
print(resp.json())  # []

# ELP – vyhledání posudků
elp = ELP(client)
resp = elp.vyhledej_posudky({"strankovani": {"page": 0, "size": 5}})
print(resp.json())  # {"totalCount": 215, "page": [...]}

# Notifikace – katalog kanálů
notif = Notifikace(client)
resp = notif.katalog_kanalu()
print(resp.json())  # {"totalCount": 9, "page": [...]}
```

### InterSystems IRIS (ObjectScript)

```objectscript
// 1. Setup (jednorázově) – vytvoření SSL konfigurace
Do ##class(SEZ.API.Installer).SetupSSL("/certs/krajska_zdravotni.pfx", "heslo")

// 2. Konfigurace klienta (private_key_jwt – přímá assertion na Gateway)
Set config = ##class(SEZ.API.Config).%New("25488627_KrajskaZdravotniVerejnyTest")
Set config.P12CertFile = "/certs/krajska_zdravotni.pfx"
Set config.P12CertPassword = "heslo"
Set config.CertUID = "85cf28c4-c190-406f-bc96-f92ad25b3202"
Set config.ICO = "25488627"

// 3. KRP – hledání pacienta
Set krp = ##class(SEZ.API.KRP).%New(config)
Set sc = krp.HledatPodleRID("7653800856", "LECBA", .resp)
Write resp.%ToJSON()

// 4. DU – vyhledání zásilek
Set du = ##class(SEZ.API.DocasneUloziste).%New(config)
Set sc = du.VyhledejZasilku("2025-01-01T00:00:00+01:00", "2026-12-31T23:59:59+01:00", , , , , , 1, 50, .resp)
Write "Zásilek: ", resp.%Get("totalCount")

// 5. SZZ – alergie pacienta
Set szz = ##class(SEZ.API.SZZ).%New(config)
Set sc = szz.NactiAlergie("7653800856", , .resp)

// 6. Notifikace – katalog šablon
Set notif = ##class(SEZ.API.Notifikace).%New(config)
Set sc = notif.KatalogSablon(, , .resp)
```
