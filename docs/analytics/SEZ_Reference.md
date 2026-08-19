# SEZ API – Kompletní reference

> **Účel:** Trvalý referenční dokument pro práci s API služeb elektronického zdravotnictví.
> Obsahuje klíčové linky, testovací identity, přehled služeb a konfiguraci.
> **Aktualizováno:** 2026-02-19 (+ DASTA4 validátor ezprava.net, FHIR R5 CH RAD Order)

---

## 1. Klíčové URL a zdroje

### Confluence – Manuál EZ pro PZS (64 stránek, prostor EPZS)

#### Hlavní sekce
| Stránka | URL |
|---------|-----|
| **Přehled (hlavní)** | https://mzcr.atlassian.net/wiki/spaces/EPZS/overview?homepageId=48005400 |
| Autentizace k API GW | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/160530443 |
| Testovací identity | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/68616204/Testovac+identity |
| Služby správy certifikátů | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/98631695 |
| Kmenové registry | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/48136196 |
| Systém notifikací | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935032 |
| eŽádanky | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/56000561 |
| Dočasné úložiště | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935071 |
| Registr oprávnění | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935041 |
| SZZ – Sdílený zdravotní záznam | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935089 |
| ELP – Elektronické posudky | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935098 |
| Služby vytvářející důvěru (EZCA) | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55935108 |
| API eŽádanky (aktualizováno 18.2.2026) | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/244023297 |
| **API endpointy (kompletní tabulka)** | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/80904194 |
| Přehled systémů EZ pro integraci PZS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55902504 |
| Testovací aplikace pro API GW (.NET) | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/313622531 |
| Aktuality (changelog) | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/190251011 |
| Otázky a odpovědi (FAQ) | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/190251018 |
| Získávání info o aktualizacích | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/333086727 |
| KRP – Kmenový registr pacientů | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55934986 |
| API KRP | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/55902489 |
| Případy užití KRP | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58753066 |
| KRZP – Registr zdrav. pracovníků | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/97845268 |
| API KRZP | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/97714184 |
| Případy užití KRZP | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/162824194 |
| KRPZS – Registr PZS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/97615905 |
| API KRPZS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/97648696 |
| Případy užití KRPZS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/163348481 |
| API Dočasného úložiště | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58916867 |
| API pro příjem notifikací IS PZS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58556420 |
| API pro zasílání notifikací od PZS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58589200 |
| Využití registru oprávnění | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58589236 |
| API registru oprávnění | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/83066888 |
| Služby pečetění dle eIDAS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/98795525 |
| Způsoby konzumace NTS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/160301089 |
| Seznam prostředí NTS | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/248020995 |
| API FHIR | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/68550658 |
| Procesy testování interoperability | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/146210831 |
| Testovací rámec IROP/NPO | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/158924803 |
| Procesní rámec IROP/NPO | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/324370433 |
| Předpoklady pro zahájení testování | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/158662660 |
| Oblasti testování | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/158924828 |
| Postup testování – obecná část | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/159088671 |
| Postup – technické připojení | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/158334981 |
| Postup – validace obsahu eZD | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/159252495 |
| Technická část – ověření komunikace | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/158662677 |
| Obsahová část – soulad dokumentů | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/159186949 |
| Metodika testování EHR fáze I | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/159219724 |
| Testovací scénáře – technické testy | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/159318025 |
| Testovací scénáře – obsah dokumentů | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/159252502 |
| Hodnocení a výsledky | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/158531615 |
| První kroky pro testování | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/68321283 |
| Minimální obsah obsahových standardů | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/144474113 |
| Laboratorní nález | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/144572417 |
| DÚ: Vyhledání zásilky | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58753128 |
| DÚ: Stažení zásilky | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58949648 |
| DÚ: Uložení zásilky | https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/58982409 |

### Swagger / OpenAPI specifikace

| API | Swagger UI / JSON | Lokální soubor |
|-----|-------------------|----------------|
| **KRP PZS v2** (gateway) | https://krp-pzs-t2.csez.cz/swagger/index.html | `swagger_specs/KrpPzs_v2.0.0.json` |
| **KRP PZS v1** (direct) – **VYPNUTO k 14. 8. 2026**, snapshot jen pro historii; používejte v3 | https://krp-pzs-t2.csez.cz/swagger/index.html | `swagger_specs/KrpPzs_v1_direct.json` |
| **TermX** (vyžaduje mTLS) | https://termx-swagger-web-t2-pub.csez.cz/swagger/?urls.primaryName=termx | `swagger_specs/TermxTerminologie_v1.0.5.json` |
| **TermX FHIR** (vyžaduje mTLS) | https://termx-swagger-web-t2-pub.csez.cz/swagger/?urls.primaryName=termx-fhir | `swagger_specs/TermxTerminologie_v1.0.5.json` |
| Dočasné úložiště v1 | (gateway) | `swagger_specs/DocasneUloziste_v1.0.0.json` |
| eŽádanky v1 | (gateway) | `swagger_specs/EZadanky_v1.0.0.json` |
| Elektronické posudky v1.0.7 | (gateway) | `swagger_specs/ElektronickePosudky_v1.0.7.json` |
| **Elektronické posudky v2.0.1** | (gateway, NOVÉ) | `swagger_specs/ElektronickePosudky_v2.0.1.json` |
| EZCA 2 v1 | (gateway) | `swagger_specs/Ezca2_v1.0.0.json` |
| KRPZS PZS v2 | (gateway) | `swagger_specs/KrpzsPzs_v2.0.0.json` |
| KRZP PZS v2 | (gateway) | `swagger_specs/KrzpPzs_v2.0.0.json` |
| Notifikace CSSN v1 | (gateway) | `swagger_specs/Notifikace_v1.0.0.json` |
| Registr oprávnění v1 | (gateway) | `swagger_specs/RegistrOpravneni_v1.0.0.json` |
| SZZ v1.0.6 | (gateway) | `swagger_specs/SdilenyZdravotniZaznam_v1.0.6.json` |

### API Gateway – prostředí

| Prostředí | Gateway URL | JSU audience (aud) |
|-----------|-------------|-------------------|
| **T2 (test)** | `https://gwy-ext-sec-t2.csez.cz` | `https://jsuint-auth-t2.csez.cz/connect/token` |
| **T1** | `https://gwy-ext-sec-t1.csez.cz` | `https://jsuint-auth-t1.csez.cz/connect/token` |
| **PROD** | `https://api.csez.gov.cz` | `https://jsuint-auth-ez.csez.cz/connect/token` |
| Swagger UI (T2) | `https://gwy-ext-sec-t2.csez.cz/apidoc/` | — |
| Swagger UI (PROD) | `https://api.csez.gov.cz/apidoc/` | — |
| ELP Swagger (T2) | `https://elp-ext-api-t2.csez.cz/swagger/index.html` | — |
| SZZ Swagger (T2) | `https://szz-ext-api-t2.csez.cz/swagger/index.html` | — |
| TermX FHIR (public, no auth) | `https://apio.csez.gov.cz/termx-fhir/` | — |
| TermX Swagger (PROD) | `https://swagger-termx.ezdravi.gov.cz/swagger/` | — |
| TermX web UI (PROD) | `https://termx.ezdravi.gov.cz/` | — |
| SNOMED browser | `https://snomed.ezdravi.gov.cz/` | — |

### TermX Swagger – přístup

TermX na CSEZ vyžaduje **mTLS klientský certifikát**. Správné URL pro spec:
- Hlavní API: `{host}/api/swagger/termx.yml`
- FHIR API: `{host}/api/fhir-swagger`
- Veřejná reference (Kodality): https://termx.kodality.dev

---

## 2. Autentizace

### Certifikát T2 (testovací)

| Parametr | Hodnota |
|----------|---------|
| Název | krajska zdravotni verejny test |
| Heslo | `Tre-987set*krajzdra321/` |
| Klíč | `oMiEHl0Wprsa8ktxObWaG4zMbQwe38E3` |
| UID (kid) | `85cf28c4-c190-406f-bc96-f92ad25b3202` |
| IČO | `25488627` |
| PZS | Krajská zdravotní, a.s. |
| client_id | `25488627_KrajskaZdravotniVerejnyTest` |

### JWT assertion – payload

```json
{
  "iss": "25488627_KrajskaZdravotniVerejnyTest",
  "sub": "25488627_KrajskaZdravotniVerejnyTest",
  "aud": "https://jsuint-auth-t2.csez.cz/connect/token",
  "iat": <unix_timestamp>,
  "exp": <unix_timestamp + 60>,
  "jti": "<UUID>"
}
```

Hlavička: `Authorization: Bearer <JWT_assertion>`

### Proces
1. Aplikace vytvoří JWT assertion podepsanou privátním klíčem certifikátu
2. Certifikát = klientský certifikát pro mTLS (TLS handshake)
3. JWT assertion → API Gateway v hlavičce `Authorization: Bearer <JWT>`
4. API GW si vyřídí access token z JSU interně
5. API GW vrátí odpověď

---

## 3. Testovací identity – Pacienti (38 osob)

| RID | Příjmení | Jméno | Datum narození | RČ |
|-----|----------|-------|---------------|-----|
| 3740100325 | MUSÍLEK | METODĚJ | 30.01.1929 | 290130126 |
| 2667873559 | MRAKOMOROVÁ | MRAČENA | 26.11.1971 | 7161264528 |
| 6534744190 | VOSÁHLO | ZORAN | 03.05.1977 | 7705034392 |
| 6653225891 | ROLNIČKA | MAREK | 11.01.1968 | 6801117389 |
| 7582120377 | ROLNIČKOVÁ | RAIMUNDA | 10.02.1978 | 7852104403 |
| 7706128004 | *(testovací RID)* | | | |
| 6259251557 | SVATÁ | ANNA | 03.03.2013 | X |
| 4568822375 | ZIKMUNDOVÁ | ZITA | 31.12.1971 | 7162314412 |
| 4464682573 | SCHRÁNKA | STANDA | 09.09.1990 | 9009094413 |
| 3976789440 | HOÂNG | TUÂŃ MINH | 19.06.1957 | 5706197794 |
| 6938376705 | CHALOUPKA | CHRUDOŠ | 24.05.1928 | 280524480 |
| 9058642060 | KRÁL | IVAN | 20.04.2010 | 1004200010 |
| 6551441377 | TICHOŠLÁPEK | TADEÁŠ | 10.07.1931 | 310710113 |
| 7457267194 | KONOPNÍČEK | JONATAN VIKTOR | 08.06.1976 | 7606084398 |
| 3349564010 | ZVONEČEK | ZVONIMÍR | 17.12.2007 | 0712179886 |
| 4151841863 | ZVONEČKOVÁ | ZAIRA ZLATICA | 17.12.2007 | 0762179880 |
| 8675569448 | ŠÍLENÁ | ŠTĚPÁNA | 13.03.1963 | 6353138385 |
| 4376319051 | RELOODON | ROLAND | 03.01.1976 | 7601034353 |
| 8754287763 | ZASNĚŽENÁ | VILEMÍNA | 07.06.1971 | 7156074530 |
| 6668063870 | ROZKOV | VALERYI | 27.05.1938 | 380527092 |
| 3919805409 | NGUYEN THU | VAN THI | 19.09.1959 | 5909197668 |
| 8949617456 | SUÁREZ | DOMINICA | 25.12.1985 | X |
| 5785446836 | NOSKOVÁ | PETRA | 26.09.1981 | 8159260010 |
| 3751233551 | PETŘÍK | ALOIS | 01.01.1971 | — |
| 1252851691 | PETŘÍKOVÁ | ALENA | 30.09.2007 | — |
| 1156887069 | KOMÁRKOVÁ | HANA | 09.04.1981 | — |
| 6907824768 | DVOŘÁKOVÁ | DARJA | 11.07.1998 | — |
| 4967435668 | DVOŘÁKOVÁ | PAVLA | 07.06.1955 | — |
| 4538984060 | ADMIRÁL | EUSTACH | 04.04.2006 | — |
| 7028236631 | BROUK | BOHUMIL | 11.11.2013 | — |
| 4422081352 | MATKA UKONČENÁ KOSTELECKÁ | ANEŽKA | 01.01.1991 | — |
| 7324290493 | ČERMÁKOVÁ | ELIŠKA | 10.10.2010 | — |
| 1294606612 | ROAMANČENÍK | JOSEF | 15.05.2020 | 2005152215 |
| 6224935470 | EINSTEIN | OSVOJENEC | 28.10.2009 | 0910288863 |
| 4860149476 | REQUEST | ZDENĚČEK | 14.04.1968 | X |
| 9214531872 | BANGLADEŽO | DEŽO | 25.06.1958 | — |
| 7651532629 | PYRENEJSKÁ | BOROVICE | 14.07.1947 | — |
| 7649628051 | KAVKAZSKÁ | LETNÍ JEDLE | 09.12.1947 | — |
| 7651669233 | LETNÍ | ŽALUD | 24.12.1947 | — |
| 6465572243 | TESTOVACÍ OSOBA S DLOUHÝM JMÉNEM | BOŘISLAVA ANNA MARIE FILOMÉNA | 09.04.1957 | 5754097503 |

*Zdroj:* https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/68616204

---

## 4. Testovací identity – Zdravotničtí pracovníci (KRZP)

| KRZP ID (NRZP) | Jméno | Příjmení | Dat. nar. | Povolání | Stát |
|-----------------|-------|----------|-----------|----------|------|
| 191331954 | LUDMILA | LÉKAŘSKÁ | 05.07.1992 | Lékař | ČR |
| 108765745 | Adrian Christoph | Liebert | 08.12.1986 | Lékař | SK |
| 100939278 | Christian Udo | Malý | 25.01.1992 | Lékař | DE |
| 102129137 | MRAČENA | MRAKOMOROVÁ | 26.11.1971 | Lékař | ČR |
| 158350302 | NORBERT | NĚMEČEK | 08.08.1988 | Zubní lékař | ČR |
| 175702010 | PETRA | NOSKOVÁ | 26.09.1981 | Lékař | ČR |
| 111665378 | ZDENĚK | AL-OSIMI | 09.11.1973 | Všeob. sestra | ČR |
| 152816631 | HANA | AMBROSOVÁ | 02.03.1956 | Lékař | ČR |
| 148425695 | RADOVAN | ASSEFA | 06.06.1977 | Lékař | ČR |
| 163643832 | Ivana | Bartošková | 13.05.1977 | Všeob. sestra | ČR |
| 111520123 | Horst | Beck | 18.01.1986 | Lékař | UA |
| 128169327 | ALEŠ | Černý | 11.06.1955 | Lékař | ČR |
| 174033508 | Oskar | Dvořák | 17.02.1983 | Lékař | ČR |
| 155348468 | PAVLA | DVOŘÁKOVÁ | 07.06.1955 | Lékař | ČR |
| 178468125 | Theodor-Alexander | Fuchss | 06.05.1985 | Lékař | DE |
| 168766466 | Nicola Margareta | Gatos | 20.07.1993 | Lékař | SK |
| 198585123 | Lucie | GEBAUEROVÁ | 19.06.1979 | Všeob. sestra | ČR |
| 161690144 | Ivan | Grabau | 28.10.1984 | Lékař | SK |
| 177687994 | Michal | Hostinský | 02.10.1969 | Zubní lékař | ČR |
| 184735628 | Pavla | Hyprová | 02.03.1976 | Všeob. sestra | ČR |
| 164425371 | MICHAELA | KIRCHMANN-KOLÁŘOVÁ | 30.07.1977 | Psycholog | ČR |
| 122645303 | KAZIMÍR | KLOBOUČEK | 25.03.1932 | Farm. asistent | ČR |
| 113343527 | Libor | Krabica | 23.04.1984 | Lékař | ČR |
| 166615152 | JANA | KUBRIČANOVÁ | 04.04.1990 | Lékař | ČR |
| 153247336 | Marta | Kulinich | 09.06.1984 | Lékař | UA |
| 100658866 | Markéta | KUŽELOVÁ | 03.01.1983 | Všeob. sestra | ČR |
| 191233405 | Petr | POLÁCH | 30.12.1985 | Lékař | ČR |
| 182630602 | JOSEF | Prchal | 30.01.1983 | Lékař | ČR |
| 177550538 | BOROVICE | PYRENEJSKÁ | 14.07.1947 | Lékař | ČR |
| 182481024 | RAIMUNDA | ROLNIČKOVÁ | 10.02.1978 | Dětská sestra | ČR |
| 183201139 | LUMÍR | ROUČKA | 03.05.1946 | Zubní lékař | ČR |
| 135988512 | ŘEHOŘ | ŘEPNÝ | 19.07.1979 | Lékař | ČR |
| 162686898 | Karel | SEDLÁČEK | 21.07.1972 | Lékař | ČR |
| 144481029 | Jiří | Seemann | 09.07.1977 | Lékař | ČR |
| 181885528 | STANDA | SCHRÁNKA | 09.09.1990 | bez povolání | ČR |
| 168857161 | Jiří | SCHUBERT | 01.06.1964 | Zubní lékař | ČR |
| 152598842 | David | SÍLA | 11.12.1974 | Lékař | ČR |
| 110683738 | SERVÁC | SOUKUP | 08.08.1988 | Lékař | ČR |
| 136808342 | BRONISLAV | STANĚK | 16.10.1987 | Zubní lékař | ČR |
| 106536485 | Jakub | STEJSKAL | 29.04.1974 | Lékař | ČR |
| 131925618 | MIROSLAV | Strachota | 18.06.1968 | Lékař | ČR |
| 152987109 | Jaroslava | ŠUPÍKOVÁ | 25.07.1975 | Všeob. sestra | ČR |
| 129410556 | Adolf | Švarc | 12.11.1956 | Lékař | ČR |
| 136391970 | TADEÁŠ | TICHOŠLÁPEK | 10.07.1931 | bez povolání | ČR |
| 195435779 | JAN | Válek | 02.08.1953 | Lékař | ČR |
| 110181995 | Petr | Vejvoda | 01.05.1968 | Lékař | ČR |
| 183209763 | Hildegarda | Kapsch | 11.11.1990 | Lékař | DE |
| 196969927 | Jaromír | Černý | 18.09.1954 | Zubní technik | ČR |

### Pracovníci navázaní na PZS

| KRZP ID | Jméno | Příjmení | IČO zaměstnavatele |
|---------|-------|----------|-------------------|
| 155348468 | PAVLA | DVOŘÁKOVÁ | 47911492 |
| 175702010 | PETRA | NOSKOVÁ | 28821599 |
| 177550538 | BOROVICE | PYRENEJSKÁ | 28375556 |
| 195435779 | JAN | Válek | 829013 |

*Pozn.: Fialově označené identity v originálním souboru jsou "ROB cyklické" – jejich data se průběžně mění.*

---

## 5. Přehled služeb SEZ

### 5.1 API služby přes Gateway

| # | API služba | Verze | Base path | EP | Paginace |
|---|-----------|-------|-----------|----|----------|
| 1 | Dočasné úložiště | v1.0.0 | `/docasneUloziste` | 5 | page=1 (1-based) |
| 2 | Elektronické posudky | v1.0.6 | `/elektronickePosudky` | 10 | page=0 (0-based) |
| 3 | eŽádanky | v1.0.0 | `/eZadanky` | 10 | — |
| 4 | EZCA 2 | v1.0.0 | `/ezca2` | 30 | — |
| 5 | KRP PZS | v2.0.0 | `/krp` | 24 | — |
| 6 | KRPZS PZS | v2.0.0 | `/krpzs` | 17 | — |
| 7 | KRZP PZS | v2.0.0 | `/krzp` | 18 | — |
| 8 | **Notifikace CSSN** | v1.0.0 | `/notifikace` | 7 | **page=0 (0-based!)** |
| 9 | Registr oprávnění | v1.0.0 | `/registrOpravneni` | 1 | — |
| 10 | SZZ | v1.0.6 | `/sdilenyZdravotniZaznam` | 40 | page=0 (0-based) |
| 11 | TermX Terminologie | v1.0.5 | `/terminologie` | 57 | — |

### 5.2 Služby mimo Gateway (přímý přístup)

| Služba | URL | Poznámka |
|--------|-----|----------|
| TermX Swagger | https://termx-swagger-web-t2-pub.csez.cz/swagger/ | vyžaduje mTLS |
| KRP Swagger | https://krp-pzs-t2.csez.cz/swagger/index.html | veřejný |

---

## 6. Popis klíčových služeb

### 6.1 KRP – Kmenový registr pacientů
Primární zdroj dat o pacientech. Jednoznačná identifikace pacientů přes **RID** (bezvýznamový identifikátor). Napojení na základní registry ČR. PZS hledá pacienty, získává RID, aktualizuje údaje.

### 6.2 KRZP – Kmenový registr zdravotnických pracovníků
Autoritativní zdroj dat o ZP. Napojení na NRZP. Identifikace přes **KRZP ID** (číslo NRZP).

### 6.3 KRPZS – Kmenový registr poskytovatelů ZS
Údaje o PZS. Identifikace přes **IČO**. Napojení na NRPZS.

### 6.4 Dočasné úložiště (DÚ)
Dočasné ukládání zásilek/dokumentů mezi PZS. Odesílání, stahování, vyhledávání zásilek. Podpora notifikací na příjem zásilek.

### 6.5 eŽádanky
Elektronická správa žádostí o zdravotní služby. Životní cyklus:
`UložŽádanku → PřijmiŽádanku → VyřiďŽádanku`
Alternativně: Storno, Vrátit do oběhu, Neproveditelnost.
Stavy: Nová (0) → Přijatá (1) → Vyřízená (2), Stornovaná (3), Vrácená do oběhu (5), Neproveditelná (4).

**Důležité:** eŽádanky vyžadují PZS kontext (autorizace). Bez PZS kontextu vrací `E01001`.

### 6.6 SZZ – Sdílený zdravotní záznam
Emergentní záznamy, alergie, léčiva, očkování, zdravotní záznamy. Oprávnění přes Registr oprávnění. Pacient může omezit přístup.

### 6.7 ELP – Elektronické lékařské posudky
Posudky zdravotní způsobilosti (řidičské oprávnění). Standard verze 2 (zveřejněn 20.2.2026).

### 6.8 Notifikace CSSN
Centrální systém upozornění. Kanály: EMAIL, SMS, PushNPEZ, PushEZKarta, PZSPSS, WEBSERVICE, DATOVA_SCHRANKA.
**Katalogy:** kanály, šablony, zdroje.
**Stránkování: 0-based!** (`page=0` = první stránka)

### 6.9 Registr oprávnění
Správa souhlasů pacientů s nahlížením. Ověření oprávnění PZS/ZP. Správa zástupců.

### 6.10 EZCA 2 – Služby vytvářející důvěru
Pečetění, podepisování, razítkování, validace dokumentů. Vydávání certifikátů.

### 6.11 TermX – Terminologický server
FHIR terminologický server. CodeSystem, ValueSet, ConceptMap operace. SNOMED, ICD-10, ATC, LOINC a další klasifikace.

**TermX hlavní API** (266 operací):
- Terminology Core (`/api/ts/`) – CodeSystem, ValueSet, MapSet CRUD
- SNOMED (`/api/snomed/`) – branches, concepts, descriptions, translations
- Edition importers – ATC, ICD-10, LOINC, Orphanet
- Wiki, Task management, StructureDefinition, ObservationDefinition

**TermX FHIR API** (standard HL7 FHIR):
- `GET /metadata` – CapabilityStatement
- ValueSet: read, search, `$expand`, `$validate-code`, `$sync`
- CodeSystem: read, search, `$lookup`, `$validate-code`, `$subsumes`
- ConceptMap: read, search, `$translate`
- StructureMap: read, search, `$transform`

---

## 7. Notifikační kanály (T2)

Z API katalogu (9 kanálů):
| Kód | Název |
|-----|-------|
| EMAIL | Emailový kanál Sendgrid |
| SMS | SMS kanál |
| PushNPEZ | NPEZ kanál (portál) |
| PushEZKarta | EZkarta kanál (mobilní app) |
| PZSPSS | PZS/PSS |
| TestKanal | Testovací kanál |
| PREFERENCE_TEST_EZKARTA | Test preferencí EZKARTA |
| PREFERENCE_TEST_NPEZ | Test Preferencí NPEZ |
| PREFERENCE_TEST_EMAIL | Test preferencí EMAIL |

Šablon: **62**, Zdrojů: **17** (včetně FNO, FNB, KNTB, JSU, JIRA, NMB, MNOF apod.)

---

## 8. Důležité dokumenty (PDF)

| Dokument | Popis | Poznámka |
|----------|-------|----------|
| EZ_SL03_RP03_Standard | Standard služby SZZ | Hledat na Confluence, stránka SZZ (aktualizováno 29.1.2026) |
| Standard ELP v2 | Standard služby ELP | Zveřejněn 20.2.2026 |
| Standard ELP v1 | Starší verze | Aktualizováno 3.12.2025 |
| Metodický materiál ELP | Pro posuzující lékaře | Zveřejněn 20.2.2026 |
| Testovací identity (XLSX) | Obsáhlá tabulka pacientů | Ke stažení na Confluence |
| ZP identity (XLSX) | Sada ZP identit | Aktualizováno 10.11.2025 |

*Pozn.: Většina PDF/XLSX je přístupná pouze po přihlášení do Confluence.*

### Standardy EHR – prioritní kategorie (IROP/NPO)

> **Zdroj:** https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/203096069/Standardy+EHR+-+prioritn+kategorie
> Platné od **1.1.2026**. Dočasná forma zpřístupnění – v Q1 2026 bude spuštěn Registr standardů EZ.
> Zákon č. 325/2021 Sb. o elektronizaci zdravotnictví §38 2) c).

5 prioritních kategorií dokumentů, každá má 2 verze (v15 + v16 metodický pokyn pro L1):

| # | Standard | Stránka | Soubory (DOCX) |
|---|----------|---------|----------------|
| 1 | **Zpráva z obrazového vyšetření** | [page/203358209](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/203358209) | `Standard EHR_Zpráva z obrazového vyšetření - metodický pokyn pro L1_v16.docx` (3.9 MB), `Standard EHR Zprava z obrazoveho vysetreni v15.docx` (3.9 MB) |
| 2 | **Zpráva z laboratorního vyšetření** | [page/203292676](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/203292676) | `Standard EHR_Zpráva z laboratorního vyšetření - metodický pokyn pro L1_v16.docx` (3.9 MB), `Standard EHR Zprava z laboratorniho vysetreni v15.docx` (3.2 MB) |
| 3 | **Záznam o výjezdu ZZS** | [page/203456513](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/203456513) | `Standard EHR_Záznam o výjezdu ZZS - metodický pokyn pro L1_v16.docx` (3.9 MB), `Standard EHR Zaznam o vyjezdu ZZS v15.docx` (3.9 MB) |
| 4 | **Pacientský souhrn** | [page/202997766](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/202997766) | `Standard EHR_Pacientský souhrn - metodický pokyn pro L1_v16.docx` (3.9 MB), `Standard EHR Pacientsky souhrn v15.docx` (3.9 MB) |
| 5 | **Propouštěcí zpráva z nemocnice** | [page/202244113](https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/202244113) | `Standard EHR_Propouštěcí zpráva - metodický pokyn pro L1_v16.docx` (3.8 MB), `Standard EHR Propousteci zprava v15.docx` (3.8 MB) |

#### Společná architektura všech standardů (L1)

Všechny standardy sdílejí architekturu **"obálky a obsahu"**:
- **Strukturovaná obálka (Hlavička):** Sada zdrojů ve formátu **HL7 FHIR** – strojově zpracovatelný základ
- **Klinický obsah (Tělo):** Neměnný dokument ve formátu **PDF/A** s digitálním podpisem, vložený jako binární příloha
- **Formát:** FHIR `Bundle` s `type="document"`, první `entry` je vždy `Composition`
- **Povinné FHIR zdroje:** Composition, Patient, Practitioner, Organization, Encounter, DocumentReference
- **Identifikátory:** KRP (RID/DRID pacienta), KRZP (pracovník), NRPZS (poskytovatel)
- **Obligation Framework:** MUSÍ / MĚL BY / MŮŽE

#### Implementační příručky (IG) – hierarchie

| Standard | Specifická IG | URL |
|----------|--------------|-----|
| Všechny | **HL7 FHIR CZ Core IG** (základ) | https://build.fhir.org/ig/HL7-cz/core/ |
| Obrazové vyšetření | **HL7 CZ IMG IG** (Imaging Report) | https://build.fhir.org/ig/HL7-cz/img/ |
| Laboratorní vyšetření | **HL7 CZ Laboratory IG** | https://build.fhir.org/ig/HL7-cz/cz-lab/ |
| Výjezd ZZS | **HL7 CZ ZOV ZZS IG** | https://build.fhir.org/ig/HL7-cz/cz-ems/ |
| Pacientský souhrn | **HL7 CZ Patient Summary IG** | https://build.fhir.org/ig/HL7-cz/ps/ |
| Propouštěcí zpráva | **HL7 CZ HDR IG** (Hospital Discharge Report) | https://build.fhir.org/ig/HL7-cz/hdr/ |

#### Specifika jednotlivých standardů

| Standard | Specifika těla dokumentu |
|----------|-------------------------|
| Obrazové vyšetření | Textový nález + PDF/A. DICOM obrazy se NEPOSÍLAJÍ v FHIR. Povinné: `AccessionNumber`, `StudyInstanceUID` (DICOM 0020,000D) |
| Laboratorní vyšetření | PDF/A **+ DASTA** (celá datová zpráva lab. výsledků ve formátu DASTA 3.x/4.x embedovaná jako binární příloha). Bundle MUSÍ obsahovat `DiagnosticReport` |
| Výjezd ZZS | Celý průběh od přijetí tísňového volání po předání pacienta. PDF/A. Identifikace přes ISZZS |
| Pacientský souhrn | **Dvě varianty:** Verze 1 = FHIR L1/L3 (povinná od 1.1.2026), Verze 2 = HL7 CDA (dočasná, jen pro systémy zprovozněné před 1.1.2026). CDA spec: https://art-decor.ehdsi.eu/ |
| Propouštěcí zpráva | Informace o ukončení jednodenní/lůžkové péče. PDF/A |

#### Úrovně strukturovanosti L1 / L2 / L3

| Charakteristika | L1 (Základní) | L2 (Přechodná) | L3 (Plná shoda) |
|----------------|---------------|-----------------|------------------|
| **Hlavička** | Plně strukturovaná FHIR | Jako L1 | Jako L1+L2 |
| **Tělo** | Nestrukturovaný PDF/A (+ DASTA u lab.) | PDF/A + narativní sekce / strukturovaná metadata | Plně strukturované FHIR zdroje |
| **Strojová zpracovatelnost** | Omezená na metadata | Rozšířená o klíčové info | Plná |
| **EHDS soulad** | Nesplňuje | Částečně | Splňuje |

#### Harmonogram povinností (EHDS)

| Milník | Úroveň | Odesílatel (NIS/LIS) | Příjemce (AIS) | EHDS |
|--------|--------|---------------------|----------------|------|
| **Do 31.12.2026** | L1 | MUSÍ generovat | MUSÍ přijímat | Vydání prováděcích aktů EK |
| **Do 31.12.2028** | L2 | MUSÍ generovat | MUSÍ přijímat | Povinnost předávat data 1. skupiny |
| **Do 26.3.2031** | L3 | MUSÍ generovat | MUSÍ plně zpracovávat | Povinnost v EU formátu |

#### Verze dokumentů
- **v15** = Starší verze standardu (metodický pokyn)
- **v16** = Aktuální verze s metodickým pokynem pro **L1** (platná od 1.1.2026)

#### Lokální kopie DOCX
Staženo do `ehr_standards/` (10 souborů, celkem ~37 MB)

**Přímé odkazy na stažení** (vyžadují přihlášení do Confluence):
- https://mzcr.atlassian.net/wiki/download/attachments/203358209/Standard%20EHR_Zpr%C3%A1va%20z%20obrazov%C3%A9ho%20vy%C5%A1et%C5%99en%C3%AD%20-%20metodick%C3%BD%20pokyn%20pro%20L1_v16.docx
- https://mzcr.atlassian.net/wiki/download/attachments/203292676/Standard%20EHR_Zpr%C3%A1va%20z%20laboratorn%C3%ADho%20vy%C5%A1et%C5%99en%C3%AD%20-%20metodick%C3%BD%20pokyn%20pro%20L1_v16.docx
- https://mzcr.atlassian.net/wiki/download/attachments/203456513/Standard%20EHR_Z%C3%A1znam%20o%20v%C3%BDjezdu%20ZZS%20-%20metodick%C3%BD%20pokyn%20pro%20L1_v16.docx
- https://mzcr.atlassian.net/wiki/download/attachments/202997766/Standard%20EHR_Pacientsk%C3%BD%20souhrn%20-%20metodick%C3%BD%20pokyn%20pro%20L1_v16.docx
- https://mzcr.atlassian.net/wiki/download/attachments/202244113/Standard%20EHR_Propou%C5%A1t%C4%9Bc%C3%AD%20zpr%C3%A1va%20-%20metodick%C3%BD%20pokyn%20pro%20L1_v16.docx

---

## 9. Známé problémy a workaroundy

| Problém | Příčina | Řešení |
|---------|---------|--------|
| eŽádanky `E01001` – "pouze pacient nebo PZS" | Chybí PZS kontext v tokenu | Simulační režim v naší app |
| Notifikace katalogy prázdné, ale totalCount > 0 | API stránkování je 0-based, posílali jsme page=1 | Opraveno: `page=0` |
| DÚ `E01060` – JSU token invalid | Problém na straně JSU/služby | Retry + fallback |
| TermX swagger timeout | Vyžaduje mTLS certifikát | Přístup přes pythouna s cert |

---

## 10. Certifikátová struktura EZCA

| Položka | Hodnota |
|---------|---------|
| Version | v3 |
| Signature Algorithm | SHA256RSA |
| Platnost | 2 roky |
| Subject serial number | Jednoznačný ID subjektu |
| OID 2.5.4.97 | IČO nebo KRZPID |
| Veřejný klíč | **4096 bitů** RSA |
| Key Usage | digitalSignature |
| Extended Key Usage | Client Authentication (1.3.6.1.5.5.7.3.2) |
| CRL | `http://ezca.mzcr.cz/EZCA1.crl`, `http://ezca.mzcr.cz/EZCA2.crl` |

---

## 11. Lokální soubory projektu

```
Analytics_SEZAPI/
├── SEZ_API_Dokumentace.md      # Detailní API dokumentace (1743 řádků)
├── SEZ_Reference.md            # TENTO SOUBOR – kompaktní reference
├── INSTALL.md                  # Instalační příručka
├── swagger_specs/              # OpenAPI specifikace (14 souborů, akt. 2026-02-19)
│   ├── DocasneUloziste_v1.0.0.json
│   ├── EZadanky_v1.0.0.json
│   ├── ElektronickePosudky_v1.0.6.json    # archiv
│   ├── ElektronickePosudky_v1.0.7.json    # aktuální v1
│   ├── ElektronickePosudky_v2.0.1.json    # NOVÉ v2 API
│   ├── Ezca2_v1.0.0.json
│   ├── KrpPzs_v1_direct.json              # přímý přístup (33 paths)
│   ├── KrpPzs_v2.0.0.json                 # gateway verze (32 paths)
│   ├── KrpzsPzs_v2.0.0.json
│   ├── KrzpPzs_v2.0.0.json
│   ├── Notifikace_v1.0.0.json
│   ├── RegistrOpravneni_v1.0.0.json
│   ├── SdilenyZdravotniZaznam_v1.0.6.json
│   └── TermxTerminologie_v1.0.5.json
└── src/                        # Zdrojové kódy

sez_api_python/sez_api/         # Python backend + web UI
├── app.py                      # FastAPI backend (73 KB)
├── client.py                   # SEZ API klient (60 KB)
├── config.py                   # Konfigurace
├── cli.py                      # CLI rozhraní
└── templates/index.html        # Web UI
```

---

## 12. Kompletní přehled API endpointů (ze stránky 80904194)

| Služba | T2 (test) | Produkce |
|--------|-----------|----------|
| KRP | `https://gwy-ext-sec-t2.csez.cz/krp/` | `https://api.csez.gov.cz/krp/` |
| KRZP | `https://gwy-ext-sec-t2.csez.cz/krzp/` | `https://api.csez.gov.cz/krzp/` |
| KRPZS | `https://gwy-ext-sec-t2.csez.cz/krpzs/` | `https://api.csez.gov.cz/krpzs/` |
| Dočasné úložiště | `https://gwy-ext-sec-t2.csez.cz/docasneUloziste/` | `https://api.csez.gov.cz/docasneUloziste/` |
| eŽádanky | `https://gwy-ext-sec-t2.csez.cz/eZadanky/` | `https://api.csez.gov.cz/eZadanky/` |
| Notifikace | `https://gwy-ext-sec-t2.csez.cz/notifikace/` | `https://api.csez.gov.cz/notifikace/` |
| Terminologie (auth) | `https://gwy-ext-sec-t2.csez.cz/terminologie/` | `https://api.csez.gov.cz/termx-fhir/` |
| Registr oprávnění | `https://gwy-ext-sec-t2.csez.cz/registrOpravneni/` | `https://api.csez.gov.cz/registrOpravneni/` |
| EZCA 2 | `https://gwy-ext-sec-t2.csez.cz/ezca2/` | `https://api.csez.gov.cz/ezca2/` |
| SZZ | `https://gwy-ext-sec-t2.csez.cz/sdilenyZdravotniZaznam/` | `https://api.csez.gov.cz/sdilenyZdravotniZaznam/` |
| ELP | `https://gwy-ext-sec-t2.csez.cz/elektronickePosudky/` | `https://api.csez.gov.cz/elektronickePosudky/` |

---

## 13. Testovací identity – Poskytovatelé zdravotních služeb (PZS)

| IČO | Název | Stav | Obec | V ROS |
|-----|-------|------|------|-------|
| 60470488 | AeskuLab k.s. | Platný | Praha 6 | NE |
| 28660706 | Aledion Medical Centre spol. s r.o. | Platný | Rožnov p.R. | NE |
| 29095034 | ALFA PRAKTIK s.r.o. | Platný | Klatovy | NE |
| 25706381 | Canadian Medical s.r.o. | Platný | Praha 6 | NE |
| 05841321 | Dětský lékař Beroun s.r.o. | Platný | Beroun | NE |
| 00064203 | Fakultní nemocnice v Motole | Platný | Praha 5 | NE |
| 28821599 | Gynekologie Jičín s.r.o. | Platný | Jičín | NE |
| 27661989 | Krajská nemocnice T. Bati, a. s. | Platný | Zlín | NE |
| 47911492 | Městská poliklinika u sv. Alžběty | Platný | Uh. Hradiště | NE |
| 02233664 | Mračena poskytuje zdravotní služby | Platný | Říčany | NE |
| 28375556 | Praktický lékař pro děti a dorost s.r.o. | Platný | Kutná Hora | NE |
| 47453745 | Poliklinika Týniště nad Orlicí | Platný | Týniště n.O. | NE |
| 829013 | ZZS Ústeckého kraje | Platný | Ústí n.L. | ANO |
| 25488627 | Krajská zdravotní, a.s. | Platný | Ústí n.L. | — |

---

## 14. FAQ z Confluence

1. **DÚ hash algoritmus:** SHA256 hash z base64 obsahu pro ověření integrity
2. **ELP GUI pro lékaře:** Ano, přes NPEZ portál
3. **Testovací data KRZP/KRPZS:** Na stránce "Testovací identity"
4. **Hromadné ztotožnění:** Vzorový XML soubor na stránce API KRP
5. **KRPZS datový zdroj:** Čerpá z NRPZS (§74-75 zákona 372/2011 Sb.)
6. **Neexistuje KRPZSID:** Identifikátor PZS = IČO (analogicky k RID pro pacienty)
7. **Atribut "stav":** Stav záznamu – "correct" (výchozí), "zpochybněný" (napadený oprávněnou osobou)
8. **Univerzální hledání pacienta:** Kombinuje všechny metody; validace kontroluje platné kombinace (min. jméno + datum narození)
9. **Rozsah pojištění:** KRP obsahuje pouze veřejné zdravotní pojištění (dle zákona), ne komerční

---

## 15. Předpoklady pro testování (Confluence checklist)

### Technické
- IS musí podporovat rozhraní a datové formáty definované MZČR
- REST API komunikace, TLS 1.2+, platné certifikáty
- Povinné integrace: KRP, KRPZS, KRZP
- NTS integrace pro číselníky

### Organizační
- Koordinátor pro připojení a testování
- IT/security dostupní během testování
- Přístup k dokumentaci (standardy, FHIR IG, metodiky, testovací scénáře)

### Datové
- Testovací identity pacientů od MZČR
- Zdravotnická data v IS pro testovací profily
- Testovací ZP identity a certifikáty spárované s PZS

### Infrastruktura
- Přístup k NCEZ test platformě s registrovanými certifikáty
- Oddělené sandbox a produkční prostředí

### Legislativní
- Smlouva s MZČR/NCEZ pro přístup k centrálním systémům
- Soulad se zákonem 325/2021 Sb. a 372/2011 Sb.

---

## 16. Certifikáty pro testování

Akceptované certifikační autority pro B2B přístup:
- `CN=EREGCA, DC=int, DC=ereg, DC=cz`
- `CN=EREG CA1 Test, DC=int, DC=ereg, DC=cz`
- `CN=EZCA Test 1, OU=TEST, O=ÚZIS ČR, C=CZ`
- `CN=EZCA Test 2, OU=TEST, O=ÚZIS ČR, C=CZ`
- `CN=SUKL G2 Issuing CA, DC=sukl, DC=cz`

Kontakt pro žádost o certifikát: `csez@mzd.gov.cz` (přiložit mobil pro doručení hesla)

EZCA II nahradí stávající systém správy certifikátů (produkční verze dosud nesprávně vystavuje certifikáty pro API GW autentizaci).

---

## 17. DASTA4 Validátor & FHIR R5 (ezprava.net)

### Validátor – ezprava.net/ds4

| Položka | URL / hodnota |
|---------|---------------|
| **Webové rozhraní** | https://ezprava.net/ds4 |
| **REST API** | `POST https://ezprava.net/ds4/api/validate` (multipart file upload) |
| **Testovací data** | https://ezprava.net/ds4/TestData |
| **Validační pravidla** | https://ezprava.net/ds4/Rules |
| **Schéma DS4** | verze 4.28.01 |
| **Certifikát** | Přístup volitelný – bez certifikátu propustí |

### Podporované formáty

| Formát | Popis |
|--------|-------|
| DASTA4.XML | Datový standard MZ ČR verze 4.x (DS4 v4.28.01) |
| LCLPPOL.XML | Lokální katalog laboratorních položek |
| FHIR.XML (R5) | FHIR R5 Bundle (type=document) |
| PDF | Kontrola PAdES digitálních podpisů (DSS EU validátor) |
| ASiC | ASiC-S, ASiC-E kontejnery (CAdES/XAdES podpisy) |
| EvidenceRecord | Evidence record validace |
| P7S/P7M | PKCS#7 podpisy |

### Klíčová validační pravidla DS4

| Element | Pravidlo |
|---------|----------|
| `dasta` (kořen) | Povinné atributy: `verze_ds`, `id_soubor`, `ur`, `verze_nclp`, `dat_vb`, `typ_odesm` |
| `ip` (identifikace pac.) | `id_pac` + `typ_id` (0=RČ, 1=jiný); RC validace mod-11 |
| `ku_z_labType` | Laboratorní výsledky – povinné `dat_real`, NCLP kódy musí existovat |
| `garant_dat` | Povinné: `id_lp` (KRZP ID), `jmeno`, `prijmeni` |
| `nrz` / `nrpot` | NCLP identifikátory – validátor kontroluje existenci kódu |
| `lclppolVetaType` | LCLPPOL soubor – validuje strukturu a vazby na NCLP |
| FHIR R5 Bundle | Kontroluje Composition, Patient, referenční integritu |
| PDF/ASiC | Digitální podpisy – DSS European Commission validátor |

### FHIR R5 – CH RAD Order (radiologická žádanka)

Implementační příručka: https://ezprava.net/ds4/doc/fhir/fhir.ch_ig_ch-rad-order.html

| FHIR zdroj | Profil | Účel |
|-------------|--------|------|
| ServiceRequest | ChRadOrderServiceRequest | Hlavní žádanka – typ vyšetření, priorita |
| Composition | ChRadOrderComposition | Obálka Bundle type=document |
| Condition | ChRadOrderDiagnosis | Hlavní diagnóza (ICD-10 / SNOMED) |
| Condition | ChRadOrderCaveat | Kontraindikace / upozornění |
| Observation | 15 typů (caveaty) | Kreatinin, GFR, TSH, těhotenství, hmotnost, výška aj. |
| Patient | ChCorePatient | Identifikace pacienta |
| Practitioner | ChCorePractitioner | Žádající lékař |
| QuestionnaireResponse | ChOrfQuestionnaireResponse | Strukturovaný formulář žádanky |

**Observation LOINC kódy (caveaty):**

| Profil | LOINC | Jednotka |
|--------|-------|----------|
| BodyWeight | 29463-7 | kg |
| BodyHeight | 8302-2 | cm |
| CreatinineClearance | 33558-8 | mL/min |
| SerumCreatinine | 2160-0 | µmol/L |
| GFR | 98979-8 | mL/min/1.73m² |
| TSH | 3016-3 | mIU/L |
| Pregnancy | 82810-3 | boolean |

Další Caveat typy: ContrastMediaAllergy, DrugPrescription, DeviceImplant, DiabetesMellitus, Claustrophobia, Pacemaker, RenalInsufficiency, PreviousResults
