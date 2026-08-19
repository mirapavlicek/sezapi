"""
SEZ API klient – Python knihovna pro práci se Sdíleným elektronickým zdravotnictvím.

Podporované služby:
  - KRP (Kmenový registr pacientů)
  - KRZP (Kmenový registr zdravotnických pracovníků)
  - DÚ (Dočasné úložiště)
  - SZZ (Sdílený zdravotní záznam – v1, v2.0.1 a NOVĚ v3.0.0 dle
      Standardu EZ SZZ 3.0: nové screeningy, položka samoplatce,
      rozsahy hodnot z přílohy Validace 3.0)
  - ELP (Elektronické posudky v1)
  - ELPv2 (Elektronické posudky v2)
  - ELPv3 (Elektronické posudky v3.0.1)
  - eŽádanky (vč. simulačního enginu)
  - Zprávy eZD (builder dokumentů dle HL7 CZ IG – 5 typů: pacientský
      souhrn, propouštěcí zpráva, zpráva z obrazového vyšetření, zpráva
      o výjezdu ZZS, laboratorní zpráva; katalog sekcí, ukázky, L1 validace)
  - FHIR Imaging Order (HL7-cz img-order IG v0.1.0-ballot, R4 → /eZadanky bridge)
      • závislosti: cz-core 0.3.0, cz-terminology 0.2.0, eu.base 2.0.0
      • taxonomie (ValueSets) napojené na živý TermX (public mirror) –
        cz-modality, cz-imagingProcedureVs, mkn-10 (Mkn10_5), mobility;
        bodySite/qualifier vedeny jako pomocné (mimo IG)
      • CodeSystem/$lookup proxy pro SNOMED, ICD-10, MKN-10, DICOM
  - Notifikace
  - EZCA2 (Služby vytvářející důvěru)
  - EZCA Validace v1.0.0 (online/offline validace dokumentů – ELP;
      swagger apio.csez.gov.cz/apidoc)
  - NCPeH – přeshraniční pacientský souhrn (MyHealth@EU/eHDSI; role A
      zdroj dat: getpsexists/getps + PS CDA L1/L3 Friendly se stabilním
      cdaLxId; role B konzument: vyhledání pacienta dle konfigurace země,
      dokumenty, stažení a zobrazení PS; lokální kontroly CDA dle
      testovacího rámce NCPeH v1.1 Kraje Vysočina; bez NCPEH_PPT_URL
      SIMULACE vč. kritického pacienta)
  - Terminologie / TermX (FHIR R4 terminologický server / NTS –
      PROD apio.csez.gov.cz/terminologie, T2 public mirror, gateway;
      swagger v1.1.0 na apio: + GET /manifest, ConceptMap/$translate
      se parametrizuje sourceCode/targetSystem)

Verze rozhraní: poslední živá kontrola T2 gateway (/apidoc/config.json,
mTLS – dostupná jen z ČR/SK) proběhla 2026-06-08: KRP v2.0.4+v3.0.3,
KRZP v2.0.2, KRPZS v2.0.3, RO/RO-NCPeH v1.0.7, DÚ a eŽádanky v1.11.17,
ELP v1.0.7/v2.0.11/v3.0.2, SZZ v1.0.9+v2.0.3, Notifikace v1.0.6,
EZCA2 v1.0.7 + Správa v1.0.4, TermX v1.0.5; img-order IG 0.1.0-ballot.
Revize veřejné dokumentace 2026-07-02: PROD katalog apio.csez.gov.cz/apidoc
ověřen živě (EZCA Validace v1.0.0 NOVÁ, Terminologie v1.1.0); dle aktualit
Manuálu EZ pro PZS (k 16. 6. 2026) dále SZZ v2.0.4 na T2 (Standard SZZ 2.1)
a Popis API DÚ v1.2 (ZpochybniZasilku). Živé T2 verze: /api/services/discover.

Builder zpráv eZD (2026-07-26): interaktivní GUI sekce „Zprávy eZD" pro
tvorbu elektronických zdravotních dokumentů dle HL7 CZ IG – pět typů zpráv
(pacientský souhrn ps 0.0.1, propouštěcí zpráva hdr 0.1.0, zpráva
z obrazového vyšetření img 0.1.0-ballot, zpráva o výjezdu ZZS cz-ems 0.0.2
a NOVĚ laboratorní zpráva cz-lab 0.5.0). Katalog všech sekcí každého
profilu (povinné i volitelné, LOINC kódy + české názvy), ukázková data,
live náhled JSON s okamžitou L1 validací, validace vlastního JSON,
stažení/kopírování a odeslání do DÚ. API: /api/zpravy/katalog,
/ukazka/{kategorie}, /nahled, /validovat, /odeslat-du.

Generátor InterSystems IRIS pro zprávy eZD (sez_api.iris_ezd + tlačítko
„Generovat IRIS kód" v builderu): z vyplněného formuláře vytvoří
ObjectScript, který tutéž zprávu sestaví, zvaliduje dle L1 a uloží do DÚ –
úryvek pro terminál, hotovou .cls třídu s předvyplněnými sekcemi a runtime
třídu SEZ.EZD.Builder (Sestav / Validuj / ZasilkaProDU / SestavAOdesli,
zná všech 5 kategorií vč. povinných i volitelných sekcí).
API: /api/zpravy/iris-kod, /api/zpravy/iris-builder.

Revize NCEZ zdrojů 2026-08-19:
- SZZ má NOVOU verzi API 3.0.0 (Standard EZ SZZ 3.0 zveřejněný 29. 7. 2026,
  aplikace nasazena na T1/T2 28. 7.). Doplněna třída SZZv3 – cesty /api/v3,
  pět nových screeningů (kolorektální karcinom – koloskopie, karcinom
  prostaty – vstupní PSA / navazující urologické / navazující bioptické
  vyšetření, karcinom plic – pneumologické vyšetření), opravený název HPV
  screeningu děložního hrdla (v2 měla dvojité „D“, přijímáme jako alias),
  souhrnné /zdravotniZaznamy/vyhledat, nová volitelná položka `samoplatce`
  (boolean, výchozí false) u všech prevencí i screeningů a `genotypyHpvTestu`
  u HPV. Doplněny rozsahy hodnot z přílohy Validace SZZ 3.0 (ntProbnp
  0–100 000, výška 10–300 cm, váha 0–400 kg a obvod pasu 10–400 cm na
  3 desetinná místa, hladina TOKS 0–500 µg/g, BBPS 0–9 celé číslo, hladina
  PSA 1 000–12 000 µg/l, objem prostaty 0–1 000 ml, PSA denzita i velocita
  0–10, volné texty max. 300 znaků) + klientská kontrola SZZv3.zkontroluj()
  a 15 nových číselníků (szz-ucast-*, gastro-*, urologie-*, pneumologie-*).
  API: /api/szz3/… vč. /api/szz3/katalog a /api/szz3/zkontrolovat.
  Verze v2 zůstává dostupná paralelně. UI: v sekci SZZ lze přepnout verzi
  API (v2/v3), zaškrtnout samoplátce a vyplnit pět nových screeningů
  i genotypy HPV testu; před zápisem se tělo ověří proti rozsahům.
- KRP vrací od 30. 7. 2026 u duplicitního pacienta více záznamů. Ztotožnění
  proto v odpovědi rozlišuje `jednoznacne` (právě jeden pacient s RID) a při
  duplicitě vrací `upozorneni`, aby NIS nepovažoval první RID za potvrzený.
- eŽádanky 1.11.20: při vyplněném `upravenyPrijemce` server ignoruje
  `upravenyPrijemceTyp` (adresátem je vždy PZS) – klient nadbytečné pole
  neposílá, aby odeslané tělo odpovídalo uloženému stavu. NactiZadanku
  navíc od 1.11.19 kontroluje integritu souboru a při nesouladu hashe
  vrací 400 místo dokumentu.
- Souhlas s nahlížením: rozšíření odpovědi (kdo a kdy nastavil) se týká
  portálové části, v API pro PZS služba není; nesouhlas pacienta se projeví
  jako HTTP 403 při čtení SZZ.
- KRP: API verze v1 pro PZS bylo k 14. 8. 2026 VYPNUTO (oznámeno 28. 7.),
  k dispozici je v3 – klient v1 nikdy nepoužíval (v2/v3), doplněna poznámka
  v přehledu specifikací. Dále opravy na produkci: návratový objekt při
  vyhledání duplicitního pacienta a hromadné ztotožnění (30. 7.), adresa
  u nově založených pacientů (12. 8.) – bez dopadu na kontrakt.
- Bez dopadu na kód: Žurnál činností 1.0.6 a MFE Notifikace 1.0.5 (22. 7.),
  RO 1.0.8, DÚ/eŽádanky 1.11.20. Katalog apio (EZCA Validace v1.0.0,
  Terminologie v1.1.0) i obě specifikace jsou bitově shodné se snapshoty.
- Stránka „API endpointy“ beze změny od 21. 7. (User-Agent povinný
  od 1. 9. 2026 – klient posílá), Manuál EZ bez nového záznamu po 30. 7.

Revize NCEZ zdrojů 2026-07-26:
- API endpointy (aktualizace 21. 7. 2026): User-Agent je nově POVINNÝ už
  od 1. 9. 2026 (dřív 1. 1. 2027) a jako prostředí se očekává hodnota
  „Test" / „Prod" – klient dřív posílal T2/PROD, opraveno mapováním dle
  base_env prostředí. X-Correlation-Id beze změny (povinné od 1. 1. 2027).
  Doplněno: název aplikace / výrobce / poznámka v User-Agent jsou
  konfigurovatelné (SEZ_APP_NAME, SEZ_VENDOR, SEZ_UA_NOTE); volitelná
  W3C hlavička traceparent (SEZ_SEND_TRACEPARENT, generuje validní
  00-<traceid>-<spanid>-01); deprecated X-Request-Id ani
  X-Manufacturer-* neposíláme. Ověřeny adresy z tabulky endpointů
  (PROD gateway api.csez.gov.cz, JSU, open apidoc apio) – souhlasí;
  doplněny adresy webového rozhraní TermX (terminologie.ezdravi.gov.cz
  pro test, termx/snomed.ezdravi.gov.cz pro produkci).
- Ostatní zdroje beze změny: apio katalog i obě specifikace (Terminologie
  v1.1.0, EZCAValidace v1.0.0 – bitově shodné se snapshoty), aktuality
  Manuálu EZ (poslední záznam 16. 6.), stránky testovacího rámce/metodiky/
  API KRP/eŽádanky/RO. CI buildy HL7 CZ IG přestavěny (HDR 24. 7., IMG
  22. 7., cz-core 22. 7.) – ověřeno, že constraints i canonicals zůstávají.
- Lint: ruff 0.16 rozšířil výchozí sadu pravidel; v pyproject zafixován
  dosavadní select (E4/E7/E9/F), aby lint nezávisel na verzi nástroje.
- Živé ověření T2 nadále blokuje expirovaný klientský certifikát
  (krajska_zdravotni.pfx, notAfter 2026-04-21 → TLS „certificate expired").

Revize NCEZ zdrojů 2026-07-20:
- apio katalog i aktuality Manuálu EZ beze změny (poslední záznam 16. 6.).
- API endpointy (aktualizace 17. 7. 2026): NOVÉ požadavky na HTTP hlavičky –
  X-Correlation-Id (UUID v4+) a User-Agent „název-aplikace/verze (prostředí;
  výrobceSW)" doporučené od 1. 9. 2026 a POVINNÉ od 1. 1. 2027; traceparent
  volitelný, X-Request-Id deprecated. Klient obě hlavičky posílá
  (SEZClient.user_agent(), session i request úroveň).
- HL7 CZ HDR IG (CI build 10. 7. 2026): přejmenován canonical composition
  profilu cz-composition-hdr → composition-cz-hdr (constraints beze změny);
  fhir_ezd aktualizován, starý canonical přijímán jako výhrada.
  ps 0.0.1 / img 0.1.0-ballot / cz-ems 0.0.2 / cz-core 1.0.0 beze změny.

UI: sekce „eHealth NIS" – pacientocentrický klinický kokpit, který kolem
jednoho RID agreguje 360° přehled napříč službami (emergentní dataset SZZ,
léky/alergie, aktivní eŽádanky, zásilky DÚ, oprávnění RO, historie KRP).
Náhledy i zakládání se otevírají INLINE přímo v kokpitu (panel pod dlaždicemi):
náhledy se vykreslí v panelu, plné moduly (eŽádanky, FHIR Img, SZZ, ELP, DÚ, RO)
se dočasně přesunou do panelu se zachováním všech funkcí a ID a po zavření se
vrátí na původní místo. Pacientský kontext zůstává stále nahoře. Náhledy se
vykreslují lidsky čitelně (české popisky, formátovaná data, zanořené tabulky)
s možností rozbalit surové JSON.

DÚ: doplněna služba ZpochybniZasilku (Popis API DÚ v1.2, 5. 6. 2026) –
PATCH/PUT /api/du/zpochybni (Id + VerzeRadku, volitelný důvod) + UI tlačítko.

EZCA II Správa certifikátů: kontrakt sladěn se swaggerem v1.0.4 –
- stav/detail/stahnout/seznam přepnuty na správné query parametry
  (IczId, SerioveCislo, ExterniIdentifikator, TypSeznamu, HledanyNazev, Stranka);
  stažení certifikátu nově dle SerioveCislo (dříve chybně requestId).
- těla vystavit/obnovit/preregistrovat/revokovat opravena na reálná schémata
  (nazevSluzby, heslo, subjekt{nazev,…}, technickyKontakt{email,…}; obnovit =
  serioveCislo+heslo; revokovat = serioveCislo/iczId) vč. odpovídajícího UI.
- v1.0.4: /seznam doplněn o VelikostStranky + řazení (SeraditPodle/SmerRazeni),
  /crl-list o filtry (ExterniIdentifikator/Stat/DatumOd/SerioveCislo); UI rozšířeno
  o filtry a řazení. Stažený certifikát lze uložit jako soubor (PEM/DER/PKCS#7)
  s automatickou detekcí formátu z Base64 dat odpovědi.

Revize proti veřejné dokumentaci 2. 7. 2026 (apio.csez.gov.cz/apidoc +
Manuál EZ pro PZS):
- NOVĚ EZCAValidace (v1.0.0) – POST /ezcaValidace/api/v1/dokumenty/validate.
- Terminologie v1.1.0: přidán GET /manifest; ConceptMap/$translate opraven na
  parametry dle swaggeru (sourceCode/targetSystem místo dřívějších code/target,
  aliasy zachovány).
- ELP v1: doplněny číselníky (GET /api/v1/ciselniky[/{kod}/polozky]).
- SZZ v2: HPV screening děložního hrdla sladěn se swaggerem –
  /screeningy/karcinomDDeloznihoHrdlaHpv (dvojité „D“ dle v2.0.1);
  jednoduché „D“ je přijímáno jako alias.

Testovací rámec IROP/NPO (revize 2. 7. 2026 dle Manuálu EZ pro PZS –
„Testovací rámec - informace k testování splnění IROP/NPO" a Metodiky
testování EHR fáze I):
- NOVÝ modul sez_api.fhir_ezd – buildery a L1 validátory dokumentů eZD
  dle HL7 CZ Implementation Guides pro prioritní kategorie:
  pacientský souhrn (HL7-cz/ps 0.0.1, LOINC 60591-5), propouštěcí zpráva
  (HL7-cz/hdr 0.1.0, LOINC 34105-7, povinný encounter + presentedForm +
  sekce Průběh hospitalizace), zpráva z obrazového vyšetření (HL7-cz/img
  0.1.0-ballot, 3 kategorie + 4 povinné sekce + DiagnosticReport) a
  zpráva o výjezdu ZZS (HL7-cz/cz-ems 0.0.2, LOINC 67796-3).
- IROP scénáře sladěny s metodikou: TS-TECH-1 všech 6 metod hledání
  v KRP, TS-TECH-2A (KRPZS: IČO+název+místo) a NOVÝ TS-TECH-2B (KRZP),
  TS-TECH-3 s nastavením URL pro push notifikace; TS-OBS-2 generuje
  IG-konformní dokumenty, TS-OBS-1/TS-OBS-4 je při příjmu validují.
- Hodnocení dle metodiky (VYHOVUJE / VYHOVUJE S VÝHRADAMI / NEVYHOVUJE)
  vč. agregace + endpointy /api/irop/povinne-scenare (matice povinných
  scénářů dle kategorie žadatele A/B/ZZS) a /api/irop/protokol
  (Protokol o provedení testu ke stažení).
"""

from sez_api.client import (
    SEZ_ENVIRONMENTS,
    SUKL_ENVIRONMENTS,
    UZIS_ENVIRONMENTS,
    SEZConfig,
    SEZAuth,
    SEZClient,
    KRP,
    KRPv3,
    KRZP,
    KRPZS,
    DocasneUloziste,
    RegistrOpravneni,
    RegistrOpravneniNcpeh,
    SZZ,
    SZZv2,
    SZZv3,
    ELP,
    ELPv2,
    ELPv3,
    EZadanky,
    Notifikace,
    EZCA2,
    EZCA2SpravaCertifikatu,
    EZCAValidace,
    Terminologie,
    TermX,
    SUKLDLP,
    SUKLeRecept,
    UZISNrpzs,
    UZIS,
    UZISObsazenostLuzek,
)

__version__ = "2.32.0"

__all__ = [
    "SEZ_ENVIRONMENTS",
    "SUKL_ENVIRONMENTS",
    "UZIS_ENVIRONMENTS",
    "SEZConfig",
    "SEZAuth",
    "SEZClient",
    "KRP",
    "KRPv3",
    "KRZP",
    "KRPZS",
    "DocasneUloziste",
    "RegistrOpravneni",
    "RegistrOpravneniNcpeh",
    "SZZ",
    "SZZv2",
    "SZZv3",
    "ELP",
    "ELPv2",
    "ELPv3",
    "EZadanky",
    "Notifikace",
    "EZCA2",
    "EZCA2SpravaCertifikatu",
    "EZCAValidace",
    "Terminologie",
    "TermX",
    "SUKLDLP",
    "SUKLeRecept",
    "UZISNrpzs",
    "UZIS",
    "UZISObsazenostLuzek",
]
