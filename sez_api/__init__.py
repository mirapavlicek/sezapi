"""
SEZ API klient – Python knihovna pro práci se Sdíleným elektronickým zdravotnictvím.

Podporované služby:
  - KRP (Kmenový registr pacientů)
  - KRZP (Kmenový registr zdravotnických pracovníků)
  - DÚ (Dočasné úložiště)
  - SZZ (Sdílený zdravotní záznam)
  - ELP (Elektronické posudky v1)
  - ELPv2 (Elektronické posudky v2)
  - ELPv3 (Elektronické posudky v3.0.1)
  - eŽádanky (vč. simulačního enginu)
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

__version__ = "2.28.0"

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
