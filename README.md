# SEZ API klient

Python klient a webové rozhraní pro **Sdílené elektronické zdravotnictví** (SEZ) -- systém MZČR pro výměnu zdravotních dat mezi poskytovateli zdravotních služeb v ČR.

## Podporované služby

| Služba | Popis |
|--------|-------|
| **KRP** | Kmenový registr pacientů -- vyhledávání pacientů podle RID, jména a rodného čísla |
| **DÚ** | Dočasné úložiště -- ukládání, vyhledávání a stahování zdravotnických zásilek |
| **SZZ** | Sdílený zdravotní záznam -- alergie, krevní skupiny, léčivé přípravky, nežádoucí události |
| **ELP** | Elektronické posudky -- vyhledávání a správa lékařských posudků |
| **eŽádanky** | Elektronické žádanky mezi poskytovateli |
| **Notifikace** | Notifikační služba -- kanály, šablony, zdroje |
| **SÚKL / eRecept** | eRecept / CÚER -- lékový záznam pacienta (LZP), předpis, výdej, doplatky a limit pojištěnce, ePoukaz, eOčkování (režim SIMULACE bez registrace u SÚKL) |
| **SÚKL / DLP** | Databáze léčivých přípravků -- vyhledávání léků podle názvu, kódu SÚKL nebo ATC (veřejná otevřená data) |
| **ÚZIS / NRPZS** | Národní registr poskytovatelů zdravotních služeb -- veřejné REST API ÚZIS (vyhledávání poskytovatelů, číselníky NZIS) |
| **ÚZIS / NZR** | Národní zdravotnické registry (NOR, NRHOSP, ISIN…) a hlášení do NZIS (režim SIMULACE bez certifikátu ÚZIS/EREG) |

## Požadavky

- Python 3.10+
- Certifikát EZCA II (`.pfx` / `.p12`) registrovaný v JSU
- Přístup k SEZ API Gateway (síťová konektivita do CSEZ)

---

## Návod: vybudování a spuštění

### Lokální spuštění (vývoj / testování)

1. **Stažení projektu**
   ```bash
   git clone https://github.com/mirapavlicek/sezapi.git
   cd sezapi
   ```

2. **Vytvoření virtuálního prostředí**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate    # Linux / macOS
   # .venv\Scripts\activate    # Windows (PowerShell)
   ```

3. **Instalace závislostí**
   ```bash
   pip install -e .
   # nebo: pip install -r requirements.txt
   ```

4. **Konfigurace**
   ```bash
   cp .env.example .env
   ```
   Upravte `.env` – povinné položky:
   - `SEZ_CLIENT_ID` – Client ID z JSU
   - `SEZ_P12_PATH` – cesta k certifikátu (např. `./krajska_zdravotni.pfx`)
   - `SEZ_P12_PASSWORD` – heslo k certifikátu

5. **Umístění certifikátu**
   Certifikát `.pfx` / `.p12` zkopírujte do složky projektu (nebo zadejte absolutní cestu v `.env`).

6. **Spuštění**
   ```bash
   sez-api serve
   ```
   Otevřete v prohlížeči: **http://localhost:8004**

   Volitelně s automatickým reloadem při změnách:
   ```bash
   sez-api serve --reload
   ```

7. **Ověření připojení**
   ```bash
   sez-api ping
   ```

---

### Spuštění na serveru (Linux / systemd)

#### Varianta A: Instalační skript (doporučeno)

1. **Připravte projekt na serveru** (např. přes `git clone` nebo `scp`)
   ```bash
   git clone https://github.com/mirapavlicek/sezapi.git
   cd sezapi
   ```

2. **Připravte konfiguraci a certifikát**
   ```bash
   cp .env.example .env
   # Upravte .env (SEZ_CLIENT_ID, SEZ_P12_PATH, SEZ_P12_PASSWORD)
   # Zkopírujte certifikát .pfx do složky projektu
   ```

3. **Spusťte instalátor jako root**
   ```bash
   sudo ./deploy/install.sh
   ```
   Skript:
   - vytvoří uživatele `sezapi`
   - nainstaluje aplikaci do `/opt/sez-api`
   - vytvoří virtuální prostředí a nainstaluje závislosti
   - zaregistruje a spustí systemd službu `sez-api`

4. **Služba běží na portu 8004**
   - URL: `http://<IP-serveru>:8004`
   - Logy: `journalctl -u sez-api -f`
   - Restart: `sudo systemctl restart sez-api`

#### Varianta B: Ruční nasazení

Předpoklad: jste na serveru v kořenu projektu (např. po `git clone`).

1. **Vytvořte adresář a zkopírujte soubory**
   ```bash
   sudo mkdir -p /opt/sez-api
   sudo cp -r sez_api/ deploy/ requirements.txt pyproject.toml .env.example /opt/sez-api/
   sudo cp .env /opt/sez-api/          # váš konfigurovaný .env
   sudo cp *.pfx /opt/sez-api/         # certifikát
   ```

2. **Vytvořte uživatele a virtuální prostředí**
   ```bash
   sudo useradd --system --no-create-home --shell /sbin/nologin sezapi
   cd /opt/sez-api
   sudo python3 -m venv .venv
   sudo .venv/bin/pip install -r requirements.txt
   ```

3. **Upravte cestu k certifikátu v `.env`** (např. `SEZ_P12_PATH=/opt/sez-api/krajska_zdravotni.pfx`)

4. **Nainstalujte systemd službu**
   ```bash
   sudo cp deploy/sez-api.service /etc/systemd/system/sez-api.service
   sudo systemctl daemon-reload
   sudo systemctl enable sez-api
   sudo systemctl start sez-api
   ```

5. **Nastavte oprávnění**
   ```bash
   sudo chown -R sezapi:sezapi /opt/sez-api
   sudo chmod 600 /opt/sez-api/.env /opt/sez-api/*.pfx
   ```

#### Upgrade na serveru (po změnách v kódu)

```bash
cd sezapi
git pull
# Zkopírujte nové soubory na server (scp/rsync) nebo spusťte install.sh znovu
sudo ./deploy/install.sh
```

---

## Instalace (stručný přehled)

### Ze zdrojového kódu (doporučeno)

```bash
git clone https://github.com/mirapavlicek/sezapi.git
cd sezapi
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
pip install -e .
cp .env.example .env
# Upravte .env: SEZ_P12_PATH, SEZ_P12_PASSWORD, SEZ_CLIENT_ID
sez-api serve
```

Otevřete http://localhost:8004 (nebo port z `.env`).

## Konfigurace

Zkopírujte `.env.example` do `.env` a doplňte přihlašovací údaje:

```bash
cp .env.example .env
```

Povinné proměnné:

| Proměnná | Popis | Příklad |
|----------|-------|---------|
| `SEZ_CLIENT_ID` | Client ID registrovaný v JSU | `25488627_NemocniceTest` |
| `SEZ_P12_PATH` | Cesta k certifikátu EZCA II | `/cesta/ke/cert.pfx` |
| `SEZ_P12_PASSWORD` | Heslo k certifikátu | `tajne-heslo` |

Volitelné proměnné:

| Proměnná | Výchozí | Popis |
|----------|---------|-------|
| `SEZ_CERT_UID` | (z certifikátu) | UID certifikátu z EZCA portálu |
| `SEZ_GATEWAY` | `https://gwy-ext-sec-t2.csez.cz` | URL API Gateway |
| `SEZ_HOST` | `0.0.0.0` | Adresa webového serveru |
| `SEZ_PORT` | `8000` | Port webového serveru |

### SÚKL -- eRecept / CÚER a DLP

Rozhraní obsahuje sekci **SÚKL / eRecept** (skupina *Preskripce / SÚKL* v levém menu):

- **Lékový záznam (LZP)** -- přehled eReceptů a aktuální medikace pacienta
- **Předepsat / Výdej / Náhled** -- kompletní životní cyklus eReceptu
- **Doplatky a limit pojištěnce** -- CÚER doplňkové služby
- **ePoukaz / eOčkování**
- **DLP -- léky** -- vyhledávání v databázi léčivých přípravků SÚKL (veřejná data)

> **eRecept** je samostatný systém SÚKL (SOAP, verze rozhraní `202501A`,
> [epreskripce.gov.cz](https://epreskripce.gov.cz)) a vyžaduje **registraci SW u SÚKL
> a certifikát**. Bez těchto přístupů běží v **režimu SIMULACE** (in-memory engine +
> builder request obálek). Po doplnění `SUKL_REG_ID` a `SUKL_ERECEPT_ENDPOINT(_TEST)`
> (viz `.env.example`) se přepne na **živé volání**.
>
> **DLP** (databáze léčivých přípravků) jsou **veřejná otevřená data**
> ([opendata.sukl.cz](https://opendata.sukl.cz)) a fungují reálně i bez certifikátu;
> při nedostupnosti se použije vestavěný vzorek přípravků.

Konfigurace (vše volitelné) -- viz `.env.example`, sekce *SÚKL*:

| Proměnná | Popis |
|----------|-------|
| `SUKL_ENABLED` | Zapnutí sekce SÚKL (výchozí `true`) |
| `SUKL_INTERFACE_VERSION` | Verze datového rozhraní eReceptu (výchozí `202501A`) |
| `SUKL_REG_ID` | Registrační ID SW přidělené SÚKL (prázdné = simulace) |
| `SUKL_ERECEPT_ENDPOINT_TEST` / `SUKL_ERECEPT_ENDPOINT` | Endpoint SOAP rozhraní eReceptu |
| `SUKL_CERT_PATH` / `SUKL_CERT_PASSWORD` | Certifikát pro mTLS k eReceptu (volitelné) |
| `SUKL_DLP_URL` | URL balíku otevřených dat DLP |
| `SUKL_DLP_CACHE_DIR` | Lokální cache DLP (výchozí `/tmp/sukl_dlp`) |

Živý režim SÚKL: pokud je prázdné `SUKL_CERT_PATH`, použije se pro mTLS certifikát
aktivního CSEZ/EZCA klienta (např. `krajska_zdravotni.pfx`); lze nastavit i vlastní
SÚKL cert. Živé volání se aktivuje po vyplnění `SUKL_REG_ID` + `SUKL_ERECEPT_ENDPOINT(_TEST)`.

### ÚZIS -- NZIS (NRPZS a Národní zdravotnické registry)

Sekce **ÚZIS / NZIS** (skupina *ÚZIS / NZIS* v menu):

- **Poskytovatelé (NRPZS)** -- vyhledávání v Národním registru poskytovatelů zdravotních
  služeb (veřejné REST API [nrpzs.uzis.cz](https://nrpzs.uzis.cz/api/doc); offline fallback = vzorky)
- **Číselníky NZIS** -- kraje, obory/formy/druhy péče
- **Registry (NZR)** -- katalog národních zdravotnických registrů (NOR, NRHOSP, LPZ, NKR,
  NRKI, NRVV…) vč. kódů bloku `*nr` datového rozhraní **DASTA v4**
  ([dastacr.cz](https://dastacr.cz/dasta/hypertext/UZANR.htm))
- **Obsazenost lůžek (NDLP)** -- ÚZIS eReg REST API (`api.uzis.cz/registr/nrpzs/v1`,
  dokumentace [apidoc.uzis.cz](https://apidoc.uzis.cz/Registr/NRPZS/index.html)):
  hlášení volných lůžek (`ObsazenostLuzek/VolnaLuzka`) + číselníky (formy/obory/vybavení/skupiny
  pacientů) dle Metodiky ÚZIS v1.2. Zápis vyžaduje certifikát ÚZIS/EREG → režim SIMULACE.
- **Hlášení do NZIS** -- odeslání hlášení do registru se **strukturovaným formulářem dle
  registru** (NOR, NRHOSP, LPZ, NRVV, NRKI, NRLUD – pole dle DASTA) i volným JSON
  (režim SIMULACE bez certifikátu ÚZIS/EREG)
- **Import (GUI)** -- nahrání **DASTA dávky** (XML/ZIP, blok `*nr`) s přehledem bloků a
  volitelným založením hlášení, a **číselníku (CSV)** `kód;název` s náhledem položek

| Proměnná | Popis |
|----------|-------|
| `UZIS_ENABLED` | Zapnutí sekce ÚZIS (výchozí `true`) |
| `UZIS_NRPZS_URL` | URL veřejného NRPZS API (výchozí `https://nrpzs.uzis.cz/api/v1`) |
| `UZIS_EREG_BASE` / `UZIS_EREG_BASE_TEST` | Základ ÚZIS eReg REST API (`api.uzis.cz` / `apitest.uzis.cz`) |
| `UZIS_NZR_ENDPOINT_TEST` / `UZIS_NZR_ENDPOINT` | Endpoint pro hlášení do NZR (prázdné = simulace) |
| `UZIS_CERT_PATH` / `UZIS_CERT_PASSWORD` | Certifikát ÚZIS/EREG (prázdné = cert CSEZ/EZCA klienta) |

## Použití

### Webové rozhraní

```bash
sez-api serve
```

Otevřete http://localhost:8000 -- webové rozhraní umožňuje:

- Procházet a vyhledávat pacienty (KRP)
- Číst a vytvářet zdravotní záznamy (SZZ) -- alergie, krevní skupiny, léčiva, nežádoucí události
- Vyhledávat zásilky v dočasném úložišti (DÚ)
- Prohlížet elektronické posudky (ELP) a žádanky
- Spouštět automatické testy API
- Posílat vlastní raw requesty

Volitelné parametry:

```bash
sez-api serve --port 9000 --reload
```

### Test připojení

```bash
sez-api ping
```

Rychle ověří konektivitu ke všem službám.

### Použití jako knihovna

```python
from sez_api import SEZAuth, SEZClient, KRP, SZZ

auth = SEZAuth(
    client_id="25488627_NemocniceTest",
    p12_path="/cesta/ke/cert.pfx",
    p12_password="heslo",
    cert_uid="uid-z-ezca",
)
client = SEZClient(auth)

# KRP -- vyhledání pacienta
krp = KRP(client)
r = krp.hledat_rid("7653800856")
print(r.json())

# SZZ -- vytvoření alergie
szz = SZZ(client)
r = szz.vytvor_alergii({
    "rid": "7706120004",
    "ico": "25488627",
    "krzpId": "102129137",
    "nazev": "Penicilin",
    "alergen": {"kod": "17005", "verze": "1.0.0"},
    "kategorieAlergenu": {"kod": "2", "verze": "1.0.0"},
    "kriticnost": {"kod": "2", "verze": "1.0.0"},
    "typReakce": {"kod": "1", "verze": "1.0.0"},
    "datumZjisteni": "2026-02-20",
})
print(r.status_code, r.json())

# Přímý API request
r = client.get("/notifikace/api/v1/notifikace/ping")
print(r.json())
```

### Spuštění testů

```bash
sez-api serve
# v prohlížeči: http://localhost:8000 → záložka "Testy" → "Spustit kompletní testy"
```

Nebo přímo:

```bash
python tests/test_dokumentace.py
```

## Struktura projektu

```
sez-api-python/
├── pyproject.toml          # Definice balíčku a závislostí
├── README.md               # Tento soubor
├── .env.example            # Vzor konfigurace
├── .gitignore
├── sez_api/                # Hlavní balíček
│   ├── __init__.py         # Exporty (SEZAuth, SEZClient, moduly)
│   ├── client.py           # API klient, autentizace, moduly služeb
│   ├── config.py           # Konfigurace z .env / proměnných prostředí
│   ├── app.py              # FastAPI backend (webové rozhraní)
│   ├── cli.py              # CLI vstupní bod (sez-api příkaz)
│   └── templates/
│       └── index.html      # SPA frontend (dark theme)
├── tests/
│   ├── test_dokumentace.py # Ověření API proti dokumentaci (živý)
│   ├── test_kontrakty.py   # Offline kontrakty vs. swagger
│   ├── test_sukl.py        # SÚKL (offline)
│   ├── test_termx.py       # TermX (živý)
│   └── test_uzis.py        # ÚZIS (offline)
├── app.py                  # Zpětná kompatibilita (python app.py) → sez_api.app
└── sez_client.py           # Zpětná kompatibilita (import sez_client) → sez_api.client
```

> Historicky existovaly dvě paralelní implementace („sezapi“ – ploché soubory
> v kořeni, a „sez_api“ – balíček). Byly sloučeny do jediného zdroje pravdy
> `sez_api/`; kořenové `app.py` a `sez_client.py` jsou jen tenké shim vrstvy
> pro zpětnou kompatibilitu starších skriptů.

## Autentizace

Klient používá **mTLS + JWT assertion** dle specifikace MZČR:

1. JWT assertion se podepíše privátním klíčem certifikátu EZCA II
2. Assertion se pošle v hlavičce `Authorization: Bearer <assertion>` na API Gateway
3. Gateway si vyřídí access token z JSU (Jednotný systém uživatelů)
4. Stejný certifikát se použije pro mTLS handshake

Jeden certifikát EZCA II slouží pro obě funkce -- mTLS i podepisování JWT.

## Známá omezení

- **DejZasilku (DÚ)**: Vyžaduje identitu konkrétního zdravotnického pracovníka (uživatelský certifikát EZCA II s KRZPID). Systémový certifikát PZS vrací 400 "Pracovník nemá oprávnění".
- **DÚ T2**: Testovací prostředí je občas nestabilní a vrací 401.
- **SZZ T2**: Testovací pacienti nemají předvyplněná klinická data -- je potřeba je vytvořit.

## Licence

MIT

## Kontakty

- Dokumentace MZČR: https://mzcr.atlassian.net/wiki/spaces/EPZS
- Podpora NCEZ: csez@mzd.gov.cz
