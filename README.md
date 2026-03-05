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

## Požadavky

- Python 3.10+
- Certifikát EZCA II (`.pfx` / `.p12`) registrovaný v JSU
- Přístup k SEZ API Gateway (síťová konektivita do CSEZ)

## Instalace

### Ze zdrojového kódu (doporučeno)

```bash
git clone https://github.com/mirapavlicek/sezapi.git
cd sezapi

# Vytvoření virtuálního prostředí
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate     # Windows

# Instalace závislostí
pip install -e .

# Konfigurace – zkopírujte .env.example do .env a doplňte certifikát
cp .env.example .env
# Upravte .env: SEZ_P12_PATH, SEZ_P12_PASSWORD, SEZ_CLIENT_ID

# Spuštění webového rozhraní
sez-api serve
```

Otevřete http://localhost:8000 (nebo port z .env).

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
│   └── test_dokumentace.py # Ověření API proti dokumentaci
├── app.py                  # Zpětná kompatibilita (python app.py)
└── sez_client.py           # Zpětná kompatibilita (import sez_client)
```

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
