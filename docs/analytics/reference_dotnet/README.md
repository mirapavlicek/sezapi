# TestovaciPZS

Jednoduchá .NET 9 konzolová aplikace, která:
- Načte konfiguraci z `appsettings.json`
- Metody převodu pro EZCA I certifikáty (PFX) pro vytvoření JWT
- Vytvoří JWT podepsané klientským certifikátem (PFX umístěný vedle EXE)
- Provede HTTP GET na konfigurovatelné API s `Authorization: Bearer <jwt>`
- Volitelně přidá klientský certifikát do HTTP požadavku

## Požadavky
- .NET SDK 9
- PFX certifikát s privátním klíčem umístěný vedle spustitelného souboru

## Konfigurace (`appsettings.json`)
```
{
  "Jwt": {
    "ClientId": "25488627_KrajskaZdravotniVerejnyTest",
    "Audience": "https://jsuint-auth-t2.csez.cz/connect/token"
  },
  "Certificate": {
    "Path": "client-cert.pfx",  // název souboru vedle EXE
    "Password": "hesloCertifikatu"
  },
  "Api": {
    "Url": "https://gwy-ext-sec-t2.csez.cz/notifikace/api/v1/kanaly/katalog"
  }
}
```

### Popis atributů v `appsettings.json`
- Jwt:ClientId — identifikátor klienta vložený do JWT.
- Jwt:Audience — audience (aud) pro JWT, typicky token endpoint.
- Certificate:Path — název PFX souboru umístěného vedle EXE (bez cesty), např. `Certifikat_systémový_Krajská_zdravotní_ICO_25488627.pfx`.
- Certificate:Password — heslo k PFX souboru.
- Api:Url — cílové URL, na které se provede HTTP GET s Bearer JWT.

## Build a spuštění
- Build: `dotnet build`
- Spuštění: `dotnet run`

## Poznámky
- Certifikát musí obsahovat privátní klíč.
- Pokud používáte jiný název certifikátu, upravte `Certificate:Path`.
- JWT je krátkodobé (expirace 1 minuta).
