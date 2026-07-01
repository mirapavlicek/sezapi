#!/usr/bin/env python3
"""
EZCA II – obnova systémového certifikátu (PZS) end-to-end.

Co skript dělá:
  1) Přihlásí se k SEZ gateway STÁVAJÍCÍM platným certifikátem (mTLS + JWT).
  2) Zjistí sériové číslo certu k obnově (zadané --serial, nebo --auto z /seznam).
  3) Zavolá PUT /api/v1/obnovit  → vznikne asynchronní požadavek (IczId).
  4) Periodicky kontroluje GET /api/v1/stav?IczId=…, dokud není VYDÁN.
  5) Zjistí sériové číslo NOVÉHO certu a stáhne ho (GET /api/v1/stahnout).
  6) Uloží certifikát ve dvou podobách:
       • Windows / IIS:  <name>.pfx        (PKCS#12 vč. privátního klíče)
       • Linux:          <name>.crt        (veřejný cert + řetězec CA, PEM)
                          <name>.key        (privátní klíč, PEM, chmod 600)

DŮLEŽITÉ – PŘIHLAŠOVACÍ CERTIFIKÁT:
  Obnova se autentizuje STÁVAJÍCÍM, v JSU registrovaným a platným certifikátem.
  Čerstvě „ručně" vydaný cert, který ještě není v JSU aktivovaný, vrací
  invalid_client – pro přihlášení tedy použijte starý/funkční cert
  (--auth-pfx / --auth-pass), nikoli ten, který chcete teprve získat.

Příklady:
  # Obnova konkrétního certu v PRODukci, přihlášení certem z .env (PROD):
  python ezca_obnova.py --env PROD --serial 210000016E08... \
      --heslo "NoveHesloKNovemuCertu" --name homolka --out-dir ./certs

  # Auto-výběr platného certu + přihlášení explicitním (starým) certem:
  python ezca_obnova.py --env PROD --auto \
      --auth-pfx homolka.pfx.bak-20260608 --auth-pass "StareHeslo" \
      --heslo "NoveHeslo" --name homolka
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
import time
from pathlib import Path

# Import balíčku sez_api (spouštějte z kořene repozitáře, kde je i .env)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sez_api import config as cfg  # noqa: E402
from sez_api.client import (  # noqa: E402
    SEZConfig, SEZAuth, SEZClient, EZCA2SpravaCertifikatu,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    pkcs12, Encoding, PrivateFormat, NoEncryption,
)

DONE_TOKENS = {"HOTOVO", "VYDANO", "VYDÁNO", "VYSTAVENO", "DOKONCENO",
               "DOKONČENO", "COMPLETED", "SUCCESS", "OK"}
ERR_TOKENS = {"CHYBA", "ZAMITNUTO", "ZAMÍTNUTO", "FAILED", "ERROR",
              "REJECTED", "ZRUSENO", "ZRUŠENO"}


# --------------------------------------------------------------------------- #
# Pomocné funkce
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def die(msg: str, code: int = 1) -> "None":
    log("CHYBA: " + msg)
    sys.exit(code)


def _json(resp):
    try:
        return resp.json()
    except Exception:
        return {"_raw": getattr(resp, "text", "")[:500]}


def _find_values(obj, keys):
    """Rekurzivně najde všechny hodnoty pro dané klíče (case-insensitive)."""
    want = {k.lower() for k in keys}
    out = []

    def rec(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and k.lower() in want and v not in (None, "", [], {}):
                    out.append(v)
                rec(v)
        elif isinstance(o, list):
            for x in o:
                rec(x)
    rec(obj)
    return out


def _first(obj, keys, default=None):
    vals = _find_values(obj, keys)
    return vals[0] if vals else default


def _extract_serial(obj):
    """Najde sériové číslo certifikátu kdekoliv v odpovědi."""
    return _first(obj, ["serioveCislo", "SerioveCislo", "serialNumber",
                        "SerialNumber", "serial"])


def _extract_iczid(obj):
    v = _first(obj, ["iczId", "IczId", "iczid", "id", "Id", "pozadavekId",
                     "PozadavekId", "requestId"])
    return v


def _state_str(obj):
    """Vrátí text stavu (uppercased) pro detekci HOTOVO/CHYBA."""
    blob = []
    for v in _find_values(obj, ["stav", "Stav", "stavKod", "StavKod",
                                "stavNazev", "StavNazev", "state", "status",
                                "stavZadosti", "kod", "nazev"]):
        if isinstance(v, (str, int)):
            blob.append(str(v))
        elif isinstance(v, dict):
            for x in v.values():
                if isinstance(x, (str, int)):
                    blob.append(str(x))
    return " ".join(blob).upper()


def _http_ok(resp) -> bool:
    return getattr(resp, "status_code", 0) < 400


# --------------------------------------------------------------------------- #
# Hlavní logika
# --------------------------------------------------------------------------- #
def build_client(env: str, auth_pfx: str | None, auth_pass: str | None,
                 client_id: str | None, cert_uid: str | None):
    SEZConfig.switch_environment(env)
    creds = cfg.ENV_CREDENTIALS.get(env, {})
    pfx = auth_pfx or creds.get("p12_path")
    pwd = auth_pass if auth_pfx else (auth_pass or creds.get("p12_password"))
    cid = client_id or creds.get("client_id")
    uid = cert_uid if cert_uid is not None else (creds.get("cert_uid") or None)
    if not pfx or not Path(pfx).exists():
        die(f"Přihlašovací certifikát nenalezen: {pfx!r} "
            f"(zadejte --auth-pfx nebo nastavte .env pro {env}).")
    if not cid:
        die(f"Chybí client_id pro prostředí {env} (zadejte --client-id nebo .env).")
    log(f"Prostředí: {env}  gateway: {SEZConfig.GATEWAY}")
    log(f"Přihlašuji certifikátem: {pfx}  client_id: {cid}")
    auth = SEZAuth(client_id=cid, p12_path=pfx, p12_password=pwd, cert_uid=uid)
    c = auth._signing_cert
    log(f"  subjekt: {c.subject.rfc4514_string()}")
    log(f"  platnost do: {c.not_valid_after_utc.isoformat()}")
    return auth, SEZClient(auth)


def pick_serial_auto(ezca: EZCA2SpravaCertifikatu) -> str:
    log("Auto-výběr: načítám seznam platných certifikátů (TypSeznamu=Platne)…")
    resp = ezca.seznam(typ_seznamu="Platne")
    if not _http_ok(resp):
        die(f"/seznam vrátil HTTP {resp.status_code}: {_json(resp)}")
    data = _json(resp)
    serials = _find_values(data, ["serioveCislo", "SerioveCislo"])
    if not serials:
        die("V seznamu platných certů nebylo nalezeno žádné sériové číslo "
            "(zadejte --serial ručně).")
    if len(serials) > 1:
        log(f"Nalezeno {len(serials)} platných certů, beru první: {serials[0]}")
        log("  (pro jiný použijte --serial)")
    return str(serials[0])


def request_renewal(ezca: EZCA2SpravaCertifikatu, serial: str, heslo: str) -> str:
    log(f"Žádám o obnovu certifikátu sériové číslo {serial} …")
    resp = ezca.obnovit({"serioveCislo": serial, "heslo": heslo})
    body = _json(resp)
    if not _http_ok(resp):
        die(f"/obnovit vrátil HTTP {resp.status_code}: {body}")
    iczid = _extract_iczid(body)
    new_serial = _extract_serial(body)
    log(f"  odpověď: HTTP {resp.status_code}  IczId={iczid}  serioveCislo={new_serial}")
    if not iczid and not new_serial:
        die(f"/obnovit neproběhlo dle očekávání (chybí IczId i sériové číslo): {body}")
    return iczid, new_serial


def poll_until_issued(ezca: EZCA2SpravaCertifikatu, iczid, interval: int,
                      timeout: int):
    if not iczid:
        return None
    log(f"Sleduji stav požadavku IczId={iczid} (interval {interval}s, "
        f"limit {timeout}s)…")
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = ezca.stav(icz_id=iczid)
        body = _json(resp)
        if not _http_ok(resp):
            log(f"  /stav HTTP {resp.status_code}: {body} – zkouším dál")
        else:
            st = _state_str(body)
            serial = _extract_serial(body)
            log(f"  stav: {st or '(neznámý)'}  serioveCislo={serial or '-'}")
            if any(t in st for t in ERR_TOKENS):
                die(f"Požadavek skončil chybou: {body}")
            if serial or any(t in st for t in DONE_TOKENS):
                log("  → certifikát je vydán.")
                return serial
        time.sleep(interval)
    die(f"Vypršel časový limit ({timeout}s) – certifikát stále není vydán.")


def resolve_new_serial(ezca, iczid, serial_hint):
    if serial_hint:
        return str(serial_hint)
    # Zkus /detail dle IczId
    if iczid:
        log(f"Zjišťuji sériové číslo nového certu přes /detail?IczId={iczid} …")
        resp = ezca.detail(icz_id=iczid)
        if _http_ok(resp):
            s = _extract_serial(_json(resp))
            if s:
                return str(s)
    die("Nepodařilo se zjistit sériové číslo nově vydaného certifikátu.")


def download_and_save(ezca, serial: str, heslo: str, out_dir: Path,
                      name: str):
    log(f"Stahuji certifikát sériové číslo {serial} …")
    resp = ezca.stahnout(serial)
    body = _json(resp)
    if not _http_ok(resp):
        die(f"/stahnout vrátil HTTP {resp.status_code}: {body}")
    b64 = _first(body, ["data", "Data"])
    if not b64:
        die(f"/stahnout nevrátil pole 'data' (base64 PFX): {body}")
    try:
        pfx_bytes = base64.b64decode(b64)
    except Exception as e:
        die(f"Data certifikátu nejsou platný base64: {e}")

    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch for ch in f"{name}_{serial}" if ch.isalnum() or ch in "._-")
    pfx_path = out_dir / f"{safe}.pfx"
    crt_path = out_dir / f"{safe}.crt"
    key_path = out_dir / f"{safe}.key"

    # 1) Windows / IIS – PFX tak, jak přišlo
    pfx_path.write_bytes(pfx_bytes)
    log(f"  ✓ Windows PFX:   {pfx_path}")

    # 2) Linux – rozbal PFX na PEM (veřejný cert + řetězec, privátní klíč)
    try:
        key, cert, addl = pkcs12.load_key_and_certificates(
            pfx_bytes, heslo.encode("utf-8") if heslo else None)
    except Exception as e:
        die("PFX uložen, ale rozbalení na PEM selhalo – zkontrolujte --heslo "
            f"(heslo musí odpovídat tomu z obnovy). Detail: {e}")

    cert_pem = cert.public_bytes(Encoding.PEM) if cert else b""
    chain_pem = b"".join(c.public_bytes(Encoding.PEM) for c in (addl or []))
    crt_path.write_bytes(cert_pem + chain_pem)
    log(f"  ✓ Linux cert:    {crt_path}  (cert + {len(addl or [])} CA v řetězci)")

    if key is not None:
        key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
                                    NoEncryption())
        key_path.write_bytes(key_pem)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        log(f"  ✓ Linux klíč:    {key_path}  (chmod 600)")
    else:
        log("  ! PFX neobsahuje privátní klíč – .key nevytvořen.")

    if cert:
        log(f"  Nový cert subjekt: {cert.subject.rfc4514_string()}")
        log(f"  Platnost: {cert.not_valid_before_utc.date()} → "
            f"{cert.not_valid_after_utc.date()}")
    return pfx_path, crt_path, key_path


def main():
    ap = argparse.ArgumentParser(
        description="EZCA II – obnova systémového certifikátu (PZS).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--env", default="PROD",
                    choices=["PROD", "PROD_CMS", "T2", "T2_CMS"],
                    help="Prostředí (default PROD).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--serial", help="Sériové číslo stávajícího platného certu k obnově.")
    g.add_argument("--auto", action="store_true",
                   help="Automaticky vyber platný cert z /seznam (TypSeznamu=Platne).")
    ap.add_argument("--heslo", required=True,
                    help="Heslo, kterým bude chráněn NOVÝ certifikát (a kterým se "
                         "PFX rozbalí do PEM).")
    ap.add_argument("--name", default="ezca", help="Základ názvu souborů (default ezca).")
    ap.add_argument("--out-dir", default="certs", help="Cílový adresář (default ./certs).")
    ap.add_argument("--poll-interval", type=int, default=10, help="Interval kontroly stavu [s].")
    ap.add_argument("--poll-timeout", type=int, default=600, help="Limit čekání na vydání [s].")
    ap.add_argument("--auth-pfx", help="Přihlašovací PFX (jinak z .env dle --env). "
                                       "Použijte STÁVAJÍCÍ platný/registrovaný cert.")
    ap.add_argument("--auth-pass", help="Heslo k přihlašovacímu PFX.")
    ap.add_argument("--client-id", help="client_id (jinak z .env dle --env).")
    ap.add_argument("--cert-uid", help="kid / UID certifikátu (jinak z .env nebo auto).")
    ap.add_argument("--download-only", action="store_true",
                    help="Jen stáhni a ulož cert dle --serial (přeskoč obnovu).")
    args = ap.parse_args()

    auth, client = build_client(args.env, args.auth_pfx, args.auth_pass,
                                args.client_id, args.cert_uid)
    ezca = EZCA2SpravaCertifikatu(client)
    try:
        if args.download_only:
            serial = args.serial or pick_serial_auto(ezca)
            download_and_save(ezca, str(serial), args.heslo,
                              Path(args.out_dir), args.name)
            log("HOTOVO (jen stažení).")
            return

        serial = args.serial or pick_serial_auto(ezca)
        iczid, new_serial = request_renewal(ezca, str(serial), args.heslo)
        issued_serial = poll_until_issued(ezca, iczid, args.poll_interval,
                                           args.poll_timeout)
        final_serial = resolve_new_serial(ezca, iczid, new_serial or issued_serial)
        log(f"Sériové číslo nového certifikátu: {final_serial}")
        download_and_save(ezca, final_serial, args.heslo,
                          Path(args.out_dir), args.name)
        log("HOTOVO – certifikát obnoven, stažen a uložen (PFX + PEM).")
    finally:
        try:
            auth.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()
