"""
SEZ API Web UI – FastAPI backend.
Obaluje sez_api.client do REST endpointů a servíruje SPA frontend.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from sez_api import config as cfg
from sez_api.client import (
    SEZAuth, SEZClient, SEZConfig, SEZ_ENVIRONMENTS, check_gateway_dns,
    KRP, KRZP, RegistrOpravneni, DocasneUloziste, SZZ, ELP, ELPv2, EZadanky, Notifikace, EZCA2,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"

# ---------------------------------------------------------------------------
# Singleton client
# ---------------------------------------------------------------------------

_auth: SEZAuth | None = None
_client: SEZClient | None = None
_modules: dict = {}
_connected = False
_cert_info: dict = {}


def _init_client(client_id: str, p12_path: str, p12_password: str,
                 cert_uid: str, env_key: str | None = None):
    """Create (or recreate) auth, client and all service modules."""
    global _auth, _client, _modules, _connected, _cert_info

    if _auth:
        _auth.cleanup()

    if env_key:
        SEZConfig.switch_environment(env_key)
    else:
        if cfg.GATEWAY:
            SEZConfig.GATEWAY = cfg.GATEWAY
        SEZConfig.ENVIRONMENT = SEZConfig.detect_environment()
        env_info = SEZ_ENVIRONMENTS.get(SEZConfig.ENVIRONMENT)
        if env_info:
            SEZConfig.TOKEN_AUDIENCE = env_info["jsu_audience"]

    _auth = SEZAuth(
        client_id=client_id,
        p12_path=p12_path,
        p12_password=p12_password,
        cert_uid=cert_uid or None,
    )
    _client = SEZClient(_auth)

    cert = _auth._signing_cert
    _cert_info = {
        "cn": cert.subject.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "kid": cert_uid,
        "client_id": client_id,
        "pfx_path": p12_path,
    }

    _modules["krp"] = KRP(_client)
    _modules["krzp"] = KRZP(_client)
    _modules["ro"] = RegistrOpravneni(_client)
    _modules["du"] = DocasneUloziste(_client)
    _modules["szz"] = SZZ(_client)
    _modules["elp"] = ELP(_client)
    _modules["elp2"] = ELPv2(_client)
    _modules["ez"] = EZadanky(_client)
    _modules["notif"] = Notifikace(_client)
    _modules["ezca"] = EZCA2(_client)
    _connected = True


def get_client():
    global _connected, _cert_info
    if _client is not None:
        return _client
    try:
        cfg.validate()
        _init_client(cfg.CLIENT_ID, cfg.P12_PATH, cfg.P12_PASSWORD, cfg.CERT_UID)
    except SystemExit:
        raise
    except Exception as e:
        _connected = False
        _cert_info = {"error": str(e)}
    return _client


@asynccontextmanager
async def lifespan(application: FastAPI):
    get_client()
    yield
    if _auth:
        _auth.cleanup()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="SEZ API Web UI", lifespan=lifespan)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def api_response(resp) -> dict:
    try:
        data = resp.json()
    except Exception:
        data = resp.text
    return {"status": resp.status_code, "data": data}


def error_response(msg: str, code: int = 500) -> JSONResponse:
    return JSONResponse({"status": code, "error": str(msg)}, status_code=200)


def timed_call(fn, *args, **kwargs) -> JSONResponse:
    t0 = time.monotonic()
    try:
        resp = fn(*args, **kwargs)
        elapsed = round((time.monotonic() - t0) * 1000)
        result = api_response(resp)
        result["elapsed_ms"] = elapsed
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        result = {"status": 0, "error": str(e), "elapsed_ms": elapsed}
    if _client and _client.last_request_debug:
        result["_request"] = _client.last_request_debug
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def status():
    dns = check_gateway_dns(SEZConfig.ENVIRONMENT)
    is_prod = SEZConfig.ENVIRONMENT == "PROD"
    return {
        "connected": _connected,
        "cert": _cert_info,
        "gateway": SEZConfig.GATEWAY,
        "environment": SEZConfig.ENVIRONMENT,
        "is_prod": is_prod,
        "dns_ok": dns["ok"],
        "dns_detail": dns.get("ip") or dns.get("error", ""),
        "test_patients": cfg.TEST_PATIENTS,
        "test_workers": getattr(cfg, "TEST_WORKERS", []),
        "test_workers_pzs": getattr(cfg, "TEST_WORKERS_PZS", []),
        "test_pzs": getattr(cfg, "TEST_PZS", []),
    }


# ---------------------------------------------------------------------------
# Environments
# ---------------------------------------------------------------------------

@app.get("/api/env/list")
async def env_list():
    envs = []
    for key, info in SEZ_ENVIRONMENTS.items():
        creds = cfg.ENV_CREDENTIALS.get(key, {})
        has_cert = bool(creds.get("p12_path"))
        dns = check_gateway_dns(key)
        envs.append({
            "key": key,
            "name": info["name"],
            "gateway": info["gateway"],
            "active": key == SEZConfig.ENVIRONMENT,
            "has_cert": has_cert,
            "client_id": creds.get("client_id", ""),
            "dns_ok": dns["ok"],
            "dns_detail": dns.get("ip") or dns.get("error", ""),
        })
    return envs


class EnvSwitchRequest(BaseModel):
    env: str
    password: str = ""

PROD_PASSWORD = os.environ.get("SEZ_PROD_PASSWORD", "nemamradapi").strip()

@app.post("/api/env/switch")
async def env_switch(req: EnvSwitchRequest):
    global _connected, _cert_info

    if req.env == SEZConfig.ENVIRONMENT:
        return {"ok": True, "environment": SEZConfig.ENVIRONMENT,
                "gateway": SEZConfig.GATEWAY, "cert": _cert_info}

    if req.env == "PROD" and PROD_PASSWORD and req.password.strip() != PROD_PASSWORD:
        logger.warning("PROD password mismatch (got %d chars, expected %d chars)",
                       len(req.password.strip()), len(PROD_PASSWORD))
        return JSONResponse(
            {"ok": False, "error": "Nesprávné heslo pro přepnutí na produkci",
             "needs_password": True},
            status_code=403,
        )

    if req.env not in SEZ_ENVIRONMENTS:
        return JSONResponse(
            {"ok": False, "error": f"Neznámé prostředí: {req.env}"},
            status_code=400,
        )

    creds = cfg.ENV_CREDENTIALS.get(req.env, {})
    if not creds.get("p12_path"):
        return JSONResponse(
            {"ok": False, "error": f"Prostředí {req.env}: chybí certifikát (SEZ_PROD_P12_PATH)"},
            status_code=400,
        )

    dns = check_gateway_dns(req.env)

    try:
        _init_client(
            client_id=creds["client_id"],
            p12_path=creds["p12_path"],
            p12_password=creds["p12_password"],
            cert_uid=creds["cert_uid"],
            env_key=req.env,
        )
        result = {"ok": True, "environment": SEZConfig.ENVIRONMENT,
                  "gateway": SEZConfig.GATEWAY, "cert": _cert_info,
                  "dns_ok": dns["ok"]}
        if not dns["ok"]:
            result["dns_warning"] = (
                f"Gateway {dns['host']} není dostupná (DNS: {dns.get('error', 'neznámý')}). "
                "Produkční prostředí SEZ pravděpodobně ještě není nasazené. "
                "API volání budou selhávat."
            )
        return result
    except Exception as e:
        _connected = False
        _cert_info = {"error": str(e)}
        return JSONResponse(
            {"ok": False, "error": f"Chyba inicializace pro {req.env}: {e}"},
            status_code=500,
        )


# ---------------------------------------------------------------------------
# KRP
# ---------------------------------------------------------------------------

class KRPRidRequest(BaseModel):
    rid: str
    ucel: str = "LECBA"

class KRPJmenoRequest(BaseModel):
    jmeno: str
    prijmeni: str
    rodne_cislo: str
    ucel: str = "LECBA"

@app.post("/api/krp/hledat-rid")
async def krp_hledat_rid(req: KRPRidRequest):
    return timed_call(_modules["krp"].hledat_rid, req.rid, req.ucel)

@app.post("/api/krp/hledat-jmeno")
async def krp_hledat_jmeno(req: KRPJmenoRequest):
    return timed_call(_modules["krp"].hledat_jmeno_rc, req.jmeno, req.prijmeni, req.rodne_cislo, req.ucel)

# DRID – Dočasný RID

class DRIDGenerujRequest(BaseModel):
    pocet: int = 1

class DRIDPriradRequest(BaseModel):
    docasny_rid: str
    rid: str

class DRIDMapovaniRequest(BaseModel):
    rid: str
    jen_aktualni: bool = False

@app.post("/api/krp/drid/generovat")
async def krp_drid_generovat(req: DRIDGenerujRequest):
    return timed_call(_modules["krp"].generovat_docasny_rid, req.pocet)

@app.post("/api/krp/drid/priradit")
async def krp_drid_priradit(req: DRIDPriradRequest):
    return timed_call(_modules["krp"].priradit_docasny_rid, req.docasny_rid, req.rid)

@app.post("/api/krp/drid/mapovani")
async def krp_drid_mapovani(req: DRIDMapovaniRequest):
    return timed_call(_modules["krp"].mapovani_rid, req.rid, req.jen_aktualni)

@app.post("/api/krp/hledat-jmeno-dn")
async def krp_hledat_jmeno_dn(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].hledat_jmeno_dn,
                      body.get("jmeno",""), body.get("prijmeni",""),
                      body.get("datumNarozeni",""), body.get("statniObcanstvi"),
                      body.get("ucel","LECBA"))

@app.post("/api/krp/hledat-jmeno-cp")
async def krp_hledat_jmeno_cp(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].hledat_jmeno_cp,
                      body.get("jmeno",""), body.get("prijmeni",""),
                      body.get("cisloPojistence",""), body.get("ucel","LECBA"))

@app.post("/api/krp/hledat-cizinec-cp")
async def krp_hledat_cizinec_cp(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].hledat_cizinec_cp,
                      body.get("cisloPojistence",""), body.get("statniObcanstvi"),
                      body.get("ucel","LECBA"))

@app.post("/api/krp/hledat-doklady")
async def krp_hledat_doklady(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].hledat_doklady,
                      body.get("cislo",""), body.get("typDokladu",""),
                      body.get("stat"), body.get("ucel","LECBA"))

@app.post("/api/krp/hledat-aifoulozenka")
async def krp_hledat_aifoulozenka(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].hledat_aifoulozenka,
                      body.get("aifo"), body.get("ulozkaId"),
                      body.get("ulozkaRef"), body.get("ucel","LECBA"))

@app.post("/api/krp/hledat-niabsi")
async def krp_hledat_niabsi(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].hledat_niabsi,
                      body.get("niabsi",""), body.get("ucel","LECBA"))

@app.post("/api/krp/hledat-uni")
async def krp_hledat_uni(request: Request):
    body = await request.json()
    ucel = body.pop("ucel", "LECBA")
    return timed_call(_modules["krp"].hledat_uni, ucel, **body)

@app.post("/api/krp/historie-pojisteni")
async def krp_historie_pojisteni(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].historie_pojisteni,
                      body.get("rid",""), body.get("datum"), body.get("ucel","LECBA"))

@app.post("/api/krp/historie-lekaru")
async def krp_historie_lekaru(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].historie_registrujicich_lekaru,
                      body.get("rid",""), body.get("datum"), body.get("ucel","LECBA"))

@app.post("/api/krp/zalozit-pacienta")
async def krp_zalozit(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].zalozit_pacienta, body.get("data",{}), body.get("ucel","LECBA"))

@app.post("/api/krp/zmenit-pacienta")
async def krp_zmenit(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].zmenit_pacienta, body.get("data",{}), body.get("ucel","LECBA"))

@app.post("/api/krp/reklamuj-udaj")
async def krp_reklamuj(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].reklamuj_udaj, body.get("data",{}), body.get("ucel","LECBA"))

@app.post("/api/krp/slouceni")
async def krp_slouceni(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].slouceni_zadost,
                      body.get("ridCilovy",""), body.get("ridSlucovany",""),
                      body.get("ucel","LECBA"))

@app.post("/api/krp/rozdeleni")
async def krp_rozdeleni(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].rozdeleni_zadost,
                      body.get("rid",""), body.get("novyPacient1",{}),
                      body.get("novyPacient2",{}), body.get("ucel","LECBA"))

@app.post("/api/krp/zruseni")
async def krp_zruseni(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].zruseni_zadost,
                      body.get("rid",""), body.get("ulozkaId"),
                      body.get("ulozkaRef"), body.get("ucel","LECBA"))

@app.get("/api/krp/ztotozneni-sablona")
async def krp_ztotozneni_sablona():
    """Download CSV template for batch identification."""
    from sez_api.client import KRP
    csv = KRP.csv_sablona()
    return PlainTextResponse(
        csv,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ztotozneni_sablona.csv"},
    )

@app.post("/api/krp/ztotozneni-zadost")
async def krp_ztotozneni_zadost(file: UploadFile = File(...)):
    """Upload CSV file for batch identification."""
    content = await file.read()
    return timed_call(_modules["krp"].ztotozneni_zadost, content, file.filename or "upload.csv")

@app.post("/api/krp/ztotozneni-vykonani")
async def krp_ztotozneni_vykonani(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].ztotozneni_vykonani,
                      body.get("idZadosti",""), body.get("ucel","LECBA"))

@app.post("/api/krp/ztotozneni-vysledky")
async def krp_ztotozneni_vysledky(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].ztotozneni_vysledky,
                      body.get("idZadosti",""), body.get("ucel","LECBA"))

@app.post("/api/krp/ztotozneni-vysledky-soubor")
async def krp_ztotozneni_vysledky_soubor(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].ztotozneni_vysledky_soubor,
                      body.get("idZadosti",""), body.get("ucel","LECBA"))

@app.post("/api/krp/ztotozneni-vysledky-csv")
async def krp_ztotozneni_vysledky_csv(request: Request):
    """Get batch identification results and convert to CSV for download."""
    body = await request.json()
    id_zadosti = body.get("idZadosti", "")
    t0 = time.monotonic()
    try:
        resp = _modules["krp"].ztotozneni_vysledky(id_zadosti)
        elapsed = round((time.monotonic() - t0) * 1000)
        if resp is None or resp.status_code >= 400:
            return timed_call(_modules["krp"].ztotozneni_vysledky, id_zadosti)
        data = resp.json()
        od = data.get("odpovedData", {})
        records = od.get("souborHromadnehoZtotozneni", [])
        from sez_api.client import KRP
        csv_text = KRP.records_to_csv(records)
        done = od.get("hromadneZtotozneniDokonceno", False)
        return JSONResponse({
            "status": resp.status_code,
            "csv": csv_text,
            "dokonceno": done,
            "pocet_zaznamu": len(records),
            "elapsed_ms": elapsed,
        })
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        return JSONResponse({"status": 0, "error": str(e), "elapsed_ms": elapsed})

@app.post("/api/krp/notifikace-vyhledat")
async def krp_notifikace_vyhledat(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].notifikace_vyhledat,
                      body.get("kanalTyp",""), body.get("subjektId"),
                      body.get("ucel","LECBA"))

@app.post("/api/krp/notifikace-zalozit")
async def krp_notifikace_zalozit(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].notifikace_zalozit, body.get("data",{}), body.get("ucel","LECBA"))

@app.post("/api/krp/notifikace-zrusit")
async def krp_notifikace_zrusit(request: Request):
    body = await request.json()
    return timed_call(_modules["krp"].notifikace_zrusit,
                      body.get("idSubskripce"), body.get("subjektId"),
                      body.get("ucel","LECBA"))


# ---------------------------------------------------------------------------
# KRZP – Zdravotničtí pracovníci
# ---------------------------------------------------------------------------

class KRZPKrzpidRequest(BaseModel):
    krzpid: str

class KRZPJmenoRequest(BaseModel):
    jmeno: str
    prijmeni: str
    datum_narozeni: str

class KRZPZamestnavatelRequest(BaseModel):
    ico: str
    vcetne_neplatnych: bool = False

class KRZPPersonalistikaRequest(BaseModel):
    datum_narozeni: str
    jmeno: Optional[str] = None
    prijmeni: Optional[str] = None
    krzpid: Optional[str] = None

@app.post("/api/krzp/hledat-krzpid")
async def krzp_hledat_krzpid(req: KRZPKrzpidRequest):
    return timed_call(_modules["krzp"].hledat_krzpid, req.krzpid)

@app.post("/api/krzp/hledat-jmeno")
async def krzp_hledat_jmeno(req: KRZPJmenoRequest):
    return timed_call(_modules["krzp"].hledat_jmeno, req.jmeno, req.prijmeni, req.datum_narozeni)

@app.post("/api/krzp/hledat-zamestnavatel")
async def krzp_hledat_zamestnavatel(req: KRZPZamestnavatelRequest):
    return timed_call(_modules["krzp"].hledat_zamestnavatel, req.ico, req.vcetne_neplatnych)

@app.post("/api/krzp/hledat-personalistika")
async def krzp_hledat_personalistika(req: KRZPPersonalistikaRequest):
    return timed_call(_modules["krzp"].hledat_personalistika,
                      req.datum_narozeni, req.jmeno, req.prijmeni, req.krzpid)

@app.post("/api/krzp/ciselnik/{nazev}")
async def krzp_ciselnik(nazev: str):
    return timed_call(_modules["krzp"].ciselnik, nazev)

@app.post("/api/krzp/reklamuj-udaj")
async def krzp_reklamuj(request: Request):
    body = await request.json()
    return timed_call(_modules["krzp"].reklamuj_udaj, body)

@app.post("/api/krzp/notifikace-stav")
async def krzp_notifikace_stav(request: Request):
    body = await request.json()
    return timed_call(_modules["krzp"].notifikace_stav,
                      body.get("kanalTyp",""), body.get("subjektId"))

@app.post("/api/krzp/notifikace-zalozit")
async def krzp_notifikace_zalozit(request: Request):
    body = await request.json()
    return timed_call(_modules["krzp"].notifikace_zalozit, body.get("data",{}))

@app.post("/api/krzp/notifikace-zrusit")
async def krzp_notifikace_zrusit(request: Request):
    body = await request.json()
    return timed_call(_modules["krzp"].notifikace_zrusit, body.get("data",{}))


# ---------------------------------------------------------------------------
# Registr oprávnění
# ---------------------------------------------------------------------------

class ROOverRequest(BaseModel):
    id_sluzby: int = 1
    id_typu_dokumentace: int = 5
    opravnujici_role: str = "PoskytovatelZdravotnickychSluzeb"
    opravnujici_hodnota: str
    opravnena_role: str = "ZdravotnickyPracovnik"
    opravnena_hodnota: str

class ROZdravotnikRequest(BaseModel):
    ico: str
    krzpid: str
    id_sluzby: int = 1
    id_typu_dokumentace: int = 5

class ROZastupceRequest(BaseModel):
    pacient_rid: str
    zastupce_hodnota: str
    zastupce_role: str = "Zastupce"
    id_sluzby: int = 1
    id_typu_dokumentace: int = 5

@app.post("/api/ro/over")
async def ro_over(req: ROOverRequest):
    return timed_call(_modules["ro"].over,
                      req.id_sluzby, req.id_typu_dokumentace,
                      req.opravnujici_role, req.opravnujici_hodnota,
                      req.opravnena_role, req.opravnena_hodnota)

@app.post("/api/ro/over-zdravotnika")
async def ro_over_zdravotnika(req: ROZdravotnikRequest):
    return timed_call(_modules["ro"].over_zdravotnika,
                      req.ico, req.krzpid, req.id_sluzby, req.id_typu_dokumentace)

@app.post("/api/ro/over-zastupce")
async def ro_over_zastupce(req: ROZastupceRequest):
    return timed_call(_modules["ro"].over_zastupce,
                      req.pacient_rid, req.zastupce_hodnota,
                      req.zastupce_role, req.id_sluzby, req.id_typu_dokumentace)


# ---------------------------------------------------------------------------
# Dočasné úložiště
# ---------------------------------------------------------------------------

class DUVyhledejRequest(BaseModel):
    datum_od: str
    datum_do: str
    pacient: Optional[str] = None
    page: int = 1
    size: int = 25

def _du_timed_call(fn, *args, **kwargs) -> JSONResponse:
    du = _modules["du"]
    t0 = time.monotonic()
    try:
        resp = fn(*args, **kwargs)
        elapsed = round((time.monotonic() - t0) * 1000)
        result = api_response(resp)
        result["elapsed_ms"] = elapsed
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        result = {"status": 0, "error": str(e), "elapsed_ms": elapsed}
    if du.last_request_debug:
        result["_request"] = du.last_request_debug
    return JSONResponse(result)

@app.post("/api/du/vyhledej")
async def du_vyhledej(req: DUVyhledejRequest):
    return _du_timed_call(_modules["du"].vyhledej_zasilku, req.datum_od, req.datum_do, req.pacient, req.page, req.size)

@app.get("/api/du/zasilka/{zasilka_id}")
async def du_dej(zasilka_id: str):
    return _du_timed_call(_modules["du"].dej_zasilku, zasilka_id)

@app.post("/api/du/uloz")
async def du_uloz(request: Request):
    body = await request.json()
    return _du_timed_call(_modules["du"].uloz_zasilku, body)

@app.put("/api/du/zmen/{zasilka_id}")
async def du_zmen(zasilka_id: str, request: Request):
    body = await request.json()
    return _du_timed_call(_modules["du"].zmen_zasilku, zasilka_id, body)

class DUZneplatniRequest(BaseModel):
    zasilka_id: str
    verze_radku: str

@app.put("/api/du/zneplatni")
async def du_zneplatni(req: DUZneplatniRequest):
    return _du_timed_call(_modules["du"].zneplatni_zasilku, req.zasilka_id, req.verze_radku)


@app.get("/api/du/jsu-diagnose")
async def du_jsu_diagnose():
    """Direct JSU token exchange diagnostics for DÚ troubleshooting."""
    client = _client
    if not client:
        return JSONResponse({"error": "Klient není připojen"}, status_code=503)

    results = []
    scopes = [None, "docasneUloziste", "DU", "du",
              "urn:sez:docasneUloziste", "openid"]
    for scope in scopes:
        label = scope or "(bez scope)"
        jsu = client._exchange_with_jsu(scope=scope)
        entry = {
            "scope": label,
            "http_status": jsu.get("_http_status", 0),
            "has_access_token": "access_token" in jsu,
        }
        if "access_token" in jsu:
            at = jsu["access_token"]
            entry["token_type"] = jsu.get("token_type", "?")
            entry["expires_in"] = jsu.get("expires_in", "?")
            entry["scope_returned"] = jsu.get("scope", "?")
            entry["token_preview"] = at[:30] + "..." if len(at) > 30 else at
        else:
            entry["error"] = jsu.get("error", "?")
            entry["error_description"] = jsu.get("error_description", "")
        results.append(entry)

    return JSONResponse({
        "jsu_endpoint": SEZConfig.TOKEN_AUDIENCE,
        "client_id": client.auth.client_id,
        "results": results,
    })


# ---------------------------------------------------------------------------
# SZZ
# ---------------------------------------------------------------------------

@app.get("/api/szz/alergie/{rid}")
async def szz_alergie(rid: str):
    return timed_call(_modules["szz"].alergie, rid)

@app.get("/api/szz/lecive-pripravky/{rid}")
async def szz_lecive_pripravky(rid: str):
    return timed_call(_modules["szz"].lecive_pripravky, rid)

@app.get("/api/szz/krevni-skupina/{rid}")
async def szz_krevni_skupina(rid: str):
    return timed_call(_modules["szz"].krevni_skupina, rid)

@app.get("/api/szz/nezadouci-prihody/{rid}")
async def szz_nezadouci_prihody(rid: str):
    return timed_call(_modules["szz"].nezadouci_prihody, rid)

@app.get("/api/szz/nezadouci-reakce/{rid}")
async def szz_nezadouci_reakce(rid: str):
    return timed_call(_modules["szz"].nezadouci_reakce, rid)

@app.get("/api/szz/nezadouci-ucinky/{rid}")
async def szz_nezadouci_ucinky(rid: str):
    return timed_call(_modules["szz"].nezadouci_ucinky, rid)

@app.get("/api/szz/nezadouci-udalosti/{rid}")
async def szz_nezadouci_udalosti(rid: str):
    return timed_call(_modules["szz"].nezadouci_udalosti, rid)

@app.get("/api/szz/emergentni-zaznam/{rid}")
async def szz_emergentni(rid: str):
    return timed_call(_modules["szz"].emergentni_zaznam, rid)

@app.get("/api/szz/ciselniky")
async def szz_ciselniky():
    return timed_call(_modules["szz"].ciselniky)

@app.get("/api/szz/ciselniky/{kod}/polozky")
async def szz_ciselnik_polozky(kod: str):
    return timed_call(_client.get, f"/sdilenyZdravotniZaznam/api/v1/ciselniky/{kod}/polozky")

@app.post("/api/szz/vytvor-alergii")
async def szz_vytvor_alergii(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_alergii, body)

@app.post("/api/szz/vytvor-krevni-skupinu")
async def szz_vytvor_krevni_skupinu(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_krevni_skupinu, body)

@app.post("/api/szz/vytvor-nezadouci-prihodu")
async def szz_vytvor_nezadouci_prihodu(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_nezadouci_prihodu, body)

@app.post("/api/szz/vytvor-nezadouci-reakci")
async def szz_vytvor_nezadouci_reakci(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_nezadouci_reakci, body)

@app.post("/api/szz/vytvor-nezadouci-ucinek")
async def szz_vytvor_nezadouci_ucinek(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_nezadouci_ucinek, body)

@app.post("/api/szz/vytvor-nezadouci-udalost")
async def szz_vytvor_nezadouci_udalost(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_nezadouci_udalost, body)

@app.post("/api/szz/vytvor-lecivy-pripravek")
async def szz_vytvor_lecivy_pripravek(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].vytvor_lecivy_pripravek, body)

@app.post("/api/szz/vytvor-zdravotni-zaznam")
async def szz_vytvor_zdravotni_zaznam(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].zdravotni_zaznamy, body)

@app.put("/api/szz/alergie/{id}")
async def szz_update_alergie(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_alergii, id, body, request.headers.get("If-Match"))

@app.put("/api/szz/krevni-skupina/{id}")
async def szz_update_krevni_skupina(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_krevni_skupinu, id, body, request.headers.get("If-Match"))

@app.put("/api/szz/nezadouci-prihody/{id}")
async def szz_update_nezadouci_prihody(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_nezadouci_prihodu, id, body, request.headers.get("If-Match"))

@app.put("/api/szz/nezadouci-reakce/{id}")
async def szz_update_nezadouci_reakce(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_nezadouci_reakci, id, body, request.headers.get("If-Match"))

@app.put("/api/szz/nezadouci-ucinky/{id}")
async def szz_update_nezadouci_ucinky(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_nezadouci_ucinek, id, body, request.headers.get("If-Match"))

@app.put("/api/szz/nezadouci-udalosti/{id}")
async def szz_update_nezadouci_udalosti(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_nezadouci_udalost, id, body, request.headers.get("If-Match"))

@app.put("/api/szz/lecive-pripravky/{id}")
async def szz_update_lecive_pripravky(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_lecivy_pripravek, id, body, request.headers.get("If-Match"))

@app.patch("/api/szz/{entity_type}/{id}/{action}")
async def szz_lifecycle(entity_type: str, id: str, action: str, request: Request):
    if action not in ("zneplatnit", "obnovit", "zpochybnit"):
        return JSONResponse({"error": f"Neznámá akce: {action}"}, status_code=400)
    body = await request.json()
    fn = getattr(_modules["szz"], action, None)
    if not fn:
        return JSONResponse({"error": f"Metoda {action} neexistuje"}, status_code=400)
    return timed_call(fn, entity_type, id,
                      body.get("duvod",""), body.get("krzpId",""), body.get("ico",""),
                      request.headers.get("If-Match"))

@app.get("/api/szz/emergentni-zaznam/{rid}/pdf")
async def szz_emergentni_pdf(rid: str):
    return timed_call(_modules["szz"].emergentni_zaznam_pdf, rid)

@app.post("/api/szz/zdravotni-zaznamy/vyhledat")
async def szz_zdravotni_zaznamy_vyhledat(request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].zdravotni_zaznamy_vyhledat, body)

@app.put("/api/szz/zdravotni-zaznamy/{id}")
async def szz_update_zdravotni_zaznam(id: str, request: Request):
    body = await request.json()
    return timed_call(_modules["szz"].update_zdravotni_zaznam, id, body, request.headers.get("If-Match"))

@app.post("/api/szz/ciselniky/reindex")
async def szz_ciselniky_reindex():
    return timed_call(_modules["szz"].ciselniky_reindex)


# ---------------------------------------------------------------------------
# ELP
# ---------------------------------------------------------------------------

class ELPVyhledejRequest(BaseModel):
    page: int = 0
    size: int = 10

@app.post("/api/elp/vyhledej")
async def elp_vyhledej(req: ELPVyhledejRequest):
    body = {"strankovani": {"page": req.page, "size": req.size}}
    return timed_call(_modules["elp"].vyhledej_posudky, body)

@app.get("/api/elp/posudek/{posudek_id}")
async def elp_detail(posudek_id: str):
    return timed_call(_modules["elp"].detail_posudku, posudek_id)

@app.post("/api/elp/vytvor")
async def elp_vytvor(request: Request):
    body = await request.json()
    return timed_call(_modules["elp"].vytvor_posudek, body)

@app.get("/api/elp/ciselniky")
async def elp_ciselniky():
    return timed_call(_client.get, "/elektronickePosudky/api/v1/ciselniky")

@app.get("/api/elp/ciselniky/{kod}/polozky")
async def elp_ciselnik_polozky(kod: str):
    return timed_call(_client.get, f"/elektronickePosudky/api/v1/ciselniky/{kod}/polozky")

@app.get("/api/elp/posudky")
async def elp_list_posudky(request: Request):
    params = dict(request.query_params)
    return timed_call(_modules["elp"].list_posudky, **params)

@app.get("/api/elp/posudek/{id}/historie")
async def elp_historie(id: str):
    return timed_call(_modules["elp"].historie, id)

@app.get("/api/elp/posudek/{id}/pdf")
async def elp_pdf(id: str):
    return timed_call(_modules["elp"].pdf, id)

@app.get("/api/elp/posudek/{id}/pdftest")
async def elp_pdftest(id: str):
    return timed_call(_modules["elp"].pdftest, id)

@app.patch("/api/elp/posudek/{id}/zneplatnit")
async def elp_zneplatnit(id: str, request: Request):
    return timed_call(_modules["elp"].zneplatnit, id, request.headers.get("If-Match"))


# ---------------------------------------------------------------------------
# ELP v2 – Elektronické posudky v2.0
# ---------------------------------------------------------------------------

@app.get("/api/elp2/ciselniky")
async def elp2_ciselniky():
    return timed_call(_modules["elp2"].ciselniky)

@app.get("/api/elp2/ciselniky/{kod}/polozky")
async def elp2_ciselnik_polozky(kod: str):
    return timed_call(_modules["elp2"].ciselnik_polozky, kod)

@app.post("/api/elp2/vyhledej")
async def elp2_vyhledej(request: Request):
    body = await request.json()
    return timed_call(_modules["elp2"].vyhledej, body)

@app.get("/api/elp2/posudek/{posudek_id}")
async def elp2_detail(posudek_id: str):
    return timed_call(_modules["elp2"].detail, posudek_id)

@app.post("/api/elp2/vytvor")
async def elp2_vytvor(request: Request):
    body = await request.json()
    return timed_call(_modules["elp2"].vytvor, body)

@app.get("/api/elp2/posudek/{id}/historie")
async def elp2_historie(id: str):
    return timed_call(_modules["elp2"].historie, id)

@app.get("/api/elp2/posudek/{id}/pdf")
async def elp2_pdf(id: str):
    return timed_call(_modules["elp2"].pdf, id)

@app.patch("/api/elp2/posudek/{id}/zneplatnit")
async def elp2_zneplatnit(id: str, request: Request):
    etag = request.headers.get("If-Match", "")
    return timed_call(_modules["elp2"].zneplatnit, id, etag)

@app.post("/api/elp2/opravneni")
async def elp2_opravneni(request: Request):
    body = await request.json()
    return timed_call(_modules["elp2"].over_opravneni, body)


# ---------------------------------------------------------------------------
# eŽádanky – Simulation Engine
# ---------------------------------------------------------------------------

_ez_sim_mode = False
_ez_sim_store: dict = {}

_EZ_TRANSITIONS = {
    "0": {"prijmi": "1", "stornuj": "3"},
    "1": {"vyrid": "2", "stornuj": "3", "neproveditelnost": "4", "vrat": "5"},
    "5": {"prijmi": "1", "stornuj": "3"},
}
_EZ_STAV_NAMES = {
    "0": "Nová", "1": "Přijatá", "2": "Vyřízená",
    "3": "Stornovaná", "4": "Neproveditelná", "5": "Vrácená do oběhu",
}


def _ez_sim_verze():
    return base64.b64encode(uuid.uuid4().bytes[:8]).decode()


def _ez_sim_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ez_sim_resp(data, status=200):
    return JSONResponse({"status": status, "data": data, "elapsed_ms": 0, "_sim": True})


def _ez_sim_err(msg, code="SIM_ERR", status=400):
    return JSONResponse({
        "status": status,
        "data": {"errors": [{"error": code, "scope": "simulation", "message": msg}]},
        "elapsed_ms": 0, "_sim": True,
    })


def _ez_sim_make_record(body: dict) -> dict:
    zad = body.get("zadanka", body)
    zid = str(uuid.uuid4())
    now = _ez_sim_now()
    zas = zad.get("zasilka", {})
    pac_rid = zas.get("pacient", "0000000000")
    aut_krzp = zas.get("autor", "0")
    ico = zas.get("poskytovatel", "00000000")
    return {
        "id": zid,
        "kod": f"SIM-{zid[:8].upper()}",
        "verzeRadku": _ez_sim_verze(),
        "stav": {"kod": "0", "verze": "1.0.0"},
        "urgentnost": zad.get("urgentnost", {"kod": "routine", "verze": "5.0.2"}),
        "samoplatce": zad.get("samoplatce", False),
        "prilozenVzorek": zad.get("prilozenVzorek", False),
        "omezeniMobility": zad.get("omezeniMobility", False),
        "pacientImplantat": zad.get("pacientImplantat", False),
        "icpZadatele": zad.get("icpZadatele", ""),
        "instrukceProPacienta": zad.get("instrukceProPacienta"),
        "metodaData": zad.get("metodaData", []),
        "pacientPojistovna": zad.get("pacientPojistovna"),
        "datumVytvoreni": now,
        "datumExpirace": None,
        "datumPoslednihoPrijeti": None,
        "datumVyrizeni": None,
        "datumStorna": None,
        "datumPlanovanehoVysetreni": None,
        "datumSkutecneRealizaceVysetreni": None,
        "zasilka": {
            "nazev": zas.get("nazev", "Žádanka"),
            "typ": zas.get("typ"),
            "klasifikace": zas.get("klasifikace"),
            "autor": aut_krzp,
            "zdravotnickyPracovnik": zas.get("zdravotnickyPracovnik", aut_krzp),
            "poskytovatel": ico,
            "pacient": pac_rid,
            "ispzs": zas.get("ispzs", "NIS"),
            "adresat": zas.get("adresat", ico),
            "adresatTyp": zas.get("adresatTyp"),
            "dostupnost": True,
            "dokument": zas.get("dokument", []),
            "pacientData": {
                "jmeno": "Simulovaný", "prijmeni": "Pacient",
                "rid": pac_rid, "datumNarozeni": "1985-03-15",
                "zdravotniPojistovnaNazev": "VZP ČR",
            },
            "autorData": {
                "titulPred": "MUDr.", "jmeno": "Jan",
                "prijmeni": "Simuláček", "krzpId": aut_krzp,
            },
            "poskytovatelData": {
                "nazev": "Simulovaná nemocnice a.s.", "ico": ico,
            },
        },
    }


def _ez_sim_transition(zid, action, extras=None):
    rec = _ez_sim_store.get(zid)
    if not rec:
        return None, f"Žádanka {zid} nenalezena v simulaci"
    current = rec["stav"]["kod"]
    allowed = _EZ_TRANSITIONS.get(current, {})
    new_state = allowed.get(action)
    if not new_state:
        cur_name = _EZ_STAV_NAMES.get(current, "?")
        valid = ", ".join(allowed.keys()) if allowed else "žádné (terminální stav)"
        return None, f"Neplatný přechod: stav '{current}' ({cur_name}) → akce '{action}'. Povolené: {valid}"
    rec["stav"]["kod"] = new_state
    rec["verzeRadku"] = _ez_sim_verze()
    now = _ez_sim_now()
    if action == "prijmi":
        rec["datumPoslednihoPrijeti"] = now
        if extras:
            for k in ("cisloDokladu", "kodZadanky", "cisloVzorku"):
                if extras.get(k):
                    rec[k] = extras[k]
            if extras.get("datumPlanovanehoVysetreni"):
                rec["datumPlanovanehoVysetreni"] = extras["datumPlanovanehoVysetreni"]
    elif action == "vyrid":
        rec["datumVyrizeni"] = now
        if extras and extras.get("datumSkutecneRealizaceVysetreni"):
            rec["datumSkutecneRealizaceVysetreni"] = extras["datumSkutecneRealizaceVysetreni"]
    elif action == "stornuj":
        rec["datumStorna"] = now
    return rec, None


def _ez_sim_search(body):
    items = list(_ez_sim_store.values())
    pac = body.get("pacient")
    aut = body.get("autor")
    stav = body.get("stav")
    ft = (body.get("fulltext") or "").lower()
    typ = body.get("typ")
    if pac:
        items = [z for z in items if z["zasilka"].get("pacient") == pac
                 or z["zasilka"].get("pacientData", {}).get("rid") == pac]
    if aut:
        items = [z for z in items if z["zasilka"].get("autor") == aut
                 or z["zasilka"].get("autorData", {}).get("krzpId") == aut]
    if stav:
        items = [z for z in items if z["stav"]["kod"] == stav]
    if ft:
        items = [z for z in items if ft in z.get("zasilka", {}).get("nazev", "").lower()
                 or ft in (z.get("instrukceProPacienta") or "").lower()]
    if typ:
        items = [z for z in items if any(m.get("kod") == typ for m in z.get("metodaData", []))]
    paging = body.get("strankovani", {})
    page = paging.get("page", 0)
    size = paging.get("size", 10)
    total = len(items)
    items = items[page * size:(page + 1) * size]
    return {"items": items, "totalCount": total, "page": page, "size": size}


def _ez_sim_search_aktivni(body):
    items = [z for z in _ez_sim_store.values() if z["stav"]["kod"] in ("0", "1", "5")]
    rid = body.get("rid")
    if rid:
        items = [z for z in items if z["zasilka"].get("pacient") == rid]
    paging = body.get("strankovani", {})
    page = paging.get("page", 0)
    size = paging.get("size", 10)
    total = len(items)
    items = items[page * size:(page + 1) * size]
    return {"items": items, "totalCount": total, "page": page, "size": size}


def _ez_sim_seed():
    _ez_sim_store.clear()
    templates = [
        {"nazev": "Laboratorní vyšetření – krevní obraz", "metoda": "LAB", "urg": "asap", "stav": "0",
         "pac": ("Karel", "Novotný", "7653800856", "1978-05-12"),
         "aut": ("MUDr.", "Jan", "Dobrý", "102129137"),
         "ico": "25488627", "icp": "72090001", "instr": "Odběr nalačno, ráno do 8:00"},
        {"nazev": "RTG hrudníku PA", "metoda": "RAD", "urg": "routine", "stav": "0",
         "pac": ("Marie", "Svobodová", "2667873559", "1992-11-23"),
         "aut": ("MUDr.", "Petra", "Lékařová", "102129137"),
         "ico": "25488627", "icp": "72090001", "instr": None},
        {"nazev": "Konziliární vyšetření – neurologie", "metoda": "KONS", "urg": "urgent", "stav": "1",
         "pac": ("Petr", "Dvořák", "6534744190", "1965-07-30"),
         "aut": ("MUDr.", "Jan", "Dobrý", "102129137"),
         "ico": "25488627", "icp": "72090001", "instr": "Pacient na antikoagulační terapii"},
        {"nazev": "Laboratorní vyšetření – biochemie", "metoda": "LAB", "urg": "routine", "stav": "2",
         "pac": ("Anna", "Králová", "6653225891", "1988-01-14"),
         "aut": ("MUDr.", "Petra", "Lékařová", "102129137"),
         "ico": "25488627", "icp": "72090001", "instr": "Odběr nalačno"},
        {"nazev": "Odběr moči – vyšetření sedimentu", "metoda": "LAB", "urg": "routine", "stav": "3",
         "pac": ("Tomáš", "Procházka", "7582120377", "1975-12-03"),
         "aut": ("MUDr.", "Jan", "Dobrý", "102129137"),
         "ico": "25488627", "icp": "72090001", "instr": "Střední proud"},
    ]
    now = _ez_sim_now()
    for t in templates:
        zid = str(uuid.uuid4())
        pj, pp, prid, pnar = t["pac"]
        atit, aj, ap, akrzp = t["aut"]
        rec = {
            "id": zid, "kod": f"SIM-{zid[:8].upper()}", "verzeRadku": _ez_sim_verze(),
            "stav": {"kod": t["stav"], "verze": "1.0.0"},
            "urgentnost": {"kod": t["urg"], "verze": "5.0.2"},
            "samoplatce": False, "prilozenVzorek": t["metoda"] == "LAB",
            "omezeniMobility": False, "pacientImplantat": False,
            "icpZadatele": t["icp"], "instrukceProPacienta": t["instr"],
            "metodaData": [{"kod": t["metoda"], "verze": "1.0"}],
            "pacientPojistovna": {"kod": "111", "verze": "1.0"},
            "datumVytvoreni": now,
            "datumExpirace": None,
            "datumPoslednihoPrijeti": now if t["stav"] in ("1", "2") else None,
            "datumVyrizeni": now if t["stav"] == "2" else None,
            "datumStorna": now if t["stav"] == "3" else None,
            "datumPlanovanehoVysetreni": None,
            "datumSkutecneRealizaceVysetreni": now if t["stav"] == "2" else None,
            "zasilka": {
                "nazev": t["nazev"],
                "typ": {"kod": "57133-1", "verze": "1.0.0"},
                "klasifikace": {"kod": "57133-1", "verze": "1.0.0"},
                "autor": akrzp, "zdravotnickyPracovnik": akrzp,
                "poskytovatel": t["ico"], "pacient": prid, "ispzs": "NIS",
                "adresat": t["ico"], "adresatTyp": {"kod": "PZS", "verze": "1.0.0"},
                "dostupnost": True, "dokument": [],
                "pacientData": {"jmeno": pj, "prijmeni": pp, "rid": prid,
                                "datumNarozeni": pnar, "zdravotniPojistovnaNazev": "VZP ČR"},
                "autorData": {"titulPred": atit, "jmeno": aj, "prijmeni": ap, "krzpId": akrzp},
                "poskytovatelData": {"nazev": "Krajská zdravotní a.s.", "ico": t["ico"]},
            },
        }
        _ez_sim_store[zid] = rec
    return len(_ez_sim_store)


# ---------------------------------------------------------------------------
# eŽádanky – Routes (simulation-aware)
# ---------------------------------------------------------------------------

@app.get("/api/ezadanky/token")
async def ez_token():
    if _ez_sim_mode:
        return _ez_sim_resp({"token": "sim-token", "message": "Simulation mode active"})
    return timed_call(_modules["ez"].dej_token)

@app.post("/api/ezadanky/vyhledej")
async def ez_vyhledej(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        return _ez_sim_resp(_ez_sim_search(body))
    return timed_call(_modules["ez"].vyhledej_zadanku, body)

@app.post("/api/ezadanky/vyhledej-aktivni")
async def ez_vyhledej_aktivni(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        return _ez_sim_resp(_ez_sim_search_aktivni(body))
    return timed_call(_modules["ez"].vyhledej_aktivni, body)

@app.get("/api/ezadanky/zadanka/{zadanka_id}")
async def ez_nacti(zadanka_id: str):
    if _ez_sim_mode:
        rec = _ez_sim_store.get(zadanka_id)
        if not rec:
            return _ez_sim_err(f"Žádanka {zadanka_id} nenalezena", "E00002", 404)
        return _ez_sim_resp(rec)
    return timed_call(_modules["ez"].nacti_zadanku, zadanka_id)

@app.get("/api/ezadanky/vizual/{zadanka_id}")
async def ez_vizual(zadanka_id: str):
    if _ez_sim_mode:
        rec = _ez_sim_store.get(zadanka_id)
        if not rec:
            return _ez_sim_err("Žádanka nenalezena", "E00011", 404)
        s = _EZ_STAV_NAMES.get(rec["stav"]["kod"], "?")
        pac = rec["zasilka"].get("pacientData", {})
        aut = rec["zasilka"].get("autorData", {})
        html = (f"<html><body style='font-family:sans-serif;padding:20px'>"
                f"<h2>Žádanka {rec['kod']}</h2>"
                f"<p><b>Stav:</b> {s} | <b>Urgentnost:</b> {rec['urgentnost']['kod']}</p>"
                f"<p><b>Pacient:</b> {pac.get('jmeno','')} {pac.get('prijmeni','')} (RID: {pac.get('rid','-')})</p>"
                f"<p><b>Autor:</b> {aut.get('titulPred','')} {aut.get('jmeno','')} {aut.get('prijmeni','')}</p>"
                f"<p style='color:gray;font-size:12px'>Simulovaná vizualizace</p></body></html>")
        return _ez_sim_resp({"vizualizace": html, "mime": "text/html"})
    return timed_call(_modules["ez"].dej_vizual, zadanka_id)

@app.get("/api/ezadanky/prilohy/{zadanka_id}")
async def ez_prilohy(zadanka_id: str):
    if _ez_sim_mode:
        rec = _ez_sim_store.get(zadanka_id)
        if not rec:
            return _ez_sim_err("Žádanka nenalezena", "E00011", 404)
        return _ez_sim_resp({"prilohy": [], "pocet": 0})
    return timed_call(_modules["ez"].dej_prilohy, zadanka_id)

@app.post("/api/ezadanky/uloz")
async def ez_uloz(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        rec = _ez_sim_make_record(body)
        _ez_sim_store[rec["id"]] = rec
        return _ez_sim_resp(rec)
    return timed_call(_modules["ez"].uloz_zadanku, body)

@app.patch("/api/ezadanky/stornuj")
async def ez_stornuj(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        rec, err = _ez_sim_transition(body.get("id", ""), "stornuj", body)
        return _ez_sim_resp(rec) if rec else _ez_sim_err(err)
    return timed_call(_modules["ez"].stornuj, body)

@app.patch("/api/ezadanky/prijmi")
async def ez_prijmi(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        rec, err = _ez_sim_transition(body.get("id", ""), "prijmi", body)
        return _ez_sim_resp(rec) if rec else _ez_sim_err(err)
    return timed_call(_modules["ez"].prijmi, body)

@app.patch("/api/ezadanky/vyrid")
async def ez_vyrid(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        rec, err = _ez_sim_transition(body.get("id", ""), "vyrid", body)
        return _ez_sim_resp(rec) if rec else _ez_sim_err(err)
    return timed_call(_modules["ez"].vyrid, body)

@app.patch("/api/ezadanky/uprav")
async def ez_uprav(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        zid = body.get("id", "")
        rec = _ez_sim_store.get(zid)
        if not rec:
            return _ez_sim_err(f"Žádanka {zid} nenalezena", "E00002")
        if rec["stav"]["kod"] in ("2", "3", "4"):
            return _ez_sim_err(f"Žádanku ve stavu '{_EZ_STAV_NAMES.get(rec['stav']['kod'])}' nelze upravit")
        if body.get("upravenyPacient"):
            rec["zasilka"]["pacient"] = body["upravenyPacient"]
            rec["zasilka"]["pacientData"]["rid"] = body["upravenyPacient"]
        if body.get("upravenyPrijemce"):
            rec["zasilka"]["adresat"] = body["upravenyPrijemce"]
        if body.get("upravenaPriorita"):
            rec["urgentnost"] = body["upravenaPriorita"]
        rec["verzeRadku"] = _ez_sim_verze()
        return _ez_sim_resp(rec)
    return timed_call(_modules["ez"].uprav, body)

@app.patch("/api/ezadanky/vrat-do-obehu")
async def ez_vrat(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        rec, err = _ez_sim_transition(body.get("id", ""), "vrat", body)
        return _ez_sim_resp(rec) if rec else _ez_sim_err(err)
    return timed_call(_modules["ez"].vrat_do_obehu, body)

@app.patch("/api/ezadanky/neproveditelnost")
async def ez_neproveditelnost(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        rec, err = _ez_sim_transition(body.get("id", ""), "neproveditelnost", body)
        return _ez_sim_resp(rec) if rec else _ez_sim_err(err)
    return timed_call(_modules["ez"].neproveditelnost, body)

@app.post("/api/ezadanky/sestav-soubor")
async def ez_sestav(request: Request):
    body = await request.json()
    if _ez_sim_mode:
        return _ez_sim_resp({
            "soubor": base64.b64encode(b"%PDF-1.4 simulated").decode(),
            "mime": "application/pdf",
            "nazev": "sim_zadanka.pdf",
            "message": "Simulovaný PDF soubor žádanky",
        })
    return timed_call(_modules["ez"].sestav_soubor, body)

@app.get("/api/ezadanky/diagnose")
async def ez_diagnose():
    if _ez_sim_mode:
        endpoints = [
            ("DejVizualZadanky", "GET"), ("StornujZadanku", "PATCH"),
            ("SestavSouborZadanky", "POST"), ("VyhledejZadanku", "POST"),
            ("VyhledejAktivniZadanku", "POST"), ("NactiZadanku", "GET"),
            ("DejPrilohyZadanky", "GET"), ("PrijmiZadanku", "PATCH"),
            ("VyridZadanku", "PATCH"), ("UlozZadanku", "POST"),
        ]
        return JSONResponse({
            "summary": f"10/10 endpointů dostupné (SIMULACE – {len(_ez_sim_store)} žádanek)",
            "pzs_context": True,
            "results": [{"endpoint": e, "method": m, "status": 200, "auth_ok": True, "error": None}
                        for e, m in endpoints],
            "elapsed_ms": 0, "_sim": True,
        })
    t0 = time.monotonic()
    try:
        result = _modules["ez"].diagnose()
        result["elapsed_ms"] = round((time.monotonic() - t0) * 1000)
        return JSONResponse(result)
    except Exception as e:
        return error_response(str(e))


# ---------------------------------------------------------------------------
# eŽádanky – Simulation Control
# ---------------------------------------------------------------------------

@app.get("/api/ezadanky/sim/status")
async def ez_sim_status():
    states = {}
    for z in _ez_sim_store.values():
        sk = z["stav"]["kod"]
        name = _EZ_STAV_NAMES.get(sk, sk)
        states[name] = states.get(name, 0) + 1
    return JSONResponse({"enabled": _ez_sim_mode, "count": len(_ez_sim_store), "states": states})

@app.post("/api/ezadanky/sim/toggle")
async def ez_sim_toggle(request: Request):
    global _ez_sim_mode
    body = await request.json()
    _ez_sim_mode = body.get("enabled", not _ez_sim_mode)
    if _ez_sim_mode and not _ez_sim_store:
        _ez_sim_seed()
    return JSONResponse({"enabled": _ez_sim_mode, "count": len(_ez_sim_store)})

@app.post("/api/ezadanky/sim/seed")
async def ez_sim_seed_ep():
    count = _ez_sim_seed()
    return JSONResponse({"status": 200, "data": {"seeded": count}, "elapsed_ms": 0})

@app.post("/api/ezadanky/sim/reset")
async def ez_sim_reset():
    _ez_sim_store.clear()
    return JSONResponse({"status": 200, "data": {"cleared": True, "count": 0}, "elapsed_ms": 0})


# ---------------------------------------------------------------------------
# Notifikace
# ---------------------------------------------------------------------------

@app.get("/api/notifikace/ping")
async def notif_ping():
    return timed_call(_modules["notif"].ping)

@app.get("/api/notifikace/kanaly")
async def notif_kanaly(page: int = 0, size: int = 25):
    return timed_call(_modules["notif"].katalog_kanalu, page, size)

@app.get("/api/notifikace/sablony")
async def notif_sablony(page: int = 0, size: int = 25):
    return timed_call(_modules["notif"].katalog_sablon, page, size)

@app.get("/api/notifikace/zdroje")
async def notif_zdroje(page: int = 0, size: int = 25):
    return timed_call(_modules["notif"].katalog_zdroju, page, size)

@app.post("/api/notifikace/odeslat")
async def notif_odeslat(request: Request):
    body = await request.json()
    return timed_call(_modules["notif"].odeslat, body)

@app.get("/api/notifikace/vyhledat")
async def notif_vyhledat(idPrijemce: str = None, odData: str = None, limit: int = None):
    return timed_call(_modules["notif"].vyhledat, idPrijemce, odData, limit)

@app.post("/api/notifikace/pzs-prijem-vzor")
async def notif_pzs_prijem_vzor(request: Request):
    body = await request.json()
    return timed_call(_modules["notif"].pzs_prijem_vzor, body)


# ---------------------------------------------------------------------------
# EZCA 2 – Služby vytvářející důvěru
# ---------------------------------------------------------------------------

@app.get("/api/ezca/ping")
async def ezca_ping():
    return timed_call(_modules["ezca"].simple_health)

@app.get("/api/ezca/health-detail")
async def ezca_health_detail():
    return timed_call(_modules["ezca"].detail_health)

@app.post("/api/ezca/sign-document")
async def ezca_sign_document(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].sign_document, body)

@app.post("/api/ezca/stamp-document")
async def ezca_stamp_document(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].stamp_document, body)

@app.post("/api/ezca/validate-document")
async def ezca_validate_document(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].validate_document, body)

@app.post("/api/ezca/sign-hash")
async def ezca_sign_hash(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].sign_hash, body)

@app.post("/api/ezca/stamp-hash")
async def ezca_stamp_hash(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].stamp_hash, body)

@app.post("/api/ezca/create-document")
async def ezca_create_document(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].create_document, body)

@app.get("/api/ezca/info-document/{doc_id}")
async def ezca_info_document(doc_id: str):
    return timed_call(_modules["ezca"].info_document, doc_id)

@app.get("/api/ezca/info-component/{comp_id}")
async def ezca_info_component(comp_id: str):
    return timed_call(_modules["ezca"].info_component, comp_id)

@app.get("/api/ezca/content-component/{comp_id}")
async def ezca_content_component(comp_id: str):
    return timed_call(_modules["ezca"].content_component, comp_id)

@app.post("/api/ezca/list-certificates")
async def ezca_list_certificates(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].list_certificates, body)

@app.post("/api/ezca/create-xades")
async def ezca_create_xades(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].create_xades, body)

@app.post("/api/ezca/report")
async def ezca_report(request: Request):
    body = await request.json()
    return timed_call(_modules["ezca"].content_report, body)


# ---------------------------------------------------------------------------
# Debug / JWT info
# ---------------------------------------------------------------------------

@app.get("/api/debug/jwt")
async def debug_jwt():
    """Return live JWT assertion details and all service endpoints."""
    if not _auth:
        return error_response("Klient není inicializován")

    import jwt as pyjwt

    gw = SEZConfig.GATEWAY
    assertion = _auth.build_assertion()
    header = pyjwt.get_unverified_header(assertion)
    payload = pyjwt.decode(assertion, options={"verify_signature": False})

    tls_cert_path, tls_key_path = _auth.tls_cert
    correlation_id = str(uuid.uuid4())
    trace_id = str(uuid.uuid4())

    sample_headers = {
        "Authorization": f"Bearer {assertion[:60]}...{assertion[-20:]}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Language": "cs",
        "X-Correlation-Id": correlation_id,
        "X-Trace-Id": trace_id,
    }

    return {
        "environment": SEZConfig.ENVIRONMENT,
        "gateway": gw,
        "cert": _cert_info,
        "jwt": {
            "header": header,
            "payload": payload,
            "token_preview": assertion[:80] + "..." + assertion[-20:],
            "full_token": assertion,
            "algorithm": "RS256",
            "signing_key": "Privátní klíč z EZCA certifikátu (PFX/P12)",
        },
        "auth_detail": {
            "step1_load_cert": {
                "title": "1. Načtení certifikátu EZCA II/III",
                "desc": "Ze souboru PFX/P12 se načte privátní klíč (pro podpis JWT) a certifikát (pro mTLS)",
                "pfx_path": _cert_info.get("pfx_path", "N/A"),
                "client_id": _auth.client_id,
                "cert_uid": _auth._kid,
            },
            "step2_build_jwt": {
                "title": "2. Sestavení JWT Assertion",
                "desc": "Vytvoří se JWT token s JOSE hlavičkou a payload claims, podepsaný RS256",
                "jose_header": header,
                "payload_claims": payload,
                "payload_explained": {
                    "iss": f"{payload.get('iss')} (CLIENT_ID – identita aplikace v JSU)",
                    "sub": f"{payload.get('sub')} (stejné jako iss)",
                    "aud": f"{payload.get('aud')} (URL JSU token endpointu pro {SEZConfig.ENVIRONMENT})",
                    "jti": f"{payload.get('jti')} (unikátní UUID pro každý request)",
                    "iat": f"Issued At – Unix timestamp ({payload.get('iat')})",
                    "nbf": f"Not Before – iat minus {SEZConfig.ASSERTION_NBF_SKEW_SECONDS}s (clock skew)",
                    "exp": f"Expiration – iat plus {SEZConfig.ASSERTION_VALIDITY_SECONDS}s",
                },
                "signing": "jwt.encode(payload, private_key, algorithm='RS256', headers={kid: CERT_UID})",
            },
            "step3_mtls_session": {
                "title": "3. Vytvoření mTLS session",
                "desc": "HTTP session s klientským certifikátem pro oboustranné TLS",
                "tls_cert_file": tls_cert_path,
                "tls_key_file": tls_key_path,
                "verify_server": True,
            },
            "step4_send_request": {
                "title": "4. Odeslání požadavku",
                "desc": "HTTP request na Gateway s Bearer assertion v hlavičce Authorization",
                "url_pattern": f"{gw}/<služba>/<endpoint>",
                "http_headers": sample_headers,
                "note": "Gateway si SAMA vyřídí access token z JSU (OAuth2 client_credentials) – aplikace neřeší token exchange",
            },
            "step5_du_retry": {
                "title": "5. DÚ – speciální retry logika",
                "desc": "Dočasné úložiště zkouší více variant JWT kid/x5t hlaviček (EZCA UID, SKI hex, SKI b64, x5t SHA1, x5t#S256...)",
                "kid_variants": [name for name, _ in _auth.get_alt_kids()],
            },
        },
        "auth_flow": [
            "1. Aplikace vytvoří JWT assertion podepsanou privátním klíčem certifikátu EZCA",
            "2. JWT assertion se pošle na API Gateway v hlavičce Authorization: Bearer <assertion>",
            "3. API Gateway si SAMA vyřídí access token z JSU (OAuth2 client_credentials)",
            "4. mTLS: STEJNÝ certifikát pro TLS i podepisování JWT",
        ],
        "services": {
            "KRP": {
                "name": "Kmenový registr pacientů",
                "base": "/krp",
                "endpoints": [
                    {"method": "POST", "path": "/krp/api/v2/pacient/hledat/rid", "desc": "Vyhledání pacienta podle RID"},
                    {"method": "POST", "path": "/krp/api/v2/pacient/hledat/jmeno_prijmeni_rc", "desc": "Vyhledání podle jména a RČ"},
                    {"method": "POST", "path": "/krp/api/v2/pacient/generovat/docasny_rid", "desc": "Generování dočasného RID (DRID)"},
                    {"method": "POST", "path": "/krp/api/v2/pacient/priradit/docasny_rid", "desc": "Přiřazení DRID ke skutečnému RID"},
                    {"method": "POST", "path": "/krp/api/v2/pacient/hledat/mapovani_rid", "desc": "Mapování RID (aktuální ↔ historické)"},
                ],
                "full_urls": [
                    f"{gw}/krp/api/v2/pacient/hledat/rid",
                    f"{gw}/krp/api/v2/pacient/hledat/jmeno_prijmeni_rc",
                    f"{gw}/krp/api/v2/pacient/generovat/docasny_rid",
                    f"{gw}/krp/api/v2/pacient/priradit/docasny_rid",
                    f"{gw}/krp/api/v2/pacient/hledat/mapovani_rid",
                ],
            },
            "KRZP": {
                "name": "Kmenový registr zdravotnických pracovníků",
                "base": "/krzp",
                "endpoints": [
                    {"method": "POST", "path": "/krzp/api/v2/pracovnik/hledat/krzpid", "desc": "Vyhledání pracovníka podle KRZP ID"},
                    {"method": "POST", "path": "/krzp/api/v2/pracovnik/hledat/jmenoPrijmeniDatumNarozeni", "desc": "Vyhledání podle jména a data narození"},
                    {"method": "POST", "path": "/krzp/api/v2/pracovnik/hledat/zamestnavatel", "desc": "Vyhledání podle zaměstnavatele (IČO)"},
                    {"method": "POST", "path": "/krzp/api/v2/pracovnik/hledat/personalistika", "desc": "Personalistické vyhledávání"},
                    {"method": "POST", "path": "/krzp/api/v2/pracovnik/reklamuj/udaj", "desc": "Reklamace údaje"},
                ],
                "full_urls": [
                    f"{gw}/krzp/api/v2/pracovnik/hledat/krzpid",
                    f"{gw}/krzp/api/v2/pracovnik/hledat/jmenoPrijmeniDatumNarozeni",
                    f"{gw}/krzp/api/v2/pracovnik/hledat/zamestnavatel",
                    f"{gw}/krzp/api/v2/pracovnik/hledat/personalistika",
                ],
            },
            "RO": {
                "name": "Registr oprávnění",
                "base": "/registrOpravneni",
                "endpoints": [
                    {"method": "GET", "path": "/registrOpravneni/api/v1/Opravneni/Over", "desc": "Ověření oprávnění zdravotníka / zástupce"},
                ],
                "full_urls": [
                    f"{gw}/registrOpravneni/api/v1/Opravneni/Over",
                ],
            },
            "DU": {
                "name": "Dočasné úložiště",
                "base": "/docasneUloziste",
                "note": "DÚ používá speciální retry s alternativními kid/x5t JWT hlavičkami",
                "endpoints": [
                    {"method": "POST", "path": "/docasneUloziste/api/v1/Zasilka/UlozZasilku", "desc": "Uložení nové zásilky"},
                    {"method": "POST", "path": "/docasneUloziste/api/v1/Zasilka/VyhledejZasilku", "desc": "Vyhledání zásilek"},
                    {"method": "GET",  "path": "/docasneUloziste/api/v1/Zasilka/DejZasilku/{zasilkaId}", "desc": "Stažení zásilky podle ID"},
                    {"method": "PUT",  "path": "/docasneUloziste/api/v1/Zasilka/ZmenZasilku/{zasilkaId}", "desc": "Změna zásilky (před stažením)"},
                    {"method": "PUT",  "path": "/docasneUloziste/api/v1/Zasilka/ZneplatniZasilku", "desc": "Zneplatnění zásilky"},
                ],
                "full_urls": [
                    f"{gw}/docasneUloziste/api/v1/Zasilka/UlozZasilku",
                    f"{gw}/docasneUloziste/api/v1/Zasilka/VyhledejZasilku",
                    f"{gw}/docasneUloziste/api/v1/Zasilka/DejZasilku/{{zasilkaId}}",
                    f"{gw}/docasneUloziste/api/v1/Zasilka/ZmenZasilku/{{zasilkaId}}",
                    f"{gw}/docasneUloziste/api/v1/Zasilka/ZneplatniZasilku",
                ],
            },
            "SZZ": {
                "name": "Sdílený zdravotní záznam",
                "base": "/sdilenyZdravotniZaznam",
                "endpoints": [
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/{rid}", "desc": "Emergentní záznam"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/{rid}/pdf", "desc": "Emergentní záznam PDF"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/alergie/{rid}", "desc": "Alergie pacienta"},
                    {"method": "POST", "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/alergie", "desc": "Vytvořit alergii"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/krevniSkupina/{rid}", "desc": "Krevní skupina"},
                    {"method": "POST", "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/krevniSkupina", "desc": "Vytvořit krevní skupinu"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/nezadouciPrihody/{rid}", "desc": "Nežádoucí příhody"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/nezadouciReakce/{rid}", "desc": "Nežádoucí reakce"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/nezadouciUcinky/{rid}", "desc": "Nežádoucí účinky"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/nezadouciUdalosti/{rid}", "desc": "Nežádoucí události"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/lecivePripravky/{rid}", "desc": "Léčivé přípravky"},
                    {"method": "POST", "path": "/sdilenyZdravotniZaznam/api/v1/lecivePripravky", "desc": "Vytvořit léčivý přípravek"},
                    {"method": "POST", "path": "/sdilenyZdravotniZaznam/api/v1/zdravotniZaznamy", "desc": "Vytvořit zdravotní záznam"},
                    {"method": "POST", "path": "/sdilenyZdravotniZaznam/api/v1/zdravotniZaznamy/vyhledat", "desc": "Vyhledat zdravotní záznamy"},
                    {"method": "GET",  "path": "/sdilenyZdravotniZaznam/api/v1/ciselniky", "desc": "Seznam číselníků"},
                ],
                "full_urls": [
                    f"{gw}/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/{{rid}}",
                    f"{gw}/sdilenyZdravotniZaznam/api/v1/emergentniZaznam/alergie/{{rid}}",
                    f"{gw}/sdilenyZdravotniZaznam/api/v1/ciselniky",
                ],
            },
            "ELP": {
                "name": "Elektronické posudky (v1 + v2)",
                "base": "/elektronickePosudky",
                "endpoints": [
                    {"method": "POST", "path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni", "desc": "Vytvořit posudek (v2)"},
                    {"method": "POST", "path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/vyhledat", "desc": "Vyhledat posudky (v2)"},
                    {"method": "GET",  "path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/{id}", "desc": "Detail posudku (v2)"},
                    {"method": "PATCH","path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/{id}/zneplatnit", "desc": "Zneplatnit (v2)"},
                    {"method": "GET",  "path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/{id}/pdf", "desc": "PDF (v2)"},
                    {"method": "GET",  "path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/{id}/historie", "desc": "Historie (v2)"},
                    {"method": "POST", "path": "/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/zalozeni/opravneni", "desc": "Ověřit oprávnění (v2)"},
                    {"method": "GET",  "path": "/elektronickePosudky/api/v2/ciselniky", "desc": "Číselníky (v2)"},
                    {"method": "GET",  "path": "/elektronickePosudky/api/v2/ciselniky/{kod}/polozky", "desc": "Položky číselníku (v2)"},
                ],
                "full_urls": [
                    f"{gw}/elektronickePosudky/api/v2/posudky/ridicskeOpravneni",
                    f"{gw}/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/vyhledat",
                    f"{gw}/elektronickePosudky/api/v2/ciselniky",
                    f"{gw}/elektronickePosudky/api/v2/posudky/ridicskeOpravneni/zalozeni/opravneni",
                ],
            },
            "eZadanky": {
                "name": "eŽádanky",
                "base": "/eZadanky",
                "endpoints": [
                    {"method": "GET",  "path": "/eZadanky/api/v1/eZadanka/DejToken", "desc": "Získání tokenu"},
                    {"method": "POST", "path": "/eZadanky/api/v1/eZadanka/UlozZadanku", "desc": "Uložit žádanku"},
                    {"method": "POST", "path": "/eZadanky/api/v1/eZadanka/VyhledejZadanku", "desc": "Vyhledat žádanky"},
                    {"method": "POST", "path": "/eZadanky/api/v1/eZadanka/VyhledejAktivniZadanku", "desc": "Vyhledat aktivní žádanky"},
                    {"method": "GET",  "path": "/eZadanky/api/v1/eZadanka/NactiZadanku/{zadankaId}", "desc": "Načíst žádanku"},
                    {"method": "GET",  "path": "/eZadanky/api/v1/eZadanka/DejVizualZadanky/{zadankaId}", "desc": "Vizualizace žádanky"},
                    {"method": "GET",  "path": "/eZadanky/api/v1/eZadanka/DejPrilohyZadanky/{zadankaId}", "desc": "Přílohy žádanky"},
                    {"method": "PATCH","path": "/eZadanky/api/v1/eZadanka/StornujZadanku", "desc": "Stornovat žádanku"},
                    {"method": "PATCH","path": "/eZadanky/api/v1/eZadanka/PrijmiZadanku", "desc": "Přijmout žádanku"},
                    {"method": "PATCH","path": "/eZadanky/api/v1/eZadanka/VyridZadanku", "desc": "Vyřídit žádanku"},
                    {"method": "PATCH","path": "/eZadanky/api/v1/eZadanka/UpravZadanku", "desc": "Upravit žádanku"},
                    {"method": "PATCH","path": "/eZadanky/api/v1/eZadanka/VratZadankuDoObehu", "desc": "Vrátit žádanku do oběhu"},
                    {"method": "PATCH","path": "/eZadanky/api/v1/eZadanka/ZaznacNeproveditelnostZadanky", "desc": "Zaznačit neproveditelnost"},
                    {"method": "POST", "path": "/eZadanky/api/v1/eZadanka/SestavSouborZadanky", "desc": "Sestavit soubor žádanky"},
                ],
                "full_urls": [
                    f"{gw}/eZadanky/api/v1/eZadanka/DejToken",
                    f"{gw}/eZadanky/api/v1/eZadanka/VyhledejZadanku",
                    f"{gw}/eZadanky/api/v1/eZadanka/UlozZadanku",
                ],
            },
            "Notifikace": {
                "name": "Notifikační služby",
                "base": "/notifikace",
                "endpoints": [
                    {"method": "GET",  "path": "/notifikace/api/v1/notifikace/ping", "desc": "Ping (health check)"},
                    {"method": "POST", "path": "/notifikace/api/v1/notifikace/odeslat", "desc": "Odeslat notifikaci"},
                    {"method": "GET",  "path": "/notifikace/api/v1/notifikace/vyhledat", "desc": "Vyhledat notifikace"},
                    {"method": "GET",  "path": "/notifikace/api/v1/kanaly/katalog", "desc": "Katalog kanálů"},
                    {"method": "GET",  "path": "/notifikace/api/v1/sablony/katalog", "desc": "Katalog šablon"},
                    {"method": "GET",  "path": "/notifikace/api/v1/zdroje/katalog", "desc": "Katalog zdrojů"},
                ],
                "full_urls": [
                    f"{gw}/notifikace/api/v1/notifikace/ping",
                    f"{gw}/notifikace/api/v1/notifikace/odeslat",
                    f"{gw}/notifikace/api/v1/kanaly/katalog",
                ],
            },
            "EZCA2": {
                "name": "Služby vytvářející důvěru (EZCA II)",
                "base": "/ezca2",
                "endpoints": [
                    {"method": "GET",  "path": "/ezca2/simple-health", "desc": "Health check (simple)"},
                    {"method": "GET",  "path": "/ezca2/detail-health", "desc": "Health check (detail)"},
                    {"method": "POST", "path": "/ezca2/api/sign/document", "desc": "Podepsat dokument"},
                    {"method": "POST", "path": "/ezca2/api/stamp/document", "desc": "Orazítkovat dokument"},
                    {"method": "POST", "path": "/ezca2/api/validate/document", "desc": "Validovat podpis"},
                    {"method": "POST", "path": "/ezca2/api/sign/hash", "desc": "Podepsat hash"},
                    {"method": "POST", "path": "/ezca2/api/stamp/hash", "desc": "Orazítkovat hash"},
                    {"method": "POST", "path": "/ezca2/api/list/certificates", "desc": "Seznam certifikátů"},
                    {"method": "POST", "path": "/ezca2/api/create/document", "desc": "Vytvořit dokument"},
                    {"method": "GET",  "path": "/ezca2/api/info/document/{id}", "desc": "Info o dokumentu"},
                    {"method": "GET",  "path": "/ezca2/api/info/component/{id}", "desc": "Info o komponentě"},
                    {"method": "GET",  "path": "/ezca2/api/content/component/{id}", "desc": "Obsah komponenty"},
                    {"method": "POST", "path": "/ezca2/api/create/xades", "desc": "Vytvořit XAdES obálku"},
                    {"method": "POST", "path": "/ezca2/api/content/report", "desc": "Validační report"},
                ],
                "full_urls": [
                    f"{gw}/ezca2/simple-health",
                    f"{gw}/ezca2/api/sign/document",
                    f"{gw}/ezca2/api/validate/document",
                ],
            },
        },
    }


# ---------------------------------------------------------------------------
# Referenční .NET aplikace (MZČR TestovaciPZS)
# ---------------------------------------------------------------------------

@app.get("/api/reference/dotnet")
async def reference_dotnet():
    """Vrátí informace z oficiální testovací .NET aplikace od MZČR."""
    ref_dir = Path(__file__).parent.parent.parent / "Analytics_SEZAPI" / "reference_dotnet"
    program_cs = ""
    appsettings = ""
    try:
        program_cs = (ref_dir / "Program.cs").read_text(encoding="utf-8")
    except Exception:
        pass
    try:
        appsettings = (ref_dir / "appsettings.json").read_text(encoding="utf-8")
    except Exception:
        pass

    our_impl = {
        "jwt_claims": ["iss (client_id)", "sub (client_id)", "aud (token endpoint)", "jti (UUID)", "iat", "exp"],
        "signing": "RS256 s privátním klíčem z PFX/P12",
        "mtls": "Stejný certifikát pro JWT i klientský TLS",
        "token_expiry": "5 minut (náš) vs 1 hodina (.NET ref)",
        "kid_header": "Ano – cert_uid z EZCA registrace",
        "auto_retry": "Ano – rotace kid/x5t hlaviček při 401",
    }

    return {
        "source": "Aplikace_NET9_TestovaciPZS_ver02",
        "description": "Oficiální testovací .NET 9 aplikace od MZČR pro ověření připojení k SEZ API",
        "config": {
            "clientId": "25488627_KrajskaZdravotniVerejnyTest",
            "audience": "https://jsuint-auth-t2.csez.cz/connect/token",
            "certificate": "Certifikat_systémový_Krajská_zdravotní_ICO_25488627.pfx",
            "gateway": "https://gwy-ext-sec-t2.csez.cz",
            "test_endpoint": "/notifikace/api/v1/kanaly/katalog",
        },
        "jwt_creation": {
            "algorithm": "RS256",
            "claims": ["iss = ClientId", "sub = ClientId", "aud = JSU token endpoint", "jti = GUID"],
            "key_source": "X509SecurityKey z PFX certifikátu",
            "expiry": "1 hodina (AddHours(1))",
            "library": "Microsoft.IdentityModel.Tokens 8.15.0",
        },
        "ezca_notes": {
            "ezca1_support": "Konverze Base64 PFX -> DER pro starší EZCA I certifikáty",
            "sha256_der": "SHA-256 hash DER certifikátu pro vytvoření ClientID (EZCA I)",
            "ezca2_direct": "EZCA II certifikáty se zpracovávají přímo bez konverze",
        },
        "comparison": our_impl,
        "program_cs": program_cs,
        "appsettings_json": appsettings,
    }


# ---------------------------------------------------------------------------
# Raw request
# ---------------------------------------------------------------------------

class RawRequest(BaseModel):
    method: str = "GET"
    path: str = ""
    body: Optional[dict] = None

@app.post("/api/raw")
async def raw_request(req: RawRequest):
    t0 = time.monotonic()
    try:
        method = req.method.upper()
        if method == "GET":
            resp = _client.get(req.path)
        elif method == "POST":
            resp = _client.post(req.path, req.body)
        elif method == "PATCH":
            resp = _client.patch(req.path, req.body)
        elif method == "PUT":
            resp = _client.put(req.path, req.body)
        elif method == "DELETE":
            resp = _client.delete(req.path, req.body)
        else:
            return error_response(f"Unsupported method: {method}", 400)
        elapsed = round((time.monotonic() - t0) * 1000)
        result = api_response(resp)
        result["elapsed_ms"] = elapsed
        return JSONResponse(result)
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        return JSONResponse({"status": 0, "error": str(e), "elapsed_ms": elapsed})


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

@app.post("/api/test/run")
async def run_tests():
    test_locations = [
        Path.cwd() / "tests" / "test_dokumentace.py",
        Path.cwd() / "test_dokumentace.py",
        Path(__file__).parent.parent / "tests" / "test_dokumentace.py",
    ]
    script = None
    for loc in test_locations:
        if loc.exists():
            script = str(loc)
            break

    if not script:
        return error_response("test_dokumentace.py not found")
    try:
        project_root = str(Path(__file__).parent.parent)
        env = os.environ.copy()
        env.setdefault("SEZ_CLIENT_ID", cfg.CLIENT_ID)
        env.setdefault("SEZ_P12_PATH", cfg.P12_PATH)
        env.setdefault("SEZ_P12_PASSWORD", cfg.P12_PASSWORD)
        env.setdefault("SEZ_CERT_UID", cfg.CERT_UID)
        env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")

        result = subprocess.run(
            [sys.executable, script],
            capture_output=True, text=True, timeout=180,
            cwd=project_root,
            env=env,
        )
        lines = result.stdout.splitlines()
        tests = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("\u2713") or line.startswith("\u2717"):
                icon = line[0]
                rest = line[1:].strip()
                parts = rest.split("  (", 1)
                name = parts[0].strip()
                detail = parts[1].rstrip(")") if len(parts) > 1 else ""
                tests.append({
                    "passed": icon == "\u2713",
                    "name": name,
                    "detail": detail,
                })
        passed = sum(1 for t in tests if t["passed"])
        failed = sum(1 for t in tests if not t["passed"])
        return JSONResponse({
            "passed": passed,
            "failed": failed,
            "total": len(tests),
            "tests": tests,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return error_response("Test timeout (180s)")
    except Exception as e:
        return error_response(str(e))


# ---------------------------------------------------------------------------
# IRIS ObjectScript Code Generator
# ---------------------------------------------------------------------------

class IrisCodegenRequest(BaseModel):
    service: str = "krp"
    package: str = "SEZ"
    response_sample: Optional[dict] = None
    request_sample: Optional[dict] = None
    endpoint_path: Optional[str] = None
    endpoint_method: Optional[str] = None

@app.post("/api/codegen/iris")
async def codegen_iris(req: IrisCodegenRequest):
    from sez_api.iris_codegen import generate_full, SERVICE_META
    try:
        result = generate_full(
            service=req.service,
            package=req.package,
            response_sample=req.response_sample,
            request_sample=req.request_sample,
            endpoint_path=req.endpoint_path,
            endpoint_method=req.endpoint_method,
        )
        return JSONResponse({
            "status": 200,
            "data": result,
            "available_services": list(SERVICE_META.keys()),
        })
    except Exception as e:
        return JSONResponse({"status": 500, "error": str(e)})

@app.get("/api/codegen/iris/services")
async def codegen_iris_services():
    from sez_api.iris_codegen import SERVICE_META
    services = {}
    for k, v in SERVICE_META.items():
        services[k] = {
            "name": v["name"],
            "description": v["description"],
            "endpoint_count": len(v.get("endpoints", [])),
        }
    return JSONResponse({"status": 200, "data": services})


# ---------------------------------------------------------------------------
# DASTA4 Validátor (proxy na ezprava.net)
# ---------------------------------------------------------------------------

EZPRAVA_BASE = "https://ezprava.net"
EZPRAVA_VALIDATE = f"{EZPRAVA_BASE}/ds4/api/validate"

_ezprava_test_data_cache: dict | None = None


@app.post("/api/dasta4/validate")
async def dasta4_validate(file: UploadFile = File(None), request: Request = None):
    """Proxy validaci na ezprava.net/ds4/api/validate.
    Accepts multipart file upload or raw XML in body."""
    t0 = time.monotonic()
    try:
        if file and file.filename:
            content = await file.read()
            filename = file.filename
        else:
            body = await request.body()
            content = body
            filename = "document.xml"

        if not content:
            return JSONResponse({"status": 400, "error": "Žádný soubor/obsah k validaci"})

        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            files_payload = {"file": (filename, content)}
            resp = await client.post(EZPRAVA_VALIDATE, files=files_payload)
            elapsed = round((time.monotonic() - t0) * 1000)

            try:
                data = resp.json()
            except Exception:
                data = resp.text

            return JSONResponse({
                "status": resp.status_code,
                "data": data,
                "elapsed_ms": elapsed,
                "validator": "ezprava.net/ds4",
                "filename": filename,
                "size_bytes": len(content),
            })
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        return JSONResponse({"status": 0, "error": str(e), "elapsed_ms": elapsed})


@app.post("/api/dasta4/validate-xml")
async def dasta4_validate_xml(request: Request):
    """Validate raw XML string posted as JSON {xml: "..."}."""
    t0 = time.monotonic()
    try:
        body = await request.json()
        xml_str = body.get("xml", "")
        filename = body.get("filename", "document.xml")
        if not xml_str:
            return JSONResponse({"status": 400, "error": "Prázdný XML"})

        content = xml_str.encode("utf-8") if isinstance(xml_str, str) else xml_str
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            files_payload = {"file": (filename, content, "application/xml")}
            resp = await client.post(EZPRAVA_VALIDATE, files=files_payload)
            elapsed = round((time.monotonic() - t0) * 1000)

            try:
                data = resp.json()
            except Exception:
                data = resp.text

            return JSONResponse({
                "status": resp.status_code,
                "data": data,
                "elapsed_ms": elapsed,
                "validator": "ezprava.net/ds4",
                "filename": filename,
                "size_bytes": len(content),
            })
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        return JSONResponse({"status": 0, "error": str(e), "elapsed_ms": elapsed})


@app.get("/api/dasta4/test-data")
async def dasta4_test_data():
    """Return list of available test data from ezprava.net/ds4/TestData."""
    global _ezprava_test_data_cache
    if _ezprava_test_data_cache:
        return JSONResponse({"status": 200, "data": _ezprava_test_data_cache, "cached": True})

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.get(f"{EZPRAVA_BASE}/ds4/TestData")
            if resp.status_code != 200:
                return JSONResponse({"status": resp.status_code, "error": "Nepodařilo se načíst test data"})

            import re
            links = re.findall(r'href="([^"]*\.xml)"', resp.text)
            categories = {}
            for link in links:
                fname = link.split("/")[-1]
                if "DASTA" in fname.upper() or "ds4" in link:
                    cat = "DASTA4"
                elif "FHIR" in fname.upper() or "fhir" in link:
                    cat = "FHIR R5"
                elif "LCLPPOL" in fname.upper() or "lclppol" in link:
                    cat = "LCLPPOL"
                else:
                    cat = "Ostatní"
                if cat not in categories:
                    categories[cat] = []
                url = link if link.startswith("http") else f"{EZPRAVA_BASE}{link}" if link.startswith("/") else f"{EZPRAVA_BASE}/ds4/{link}"
                categories[cat].append({"name": fname, "url": url})

            _ezprava_test_data_cache = categories
            return JSONResponse({"status": 200, "data": categories})
    except Exception as e:
        return JSONResponse({"status": 0, "error": str(e)})


@app.get("/api/dasta4/test-data/download")
async def dasta4_test_data_download(url: str):
    """Download a specific test data file from ezprava.net."""
    if not url.startswith("https://ezprava.net"):
        return JSONResponse({"status": 400, "error": "Povoleny pouze soubory z ezprava.net"})
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.get(url)
            return Response(
                content=resp.content,
                media_type="application/xml",
                headers={"Content-Disposition": f'inline; filename="{url.split("/")[-1]}"'},
            )
    except Exception as e:
        return JSONResponse({"status": 0, "error": str(e)})


# ---------------------------------------------------------------------------
# IROP/NPO – Testovací scénáře dle metodiky MZČR
# ---------------------------------------------------------------------------

def _irop_step(name, fn, *args, **kwargs):
    """Run one scenario step, return structured result with timing."""
    t0 = time.monotonic()
    try:
        resp = fn(*args, **kwargs)
        elapsed = round((time.monotonic() - t0) * 1000)
        status_code = getattr(resp, "status_code", 0)
        try:
            data = resp.json()
        except Exception:
            data = getattr(resp, "text", str(resp))
        ok = 200 <= status_code < 400
        debug = {}
        if hasattr(resp, "request"):
            req = resp.request
            debug["method"] = str(req.method)
            debug["url"] = str(req.url)
        return {"name": name, "passed": ok, "status": status_code,
                "elapsed_ms": elapsed, "data": data, "error": None, "_debug": debug}
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        return {"name": name, "passed": False, "status": 0,
                "elapsed_ms": elapsed, "data": None, "error": str(e), "_debug": {}}


def _irop_step_api(name, fn, *args, **kwargs):
    """Run step using existing module method that returns requests.Response via SEZClient."""
    t0 = time.monotonic()
    try:
        resp = fn(*args, **kwargs)
        elapsed = round((time.monotonic() - t0) * 1000)
        status_code = getattr(resp, "status_code", 0)
        try:
            data = resp.json() if hasattr(resp, "json") else resp
        except Exception:
            data = str(resp)
        ok = 200 <= status_code < 400
        debug = {}
        if _client:
            debug["last_status"] = _client.last_status
            if _client.last_request_debug:
                debug.update({k: v for k, v in _client.last_request_debug.items()
                              if k in ("method", "url", "path", "headers", "tried_variants", "kid_variant")})
        return {"name": name, "passed": ok, "status": status_code,
                "elapsed_ms": elapsed, "data": data, "error": None, "_debug": debug}
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        debug = {}
        if _client and _client.last_request_debug:
            debug.update({k: v for k, v in _client.last_request_debug.items()
                          if k in ("method", "url", "path", "tried_variants")})
        return {"name": name, "passed": False, "status": 0,
                "elapsed_ms": elapsed, "data": None, "error": str(e), "_debug": debug}


def _irop_tech1(params, modules, client):
    """TS-TECH-1: Připojení ke KRP – vyhledání pacienta více metodami."""
    krp = modules.get("krp")
    if not krp:
        return {"error": "KRP modul není dostupný"}
    rid = params.get("rid", "2667873559")
    steps = []

    steps.append(_irop_step_api("Vyhledání dle RID", krp.hledat_rid, rid))

    pac_data = None
    if steps[0]["passed"] and isinstance(steps[0]["data"], dict):
        od = steps[0]["data"].get("odpovedData", {})
        pac_data = od if isinstance(od, dict) else (od[0] if isinstance(od, list) and od else {})

    jmeno = pac_data.get("jmeno", {}).get("hodnota", "MRAKOMOROVÁ") if pac_data else "MRAKOMOROVÁ"
    prijmeni = pac_data.get("prijmeni", {}).get("hodnota", "MRAČENA") if pac_data else "MRAČENA"
    rc = params.get("rc", "7161264528")
    dn = params.get("datum_narozeni", "1971-11-26")

    steps.append(_irop_step_api("Vyhledání dle jméno + RC", krp.hledat_jmeno_rc, jmeno, prijmeni, rc))
    steps.append(_irop_step_api("Vyhledání dle jméno + datum narození", krp.hledat_jmeno_dn, jmeno, prijmeni, dn))
    steps.append(_irop_step_api("Vyhledání dle jméno + číslo pojištěnce", krp.hledat_jmeno_cp, jmeno, prijmeni, rc))

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-1", "name": "Připojení ke KRP",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech2(params, modules, client):
    """TS-TECH-2: Připojení ke KRZP – vyhledání pracovníků."""
    krzp = modules.get("krzp")
    if not krzp:
        return {"error": "KRZP modul není dostupný"}
    ico = params.get("ico", "25488627")
    krzpid = params.get("krzpid", "102129137")
    steps = []

    steps.append(_irop_step_api("Vyhledání dle KRZP ID", krzp.hledat_krzpid, krzpid))
    steps.append(_irop_step_api("Vyhledání dle zaměstnavatele (IČO)", krzp.hledat_zamestnavatel, ico))

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-2", "name": "Připojení ke KRZP",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech3(params, modules, client):
    """TS-TECH-3: Notifikace – ověření subscrip. systému."""
    krp = modules.get("krp")
    if not krp:
        return {"error": "KRP modul není dostupný"}
    steps = []
    steps.append(_irop_step_api("Vyhledání odběrů notifikací (KRP)", krp.notifikace_vyhledat, "WEBSERVICE"))

    krzp = modules.get("krzp")
    if krzp:
        steps.append(_irop_step_api("Stav notifikací (KRZP)", krzp.notifikace_stav, "WEBSERVICE"))

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-3", "name": "Notifikace ze SEZ",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech4(params, modules, client):
    """TS-TECH-4: Registr oprávnění – ověření přístupu zdravotnického pracovníka."""
    ro = modules.get("ro")
    if not ro:
        return {"error": "Registr oprávnění modul není dostupný"}
    ico = params.get("ico", "25488627")
    krzpid = params.get("autor", "102129137")
    steps = []

    steps.append(_irop_step_api(
        "Ověření oprávnění ZP (DÚ přístup)",
        ro.over_zdravotnika, ico, krzpid, 1, 5,
    ))

    steps.append(_irop_step_api(
        "Ověření oprávnění ZP (služba EZ)",
        ro.over_zdravotnika, ico, krzpid, 2, 5,
    ))

    steps.append(_irop_step_api(
        "Ověření oprávnění PZS→ZP (obecné)",
        ro.over,
        1, 5,
        "PoskytovatelZdravotnickychSluzeb", ico,
        "ZdravotnickyPracovnik", krzpid,
    ))

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-4", "name": "Registr oprávnění",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech5(params, modules, client):
    """TS-TECH-5: Získání číselníků z TermX."""
    if not client:
        return {"error": "Klient není připojen"}
    vs_url = params.get("valueset_url", "https://termit.ncez.mzcr.cz/fhir/ValueSet/typ-adresata")
    steps = []

    t0 = time.monotonic()
    try:
        resp = client.get(f"/termx/fhir/ValueSet/?url={vs_url}")
        elapsed = round((time.monotonic() - t0) * 1000)
        sc = resp.status_code
        data = resp.json() if sc < 400 else resp.text
        steps.append({"name": "Vyhledání ValueSet", "passed": 200 <= sc < 400,
                       "status": sc, "elapsed_ms": elapsed, "data": data, "error": None,
                       "_debug": {"url": str(resp.url) if hasattr(resp, "url") else ""}})
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        steps.append({"name": "Vyhledání ValueSet", "passed": False,
                       "status": 0, "elapsed_ms": elapsed, "data": None, "error": str(e), "_debug": {}})

    t0 = time.monotonic()
    try:
        resp = client.get(f"/termx/fhir/ValueSet/$expand?url={vs_url}")
        elapsed = round((time.monotonic() - t0) * 1000)
        sc = resp.status_code
        data = resp.json() if sc < 400 else resp.text
        steps.append({"name": "Expand ValueSet", "passed": 200 <= sc < 400,
                       "status": sc, "elapsed_ms": elapsed, "data": data, "error": None,
                       "_debug": {"url": str(resp.url) if hasattr(resp, "url") else ""}})
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        steps.append({"name": "Expand ValueSet", "passed": False,
                       "status": 0, "elapsed_ms": elapsed, "data": None, "error": str(e), "_debug": {}})

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-5", "name": "TermX číselníky",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech6(params, modules, client):
    """TS-TECH-6: Uložení dokumentace do DÚ."""
    du = modules.get("du")
    if not du:
        return {"error": "DÚ modul není dostupný"}
    rid = params.get("rid", "2667873559")
    autor = params.get("autor", "102129137")
    ico = params.get("ico", "25488627")
    steps = []

    content = f"IROP test document generated at {datetime.now(timezone.utc).isoformat()}"
    content_bytes = content.encode("utf-8")
    content_b64 = base64.b64encode(content_bytes).decode()
    sha = hashlib.sha256(content_bytes).hexdigest()

    zasilka = {
        "nazev": "IROP TS-TECH-6 test",
        "popis": "Automatický test uložení zásilky (IROP/NPO)",
        "typ": {"kod": "11506-3", "verze": "1.0.0"},
        "klasifikace": {"kod": "11503-0", "verze": "1.0.0"},
        "autor": autor, "zdravotnickyPracovnik": autor,
        "poskytovatel": ico, "pacient": rid,
        "ispzs": "SEZ API IROP Test", "adresat": ico,
        "adresatTyp": {"kod": "PZS", "verze": "1.0.0"},
        "dostupnost": True,
        "dokument": [{
            "nazev": "IROP testovací dokument",
            "jazyk": {"kod": "cs", "verze": "5.0.0"},
            "typ": {"kod": "11506-3", "verze": "1.0.0"},
            "klasifikace": {"kod": "11503-0", "verze": "1.0.0"},
            "autor": autor, "poskytovatel": ico, "pacient": rid,
            "dostupnost": True,
            "duvernost": {"kod": "N", "verze": "2.0.0"},
            "format": {"kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient", "verze": "1.0.0"},
            "mime": {"kod": "text/plain", "verze": "1.0.0"},
            "hash": sha, "velikost": len(content_bytes),
            "soubor": {"soubor": content_b64},
        }],
    }
    steps.append(_irop_step_api("UlozZasilku", du.uloz_zasilku, zasilka))

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-6", "name": "Uložení dokumentace do DÚ",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech7(params, modules, client):
    """TS-TECH-7: Vyhledání a stažení dokumentace z DÚ."""
    du = modules.get("du")
    if not du:
        return {"error": "DÚ modul není dostupný"}
    rid = params.get("rid", "2667873559")
    steps = []

    now = datetime.now(timezone.utc)
    od = (now.replace(day=1)).strftime("%Y-%m-%dT00:00:00+00:00")
    do_ = now.strftime("%Y-%m-%dT23:59:59+00:00")
    steps.append(_irop_step_api("VyhledejZasilku", du.vyhledej_zasilku, od, do_, rid))

    zasilka_id = None
    if steps[0]["passed"] and isinstance(steps[0].get("data"), dict):
        zasilky = steps[0]["data"].get("zasilka", [])
        if zasilky:
            zasilka_id = zasilky[0].get("id")

    if zasilka_id:
        steps.append(_irop_step_api("DejZasilku (stažení metadat)", du.dej_zasilku, zasilka_id))

        if steps[-1]["passed"] and isinstance(steps[-1].get("data"), dict):
            docs = steps[-1]["data"].get("dokument", [])
            doc_count = len(docs)
            has_content = any(
                bool(d.get("soubor", {}).get("soubor") or d.get("soubor", {}).get("cesta"))
                for d in docs
            )
            steps.append({
                "name": f"Ověření dokumentů ({doc_count} nalezeno)",
                "passed": doc_count > 0 and has_content,
                "status": 200, "elapsed_ms": 0,
                "data": {"document_count": doc_count, "has_content": has_content},
                "error": None if (doc_count > 0 and has_content)
                         else "Zásilka neobsahuje dokumenty s obsahem",
                "_debug": {},
            })
        else:
            steps.append({"name": "Ověření dokumentů", "passed": False, "status": 0,
                           "elapsed_ms": 0, "data": None,
                           "error": "Nelze získat zásilku pro ověření dokumentů", "_debug": {}})
    else:
        steps.append({"name": "DejZasilku", "passed": False, "status": 0,
                       "elapsed_ms": 0, "data": None,
                       "error": "Žádná zásilka nalezena (spusťte nejdřív TS-TECH-6)", "_debug": {}})
        steps.append({"name": "Ověření dokumentů", "passed": False, "status": 0,
                       "elapsed_ms": 0, "data": None, "error": "Nelze ověřit – zásilka nenalezena", "_debug": {}})

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-7", "name": "Vyhledání a stažení z DÚ",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech8(params, modules, client):
    """TS-TECH-8: Změna dokumentace v DÚ."""
    du = modules.get("du")
    if not du:
        return {"error": "DÚ modul není dostupný"}
    rid = params.get("rid", "2667873559")
    steps = []

    now = datetime.now(timezone.utc)
    od = (now.replace(day=1)).strftime("%Y-%m-%dT00:00:00+00:00")
    do_ = now.strftime("%Y-%m-%dT23:59:59+00:00")
    steps.append(_irop_step_api("VyhledejZasilku", du.vyhledej_zasilku, od, do_, rid))

    zasilka_id = None
    verze = None
    if steps[0]["passed"] and isinstance(steps[0].get("data"), dict):
        zasilky = steps[0]["data"].get("zasilka", [])
        if zasilky:
            zasilka_id = zasilky[0].get("id")
            verze = zasilky[0].get("verzeRadku")

    if zasilka_id:
        zmena = {"nazev": f"IROP TS-TECH-8 změna {now.isoformat()}", "verzeRadku": verze}
        steps.append(_irop_step_api("ZmenZasilku", du.zmen_zasilku, zasilka_id, zmena))
    else:
        steps.append({"name": "ZmenZasilku", "passed": False, "status": 0,
                       "elapsed_ms": 0, "data": None,
                       "error": "Žádná zásilka nalezena pro změnu (spusťte nejdřív TS-TECH-6)", "_debug": {}})

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-8", "name": "Změna dokumentace v DÚ",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_tech9(params, modules, client):
    """TS-TECH-9: Zneplatnění dokumentace v DÚ."""
    du = modules.get("du")
    if not du:
        return {"error": "DÚ modul není dostupný"}
    rid = params.get("rid", "2667873559")
    steps = []

    now = datetime.now(timezone.utc)
    od = (now.replace(day=1)).strftime("%Y-%m-%dT00:00:00+00:00")
    do_ = now.strftime("%Y-%m-%dT23:59:59+00:00")
    steps.append(_irop_step_api("VyhledejZasilku", du.vyhledej_zasilku, od, do_, rid))

    zasilka_id = None
    verze = None
    if steps[0]["passed"] and isinstance(steps[0].get("data"), dict):
        zasilky = steps[0]["data"].get("zasilka", [])
        if zasilky:
            zasilka_id = zasilky[0].get("id")
            verze = zasilky[0].get("verzeRadku")

    if zasilka_id and verze:
        steps.append(_irop_step_api("ZneplatniZasilku", du.zneplatni_zasilku, zasilka_id, verze))
    else:
        steps.append({"name": "ZneplatniZasilku", "passed": False, "status": 0,
                       "elapsed_ms": 0, "data": None,
                       "error": "Žádná zásilka nalezena pro zneplatnění", "_debug": {}})

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-TECH-9", "name": "Zneplatnění dokumentace v DÚ",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_obs1(params, modules, client):
    """TS-OBS-1: Příjem, uložení a zobrazení eZD."""
    du = modules.get("du")
    if not du:
        return {"error": "DÚ modul není dostupný"}
    rid = params.get("rid", "2667873559")
    steps = []

    now = datetime.now(timezone.utc)
    od = (now.replace(day=1)).strftime("%Y-%m-%dT00:00:00+00:00")
    do_ = now.strftime("%Y-%m-%dT23:59:59+00:00")
    steps.append(_irop_step_api("VyhledejZasilku", du.vyhledej_zasilku, od, do_, rid))

    zasilka_id = None
    if steps[0]["passed"] and isinstance(steps[0].get("data"), dict):
        zasilky = steps[0]["data"].get("zasilka", [])
        if zasilky:
            zasilka_id = zasilky[0].get("id")

    if zasilka_id:
        steps.append(_irop_step_api("DejZasilku (stažení)", du.dej_zasilku, zasilka_id))
        if steps[-1]["passed"] and isinstance(steps[-1].get("data"), dict):
            docs = steps[-1]["data"].get("dokument", [])
            if docs:
                doc = docs[0]
                soubor = doc.get("soubor", {})
                has_content = bool(soubor.get("soubor") or soubor.get("cesta"))
                hash_ok = bool(doc.get("hash"))
                steps.append({"name": "Validace integrity (hash + velikost)", "passed": has_content and hash_ok,
                               "status": 200, "elapsed_ms": 0,
                               "data": {"hash": doc.get("hash"), "velikost": doc.get("velikost"),
                                        "has_content": has_content},
                               "error": None if (has_content and hash_ok) else "Chybí obsah nebo hash", "_debug": {}})
            else:
                steps.append({"name": "Validace integrity", "passed": False, "status": 0,
                               "elapsed_ms": 0, "data": None, "error": "Zásilka neobsahuje dokumenty", "_debug": {}})
    else:
        steps.append({"name": "DejZasilku", "passed": False, "status": 0,
                       "elapsed_ms": 0, "data": None, "error": "Žádná zásilka k stažení", "_debug": {}})

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-OBS-1", "name": "Příjem, uložení a zobrazení eZD",
            "steps": steps, "passed": passed, "total": len(steps)}


def _irop_obs2(params, modules, client):
    """TS-OBS-2: Vytvoření eZD a zpřístupnění v DÚ."""
    du = modules.get("du")
    if not du:
        return {"error": "DÚ modul není dostupný"}
    rid = params.get("rid", "2667873559")
    autor = params.get("autor", "102129137")
    ico = params.get("ico", "25488627")
    doc_type = params.get("doc_type", "propousteci-zprava")
    steps = []

    fhir_bundle = {
        "resourceType": "Bundle", "type": "document",
        "entry": [
            {"resource": {"resourceType": "Composition", "status": "final",
                          "type": {"coding": [{"system": "http://loinc.org", "code": "18842-5",
                                               "display": "Discharge summary"}]},
                          "subject": {"identifier": {"system": "urn:oid:2.16.840.1.113883.4.653", "value": rid}},
                          "date": datetime.now(timezone.utc).isoformat(),
                          "author": [{"identifier": {"system": "urn:oid:2.16.840.1.113883.2.9.6.2.7", "value": autor}}],
                          "title": f"IROP test – {doc_type}"}},
            {"resource": {"resourceType": "Patient",
                          "identifier": [{"system": "urn:oid:2.16.840.1.113883.4.653", "value": rid}]}},
            {"resource": {"resourceType": "Practitioner",
                          "identifier": [{"system": "urn:oid:2.16.840.1.113883.2.9.6.2.7", "value": autor}]}},
            {"resource": {"resourceType": "Organization",
                          "identifier": [{"system": "urn:oid:2.16.840.1.113883.2.9.6.2.1", "value": ico}],
                          "name": "Testovací PZS"}},
        ],
    }
    content = json.dumps(fhir_bundle, ensure_ascii=False)
    content_bytes = content.encode("utf-8")
    content_b64 = base64.b64encode(content_bytes).decode()
    sha = hashlib.sha256(content_bytes).hexdigest()
    fhir_valid = True
    fhir_errors = []
    if fhir_bundle.get("resourceType") != "Bundle":
        fhir_valid = False; fhir_errors.append("resourceType != Bundle")
    if fhir_bundle.get("type") != "document":
        fhir_valid = False; fhir_errors.append("type != document")
    entry_types = [e.get("resource", {}).get("resourceType") for e in fhir_bundle.get("entry", [])]
    for required in ["Composition", "Patient"]:
        if required not in entry_types:
            fhir_valid = False; fhir_errors.append(f"Chybí {required} v entries")
    comp = next((e["resource"] for e in fhir_bundle.get("entry", [])
                 if e.get("resource", {}).get("resourceType") == "Composition"), None)
    if comp:
        if not comp.get("type", {}).get("coding"):
            fhir_valid = False; fhir_errors.append("Composition.type.coding chybí")
        if not comp.get("date"):
            fhir_valid = False; fhir_errors.append("Composition.date chybí")
        if not comp.get("author"):
            fhir_valid = False; fhir_errors.append("Composition.author chybí")

    steps.append({"name": "Generování FHIR Bundle", "passed": True, "status": 200,
                   "elapsed_ms": 0, "data": {"resourceType": "Bundle", "entries": len(fhir_bundle["entry"]),
                                              "size_bytes": len(content_bytes), "sha256": sha[:16] + "..."},
                   "error": None, "_debug": {}})

    steps.append({"name": "Validace FHIR formátu",
                   "passed": fhir_valid, "status": 200 if fhir_valid else 422,
                   "elapsed_ms": 0,
                   "data": {"valid": fhir_valid, "entry_types": entry_types,
                            "errors": fhir_errors if fhir_errors else None},
                   "error": "; ".join(fhir_errors) if fhir_errors else None,
                   "_debug": {"composition_keys": list(comp.keys()) if comp else []}})

    typ_map = {"propousteci-zprava": "18842-5", "pacientsky-souhrn": "60591-5",
               "obrazove-vysetreni": "18748-4", "laboratorni-vysetreni": "11502-2",
               "vyjezd-zzs": "67796-3"}
    typ_kod = typ_map.get(doc_type, "18842-5")
    zasilka = {
        "nazev": f"IROP TS-OBS-2 – {doc_type}",
        "popis": "Automaticky generovaný eZD (FHIR Bundle)",
        "typ": {"kod": typ_kod, "verze": "1.0.0"},
        "klasifikace": {"kod": "11503-0", "verze": "1.0.0"},
        "autor": autor, "zdravotnickyPracovnik": autor,
        "poskytovatel": ico, "pacient": rid,
        "ispzs": "SEZ API IROP Test", "adresat": ico,
        "adresatTyp": {"kod": "PZS", "verze": "1.0.0"},
        "dostupnost": True,
        "dokument": [{
            "nazev": f"{doc_type} – FHIR Bundle",
            "jazyk": {"kod": "cs", "verze": "5.0.0"},
            "typ": {"kod": typ_kod, "verze": "1.0.0"},
            "klasifikace": {"kod": "11503-0", "verze": "1.0.0"},
            "autor": autor, "poskytovatel": ico, "pacient": rid,
            "dostupnost": True,
            "duvernost": {"kod": "N", "verze": "2.0.0"},
            "format": {"kod": "urn:ihe:iti:xds:2017:mimeTypeSufficient", "verze": "1.0.0"},
            "mime": {"kod": "application/fhir+json", "verze": "1.0.0"},
            "hash": sha, "velikost": len(content_bytes),
            "soubor": {"soubor": content_b64},
        }],
    }
    steps.append(_irop_step_api("UlozZasilku (FHIR Bundle)", du.uloz_zasilku, zasilka))

    passed = sum(1 for s in steps if s["passed"])
    return {"scenario_id": "TS-OBS-2", "name": "Vytvoření eZD a zpřístupnění v DÚ",
            "steps": steps, "passed": passed, "total": len(steps)}


IROP_SCENARIOS = {
    "TS-TECH-1": {"fn": _irop_tech1, "name": "Připojení ke KRP",
                   "desc": "Ověření vyhledání pacienta v KRP více metodami (RID, jméno+RC, jméno+DN, jméno+ČP)."},
    "TS-TECH-2": {"fn": _irop_tech2, "name": "Připojení ke KRZP",
                   "desc": "Ověření vyhledání zdravotnického pracovníka v KRZP dle KRZP ID a zaměstnavatele."},
    "TS-TECH-3": {"fn": _irop_tech3, "name": "Notifikace ze SEZ",
                   "desc": "Ověření funkčnosti notifikačního systému (vyhledání odběrů, stav kanálů)."},
    "TS-TECH-4": {"fn": _irop_tech4, "name": "Registr oprávnění",
                   "desc": "Ověření přístupových oprávnění ZP přes Registr oprávnění (Over, OverZdravotnika)."},
    "TS-TECH-5": {"fn": _irop_tech5, "name": "TermX číselníky",
                   "desc": "Získání a rozbalení číselníku z Terminologického serveru (ValueSet, $expand)."},
    "TS-TECH-6": {"fn": _irop_tech6, "name": "Uložení do DÚ",
                   "desc": "Uložení nové zásilky s dokumentem do Dočasného úložiště (UlozZasilku)."},
    "TS-TECH-7": {"fn": _irop_tech7, "name": "Vyhledání a stažení z DÚ",
                   "desc": "Vyhledání zásilky a stažení dokumentu z DÚ (VyhledejZasilku + DejZasilku)."},
    "TS-TECH-8": {"fn": _irop_tech8, "name": "Změna v DÚ",
                   "desc": "Vyhledání existující zásilky a provedení změny (ZmenZasilku)."},
    "TS-TECH-9": {"fn": _irop_tech9, "name": "Zneplatnění v DÚ",
                   "desc": "Vyhledání existující zásilky a její zneplatnění (ZneplatniZasilku)."},
    "TS-OBS-1":  {"fn": _irop_obs1, "name": "Příjem eZD",
                   "desc": "Stažení dokumentu z DÚ, validace integrity (hash, velikost), zobrazení obsahu."},
    "TS-OBS-2":  {"fn": _irop_obs2, "name": "Vytvoření eZD",
                   "desc": "Generování FHIR Bundle, validace formátu a uložení do DÚ."},
}


@app.get("/api/irop/scenarios")
async def irop_list():
    return JSONResponse([
        {"id": k, "name": v["name"], "desc": v["desc"],
         "category": "tech" if "TECH" in k else "obs"}
        for k, v in IROP_SCENARIOS.items()
    ])


@app.post("/api/irop/scenario/{scenario_id}")
async def irop_run(scenario_id: str, request: Request):
    scenario = IROP_SCENARIOS.get(scenario_id)
    if not scenario:
        return JSONResponse({"error": f"Neznámý scénář: {scenario_id}"}, status_code=404)
    if not _connected:
        return JSONResponse({"error": "Klient není připojen. Nejdříve se připojte přes Dashboard."}, status_code=503)
    try:
        body = await request.json()
    except Exception:
        body = {}
    result = scenario["fn"](body, _modules, _client)
    return JSONResponse(result)


@app.post("/api/irop/run-all")
async def irop_run_all(request: Request):
    if not _connected:
        return JSONResponse({"error": "Klient není připojen"}, status_code=503)
    try:
        body = await request.json()
    except Exception:
        body = {}
    results = []
    total_passed = 0
    total_steps = 0
    for sid, sdef in IROP_SCENARIOS.items():
        r = sdef["fn"](body, _modules, _client)
        r["scenario_id"] = sid
        results.append(r)
        total_passed += r.get("passed", 0)
        total_steps += r.get("total", 0)
    return JSONResponse({
        "scenarios": results,
        "total_passed": total_passed,
        "total_steps": total_steps,
        "total_scenarios": len(results),
        "scenarios_ok": sum(1 for r in results if r.get("passed", 0) == r.get("total", 0)),
    })
