"""
IRIS ObjectScript Code Generator
---------------------------------
Takes API call context (service, endpoint, request, response)
and generates InterSystems IRIS / Caché code:
  - Persistent class for data storage
  - Client class with %Net.HttpRequest calls
  - JWT + mTLS setup
  - CSP / REST dispatch snippets
"""

from __future__ import annotations
import re
import json
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Type mapping JSON -> IRIS
# ---------------------------------------------------------------------------

_IRIS_TYPE_MAP = {
    str: "%String",
    int: "%Integer",
    float: "%Double",
    bool: "%Boolean",
    list: "%ListOfDataTypes",
    type(None): "%String",
}


def _iris_type(val: Any) -> str:
    if isinstance(val, dict):
        return "%DynamicObject"
    if isinstance(val, list):
        if val and isinstance(val[0], dict):
            return "%DynamicArray"
        return "%ListOfDataTypes"
    return _IRIS_TYPE_MAP.get(type(val), "%String")


def _safe_prop(name: str) -> str:
    """Convert JSON key to valid IRIS property name."""
    name = re.sub(r"[^a-zA-Z0-9_]", "", name.replace("-", "_"))
    if name and name[0].isdigit():
        name = "P" + name
    return name or "Unnamed"


def _classify(name: str) -> str:
    """Convert endpoint/service name to PascalCase class name."""
    parts = re.split(r"[-_/\s]+", name)
    return "".join(p.capitalize() for p in parts if p)


# ---------------------------------------------------------------------------
# Persistent class generator
# ---------------------------------------------------------------------------

def gen_persistent_class(
    package: str,
    class_name: str,
    sample_data: dict | list,
    description: str = "",
) -> str:
    if isinstance(sample_data, list):
        sample_data = sample_data[0] if sample_data else {}
    if not isinstance(sample_data, dict):
        sample_data = {"value": sample_data}

    lines = [
        f'/// {description}',
        f'/// Vygenerováno: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
        f'Class {package}.Data.{class_name} Extends %Persistent',
        '{',
        '',
    ]

    props = []
    for key, val in sample_data.items():
        pname = _safe_prop(key)
        ptype = _iris_type(val)
        maxlen = ""
        if isinstance(val, str) and len(val) > 50:
            maxlen = "(MAXLEN = 32000)"
        elif isinstance(val, str):
            maxlen = "(MAXLEN = 250)"
        props.append((pname, ptype, maxlen, key))
        lines.append(f'Property {pname} As {ptype}{maxlen};')

    lines.append('')

    # FromJSON class method
    lines.append('ClassMethod FromJSON(json As %DynamicObject) As %Status')
    lines.append('{')
    lines.append(f'    set obj = ..%New()')
    for pname, ptype, _, key in props:
        if ptype in ("%DynamicObject", "%DynamicArray", "%ListOfDataTypes"):
            lines.append(f'    set obj.{pname} = json.%Get("{key}")')
        else:
            lines.append(f'    set obj.{pname} = json.%Get("{key}")')
    lines.append(f'    set sc = obj.%Save()')
    lines.append(f'    quit sc')
    lines.append('}')
    lines.append('')

    # ToJSON instance method
    lines.append('Method ToJSON() As %DynamicObject')
    lines.append('{')
    lines.append('    set json = ##class(%DynamicObject).%New()')
    for pname, ptype, _, key in props:
        lines.append(f'    do json.%Set("{key}", ..{pname})')
    lines.append('    quit json')
    lines.append('}')
    lines.append('')

    # SQL index on first string property
    first_str = next((p for p in props if p[1] == "%String"), None)
    if first_str:
        lines.append(f'Index idx{first_str[0]} On {first_str[0]};')
        lines.append('')

    lines.append('}')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Client class generator
# ---------------------------------------------------------------------------

def gen_client_class(
    package: str,
    service_name: str,
    endpoints: list[dict],
) -> str:
    """Generate a client class with REST methods.

    endpoints: [{"method":"POST", "path":"/krp/api/v1/...", "name":"HledatRid",
                 "body_sample": {...}, "description": "..."}]
    """
    cls = _classify(service_name)

    lines = [
        f'/// SEZ API klient pro službu {service_name}',
        f'/// Vygenerováno: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
        f'Class {package}.Client.{cls} Extends %RegisteredObject',
        '{',
        '',
        'Property GatewayURL As %String(MAXLEN = 500);',
        'Property BearerToken As %String(MAXLEN = 8000);',
        'Property SSLConfig As %String [ InitialExpression = "SEZ_SSL" ];',
        '',
        '/// Získání tokenu přes JWT assertion + client_credentials',
        'Method GetToken(clientId As %String, tokenEndpoint As %String, '
        'certFile As %String, keyFile As %String) As %Status',
        '{',
        '    // 1. Sestavení JWT assertion',
        '    set jwt = ##class(%DynamicObject).%New()',
        '    do jwt.%Set("iss", clientId)',
        '    do jwt.%Set("sub", clientId)',
        '    do jwt.%Set("aud", tokenEndpoint)',
        '    set jti = $system.Util.CreateGUID()',
        '    do jwt.%Set("jti", jti)',
        '    set now = $zdatetime($horolog, -2)',
        '    do jwt.%Set("iat", now)',
        '    do jwt.%Set("exp", now + 300)',
        '    ',
        '    // 2. Podpis RS256 s privátním klíčem',
        '    set header = ##class(%DynamicObject).%New()',
        '    do header.%Set("alg", "RS256")',
        '    do header.%Set("typ", "JWT")',
        '    // kid = cert_uid z EZCA registrace',
        '    ',
        '    // 3. Token request',
        '    set req = ##class(%Net.HttpRequest).%New()',
        '    set req.Server = $piece(tokenEndpoint, "/", 3)',
        '    set req.SSLConfiguration = ..SSLConfig',
        '    set req.ContentType = "application/x-www-form-urlencoded"',
        '    do req.EntityBody.Write("grant_type=client_credentials"',
        '        _"&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"',
        '        _"&client_assertion="_assertion',
        '        _"&client_id="_clientId)',
        '    set sc = req.Post(tokenEndpoint)',
        '    if $$$ISERR(sc) quit sc',
        '    ',
        '    set resp = ##class(%DynamicObject).%FromJSON(req.HttpResponse.Data)',
        '    set ..BearerToken = resp.%Get("access_token")',
        '    quit $$$OK',
        '}',
        '',
        '/// Základní REST volání',
        'Method Call(method As %String, path As %String, body As %DynamicObject = "") As %DynamicObject',
        '{',
        '    set req = ##class(%Net.HttpRequest).%New()',
        '    set req.Server = ..GatewayURL',
        '    set req.SSLConfiguration = ..SSLConfig',
        '    set req.ContentType = "application/json"',
        '    do req.SetHeader("Authorization", "Bearer "_..BearerToken)',
        '    do req.SetHeader("Accept", "application/json")',
        '    ',
        '    if body \'= "" {',
        '        do req.EntityBody.Write(body.%ToJSON())',
        '    }',
        '    ',
        '    if method = "GET" {',
        '        set sc = req.Get(path)',
        '    } elseif method = "POST" {',
        '        set sc = req.Post(path)',
        '    } elseif method = "PUT" {',
        '        set sc = req.Put(path)',
        '    } elseif method = "DELETE" {',
        '        set sc = req.Delete(path)',
        '    }',
        '    ',
        '    if $$$ISERR(sc) quit ""',
        '    set result = ##class(%DynamicObject).%FromJSON(req.HttpResponse.Data)',
        '    quit result',
        '}',
        '',
    ]

    for ep in endpoints:
        m = ep.get("method", "GET")
        path = ep.get("path", "/")
        name = ep.get("name", _classify(path.split("/")[-1]))
        desc = ep.get("description", f"{m} {path}")
        body_sample = ep.get("body_sample")

        lines.append(f'/// {desc}')
        if body_sample and m in ("POST", "PUT"):
            params = _build_method_params(body_sample)
            lines.append(f'Method {name}({params}) As %DynamicObject')
            lines.append('{')
            lines.append(f'    set body = ##class(%DynamicObject).%New()')
            for k in body_sample:
                pname = _safe_prop(k)
                lines.append(f'    do body.%Set("{k}", {pname})')
            lines.append(f'    quit ..Call("{m}", "{path}", body)')
            lines.append('}')
        else:
            lines.append(f'Method {name}() As %DynamicObject')
            lines.append('{')
            lines.append(f'    quit ..Call("{m}", "{path}")')
            lines.append('}')
        lines.append('')

    lines.append('}')
    return '\n'.join(lines)


def _build_method_params(sample: dict) -> str:
    parts = []
    for k, v in sample.items():
        pname = _safe_prop(k)
        ptype = _iris_type(v)
        if ptype in ("%DynamicObject", "%DynamicArray"):
            ptype = "%String"
        parts.append(f'{pname} As {ptype}')
    return ', '.join(parts)


# ---------------------------------------------------------------------------
# SSL Configuration setup code
# ---------------------------------------------------------------------------

def gen_ssl_setup() -> str:
    return '''/// Nastavení SSL/TLS konfigurace pro mTLS komunikaci se SEZ API
/// Spustit jednou v terminálu nebo při inicializaci systému
ClassMethod SetupSSL() As %Status
{
    set ssl = ##class(Security.SSLConfigs).%New()
    set ssl.Name = "SEZ_SSL"
    set ssl.Description = "SEZ API Gateway - mTLS"
    
    // Cesta k certifikátu (PFX/P12 převedený na PEM)
    set ssl.CertificateFile = "/opt/iris/certs/sez_client.pem"
    set ssl.PrivateKeyFile = "/opt/iris/certs/sez_client_key.pem"
    // Heslo k privátnímu klíči (pokud je šifrovaný)
    // set ssl.PrivateKeyPassword = "..."
    
    // CA certifikát pro ověření serveru
    set ssl.CAFile = "/opt/iris/certs/sez_ca_chain.pem"
    
    set ssl.Protocols = 8+16  // TLS 1.2 + 1.3
    set ssl.VerifyPeer = 1
    
    set sc = ssl.%Save()
    if $$$ISERR(sc) {
        write "Chyba při ukládání SSL konfigurace: ", $system.Status.GetErrorText(sc), !
    } else {
        write "SSL konfigurace 'SEZ_SSL' vytvořena.", !
    }
    quit sc
}'''


# ---------------------------------------------------------------------------
# CSP REST Dispatch class
# ---------------------------------------------------------------------------

def gen_rest_dispatch(
    package: str,
    service_name: str,
    endpoints: list[dict],
) -> str:
    cls = _classify(service_name)
    routes = []
    methods = []

    for ep in endpoints:
        m = ep.get("method", "GET")
        path = ep.get("path", "/")
        name = ep.get("name", _classify(path.split("/")[-1]))
        route_path = "/" + name.lower()
        routes.append(f'        <Route Url="{route_path}" Method="{m}" Call="{name}" />')

        methods.append(f'ClassMethod {name}() As %Status')
        methods.append('{')
        methods.append(f'    set client = ##class({package}.Client.{cls}).%New()')
        methods.append(f'    set client.GatewayURL = ##class({package}.Config).GetGateway()')
        methods.append(f'    set client.BearerToken = ##class({package}.Auth).GetCachedToken()')
        if m in ("POST", "PUT"):
            methods.append(f'    set body = ##class(%DynamicObject).%FromJSON(%request.Content)')
            methods.append(f'    set result = client.{name}(body)')
        else:
            methods.append(f'    set result = client.{name}()')
        methods.append(f'    set %response.ContentType = "application/json"')
        methods.append(f'    if result \'= "" {{')
        methods.append(f'        write result.%ToJSON()')
        methods.append(f'    }} else {{')
        methods.append(f'        write "{{}}"')
        methods.append(f'    }}')
        methods.append(f'    quit $$$OK')
        methods.append('}')
        methods.append('')

    lines = [
        f'/// REST dispatch pro {service_name}',
        f'/// Vygenerováno: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
        f'Class {package}.REST.{cls} Extends %CSP.REST',
        '{',
        '',
        'Parameter UseSession = 1;',
        'Parameter CHARSET = "utf-8";',
        'Parameter CONTENTTYPE = "application/json";',
        '',
        'XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]',
        '{',
        '    <Routes>',
        *routes,
        '    </Routes>',
        '}',
        '',
        *methods,
        '}',
    ]
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Smart generator: auto-detect from API call context
# ---------------------------------------------------------------------------

SERVICE_META = {
    "krp": {
        "name": "KRP",
        "description": "Kmenový registr pacientů",
        "base_path": "/krp-pzs/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/krp-pzs/api/v1/pacient/vyhledani/rid",
             "name": "HledatRid", "description": "Vyhledání pacienta dle RID",
             "body_sample": {"rid": "1234567890", "ucelPristupuKUdajumPacienta": "LECBA"}},
            {"method": "POST", "path": "/krp-pzs/api/v1/pacient/vyhledani/jmeno",
             "name": "HledatJmeno", "description": "Vyhledání pacienta dle jména",
             "body_sample": {"jmeno": "Jan", "prijmeni": "Novák"}},
            {"method": "POST", "path": "/krp-pzs/api/v1/pacient/zalozeni",
             "name": "ZalozitPacienta", "description": "Založení nového pacienta"},
            {"method": "POST", "path": "/krp-pzs/api/v1/pacient/zmena",
             "name": "ZmenitPacienta", "description": "Změna údajů pacienta"},
        ],
    },
    "notifikace": {
        "name": "Notifikace",
        "description": "Systém notifikací",
        "base_path": "/notifikace/api/v1",
        "endpoints": [
            {"method": "GET", "path": "/notifikace/api/v1/kanaly/katalog",
             "name": "KatalogKanalu", "description": "Katalog notifikačních kanálů"},
            {"method": "GET", "path": "/notifikace/api/v1/sablony/katalog",
             "name": "KatalogSablon", "description": "Katalog šablon"},
            {"method": "GET", "path": "/notifikace/api/v1/zdroje/katalog",
             "name": "KatalogZdroju", "description": "Katalog zdrojů"},
            {"method": "GET", "path": "/notifikace/api/v1/notifikace/vyhledat",
             "name": "Vyhledat", "description": "Vyhledání notifikací"},
        ],
    },
    "ezadanky": {
        "name": "EZadanky",
        "description": "eŽádanky (elektronické žádanky)",
        "base_path": "/ezadanky/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/ezadanky/api/v1/ezadanka/vytvorit",
             "name": "Vytvorit", "description": "Vytvoření eŽádanky",
             "body_sample": {"typZadanky": "VYSETRENI", "priorita": "NORMALNI",
                             "ridPacienta": "1234567890"}},
            {"method": "POST", "path": "/ezadanky/api/v1/ezadanka/vyhledat",
             "name": "Vyhledat", "description": "Vyhledání eŽádanek",
             "body_sample": {"ridPacienta": "1234567890"}},
            {"method": "POST", "path": "/ezadanky/api/v1/ezadanka/zmenit-stav",
             "name": "ZmenitStav", "description": "Změna stavu eŽádanky"},
        ],
    },
    "ezca2": {
        "name": "EZCA2",
        "description": "Služby vytvářející důvěru (EZCA 2)",
        "base_path": "/ezca2",
        "endpoints": [
            {"method": "POST", "path": "/ezca2/api/sign/document",
             "name": "SignDocument", "description": "Elektronický podpis dokumentu",
             "body_sample": {"documentId": "doc-123",
                             "authentication": {"userLogin": None}}},
            {"method": "POST", "path": "/ezca2/api/stamp/document",
             "name": "StampDocument", "description": "Elektronické razítko dokumentu"},
            {"method": "POST", "path": "/ezca2/api/validate/document",
             "name": "ValidateDocument", "description": "Validace podpisu dokumentu"},
            {"method": "POST", "path": "/ezca2/api/create/document",
             "name": "CreateDocument", "description": "Vytvoření dokumentu pro podpis"},
            {"method": "POST", "path": "/ezca2/api/list/certificates",
             "name": "ListCertificates", "description": "Výpis certifikátů"},
            {"method": "GET", "path": "/ezca2/simple-health",
             "name": "HealthCheck", "description": "Kontrola dostupnosti EZCA2"},
        ],
    },
    "du": {
        "name": "DU",
        "description": "Dočasné úložiště",
        "base_path": "/du/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/du/api/v1/dokumenty/ulozit",
             "name": "UlozitDokument", "description": "Uložení dokumentu"},
            {"method": "GET", "path": "/du/api/v1/dokumenty/stahnout",
             "name": "StahnoutDokument", "description": "Stažení dokumentu"},
        ],
    },
    "szz": {
        "name": "SZZ",
        "description": "Systém pro sdílený zdravotní záznam",
        "base_path": "/szz/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/szz/api/v1/dokument/ulozit",
             "name": "UlozitDokument", "description": "Uložení do SZZ"},
            {"method": "POST", "path": "/szz/api/v1/dokument/vyhledat",
             "name": "VyhledatDokument", "description": "Vyhledání v SZZ"},
        ],
    },
    "elp": {
        "name": "ELP",
        "description": "Elektronické lékařské posudky",
        "base_path": "/elp/api/v2",
        "endpoints": [
            {"method": "POST", "path": "/elp/api/v2/posudek/vytvorit",
             "name": "VytvoritPosudek", "description": "Vytvoření posudku"},
            {"method": "POST", "path": "/elp/api/v2/posudek/vyhledat",
             "name": "VyhledatPosudek", "description": "Vyhledání posudku"},
        ],
    },
    "krzp": {
        "name": "KRZP",
        "description": "Kmenový registr zdravotnických pracovníků",
        "base_path": "/krzp-pzs/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/krzp-pzs/api/v1/pracovnik/vyhledani",
             "name": "VyhledatPracovnika", "description": "Vyhledání ZP dle parametrů"},
        ],
    },
}


def generate_full(
    service: str,
    package: str = "SEZ",
    response_sample: dict | None = None,
    request_sample: dict | None = None,
    endpoint_path: str | None = None,
    endpoint_method: str | None = None,
) -> dict:
    """Generate complete IRIS code for a given service or API call context.

    Returns dict with keys:
      persistent_class, client_class, rest_dispatch, ssl_setup, usage_example
    """
    meta = SERVICE_META.get(service, {})
    sname = meta.get("name", _classify(service))
    desc = meta.get("description", service)
    endpoints = meta.get("endpoints", [])

    if endpoint_path and endpoint_method:
        ep_name = _classify(endpoint_path.split("/")[-1])
        found = False
        for ep in endpoints:
            if ep["path"] == endpoint_path:
                found = True
                break
        if not found:
            ep = {"method": endpoint_method, "path": endpoint_path,
                  "name": ep_name, "description": f"{endpoint_method} {endpoint_path}"}
            if request_sample:
                ep["body_sample"] = request_sample
            endpoints.append(ep)

    sample = response_sample or {"id": "example-1", "status": "OK"}

    result = {
        "persistent_class": gen_persistent_class(package, sname + "Data", sample, desc),
        "client_class": gen_client_class(package, sname, endpoints),
        "rest_dispatch": gen_rest_dispatch(package, sname, endpoints),
        "ssl_setup": gen_ssl_setup(),
        "usage_example": _gen_usage(package, sname),
    }
    return result


def _gen_usage(package: str, sname: str) -> str:
    return f'''/// Příklad použití v IRIS terminálu
/// =====================================

// 1. Jednorázová konfigurace SSL (stačí jednou)
do ##class({package}.Setup).SetupSSL()

// 2. Vytvoření klienta
set client = ##class({package}.Client.{sname}).%New()
set client.GatewayURL = "gwy-ext-sec-t2.csez.cz"

// 3. Získání tokenu
set sc = client.GetToken(
    "25488627_KrajskaZdravotniVerejnyTest",
    "https://jsuint-auth-t2.csez.cz/connect/token",
    "/opt/iris/certs/client.pem",
    "/opt/iris/certs/client_key.pem")
if $$$ISERR(sc) write "Chyba tokenu: ", $system.Status.GetErrorText(sc), ! quit

// 4. Volání API
set result = client.{sname}()
if result '= "" {{
    write result.%ToJSON(), !
}}

// 5. REST dispatch - konfigurace v Management Portal:
//    System > Security > Applications > Web Applications
//    Název: /api/sez/{sname.lower()}
//    Dispatch class: {package}.REST.{sname}
//    Namespace: váš namespace
'''
