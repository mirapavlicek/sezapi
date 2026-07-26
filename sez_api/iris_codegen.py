"""
IRIS ObjectScript Code Generator
---------------------------------
Z kontextu API volání (služba, endpoint, request, response) generuje
InterSystems IRIS / IRIS for Health kód podle konvencí platformy
(skill `iris-objectscript`):

  - Persistentní třída pro uložení dat (%Persistent, %DynamicObject I/O)
  - Klientská třída s %Net.HttpRequest (mTLS + JWT assertion RS256)
  - SSL/TLS setup
  - %CSP.REST dispatch

House rules: idiomatický UDL, PascalCase příkazy, Try/Catch + %Status,
$$$ThrowOnError, %DynamicObject pro JSON, /// doc komentáře. Ověřeno
strukturálně skill linterem (scripts/lint_udl.py).
"""

from __future__ import annotations
import re
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
    type(None): "%String",
}


def _is_nested(val: Any) -> bool:
    return isinstance(val, (dict, list))


def _iris_type(val: Any) -> str:
    if isinstance(val, dict):
        return "%DynamicObject"
    if isinstance(val, list):
        return "%DynamicArray"
    return _IRIS_TYPE_MAP.get(type(val), "%String")


def _safe_prop(name: str) -> str:
    """Převede JSON klíč na validní název IRIS property (PascalCase)."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "", str(name).replace("-", "_"))
    if not cleaned:
        return "Unnamed"
    out = cleaned[0].upper() + cleaned[1:]
    if out[0].isdigit():
        out = "P" + out
    return out


def _param(name: str) -> str:
    """Název parametru metody (p + PascalCase)."""
    return "p" + _safe_prop(name)


def _classify(name: str) -> str:
    parts = re.split(r"[-_/\s]+", str(name))
    return "".join(p.capitalize() for p in parts if p) or "Sluzba"


def _gen_header() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Persistent class generator
# ---------------------------------------------------------------------------

def gen_persistent_class(package: str, class_name: str,
                         sample_data: dict | list, description: str = "") -> str:
    if isinstance(sample_data, list):
        sample_data = sample_data[0] if sample_data else {}
    if not isinstance(sample_data, dict):
        sample_data = {"value": sample_data}

    props = []  # (pname, ptype, jsonkey, nested)
    for key, val in sample_data.items():
        pname = _safe_prop(key)
        if _is_nested(val):
            props.append((pname, '%String(MAXLEN = 32000)', key, True))
        elif isinstance(val, str):
            maxlen = 32000 if len(val) > 200 else 250
            props.append((pname, f'%String(MAXLEN = {maxlen})', key, False))
        else:
            props.append((pname, _iris_type(val), key, False))

    L = []
    if description:
        L.append(f'/// {description}')
    L.append(f'/// Datová třída pro {class_name}. Generováno {_gen_header()}.')
    L.append(f'Class {package}.Data.{class_name} Extends %Persistent')
    L.append('{')
    L.append('')
    for pname, ptype, key, nested in props:
        L.append(f'/// {key}')
        L.append(f'Property {pname} As {ptype};')
        L.append('')

    first_scalar = next((p for p in props if p[1].startswith('%String') and not p[3]), None)
    if first_scalar:
        L.append(f'Index Idx{first_scalar[0]} On {first_scalar[0]};')
        L.append('')

    # ImportFromJSON
    L.append('/// Vytvoří a uloží instanci z JSON řetězce. Vrací %Status, do pId ID.')
    L.append('ClassMethod ImportFromJSON(pJSON As %String, Output pId As %String = "") As %Status')
    L.append('{')
    L.append('    Set sc = $$$OK')
    L.append('    Try {')
    L.append('        Set src = ##class(%DynamicObject).%FromJSON(pJSON)')
    L.append('        Set obj = ..%New()')
    for pname, ptype, key, nested in props:
        if nested:
            L.append(f'        Set val = src.%Get("{key}")')
            L.append(f'        If $IsObject(val) {{ Set obj.{pname} = val.%ToJSON() }}')
        else:
            L.append(f'        Set obj.{pname} = src.%Get("{key}")')
    L.append('        $$$ThrowOnError(obj.%Save())')
    L.append('        Set pId = obj.%Id()')
    L.append('    }')
    L.append('    Catch ex {')
    L.append('        Set sc = ex.AsStatus()')
    L.append('    }')
    L.append('    Return sc')
    L.append('}')
    L.append('')

    # ExportToJSON
    L.append('/// Serializuje instanci do JSON řetězce (pJSON). Vrací %Status.')
    L.append('Method ExportToJSON(Output pJSON As %String = "") As %Status')
    L.append('{')
    L.append('    Set sc = $$$OK')
    L.append('    Try {')
    L.append('        Set out = ##class(%DynamicObject).%New()')
    for pname, ptype, key, nested in props:
        if nested:
            L.append(f'        If ..{pname} \'= "" {{ Do out.%Set("{key}", ##class(%DynamicAbstractObject).%FromJSON(..{pname})) }}')
        else:
            L.append(f'        Do out.%Set("{key}", ..{pname})')
    L.append('        Set pJSON = out.%ToJSON()')
    L.append('    }')
    L.append('    Catch ex {')
    L.append('        Set sc = ex.AsStatus()')
    L.append('    }')
    L.append('    Return sc')
    L.append('}')
    L.append('')
    L.append('}')
    return '\n'.join(L)


# ---------------------------------------------------------------------------
# Client class generator
# ---------------------------------------------------------------------------

def gen_client_class(package: str, service_name: str, endpoints: list[dict]) -> str:
    cls = _classify(service_name)
    L = [
        f'/// SEZ API klient pro službu {service_name}.',
        '/// Autentizace: mTLS (SSL/TLS konfigurace) + JWT Bearer assertion (RS256),',
        '/// assertion se posílá přímo jako Authorization: Bearer na bránu.',
        f'/// Generováno {_gen_header()}.',
        f'Class {package}.Client.{cls} Extends %RegisteredObject',
        '{',
        '',
        '/// Hostname brány (bez schématu), např. "api.csez.gov.cz".',
        'Property Server As %String(MAXLEN = 256);',
        '',
        'Property Port As %Integer [ InitialExpression = 443 ];',
        '',
        '/// Název SSL/TLS konfigurace s klientským certifikátem PZS (mTLS).',
        'Property SSLConfig As %String(MAXLEN = 128) [ InitialExpression = "SEZ_PZS" ];',
        '',
        '/// client_id přidělené v EZCA registraci.',
        'Property ClientId As %String(MAXLEN = 256);',
        '',
        '/// kid (UID certifikátu) vkládané do hlavičky JWT.',
        'Property Kid As %String(MAXLEN = 256);',
        '',
        '/// Audience JWT (token endpoint dané gateway).',
        'Property Audience As %String(MAXLEN = 500);',
        '',
        '/// DER kódovaný privátní RSA klíč (naplní LoadPrivateKey).',
        'Property PrivateKey As %String(MAXLEN = "") [ Internal ];',
        '',
        '/// Název volající aplikace pro hlavičku User-Agent (bez mezer a lomítek).',
        'Property AppName As %String(MAXLEN = 64) [ InitialExpression = "sez-api-iris" ];',
        '',
        '/// Verze volající aplikace pro hlavičku User-Agent.',
        'Property AppVersion As %String(MAXLEN = 32) [ InitialExpression = "1.0.0" ];',
        '',
        '/// Výrobce SW pro hlavičku User-Agent (bez závorek a středníků).',
        'Property Vendor As %String(MAXLEN = 128) [ InitialExpression = "Neznamy vyrobce" ];',
        '',
        '/// Prostředí uvedené v User-Agent: "Test" nebo "Prod".',
        'Property Prostredi As %String(VALUELIST = ",Test,Prod") [ InitialExpression = "Test" ];',
        '',
        '/// Hlavička User-Agent dle SEZ API: <aplikace>/<verze> (Test|Prod; výrobceSW).',
        '/// POVINNÁ od 1. 9. 2026 – bez ní brána volání odmítne.',
        'Method UserAgent() As %String',
        '{',
        '    Return ..AppName _ "/" _ ..AppVersion _ " (" _ ..Prostredi _ "; " _ ..Vendor _ ")"',
        '}',
        '',
        '/// Načte privátní klíč z PEM souboru a uloží jako DER do ..PrivateKey.',
        'Method LoadPrivateKey(pPemFile As %String) As %Status',
        '{',
        '    Set sc = $$$OK',
        '    Try {',
        '        Set stream = ##class(%Stream.FileCharacter).%New()',
        '        $$$ThrowOnError(stream.LinkToFile(pPemFile))',
        '        Set b64 = ""',
        "        While 'stream.AtEnd {",
        '            Set line = stream.ReadLine()',
        '            If line [ "-----" { Continue }',
        '            Set b64 = b64 _ $ZStrip(line, "*W")',
        '        }',
        '        Set ..PrivateKey = $System.Encryption.Base64Decode(b64)',
        '    }',
        '    Catch ex {',
        '        Set sc = ex.AsStatus()',
        '    }',
        '    Return sc',
        '}',
        '',
        '/// Base64URL kódování (bez zarovnání a zalomení).',
        'ClassMethod Base64Url(pData As %String) As %String',
        '{',
        '    Set b64 = $System.Encryption.Base64Encode(pData, 1)',
        '    Set b64 = $Translate(b64, $Char(13, 10))',
        '    Set b64 = $Translate(b64, "+/", "-_")',
        '    Set b64 = $Translate(b64, "=")',
        '    Return b64',
        '}',
        '',
        '/// Sestaví a podepíše JWT assertion (RS256) pro autentizaci k bráně.',
        'Method BuildAssertion(Output pAssertion As %String = "") As %Status',
        '{',
        '    Set sc = $$$OK',
        '    Try {',
        '        If ..PrivateKey = "" {',
        '            $$$ThrowOnError($$$ERROR($$$GeneralError, "Privátní klíč není načten (LoadPrivateKey)."))',
        '        }',
        '        Set now = $ZDateTime($ZTimeStamp, -2)',
        '        Set header = ##class(%DynamicObject).%New()',
        '        Do header.%Set("alg", "RS256")',
        '        Do header.%Set("typ", "JWT")',
        '        Do header.%Set("kid", ..Kid)',
        '        Set payload = ##class(%DynamicObject).%New()',
        '        Do payload.%Set("iss", ..ClientId)',
        '        Do payload.%Set("sub", ..ClientId)',
        '        Do payload.%Set("aud", ..Audience)',
        '        Do payload.%Set("jti", $System.Util.CreateGUID())',
        '        Do payload.%Set("iat", now)',
        '        Do payload.%Set("nbf", now - 60)',
        '        Do payload.%Set("exp", now + 300)',
        '        Set signingInput = ..Base64Url(header.%ToJSON()) _ "." _ ..Base64Url(payload.%ToJSON())',
        '        Set signature = $System.Encryption.RSASHASign(256, signingInput, ..PrivateKey)',
        '        Set pAssertion = signingInput _ "." _ ..Base64Url(signature)',
        '    }',
        '    Catch ex {',
        '        Set sc = ex.AsStatus()',
        '    }',
        '    Return sc',
        '}',
        '',
        '/// Obecné REST volání na bránu. Vrací %Status; JSON odpověď do pResponse,',
        '/// HTTP status do pHttpStatus.',
        'Method Call(pMethod As %String, pPath As %String, pBody As %DynamicObject = "", Output pResponse As %DynamicObject = "", Output pHttpStatus As %Integer = 0) As %Status',
        '{',
        '    Set sc = $$$OK',
        '    Try {',
        '        Set assertion = ""',
        '        $$$ThrowOnError(..BuildAssertion(.assertion))',
        '        Set req = ##class(%Net.HttpRequest).%New()',
        '        Set req.Server = ..Server',
        '        Set req.Port = ..Port',
        '        Set req.Https = 1',
        '        Set req.SSLConfiguration = ..SSLConfig',
        '        Set req.ContentType = "application/json"',
        '        Set req.Authorization = "Bearer "_assertion',
        '        Do req.SetHeader("Accept", "application/json")',
        '        Do req.SetHeader("Accept-Language", "cs")',
        '        Do req.SetHeader("User-Agent", ..UserAgent())',
        '        Do req.SetHeader("X-Correlation-Id", $System.Util.CreateGUID())',
        '        If $IsObject(pBody) {',
        '            Do req.EntityBody.Write(pBody.%ToJSON())',
        '        }',
        '        If pMethod = "GET" {',
        '            $$$ThrowOnError(req.Get(pPath))',
        '        } ElseIf pMethod = "POST" {',
        '            $$$ThrowOnError(req.Post(pPath))',
        '        } ElseIf pMethod = "PUT" {',
        '            $$$ThrowOnError(req.Put(pPath))',
        '        } ElseIf pMethod = "DELETE" {',
        '            $$$ThrowOnError(req.Delete(pPath))',
        '        } Else {',
        '            $$$ThrowOnError($$$ERROR($$$GeneralError, "Nepodporovaná metoda: "_pMethod))',
        '        }',
        '        Set resp = req.HttpResponse',
        '        Set pHttpStatus = resp.StatusCode',
        '        If $IsObject(resp.Data) {',
        '            Set pResponse = ##class(%DynamicObject).%FromJSON(resp.Data)',
        '        }',
        "        If (resp.StatusCode '= 200) && (resp.StatusCode '= 201) {",
        '            Set sc = $$$ERROR($$$GeneralError, "Brána vrátila HTTP "_resp.StatusCode)',
        '        }',
        '    }',
        '    Catch ex {',
        '        Set sc = ex.AsStatus()',
        '    }',
        '    Return sc',
        '}',
        '',
    ]

    for ep in endpoints:
        m = ep.get("method", "GET")
        path = ep.get("path", "/")
        name = ep.get("name", _classify(path.split("/")[-1]))
        desc = ep.get("description", f"{m} {path}")
        body_sample = ep.get("body_sample")
        L.append(f'/// {desc}')
        if body_sample and isinstance(body_sample, dict) and m in ("POST", "PUT"):
            params = ", ".join(f'{_param(k)} As {_param_type(v)}' for k, v in body_sample.items())
            sig = (params + ", " if params else "") + 'Output pResponse As %DynamicObject = ""'
            L.append(f'Method {name}({sig}) As %Status')
            L.append('{')
            L.append('    Set body = ##class(%DynamicObject).%New()')
            for k in body_sample:
                L.append(f'    Do body.%Set("{k}", {_param(k)})')
            L.append(f'    Return ..Call("{m}", "{path}", body, .pResponse)')
            L.append('}')
        else:
            L.append(f'Method {name}(Output pResponse As %DynamicObject = "") As %Status')
            L.append('{')
            L.append(f'    Return ..Call("{m}", "{path}", , .pResponse)')
            L.append('}')
        L.append('')

    L.append('}')
    return '\n'.join(L)


def _param_type(v: Any) -> str:
    t = _iris_type(v)
    if t in ("%DynamicObject", "%DynamicArray"):
        return "%String"
    return t


# ---------------------------------------------------------------------------
# SSL Configuration setup
# ---------------------------------------------------------------------------

def gen_ssl_setup() -> str:
    return '''/// Jednorázové nastavení SSL/TLS konfigurace pro mTLS komunikaci se SEZ API.
/// Spusťte jednou (Terminal) – vytvoří konfiguraci "SEZ_PZS".
Class SEZ.Setup Extends %RegisteredObject
{

/// Vytvoří/aktualizuje SSL/TLS konfiguraci s klientským certifikátem PZS.
ClassMethod SetupSSL() As %Status
{
    Set sc = $$$OK
    Try {
        Set name = "SEZ_PZS"
        If ##class(Security.SSLConfigs).Exists(name) {
            Set ssl = ##class(Security.SSLConfigs).%OpenId(name)
        } Else {
            Set ssl = ##class(Security.SSLConfigs).%New()
            Set ssl.Name = name
        }
        Set ssl.Description = "SEZ API Gateway - mTLS klient PZS"
        Set ssl.CertificateFile = "/opt/iris/certs/sez_client.pem"
        Set ssl.PrivateKeyFile = "/opt/iris/certs/sez_client_key.pem"
        Set ssl.CAFile = "/opt/iris/certs/sez_ca_chain.pem"
        Set ssl.VerifyPeer = 1
        $$$ThrowOnError(ssl.%Save())
        Write "SSL/TLS konfigurace '"_name_"' uložena.", !
    }
    Catch ex {
        Set sc = ex.AsStatus()
        Write "Chyba: ", $System.Status.GetErrorText(sc), !
    }
    Return sc
}

}'''


# ---------------------------------------------------------------------------
# CSP REST Dispatch
# ---------------------------------------------------------------------------

def gen_rest_dispatch(package: str, service_name: str, endpoints: list[dict]) -> str:
    cls = _classify(service_name)
    routes = []
    methods = []

    for ep in endpoints:
        m = ep.get("method", "GET")
        path = ep.get("path", "/")
        name = ep.get("name", _classify(path.split("/")[-1]))
        route_path = "/" + name.lower()
        routes.append(f'    <Route Url="{route_path}" Method="{m}" Call="{name}" />')

        methods.append(f'/// {ep.get("description", m + " " + path)}')
        methods.append(f'ClassMethod {name}() As %Status')
        methods.append('{')
        methods.append('    Set sc = $$$OK')
        methods.append('    Try {')
        methods.append(f'        Set client = ##class({package}.Client.{cls}).%New()')
        methods.append('        Set client.Server = "api.csez.gov.cz"')
        methods.append('        // TODO: doplnit client.ClientId/Audience/Kid + LoadPrivateKey z konfigurace')
        methods.append('        Set response = ""')
        if m in ("POST", "PUT"):
            methods.append('        Set body = ##class(%DynamicObject).%FromJSON(%request.Content)')
            methods.append(f'        $$$ThrowOnError(client.{name}(body, .response))')
        else:
            methods.append(f'        $$$ThrowOnError(client.{name}(.response))')
        methods.append('        Set %response.ContentType = "application/json"')
        methods.append('        If $IsObject(response) {')
        methods.append('            Write response.%ToJSON()')
        methods.append('        } Else {')
        methods.append('            Write "{}"')
        methods.append('        }')
        methods.append('    }')
        methods.append('    Catch ex {')
        methods.append('        Set sc = ex.AsStatus()')
        methods.append('        Set %response.Status = "500 Internal Server Error"')
        methods.append('        Set %response.ContentType = "application/json"')
        methods.append('        Set err = ##class(%DynamicObject).%New()')
        methods.append('        Do err.%Set("error", $System.Status.GetErrorText(sc))')
        methods.append('        Write err.%ToJSON()')
        methods.append('    }')
        methods.append('    Return sc')
        methods.append('}')
        methods.append('')

    L = [
        f'/// REST dispatch pro {service_name}. Generováno {_gen_header()}.',
        f'Class {package}.REST.{cls} Extends %CSP.REST',
        '{',
        '',
        'Parameter CHARSET = "utf-8";',
        '',
        'Parameter CONTENTTYPE = "application/json";',
        '',
        'XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]',
        '{',
        '<Routes>',
        *routes,
        '</Routes>',
        '}',
        '',
        *methods,
        '}',
    ]
    return '\n'.join(L)


# ---------------------------------------------------------------------------
# Service metadata + smart generator
# ---------------------------------------------------------------------------

SERVICE_META = {
    "krp": {
        "name": "KRP", "description": "Kmenový registr pacientů",
        "base_path": "/krp/api/v2",
        "endpoints": [
            {"method": "POST", "path": "/krp/api/v2/pacient/hledat/rid",
             "name": "HledatRid", "description": "Vyhledání pacienta dle RID",
             "body_sample": {"rid": "1234567890"}},
            {"method": "POST", "path": "/krp/api/v2/pacient/hledat/jmeno_prijmeni_rc",
             "name": "HledatJmenoRc", "description": "Vyhledání dle jména/příjmení/RČ",
             "body_sample": {"jmeno": "Jan", "prijmeni": "Novák", "rodneCislo": "8001011234"}},
        ],
    },
    "notifikace": {
        "name": "Notifikace", "description": "Systém notifikací",
        "base_path": "/notifikace/api/v1",
        "endpoints": [
            {"method": "GET", "path": "/notifikace/api/v1/kanaly/katalog",
             "name": "KatalogKanalu", "description": "Katalog notifikačních kanálů"},
        ],
    },
    "ezadanky": {
        "name": "EZadanky", "description": "eŽádanky",
        "base_path": "/ezadanky/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/ezadanky/api/v1/ezadanka/vyhledat",
             "name": "Vyhledat", "description": "Vyhledání eŽádanek",
             "body_sample": {"ridPacienta": "1234567890"}},
        ],
    },
    "ezca2": {
        "name": "EZCA2", "description": "Služby vytvářející důvěru (EZCA 2)",
        "base_path": "/ezca2",
        "endpoints": [
            {"method": "GET", "path": "/ezca2/simple-health",
             "name": "HealthCheck", "description": "Kontrola dostupnosti EZCA2"},
        ],
    },
    "du": {
        "name": "DU", "description": "Dočasné úložiště",
        "base_path": "/docasneUloziste/api/v1",
        "endpoints": [
            {"method": "GET", "path": "/docasneUloziste/api/v1/dokumenty/stahnout",
             "name": "StahnoutDokument", "description": "Stažení dokumentu"},
        ],
    },
    "szz": {
        "name": "SZZ", "description": "Systém pro sdílený zdravotní záznam",
        "base_path": "/szz/api/v1",
        "endpoints": [
            {"method": "POST", "path": "/szz/api/v1/dokument/vyhledat",
             "name": "VyhledatDokument", "description": "Vyhledání v SZZ",
             "body_sample": {"rid": "1234567890"}},
        ],
    },
    "elp": {
        "name": "ELP", "description": "Elektronické lékařské posudky",
        "base_path": "/elp/api/v2",
        "endpoints": [
            {"method": "POST", "path": "/elp/api/v2/posudek/vyhledat",
             "name": "VyhledatPosudek", "description": "Vyhledání posudku",
             "body_sample": {"rid": "1234567890"}},
        ],
    },
    "krzp": {
        "name": "KRZP", "description": "Kmenový registr zdravotnických pracovníků",
        "base_path": "/krzp/api/v2",
        "endpoints": [
            {"method": "POST", "path": "/krzp/api/v2/pracovnik/hledat/krzpid",
             "name": "HledatKrzpId", "description": "Vyhledání ZP dle KRZP ID",
             "body_sample": {"krzpId": "191331954"}},
        ],
    },
}


def generate_full(service: str, package: str = "SEZ",
                  response_sample: dict | None = None,
                  request_sample: dict | None = None,
                  endpoint_path: str | None = None,
                  endpoint_method: str | None = None) -> dict:
    """Vygeneruje kompletní IRIS kód pro službu / kontext API volání.

    Vrací dict: persistent_class, client_class, rest_dispatch, ssl_setup,
    usage_example.
    """
    meta = SERVICE_META.get(service, {})
    sname = meta.get("name", _classify(service))
    desc = meta.get("description", service)
    endpoints = list(meta.get("endpoints", []))

    if endpoint_path and endpoint_method:
        if not any(ep.get("path") == endpoint_path for ep in endpoints):
            ep = {"method": endpoint_method, "path": endpoint_path,
                  "name": _classify(endpoint_path.split("/")[-1]) or "Volat",
                  "description": f"{endpoint_method} {endpoint_path}"}
            if request_sample:
                ep["body_sample"] = request_sample
            endpoints.append(ep)

    sample = response_sample or {"id": "example-1", "status": "OK"}
    return {
        "persistent_class": gen_persistent_class(package, sname + "Data", sample, desc),
        "client_class": gen_client_class(package, sname, endpoints),
        "rest_dispatch": gen_rest_dispatch(package, sname, endpoints),
        "ssl_setup": gen_ssl_setup(),
        "usage_example": _gen_usage(package, sname),
    }


def _gen_usage(package: str, sname: str) -> str:
    return f'''/// Příklad použití v IRIS Terminálu
/// =====================================

// 1. Jednorázová konfigurace SSL/TLS (mTLS klient PZS)
Do ##class({package}.Setup).SetupSSL()

// 2. Vytvoření a konfigurace klienta
Set client = ##class({package}.Client.{sname}).%New()
Set client.Server = "api.csez.gov.cz"
Set client.ClientId = "00064203_NIS2"
Set client.Audience = "https://jsuint-auth-ez.csez.cz/connect/token"
Set client.Kid = "<uid-certifikatu>"
Set sc = client.LoadPrivateKey("/opt/iris/certs/sez_client_key.pem")
If $$$ISERR(sc) {{ Write $System.Status.GetErrorText(sc), ! Quit }}

// 3. Volání API – assertion se podepíše a pošle automaticky
Set response = ""
Set sc = client.HledatRid("7306214864", .response)
If $$$ISERR(sc) {{ Write $System.Status.GetErrorText(sc), ! Quit }}
Write response.%ToJSON(), !

// 4. REST dispatch (Management Portal → Web Applications):
//    Dispatch class: {package}.REST.{sname}
'''
