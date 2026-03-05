"""
SEZ API Python klient
Autentizace dle https://mzcr.atlassian.net/wiki/spaces/EPZS/pages/160530443

Flow:
  1. Aplikace vytvoří JWT assertion podepsanou privátním klíčem certifikátu EZCA II
  2. JWT assertion se pošle PŘÍMO na API Gateway v hlavičce Authorization: Bearer <assertion>
  3. API Gateway si sama vyřídí access token z JSU
  4. mTLS: MUSÍ být použit STEJNÝ certifikát krajska_zdravotni.pfx (EZCA II)
     pro mTLS i podepisování JWT assertion. Jiný certifikát (pytloun apod.)
     vede k 401 na DÚ a dalších službách.
"""

import json
import time
import uuid
import logging
import tempfile
import os
import base64

import jwt
import requests
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.extensions import SubjectKeyIdentifier

logger = logging.getLogger("sez_api")


_PROD_GATEWAY_DEFAULT = "https://api.csez.gov.cz"
_PROD_JSU_DEFAULT = "https://jsuint-auth-ez.csez.cz/connect/token"

SEZ_ENVIRONMENTS = {
    "T2": {
        "name": "Test T2",
        "gateway": "https://gwy-ext-sec-t2.csez.cz",
        "jsu_audience": "https://jsuint-auth-t2.csez.cz/connect/token",
    },
    "T1": {
        "name": "Test T1",
        "gateway": "https://gwy-ext-sec-t1.csez.cz",
        "jsu_audience": "https://jsuint-auth-t1.csez.cz/connect/token",
    },
    "PROD": {
        "name": "Produkce",
        "gateway": _PROD_GATEWAY_DEFAULT,
        "jsu_audience": _PROD_JSU_DEFAULT,
    },
}


def _apply_prod_overrides():
    """Allow overriding PROD gateway/JSU URLs from env vars."""
    try:
        from sez_api import config as _cfg
        gw = getattr(_cfg, "PROD_GATEWAY", "") or ""
        jsu = getattr(_cfg, "PROD_JSU_AUDIENCE", "") or ""
        if gw:
            SEZ_ENVIRONMENTS["PROD"]["gateway"] = gw
        if jsu:
            SEZ_ENVIRONMENTS["PROD"]["jsu_audience"] = jsu
    except Exception:
        pass

_apply_prod_overrides()


def check_gateway_dns(env_key: str) -> dict:
    """Quick DNS check for a gateway hostname. Returns {ok, host, ip|error}."""
    import socket
    from urllib.parse import urlparse
    env = SEZ_ENVIRONMENTS.get(env_key)
    if not env:
        return {"ok": False, "host": "?", "error": "Neznámé prostředí"}
    host = urlparse(env["gateway"]).hostname
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        return {"ok": True, "host": host, "ip": ip}
    except socket.gaierror as e:
        return {"ok": False, "host": host, "error": f"DNS nelze resolvovat: {e}"}


class SEZConfig:
    GATEWAY = "https://gwy-ext-sec-t2.csez.cz"
    TOKEN_AUDIENCE = "https://jsuint-auth-t2.csez.cz/connect/token"
    ASSERTION_VALIDITY_SECONDS = 300
    ASSERTION_NBF_SKEW_SECONDS = 60
    ENVIRONMENT = "T2"

    @classmethod
    def switch_environment(cls, env_key: str) -> bool:
        env = SEZ_ENVIRONMENTS.get(env_key)
        if not env:
            return False
        cls.GATEWAY = env["gateway"]
        cls.TOKEN_AUDIENCE = env["jsu_audience"]
        cls.ENVIRONMENT = env_key
        logger.info("Prostředí přepnuto na %s (%s)", env_key, env["gateway"])
        return True

    @classmethod
    def detect_environment(cls) -> str:
        for key, env in SEZ_ENVIRONMENTS.items():
            if cls.GATEWAY == env["gateway"]:
                return key
        return "CUSTOM"


class SEZAuth:
    """
    Autentizace pro SEZ API Gateway.
    Dle oficiální testovací aplikace MZČR se JEDEN certifikát EZCA II
    používá pro obojí: mTLS i podepisování JWT assertion.
    """

    def __init__(self, client_id: str,
                 p12_path: str, p12_password: str,
                 cert_uid: str = None,
                 config: SEZConfig = None,
                 # zpětná kompatibilita
                 signing_p12_path: str = None, signing_p12_password: str = None,
                 tls_p12_path: str = None, tls_p12_password: str = None):
        self.client_id = client_id
        self.config = config or SEZConfig()

        actual_path = signing_p12_path or p12_path
        actual_pwd = signing_p12_password or p12_password

        self._signing_key, self._signing_cert, self._signing_ca = self._load_p12(
            actual_path, actual_pwd
        )
        self._kid = cert_uid or self._get_kid(self._signing_cert)

        if tls_p12_path and tls_p12_path != actual_path:
            self._tls_key, self._tls_cert, self._tls_ca = self._load_p12(
                tls_p12_path, tls_p12_password
            )
        else:
            self._tls_key = self._signing_key
            self._tls_cert = self._signing_cert
            self._tls_ca = self._signing_ca

        self._tmp_dir = tempfile.mkdtemp(prefix="sez_")
        self._tls_cert_path, self._tls_key_path = self._write_pem(
            self._tls_cert, self._tls_key, self._tls_ca, "tls"
        )

    @staticmethod
    def _load_p12(path, password):
        pwd = password.encode() if isinstance(password, str) else password
        with open(path, "rb") as f:
            data = f.read()
        try:
            return pkcs12.load_key_and_certificates(data, pwd)
        except ValueError:
            decoded = base64.b64decode(data)
            return pkcs12.load_key_and_certificates(decoded, pwd)

    @staticmethod
    def _get_kid(cert) -> str:
        """Fallback: SubjectKeyIdentifier. Preferujte explicitní uid z EZCA."""
        try:
            ski = cert.extensions.get_extension_for_class(SubjectKeyIdentifier)
            return ski.value.digest.hex()
        except Exception:
            return cert.fingerprint(SHA256()).hex()

    def get_alt_kids(self) -> list[tuple[str, dict]]:
        """All plausible JWT header combos derived from the certificate."""
        cert = self._signing_cert
        alts = []

        alts.append(("ezca_uid", {"kid": self._kid}))

        try:
            ski = cert.extensions.get_extension_for_class(SubjectKeyIdentifier)
            ski_hex = ski.value.digest.hex()
            ski_b64 = base64.urlsafe_b64encode(ski.value.digest).decode().rstrip("=")
            if ski_hex != self._kid:
                alts.append(("ski_hex", {"kid": ski_hex}))
            alts.append(("ski_b64", {"kid": ski_b64}))
        except Exception:
            pass

        fp1 = cert.fingerprint(SHA256())
        from cryptography.hazmat.primitives.hashes import SHA1
        fp1_sha1 = cert.fingerprint(SHA1())

        x5t_s256 = base64.urlsafe_b64encode(fp1).decode().rstrip("=")
        x5t = base64.urlsafe_b64encode(fp1_sha1).decode().rstrip("=")

        alts.append(("x5t_sha1", {"kid": self._kid, "x5t": x5t}))
        alts.append(("x5t#S256", {"kid": self._kid, "x5t#S256": x5t_s256}))
        alts.append(("kid_sha1hex", {"kid": fp1_sha1.hex()}))
        alts.append(("kid_sha256hex", {"kid": fp1.hex()}))
        alts.append(("kid_x5t_combo", {"kid": x5t, "x5t": x5t}))

        return alts

    def _write_pem(self, cert, key, ca_certs, prefix):
        cert_path = os.path.join(self._tmp_dir, f"{prefix}_cert.pem")
        key_path = os.path.join(self._tmp_dir, f"{prefix}_key.pem")

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
            if ca_certs:
                for ca in ca_certs:
                    f.write(ca.public_bytes(Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

        return cert_path, key_path

    @property
    def tls_cert(self):
        return (self._tls_cert_path, self._tls_key_path)

    def build_assertion(self, extra_headers: dict = None) -> str:
        now = int(time.time())
        payload = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.config.TOKEN_AUDIENCE,
            "jti": str(uuid.uuid4()),
            "nbf": now - self.config.ASSERTION_NBF_SKEW_SECONDS,
            "iat": now,
            "exp": now + self.config.ASSERTION_VALIDITY_SECONDS,
        }
        headers = {"kid": self._kid}
        if extra_headers:
            headers.update(extra_headers)
        token = jwt.encode(payload, self._signing_key, algorithm="RS256", headers=headers)
        logger.debug("JWT assertion: headers=%s iss=%s jti=%s", headers, self.client_id, payload["jti"])
        return token

    def cleanup(self):
        import shutil
        if hasattr(self, "_tmp_dir") and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def __del__(self):
        self.cleanup()


class SEZClient:
    """HTTP klient pro SEZ API Gateway s robustním retry."""

    MAX_RETRIES = 3
    RETRY_CODES = {401, 403, 500, 502, 503, 504}
    RETRY_BACKOFF = [0.5, 1.5, 3.0]
    TOKEN_ERROR_CODES = {"E01060", "E01061", "E01062", "E01050"}

    def __init__(self, auth: SEZAuth):
        self.auth = auth
        self.config = auth.config
        self.session = self._new_session()
        self.last_status = 0
        self.last_response = None
        self.last_request_debug = None

    def _new_session(self):
        s = requests.Session()
        s.cert = self.auth.tls_cert
        s.verify = True
        return s

    def _reset_session(self):
        """Drop pooled connections and create a fresh TLS session."""
        try:
            self.session.close()
        except Exception:
            pass
        self.session = self._new_session()
        logger.info("TLS session reset")

    def _exchange_with_jsu(self, extra_jwt_headers: dict = None,
                           scope: str = None) -> dict:
        """Direct OAuth2 client_credentials grant against JSU token endpoint.

        Returns the parsed JSON from JSU (contains access_token on success,
        or error/error_description on failure).
        """
        assertion = self.auth.build_assertion(extra_headers=extra_jwt_headers)
        data = {
            "grant_type": "client_credentials",
            "client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }
        if scope:
            data["scope"] = scope
        try:
            resp = self.session.post(
                self.config.TOKEN_AUDIENCE,
                data=data,
                timeout=30,
            )
            try:
                result = resp.json()
            except Exception:
                result = {"raw": resp.text[:500]}
            result["_http_status"] = resp.status_code
            return result
        except Exception as e:
            return {"error": str(e), "_http_status": 0}

    def _has_token_error(self, resp) -> str | None:
        """Check response body for JSU/auth error codes that warrant a retry."""
        try:
            body = resp.json()
        except Exception:
            return None
        if not isinstance(body, dict):
            return None
        errors = body.get("Errors") or body.get("errors") or []
        if not isinstance(errors, list):
            return None
        for err in errors:
            if not isinstance(err, dict):
                continue
            code = err.get("Error") or err.get("error") or ""
            if code in self.TOKEN_ERROR_CODES:
                return code
        return None

    @staticmethod
    def _decode_jwt_debug(auth_header: str) -> dict:
        """Decode JWT assertion from Authorization header for debug display."""
        try:
            token = auth_header.replace("Bearer ", "", 1) if auth_header.startswith("Bearer ") else auth_header
            claims = jwt.decode(token, options={"verify_signature": False})
            from datetime import datetime, timezone
            fmt = "%H:%M:%S"
            return {
                "jti": claims.get("jti", "?"),
                "iat": datetime.fromtimestamp(claims["iat"], tz=timezone.utc).strftime(fmt) if "iat" in claims else "?",
                "exp": datetime.fromtimestamp(claims["exp"], tz=timezone.utc).strftime(fmt) if "exp" in claims else "?",
                "iss": claims.get("iss", "?"),
                "kid": jwt.get_unverified_header(token).get("kid", "?"),
            }
        except Exception:
            return {}

    def _headers(self, extra: dict = None) -> dict:
        h = {
            "Authorization": f"Bearer {self.auth.build_assertion()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "cs",
            "X-Correlation-Id": str(uuid.uuid4()),
            "X-Trace-Id": str(uuid.uuid4()),
        }
        if extra:
            h.update(extra)
        return h

    def _request(self, method: str, path: str, retry: bool = True, **kwargs) -> requests.Response:
        url = self.config.GATEWAY + path
        kwargs.setdefault("timeout", 30)

        extra_headers = kwargs.pop("extra_headers", None)
        max_attempts = (self.MAX_RETRIES + 1) if retry else 1

        self.last_request_debug = {
            "method": method,
            "url": url,
            "path": path,
            "body": kwargs.get("json"),
        }

        last_exc = None
        attempts_log = []
        for attempt in range(max_attempts):
            hdrs = self._headers(extra_headers)
            kwargs["headers"] = hdrs
            safe_hdrs = {
                k: (v[:40] + "..." if k == "Authorization" and len(v) > 40 else v)
                for k, v in hdrs.items()
            }
            jwt_debug = self._decode_jwt_debug(hdrs.get("Authorization", ""))
            try:
                resp = self.session.request(method, url, **kwargs)
                self.last_status = resp.status_code

                is_last = attempt == max_attempts - 1

                token_err = self._has_token_error(resp)

                attempt_info = {
                    "attempt": attempt + 1,
                    "status": resp.status_code,
                    "headers": safe_hdrs,
                }
                if jwt_debug:
                    attempt_info["jwt"] = jwt_debug
                if token_err:
                    attempt_info["token_error"] = token_err
                if resp.status_code >= 400:
                    try:
                        attempt_info["response"] = resp.json()
                    except Exception:
                        attempt_info["response"] = resp.text[:500]
                attempts_log.append(attempt_info)

                if token_err and not is_last:
                    delay = self.RETRY_BACKOFF[min(attempt, len(self.RETRY_BACKOFF) - 1)]
                    logger.warning(
                        "%s (HTTP %d) %s (pokus %d/%d) – reset session, čekám %.1fs",
                        token_err, resp.status_code, path,
                        attempt + 1, max_attempts, delay
                    )
                    self._reset_session()
                    time.sleep(delay)
                    continue

                if resp.status_code < 400 or is_last:
                    break

                if resp.status_code not in self.RETRY_CODES:
                    break

                delay = self.RETRY_BACKOFF[min(attempt, len(self.RETRY_BACKOFF) - 1)]
                logger.warning(
                    "HTTP %d %s (pokus %d/%d) – čekám %.1fs a opakuji",
                    resp.status_code, path, attempt + 1, max_attempts, delay
                )

                if resp.status_code in (401, 403):
                    self._reset_session()

                time.sleep(delay)

            except (requests.ConnectionError, requests.Timeout) as e:
                last_exc = e
                attempts_log.append({
                    "attempt": attempt + 1,
                    "error": f"{type(e).__name__}: {e}",
                    "headers": safe_hdrs,
                })
                if attempt == max_attempts - 1:
                    self.last_request_debug["headers"] = safe_hdrs
                    self.last_request_debug["attempts"] = attempts_log
                    raise
                delay = self.RETRY_BACKOFF[min(attempt, len(self.RETRY_BACKOFF) - 1)]
                logger.warning(
                    "Chyba spojení %s (pokus %d/%d) – reset session, čekám %.1fs",
                    type(e).__name__, attempt + 1, max_attempts, delay
                )
                self._reset_session()
                time.sleep(delay)

        self.last_request_debug["headers"] = safe_hdrs
        self.last_request_debug["attempts"] = attempts_log

        try:
            self.last_response = resp.json()
        except Exception:
            self.last_response = resp.text

        if resp.status_code >= 400:
            logger.error("HTTP %d %s: %s", resp.status_code, path, resp.text[:500])

        return resp

    def get(self, path, params=None):
        return self._request("GET", path, params=params)

    def post(self, path, body=None):
        return self._request("POST", path, json=body)

    def patch(self, path, body=None, params=None, **kwargs):
        return self._request("PATCH", path, json=body, params=params, **kwargs)

    def put(self, path, body=None, **kwargs):
        return self._request("PUT", path, json=body, **kwargs)

    def delete(self, path, body=None):
        return self._request("DELETE", path, json=body)


# ---------------------------------------------------------------------------
# API moduly
# ---------------------------------------------------------------------------

class KRP:
    BASE = "/krp"

    def __init__(self, client: SEZClient):
        self.c = client

    def _envelope(self, ucel, data):
        from datetime import date
        return {
            "zadostInfo": {
                "datum": date.today().isoformat(),
                "ucel": ucel,
                "zadostId": str(uuid.uuid4()),
            },
            "zadostData": data,
        }

    @staticmethod
    def _now():
        from datetime import date
        return date.today().isoformat()

    def hledat_rid(self, rid, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/rid", self._envelope(ucel, {"rid": rid}))

    def hledat_jmeno_rc(self, jmeno, prijmeni, rc, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/jmeno_prijmeni_rc",
                           self._envelope(ucel, {"jmeno": jmeno, "prijmeni": prijmeni, "rodneCislo": rc}))

    def generovat_docasny_rid(self, pocet: int = 1, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/generovat/docasny_rid",
                           self._envelope(ucel, {"pocet": pocet}))

    def priradit_docasny_rid(self, docasny_rid: str, rid: str, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/priradit/docasny_rid",
                           self._envelope(ucel, {"docasnyRID": docasny_rid, "rid": rid}))

    def mapovani_rid(self, rid: str, jen_aktualni: bool = False, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/mapovani_rid",
                           self._envelope(ucel, {"rid": rid, "jenAktualni": jen_aktualni}))

    def hledat_jmeno_dn(self, jmeno, prijmeni, datum_narozeni, statni_obcanstvi=None, ucel="LECBA"):
        data = {"jmeno": jmeno, "prijmeni": prijmeni, "datumNarozeni": datum_narozeni}
        if statni_obcanstvi:
            data["statniObcanstvi"] = statni_obcanstvi
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/jmeno_prijmeni_datum_narozeni",
                           self._envelope(ucel, data))

    def hledat_jmeno_cp(self, jmeno, prijmeni, cislo_pojistence, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/jmeno_prijmeni_cp",
                           self._envelope(ucel, {"jmeno": jmeno, "prijmeni": prijmeni, "cisloPojistence": cislo_pojistence}))

    def hledat_cizinec_cp(self, cislo_pojistence, statni_obcanstvi=None, ucel="LECBA"):
        data = {"cisloPojistence": cislo_pojistence}
        if statni_obcanstvi:
            data["statniObcanstvi"] = statni_obcanstvi
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/cizinec_cp",
                           self._envelope(ucel, data))

    def hledat_doklady(self, cislo, typ_dokladu, stat=None, ucel="LECBA"):
        data = {"cislo": cislo, "typDokladu": typ_dokladu}
        if stat:
            data["stat"] = stat
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/doklady",
                           self._envelope(ucel, data))

    def hledat_aifoulozenka(self, aifo=None, ulozka_id=None, ulozka_ref=None, ucel="LECBA"):
        data = {}
        if aifo: data["aifo"] = aifo
        if ulozka_id: data["ulozkaId"] = ulozka_id
        if ulozka_ref is not None: data["ulozkaRef"] = ulozka_ref
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/aifoulozenka",
                           self._envelope(ucel, data))

    def hledat_niabsi(self, niabsi, ucel="LECBA"):
        body = {"niabsi": niabsi, "zadostInfo": {"datum": self._now(), "ucel": ucel}}
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/niabsi", body)

    def hledat_uni(self, ucel="LECBA", **kwargs):
        data = {k: v for k, v in kwargs.items() if v is not None}
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/uni",
                           self._envelope(ucel, data))

    def historie_pojisteni(self, rid, datum=None, ucel="LECBA"):
        data = {"rid": rid}
        if datum: data["datum"] = datum
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/historie_pojisteni",
                           self._envelope(ucel, data))

    def historie_registrujicich_lekaru(self, rid, datum=None, ucel="LECBA"):
        data = {"rid": rid}
        if datum: data["datum"] = datum
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/historie_registrujicich_lekaru",
                           self._envelope(ucel, data))

    def zalozit_pacienta(self, pacient_data, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/zalozit/pacient",
                           self._envelope(ucel, pacient_data))

    def zmenit_pacienta(self, pacient_data, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/zmenit/pacient",
                           self._envelope(ucel, pacient_data))

    def reklamuj_udaj(self, reklamace_data, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/reklamuj/udaj",
                           self._envelope(ucel, reklamace_data))

    def slouceni_zadost(self, rid_cilovy, rid_slucovany, ucel="LECBA"):
        data = {"ridCilovehoSlucujicihoPacienta": rid_cilovy,
                "ridSlucovanehoPacienta": rid_slucovany}
        return self.c.post(f"{self.BASE}/api/v2/pacient/slouceni/zadost",
                           self._envelope(ucel, data))

    def rozdeleni_zadost(self, rid, novy_pacient1, novy_pacient2, ucel="LECBA"):
        data = {"rid": rid, "novyPacient1": novy_pacient1, "novyPacient2": novy_pacient2}
        return self.c.post(f"{self.BASE}/api/v2/pacient/rozdeleni/zadost",
                           {"data": data, "zadostInfo": {"datum": self._now(), "ucel": ucel}})

    def zruseni_zadost(self, rid, ulozka_id=None, ulozka_ref=None, ucel="LECBA"):
        data = {"rid": rid}
        if ulozka_id: data["ulozkaId"] = ulozka_id
        if ulozka_ref is not None: data["ulozkaRef"] = ulozka_ref
        return self.c.post(f"{self.BASE}/api/v2/pacient/zruseni/zadost",
                           self._envelope(ucel, data))

    def ztotozneni_zadost(self, file_bytes: bytes, filename: str = "ztotozneni.csv",
                          ucel="LECBA", registrovat_odber: bool = False):
        """Submit a batch identification request via multipart/form-data file upload."""
        url = self.c.config.GATEWAY + f"{self.BASE}/api/v2/pacient/ztotoznihromadne/zadost"
        assertion = self.c.auth.build_assertion()
        headers = {
            "Authorization": f"Bearer {assertion}",
            "Accept": "application/json",
            "Accept-Language": "cs",
            "X-Correlation-Id": str(uuid.uuid4()),
            "X-Trace-Id": str(uuid.uuid4()),
        }
        form_data = {
            "ZadostInfo.Datum": self._now(),
            "ZadostInfo.Ucel": ucel,
            "ZadostInfo.ZadostId": str(uuid.uuid4()),
            "ZadostData.RegistrovatOdber": str(registrovat_odber).lower(),
        }
        files = {"file": (filename, file_bytes, "text/csv")}
        resp = self.c.session.post(url, headers=headers, data=form_data,
                                   files=files, timeout=60)
        self.c.last_status = resp.status_code
        try:
            self.c.last_response = resp.json()
        except Exception:
            self.c.last_response = resp.text
        return resp

    def ztotozneni_vykonani(self, id_zadosti, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/ztotoznihromadne/vykonani",
                           self._envelope(ucel, {"idZadosti": id_zadosti}))

    def ztotozneni_vysledky(self, id_zadosti, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/ztotoznihromadne/vysledky",
                           self._envelope(ucel, {"idZadosti": id_zadosti}))

    def ztotozneni_vysledky_soubor(self, id_zadosti, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/ztotoznihromadne/vysledky/soubor",
                           self._envelope(ucel, {"idZadosti": id_zadosti}))

    @staticmethod
    def csv_sablona() -> str:
        """Return a CSV template for batch identification."""
        return (
            "jmeno;prijmeni;rodneCislo;datumNarozeni;cisloDokladu;typDokladu;datumUmrti\r\n"
            "Jan;Novák;8501011234;1985-01-01;;;\r\n"
            "Marie;Svobodová;;1990-05-15;AB123456;OP;\r\n"
        )

    @staticmethod
    def csv_to_records(csv_text: str) -> list[dict]:
        """Parse a CSV (semicolon-separated) into patient records."""
        import csv, io
        reader = csv.DictReader(io.StringIO(csv_text), delimiter=";")
        records = []
        for row in reader:
            rec = {}
            for k, v in row.items():
                key = k.strip()
                val = (v or "").strip()
                if val:
                    rec[key] = val
            if rec:
                records.append(rec)
        return records

    @staticmethod
    def records_to_csv(records: list[dict]) -> str:
        """Convert result records to CSV for download."""
        import csv, io
        if not records:
            return ""
        fields = ["jmeno", "prijmeni", "rodneCislo", "datumNarozeni",
                   "rid", "substavZtotozneni", "subskripceID",
                   "cisloDokladu", "typDokladu", "datumUmrti"]
        out = io.StringIO()
        w = csv.DictWriter(out, fieldnames=fields, delimiter=";",
                           extrasaction="ignore", lineterminator="\r\n")
        w.writeheader()
        for r in records:
            flat = dict(r)
            doklady = r.get("doklady")
            if isinstance(doklady, list) and doklady:
                flat["cisloDokladu"] = doklady[0].get("cislo", "")
                flat["typDokladu"] = doklady[0].get("typDokladu", "")
            w.writerow(flat)
        return out.getvalue()

    def notifikace_vyhledat(self, kanal_typ, subjekt_id=None, ucel="LECBA"):
        data = {"kanalTyp": kanal_typ}
        if subjekt_id: data["subjektId"] = subjekt_id
        return self.c.post(f"{self.BASE}/api/v2/notifikace/vyhledat/odber",
                           self._envelope(ucel, data))

    def notifikace_zalozit(self, nastaveni, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zalozit/odber",
                           self._envelope(ucel, nastaveni))

    def notifikace_zrusit(self, id_subskripce=None, subjekt_id=None, ucel="LECBA"):
        data = {}
        if id_subskripce: data["idSubskripce"] = id_subskripce
        if subjekt_id: data["subjektId"] = subjekt_id
        return self.c.delete(f"{self.BASE}/api/v2/notifikace/zrusit/odber",
                             self._envelope(ucel, data))


class DocasneUloziste:
    BASE = "/docasneUloziste"

    def __init__(self, client: SEZClient):
        self.c = client
        self._working_kid = None
        self.last_request_debug = None

    RETRY_BACKOFF = [1.0, 2.0, 4.0]

    def _du_request(self, method, path, **kwargs):
        """DÚ request with retry + session-reset for transient token errors,
        then kid-variant fallback, then direct JSU exchange."""
        url = self.c.config.GATEWAY + path
        body = kwargs.pop("body", None)
        timeout = kwargs.pop("timeout", 30)

        self.last_request_debug = {
            "method": method,
            "url": url,
            "path": path,
            "body": body,
        }

        alt_kids = self.c.auth.get_alt_kids()
        if self._working_kid and not self._working_kid.startswith("jsu_"):
            for i, (name, _) in enumerate(alt_kids):
                if name == self._working_kid:
                    alt_kids.insert(0, alt_kids.pop(i))
                    break

        last_resp = None
        tried_variants = []
        last_headers = None
        last_kid_name = None

        primary_kid, primary_jwt_hdrs = alt_kids[0]
        primary_retries = len(self.RETRY_BACKOFF)
        for attempt in range(primary_retries + 1):
            assertion = self.c.auth.build_assertion(extra_headers=primary_jwt_hdrs)
            headers = self._build_headers(assertion)
            last_headers = headers
            last_kid_name = primary_kid

            resp, err = self._try_request(method, url, headers, body, timeout)
            if err:
                tried_variants.append({
                    "kid": f"{primary_kid} (pokus {attempt + 1})",
                    "error": str(err),
                })
                self.c._reset_session()
                continue

            self.c.last_status = resp.status_code
            token_err = self.c._has_token_error(resp)

            if not token_err and resp.status_code < 400:
                return self._du_success(resp, primary_kid, headers,
                                        tried_variants)

            err_detail = token_err or f"HTTP {resp.status_code}"
            err_body = self._safe_body(resp)
            tried_variants.append({
                "kid": f"{primary_kid} (pokus {attempt + 1})",
                "status": resp.status_code,
                "error": err_detail,
                "response": err_body,
            })
            last_resp = resp

            if token_err and attempt < primary_retries:
                delay = self.RETRY_BACKOFF[attempt]
                logger.warning(
                    "DÚ [%s] %s (HTTP %d) pokus %d/%d – reset, čekám %.1fs",
                    primary_kid, token_err, resp.status_code,
                    attempt + 1, primary_retries + 1, delay,
                )
                self.c._reset_session()
                time.sleep(delay)
                continue
            if not token_err and resp.status_code < 500:
                break

        for kid_name, jwt_headers in alt_kids[1:]:
            assertion = self.c.auth.build_assertion(extra_headers=jwt_headers)
            headers = self._build_headers(assertion)
            last_headers = headers
            last_kid_name = kid_name

            resp, err = self._try_request(method, url, headers, body, timeout)
            if err:
                tried_variants.append({"kid": kid_name, "error": str(err)})
                self.c._reset_session()
                continue

            self.c.last_status = resp.status_code
            token_err = self.c._has_token_error(resp)

            if not token_err and resp.status_code < 400:
                return self._du_success(resp, kid_name, headers,
                                        tried_variants)

            err_detail = token_err or f"HTTP {resp.status_code}"
            tried_variants.append({
                "kid": kid_name, "status": resp.status_code,
                "error": err_detail, "response": self._safe_body(resp),
            })
            last_resp = resp

        self.last_request_debug["tried_variants"] = tried_variants

        all_token = all(
            v.get("error", "") in self.c.TOKEN_ERROR_CODES
            for v in tried_variants if "error" in v
        ) and tried_variants
        if all_token:
            fb = self._jsu_fallback(method, url, body, timeout, tried_variants)
            if fb is not None:
                return fb

        if last_headers:
            self.last_request_debug["kid_variant"] = (
                f"{last_kid_name} (poslední – neúspěšný)")
            self.last_request_debug["headers"] = self._safe_headers(last_headers)

        if last_resp is not None:
            self.c.last_status = last_resp.status_code
            try:
                self.c.last_response = last_resp.json()
            except Exception:
                self.c.last_response = last_resp.text
            if last_resp.status_code >= 400:
                logger.error("DÚ: všechny pokusy selhaly. HTTP %d: %s",
                             last_resp.status_code, last_resp.text[:500])
        return last_resp

    @staticmethod
    def _build_headers(assertion):
        return {
            "Authorization": f"Bearer {assertion}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "cs",
            "X-Correlation-Id": str(uuid.uuid4()),
            "X-Trace-Id": str(uuid.uuid4()),
        }

    @staticmethod
    def _safe_headers(headers):
        return {
            k: (v[:40] + "..." if k == "Authorization" and len(v) > 40 else v)
            for k, v in headers.items()
        }

    @staticmethod
    def _safe_body(resp):
        try:
            return resp.json()
        except Exception:
            return resp.text[:300]

    def _try_request(self, method, url, headers, body, timeout):
        try:
            if method == "GET":
                r = self.c.session.request("GET", url, headers=headers,
                                           timeout=timeout)
            else:
                r = self.c.session.request(method, url, headers=headers,
                                           json=body, timeout=timeout)
            return r, None
        except (requests.ConnectionError, requests.Timeout) as e:
            logger.warning("DÚ spojení selhalo: %s", e)
            return None, e

    def _du_success(self, resp, kid_name, headers, tried_variants):
        if kid_name != (self._working_kid or "ezca_uid"):
            logger.info("DÚ: kid varianta '%s' FUNGUJE", kid_name)
        self._working_kid = kid_name
        self.last_request_debug["kid_variant"] = kid_name
        self.last_request_debug["headers"] = self._safe_headers(headers)
        self.last_request_debug["tried_variants"] = tried_variants
        try:
            self.c.last_response = resp.json()
        except Exception:
            self.c.last_response = resp.text
        return resp

    def _jsu_fallback(self, method, url, body, timeout, tried_variants):
        """Try direct JSU token exchange when Gateway auth fails for DÚ."""
        logger.info("DÚ: všechny kid varianty selhaly s token errorém – "
                     "zkouším přímý JSU token exchange")

        DU_SCOPES = [None, "docasneUloziste", "DU"]
        jsu_log = []

        for scope in DU_SCOPES:
            scope_label = scope or "(bez scope)"
            jsu = self.c._exchange_with_jsu(scope=scope)

            if "access_token" in jsu:
                logger.info("DÚ JSU: scope=%s → access_token získán, zkouším DÚ",
                            scope_label)
                at = jsu["access_token"]
                headers = {
                    "Authorization": f"Bearer {at}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Language": "cs",
                    "X-Correlation-Id": str(uuid.uuid4()),
                    "X-Trace-Id": str(uuid.uuid4()),
                }
                try:
                    if method == "GET":
                        resp = self.c.session.request(
                            "GET", url, headers=headers, timeout=timeout)
                    else:
                        resp = self.c.session.request(
                            method, url, headers=headers, json=body,
                            timeout=timeout)
                except Exception as e:
                    jsu_log.append({
                        "scope": scope_label, "jsu_status": jsu["_http_status"],
                        "access_token": True,
                        "du_error": str(e),
                    })
                    self.c._reset_session()
                    continue

                self.c.last_status = resp.status_code
                if resp.status_code < 400:
                    self._working_kid = f"jsu_direct:{scope_label}"
                    self.last_request_debug["kid_variant"] = (
                        f"JSU direct token (scope={scope_label})")
                    self.last_request_debug["headers"] = {
                        k: (v[:40] + "..." if k == "Authorization" else v)
                        for k, v in headers.items()
                    }
                    self.last_request_debug["jsu_fallback"] = jsu_log
                    self.last_request_debug["tried_variants"] = tried_variants
                    try:
                        self.c.last_response = resp.json()
                    except Exception:
                        self.c.last_response = resp.text
                    logger.info("DÚ JSU fallback FUNGUJE scope=%s HTTP %d",
                                scope_label, resp.status_code)
                    return resp

                try:
                    du_body = resp.json()
                except Exception:
                    du_body = resp.text[:300]
                jsu_log.append({
                    "scope": scope_label, "jsu_status": jsu["_http_status"],
                    "access_token": True,
                    "du_status": resp.status_code, "du_response": du_body,
                })
            else:
                jsu_err = jsu.get("error", "unknown")
                jsu_desc = jsu.get("error_description", "")
                jsu_log.append({
                    "scope": scope_label, "jsu_status": jsu["_http_status"],
                    "access_token": False,
                    "jsu_error": jsu_err, "jsu_description": jsu_desc,
                })
                logger.warning("DÚ JSU: scope=%s → %s: %s",
                               scope_label, jsu_err, jsu_desc)

        self.last_request_debug["jsu_fallback"] = jsu_log
        self.last_request_debug["tried_variants"] = tried_variants
        logger.error("DÚ: JSU fallback nepomohl: %s", jsu_log)
        return None

    def dej_zasilku(self, zasilka_id):
        return self._du_request("GET", f"{self.BASE}/api/v1/Zasilka/DejZasilku/{zasilka_id}")

    def vyhledej_zasilku(self, datum_od, datum_do, pacient=None, page=1, size=25):
        body = {"datumOd": datum_od, "datumDo": datum_do, "strankovani": {"page": page, "size": size}}
        if pacient:
            body["pacient"] = pacient
        return self._du_request("POST", f"{self.BASE}/api/v1/Zasilka/VyhledejZasilku", body=body)

    def uloz_zasilku(self, zasilka):
        return self._du_request("POST", f"{self.BASE}/api/v1/Zasilka/UlozZasilku", body=zasilka)

    def zmen_zasilku(self, zasilka_id, zasilka):
        return self._du_request("PUT", f"{self.BASE}/api/v1/Zasilka/ZmenZasilku/{zasilka_id}", body=zasilka)

    def zneplatni_zasilku(self, zasilka_id, verze_radku):
        body = {"id": zasilka_id, "verzeRadku": verze_radku}
        return self._du_request("PUT", f"{self.BASE}/api/v1/Zasilka/ZneplatniZasilku", body=body)


class KRZP:
    """Kmenový registr zdravotnických pracovníků – PZS API v2."""
    BASE = "/krzp"

    def __init__(self, client: SEZClient):
        self.c = client

    def _envelope(self, ucel, data, key="zadostData"):
        from datetime import date
        return {
            key: data,
            "zadostInfo": {
                "datum": date.today().isoformat(),
                "ucel": ucel,
                "zadostId": str(uuid.uuid4()),
            },
        }

    @staticmethod
    def _now():
        from datetime import date
        return date.today().isoformat()

    def hledat_krzpid(self, krzpid: str):
        return self.c.post(
            f"{self.BASE}/api/v2/pracovnik/hledat/krzpid",
            self._envelope("LECBA", {"krzpid": krzpid}),
        )

    def hledat_jmeno(self, jmeno: str, prijmeni: str, datum_narozeni: str):
        return self.c.post(
            f"{self.BASE}/api/v2/pracovnik/hledat/jmenoPrijmeniDatumNarozeni",
            self._envelope("LECBA", {"jmeno": jmeno, "prijmeni": prijmeni, "datumNarozeni": datum_narozeni}, key="data"),
        )

    def hledat_zamestnavatel(self, ico: str, vcetne_neplatnych: bool = False):
        return self.c.post(
            f"{self.BASE}/api/v2/pracovnik/hledat/zamestnavatel",
            self._envelope("LECBA", {"ico": ico, "vcetneNeplatnych": vcetne_neplatnych}, key="data"),
        )

    def hledat_personalistika(self, datum_narozeni: str, jmeno: str = None,
                               prijmeni: str = None, krzpid: str = None):
        data = {"datumNarozeni": datum_narozeni}
        if jmeno:
            data["jmeno"] = jmeno
        if prijmeni:
            data["prijmeni"] = prijmeni
        if krzpid:
            data["krzpid"] = krzpid
        return self.c.post(
            f"{self.BASE}/api/v2/pracovnik/hledat/personalistika",
            self._envelope("LECBA", data, key="data"),
        )

    def reklamuj_udaj(self, reklamace_data, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/pracovnik/reklamuj/udaj",
                           self._envelope(ucel, reklamace_data))

    def ciselnik(self, nazev_ciselniku, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/ciselnik/{nazev_ciselniku}",
                           {"zadostInfo": {"datum": self._now(), "ucel": ucel}})

    def notifikace_stav(self, kanal_typ, subjekt_id=None, ucel="OVERENI"):
        data = {"kanalTyp": kanal_typ}
        if subjekt_id: data["subjektId"] = subjekt_id
        return self.c.post(f"{self.BASE}/api/v2/notifikace/stav",
                           self._envelope(ucel, data))

    def notifikace_zalozit(self, nastaveni, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zalozit",
                           self._envelope(ucel, nastaveni))

    def notifikace_zrusit(self, data, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zrusit",
                           self._envelope(ucel, data))


class RegistrOpravneni:
    """Registr oprávnění – ověřování přístupových oprávnění zdravotníků."""
    BASE = "/registrOpravneni"

    ROLE_TYPES = [
        "Interni", "Pacient", "PoskytovatelZdravotnickychSluzeb",
        "ZdravotnickyPracovnik", "PravnickaOsoba", "Zastupce", "FyzickaOsoba",
    ]

    def __init__(self, client: SEZClient):
        self.c = client

    def over(self, id_sluzby: int, id_typu_dokumentace: int,
             opravnujici_role: str, opravnujici_hodnota: str,
             opravnena_role: str, opravnena_hodnota: str):
        params = {
            "IdSluzbyEZ": id_sluzby,
            "IdTypuDokumentace": id_typu_dokumentace,
            "OpravnujiciOsoba.Role": opravnujici_role,
            "OpravnujiciOsoba.Hodnota": opravnujici_hodnota,
            "OpravnenaOsoba.Role": opravnena_role,
            "OpravnenaOsoba.Hodnota": opravnena_hodnota,
        }
        return self.c.get(f"{self.BASE}/api/v1/Opravneni/Over", params=params)

    def over_zdravotnika(self, ico: str, krzpid: str,
                         id_sluzby: int = 1, id_typu_dokumentace: int = 5):
        return self.over(
            id_sluzby=id_sluzby,
            id_typu_dokumentace=id_typu_dokumentace,
            opravnujici_role="PoskytovatelZdravotnickychSluzeb",
            opravnujici_hodnota=ico,
            opravnena_role="ZdravotnickyPracovnik",
            opravnena_hodnota=krzpid,
        )

    def over_zastupce(self, pacient_rid: str, zastupce_hodnota: str,
                      zastupce_role: str = "Zastupce",
                      id_sluzby: int = 1, id_typu_dokumentace: int = 5):
        return self.over(
            id_sluzby=id_sluzby,
            id_typu_dokumentace=id_typu_dokumentace,
            opravnujici_role="Pacient",
            opravnujici_hodnota=pacient_rid,
            opravnena_role=zastupce_role,
            opravnena_hodnota=zastupce_hodnota,
        )


class SZZ:
    BASE = "/sdilenyZdravotniZaznam"

    def __init__(self, client: SEZClient):
        self.c = client

    def emergentni_zaznam(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/{rid}")

    def emergentni_zaznam_pdf(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/{rid}/pdf")

    def alergie(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/alergie/{rid}")

    def vytvor_alergii(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/alergie", body)

    def krevni_skupina(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina/{rid}")

    def vytvor_krevni_skupinu(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina", body)

    def nezadouci_prihody(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody/{rid}")

    def vytvor_nezadouci_prihodu(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody", body)

    def nezadouci_reakce(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce/{rid}")

    def vytvor_nezadouci_reakci(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce", body)

    def nezadouci_ucinky(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky/{rid}")

    def vytvor_nezadouci_ucinek(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky", body)

    def nezadouci_udalosti(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti/{rid}")

    def vytvor_nezadouci_udalost(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti", body)

    def lecive_pripravky(self, rid):
        return self.c.get(f"{self.BASE}/api/v1/lecivePripravky/{rid}")

    def vytvor_lecivy_pripravek(self, body):
        return self.c.post(f"{self.BASE}/api/v1/lecivePripravky", body)

    def zdravotni_zaznamy(self, body):
        return self.c.post(f"{self.BASE}/api/v1/zdravotniZaznamy", body)

    def zdravotni_zaznamy_vyhledat(self, body):
        return self.c.post(f"{self.BASE}/api/v1/zdravotniZaznamy/vyhledat", body)

    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v1/ciselniky")

    # --- Lifecycle: Update (PUT) ---

    def update_alergii(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/alergie/{id}", body, **kw)

    def update_krevni_skupinu(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina/{id}", body, **kw)

    def update_nezadouci_prihodu(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody/{id}", body, **kw)

    def update_nezadouci_reakci(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce/{id}", body, **kw)

    def update_nezadouci_ucinek(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky/{id}", body, **kw)

    def update_nezadouci_udalost(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti/{id}", body, **kw)

    def update_lecivy_pripravek(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/lecivePripravky/{id}", body, **kw)

    def update_zdravotni_zaznam(self, id, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/zdravotniZaznamy/{id}", body, **kw)

    # --- Lifecycle: Generic action (zneplatnit/obnovit/zpochybnit) ---

    def _lifecycle_action(self, entity_path, id, action, body, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.patch(f"{self.BASE}/api/v1/{entity_path}/{id}/{action}", body, **kw)

    def zneplatnit(self, entity_type, id, duvod, krzp_id, ico, etag=None):
        body = {"duvod": duvod, "krzpId": krzp_id, "ico": ico}
        return self._lifecycle_action(self._entity_path(entity_type), id, "zneplatnit", body, etag)

    def obnovit(self, entity_type, id, duvod, krzp_id, ico, etag=None):
        body = {"duvod": duvod, "krzpId": krzp_id, "ico": ico}
        return self._lifecycle_action(self._entity_path(entity_type), id, "obnovit", body, etag)

    def zpochybnit(self, entity_type, id, duvod, krzp_id, ico, etag=None):
        body = {"duvod": duvod, "krzpId": krzp_id, "ico": ico}
        return self._lifecycle_action(self._entity_path(entity_type), id, "zpochybnit", body, etag)

    @staticmethod
    def _entity_path(entity_type):
        paths = {
            "alergie": "emergentniZaznam/alergie",
            "krevniSkupina": "emergentniZaznam/krevniSkupina",
            "nezadouciPrihody": "emergentniZaznam/nezadouciPrihody",
            "nezadouciReakce": "emergentniZaznam/nezadouciReakce",
            "nezadouciUcinky": "emergentniZaznam/nezadouciUcinky",
            "nezadouciUdalosti": "emergentniZaznam/nezadouciUdalosti",
            "lecivePripravky": "lecivePripravky",
            "zdravotniZaznamy": "zdravotniZaznamy",
        }
        return paths.get(entity_type, entity_type)

    # --- Ciselniky reindex ---

    def ciselniky_reindex(self):
        return self.c.post(f"{self.BASE}/api/v1/ciselniky/reindex", {})


class ELP:
    BASE = "/elektronickePosudky"

    def __init__(self, client: SEZClient):
        self.c = client

    def vytvor_posudek(self, posudek):
        return self.c.post(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni", posudek)

    def vyhledej_posudky(self, body):
        return self.c.post(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/vyhledat", body)

    def detail_posudku(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}")

    def list_posudky(self, **params):
        qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        url = f"{self.BASE}/api/v1/posudky/ridicskeOpravneni"
        if qs: url += f"?{qs}"
        return self.c.get(url)

    def historie(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/historie")

    def pdf(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/pdf")

    def pdftest(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/pdftest")

    def zneplatnit(self, posudek_id, etag=None):
        kw = {}
        if etag: kw["extra_headers"] = {"If-Match": etag}
        return self.c.patch(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/zneplatnit", {}, **kw)


class EZadanky:
    BASE = "/eZadanky"

    def __init__(self, client: SEZClient):
        self.c = client

    def dej_token(self):
        return self.c.get(f"{self.BASE}/api/v1/eZadanka/DejToken")

    def uloz_zadanku(self, zadanka):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/UlozZadanku", zadanka)

    def vyhledej_zadanku(self, body):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/VyhledejZadanku", body)

    def vyhledej_aktivni(self, body):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/VyhledejAktivniZadanku", body)

    def nacti_zadanku(self, zadanka_id):
        return self.c.get(f"{self.BASE}/api/v1/eZadanka/NactiZadanku/{zadanka_id}")

    def dej_vizual(self, zadanka_id):
        return self.c.get(f"{self.BASE}/api/v1/eZadanka/DejVizualZadanky/{zadanka_id}")

    def dej_prilohy(self, zadanka_id):
        return self.c.get(f"{self.BASE}/api/v1/eZadanka/DejPrilohyZadanky/{zadanka_id}")

    def stornuj(self, body):
        return self.c.patch(f"{self.BASE}/api/v1/eZadanka/StornujZadanku", body)

    def prijmi(self, body):
        return self.c.patch(f"{self.BASE}/api/v1/eZadanka/PrijmiZadanku", body)

    def vyrid(self, body):
        return self.c.patch(f"{self.BASE}/api/v1/eZadanka/VyridZadanku", body)

    def uprav(self, body):
        return self.c.patch(f"{self.BASE}/api/v1/eZadanka/UpravZadanku", body)

    def vrat_do_obehu(self, body):
        return self.c.patch(f"{self.BASE}/api/v1/eZadanka/VratZadankuDoObehu", body)

    def neproveditelnost(self, body):
        return self.c.patch(f"{self.BASE}/api/v1/eZadanka/ZaznacNeproveditelnostZadanky", body)

    def sestav_soubor(self, body):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/SestavSouborZadanky", body)

    def diagnose(self) -> dict:
        """Probe each endpoint to determine auth status without side effects."""
        results = []
        dummy_uuid = "00000000-0000-0000-0000-000000000001"
        dummy_verze = "AAAAAAA="

        probes = [
            ("DejVizualZadanky", "GET",
             f"{self.BASE}/api/v1/eZadanka/DejVizualZadanky/{dummy_uuid}", None),
            ("StornujZadanku", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/StornujZadanku",
             {"id": dummy_uuid, "verzeRadku": dummy_verze,
              "duvodStornaZadanky": {"kod": "1", "verze": "1.0.0"}}),
            ("SestavSouborZadanky", "POST",
             f"{self.BASE}/api/v1/eZadanka/SestavSouborZadanky",
             {"autorId": "0", "zadatelId": "0", "pacient": "0",
              "adresatId": "0", "typZadanky": "Z",
              "uhrada": {"coding": [{"system": "x", "code": "x"}]}}),
            ("VyhledejZadanku", "POST",
             f"{self.BASE}/api/v1/eZadanka/VyhledejZadanku",
             {"strankovani": {"page": 1, "size": 1}}),
            ("VyhledejAktivniZadanku", "POST",
             f"{self.BASE}/api/v1/eZadanka/VyhledejAktivniZadanku",
             {"strankovani": {"page": 1, "size": 1}}),
            ("NactiZadanku", "GET",
             f"{self.BASE}/api/v1/eZadanka/NactiZadanku/{dummy_uuid}", None),
            ("DejPrilohyZadanky", "GET",
             f"{self.BASE}/api/v1/eZadanka/DejPrilohyZadanky/{dummy_uuid}", None),
            ("PrijmiZadanku", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/PrijmiZadanku",
             {"id": dummy_uuid, "verzeRadku": dummy_verze}),
            ("VyridZadanku", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/VyridZadanku",
             {"id": dummy_uuid, "verzeRadku": dummy_verze,
              "zpusobVyrizeniZadanky": {"kod": "1", "verze": "1.0.0"}}),
            ("UlozZadanku", "POST",
             f"{self.BASE}/api/v1/eZadanka/UlozZadanku",
             {"zadanka": {
                 "stav": {"kod": "0"}, "urgentnost": {"kod": "routine"},
                 "samoplatce": False, "prilozenVzorek": False,
                 "omezeniMobility": False, "pacientImplantat": False,
                 "icpZadatele": "0", "metodaData": [],
                 "zasilka": {
                     "nazev": "Test", "typ": {"kod": "Z"},
                     "klasifikace": {"kod": "57133-1"},
                     "autor": "0", "zdravotnickyPracovnik": "0",
                     "poskytovatel": "0", "pacient": "0", "ispzs": "0",
                 }
             }}),
        ]

        for label, method, path, body in probes:
            try:
                if method == "GET":
                    r = self.c.get(path)
                elif method == "POST":
                    r = self.c.post(path, body)
                else:
                    r = self.c.patch(path, body)

                code = r.status_code
                try:
                    data = r.json()
                except Exception:
                    data = r.text[:200]

                is_e01001 = "E01001" in str(data)
                auth_ok = not is_e01001

                results.append({
                    "endpoint": label,
                    "method": method,
                    "status": code,
                    "auth_ok": auth_ok,
                    "error": data if code >= 400 else None,
                })
            except Exception as exc:
                results.append({
                    "endpoint": label,
                    "method": method,
                    "status": 0,
                    "auth_ok": False,
                    "error": str(exc)[:200],
                })

        auth_ok = sum(1 for r in results if r["auth_ok"])
        return {
            "summary": f"{auth_ok}/{len(results)} endpointů prošlo autorizací",
            "pzs_context": auth_ok == len(results),
            "results": results,
        }


class Notifikace:
    BASE = "/notifikace"

    def __init__(self, client: SEZClient):
        self.c = client

    def ping(self):
        return self.c.get(f"{self.BASE}/api/v1/notifikace/ping")

    def odeslat(self, notifikace):
        return self.c.post(f"{self.BASE}/api/v1/notifikace/odeslat", notifikace)

    def vyhledat(self, id_prijemce, od_data, page=0, size=25):
        return self.c.get(f"{self.BASE}/api/v1/notifikace/vyhledat",
                          params={"idPrijemce": id_prijemce, "odData": od_data, "page": page, "size": size})

    def katalog_kanalu(self, page=0, size=25):
        return self.c.get(f"{self.BASE}/api/v1/kanaly/katalog", params={"page": page, "size": size})

    def katalog_sablon(self, page=0, size=25):
        return self.c.get(f"{self.BASE}/api/v1/sablony/katalog", params={"page": page, "size": size})

    def katalog_zdroju(self, page=0, size=25):
        return self.c.get(f"{self.BASE}/api/v1/zdroje/katalog", params={"page": page, "size": size})

    def pzs_prijem_vzor(self, body):
        return self.c.post(f"{self.BASE}/api/v1/pzs/prijem/vzor", body)


class EZCA2:
    BASE = "/ezca2"

    def __init__(self, client: SEZClient):
        self.c = client

    def _auth_wrap(self, body):
        """Add authentication: {userLogin: None} to body if not present."""
        if body is None:
            return {"authentication": {"userLogin": None}}
        if not isinstance(body, dict):
            return body
        if "authentication" not in body:
            return {**body, "authentication": {"userLogin": None}}
        return body

    # --- HealthCheck ---
    def simple_health(self):
        return self.c.get(f"{self.BASE}/simple-health")

    def detail_health(self):
        return self.c.get(f"{self.BASE}/detail-health")

    # --- Certificate ---
    def list_certificates(self, body):
        return self.c.post(f"{self.BASE}/api/list/certificates", body)

    # --- Component ---
    def info_component(self, id_):
        return self.c.get(f"{self.BASE}/api/info/component/{id_}")

    def content_component(self, id_):
        return self.c.get(f"{self.BASE}/api/content/component/{id_}")

    # --- Document ---
    def create_document(self, body):
        return self.c.post(f"{self.BASE}/api/create/document", body)

    def info_document(self, id_):
        return self.c.get(f"{self.BASE}/api/info/document/{id_}")

    # --- SignDocument ---
    def sign_document(self, body):
        return self.c.post(f"{self.BASE}/api/sign/document", self._auth_wrap(body))

    # --- SignHash ---
    def sign_hash(self, body):
        return self.c.post(f"{self.BASE}/api/sign/hash", self._auth_wrap(body))

    # --- StampDocument ---
    def stamp_document(self, body):
        return self.c.post(f"{self.BASE}/api/stamp/document", self._auth_wrap(body))

    # --- StampHash ---
    def stamp_hash(self, body):
        return self.c.post(f"{self.BASE}/api/stamp/hash", self._auth_wrap(body))

    # --- ValidateDocument ---
    def validate_document(self, body):
        return self.c.post(f"{self.BASE}/api/validate/document", self._auth_wrap(body))

    # --- XADES ---
    def create_xades(self, body):
        return self.c.post(f"{self.BASE}/api/create/xades", body)

    # --- SpecificReport ---
    def content_report(self, body):
        return self.c.post(f"{self.BASE}/api/content/report", body)

    def external_report(self, body):
        return self.c.post(f"{self.BASE}/api/external/report", body)
