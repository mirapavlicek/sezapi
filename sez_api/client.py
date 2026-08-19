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

# CMS2 = Centrální místo služeb 2 – alternativní cesta pro PZS k SEZ API
# přes neveřejnou síť spravovanou NAKIT (vs. cesta přes Internet).
# Specifika dle Standardu Akreditovaných afinitních domén AAfD v0.9d
# a katalogu služeb CMS v2.9.0 (NAKIT/MV ČR):
#   • Stejné EZCA II certifikáty, stejný JWT assertion, stejný JSU audience
#   • Stejný client_id, stejné API endpointy/služby (musí být dostupné z obou cest)
#   • Hostnames žijí v privátní DNS zóně cms2.cz (resolver 10.254.8.10),
#     publikované službou CMS2-02-1 a NEresolvovatelné z Internetu.
#   • Konkrétní hostnamy MZČR/NAKIT vydává až při CMS2 onboardingu (CMS2-08-*).
# Default placeholder hodnoty – přebijí se env proměnnými
# SEZ_T2_CMS_GATEWAY a SEZ_PROD_CMS_GATEWAY.
_T2_CMS_GATEWAY_DEFAULT = "https://gwy-ext-sec-t2.csez.cz"  # nepředělané – stejné jako Internet (placeholder)
_PROD_CMS_GATEWAY_DEFAULT = "https://api.csez.gov.cz"  # nepředělané – stejné jako Internet (placeholder)

SEZ_ENVIRONMENTS = {
    "T2": {
        "name": "Test T2 (Internet)",
        "gateway": "https://gwy-ext-sec-t2.csez.cz",
        "jsu_audience": "https://jsuint-auth-t2.csez.cz/connect/token",
        "channel": "INTERNET",
        "base_env": "T2",
    },
    "T2_CMS": {
        "name": "Test T2 (CMS2)",
        "gateway": _T2_CMS_GATEWAY_DEFAULT,
        "jsu_audience": "https://jsuint-auth-t2.csez.cz/connect/token",
        "channel": "CMS2",
        "base_env": "T2",
    },
    "PROD": {
        "name": "Produkce (Internet)",
        "gateway": _PROD_GATEWAY_DEFAULT,
        "jsu_audience": _PROD_JSU_DEFAULT,
        "channel": "INTERNET",
        "base_env": "PROD",
    },
    "PROD_CMS": {
        "name": "Produkce (CMS2)",
        "gateway": _PROD_CMS_GATEWAY_DEFAULT,
        "jsu_audience": _PROD_JSU_DEFAULT,
        "channel": "CMS2",
        "base_env": "PROD",
    },
}


def _apply_prod_overrides():
    """Allow overriding PROD/CMS gateway and JSU URLs from env vars."""
    try:
        from sez_api import config as _cfg
        gw = getattr(_cfg, "PROD_GATEWAY", "") or ""
        jsu = getattr(_cfg, "PROD_JSU_AUDIENCE", "") or ""
        if gw:
            SEZ_ENVIRONMENTS["PROD"]["gateway"] = gw
        if jsu:
            SEZ_ENVIRONMENTS["PROD"]["jsu_audience"] = jsu
            SEZ_ENVIRONMENTS["PROD_CMS"]["jsu_audience"] = jsu
        # CMS overrides
        t2_cms = getattr(_cfg, "T2_CMS_GATEWAY", "") or os.environ.get("SEZ_T2_CMS_GATEWAY", "")
        prod_cms = getattr(_cfg, "PROD_CMS_GATEWAY", "") or os.environ.get("SEZ_PROD_CMS_GATEWAY", "")
        if t2_cms:
            SEZ_ENVIRONMENTS["T2_CMS"]["gateway"] = t2_cms
        if prod_cms:
            SEZ_ENVIRONMENTS["PROD_CMS"]["gateway"] = prod_cms
    except Exception:
        pass

_apply_prod_overrides()


def check_gateway_dns(env_key: str, timeout: float = 3.0) -> dict:
    """Quick DNS check for a gateway hostname. Returns {ok, host, ip|error}."""
    import socket
    import concurrent.futures
    from urllib.parse import urlparse
    env = SEZ_ENVIRONMENTS.get(env_key)
    if not env:
        return {"ok": False, "host": "?", "error": "Neznámé prostředí"}
    host = urlparse(env["gateway"]).hostname
    def _resolve():
        return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            ip = pool.submit(_resolve).result(timeout=timeout)
        return {"ok": True, "host": host, "ip": ip}
    except concurrent.futures.TimeoutError:
        return {"ok": False, "host": host, "error": f"DNS timeout ({timeout}s)"}
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
    # Výchozí timeout jednoho HTTP volání. Synchronní rozhraní (interní API
    # se svým vlastním timeoutem) si ho na instanci klienta snižuje.
    DEFAULT_TIMEOUT = 30
    TOKEN_ERROR_CODES = {"E01060", "E01061", "E01062", "E01050"}

    def __init__(self, auth: SEZAuth):
        self.auth = auth
        self.config = auth.config
        self.session = self._new_session()
        self.last_status = 0
        self.last_response = None
        self.last_request_debug = None
        self._deadline = None

    def nastav_deadline(self, sekundy: float = None) -> None:
        """Tvrdý strop pro volání na bránu (sekundy od teď), None = bez stropu.

        Timeout jednoho volání sám nestačí: s opakováním může jedna operace
        trvat několikanásobek (timeout + pauza + timeout). Synchronní volající
        s krátkým timeoutem tak zůstane bez odpovědi. S deadlinem se timeout
        každého pokusu zkrátí na zbývající čas a opakování se nezahájí, pokud
        by strop přeteklo."""
        self._deadline = (time.monotonic() + sekundy) if sekundy else None

    def _zbyva_do_deadline(self):
        """Zbývající čas v sekundách, nebo None při vypnutém deadlinu."""
        if self._deadline is None:
            return None
        return self._deadline - time.monotonic()

    def _muze_opakovat(self, delay: float) -> bool:
        """Vejde se do stropu ještě pauza a další pokus?"""
        zbyva = self._zbyva_do_deadline()
        if zbyva is None:
            return True
        return (zbyva - delay) > 0.3

    @staticmethod
    def user_agent() -> str:
        """User-Agent dle požadavku API endpointy (aktualizace 21. 7. 2026):
        formát ``název-aplikace/verze (prostředí; výrobceSW[; poznámka])``,
        kde prostředí musí být hodnota **Test** nebo **Prod** (nikoli
        T2/PROD). POVINNÉ od 1. 9. 2026 (dřívější znění uvádělo
        1. 1. 2027); RFC 9110 §10.1.5.

        Název aplikace, výrobce i volitelnou poznámku lze přenastavit přes
        SEZ_APP_NAME / SEZ_VENDOR / SEZ_UA_NOTE."""
        try:
            from sez_api import __version__ as _ver
        except Exception:
            _ver = "0"
        try:
            from sez_api import config as _cfg
            nazev = _cfg.SEZ_APP_NAME or "sez-api"
            vyrobce = _cfg.SEZ_VENDOR or "Krajska zdravotni a.s."
            poznamka = _cfg.SEZ_UA_NOTE or ""
        except Exception:
            nazev, vyrobce, poznamka = "sez-api", "Krajska zdravotni a.s.", ""
        env_key = getattr(SEZConfig, "ENVIRONMENT", "T2")
        env = SEZ_ENVIRONMENTS.get(env_key, {})
        prostredi = "Prod" if env.get("base_env") == "PROD" else "Test"
        detail = f"{prostredi}; {vyrobce}" + (f"; {poznamka}" if poznamka else "")
        return f"{nazev}/{_ver} ({detail})"

    @staticmethod
    def traceparent() -> str:
        """W3C Trace Context hlavička ``traceparent`` – volitelná dle API
        endpointy, ale pokud se pošle, MUSÍ odpovídat specifikaci:
        ``00-<32 hex trace-id>-<16 hex span-id>-01`` (nenulové id)."""
        trace_id = uuid.uuid4().hex                    # 32 hex znaků
        span_id = uuid.uuid4().hex[:16]                # 16 hex znaků
        return f"00-{trace_id}-{span_id}-01"

    def _new_session(self):
        s = requests.Session()
        s.cert = self.auth.tls_cert
        s.verify = True
        # Session-level default: pokryje gateway, DÚ, JSU, TermX public
        # i multipart uploady (explicitní hlavičky requestu mají přednost).
        s.headers["User-Agent"] = self.user_agent()
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
        # X-Correlation-Id: doporučené od 1. 9. 2026, POVINNÉ od 1. 1. 2027
        # (UUID v4+, max 128 znaků); User-Agent POVINNÝ už od 1. 9. 2026
        # (viz user_agent()). Zdroj: API endpointy (Manuál EZ pro PZS),
        # aktualizace 21. 7. 2026.
        h = {
            "Authorization": f"Bearer {self.auth.build_assertion()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "cs",
            "User-Agent": self.user_agent(),
            "X-Correlation-Id": str(uuid.uuid4()),
            "X-Trace-Id": str(uuid.uuid4()),
        }
        # traceparent (W3C) je volitelný – posílá se jen při zapnutí
        # SEZ_SEND_TRACEPARENT, aby se nikdy neodeslal neplatný formát.
        try:
            from sez_api import config as _cfg
            if getattr(_cfg, "SEZ_SEND_TRACEPARENT", False):
                h["traceparent"] = self.traceparent()
        except Exception:
            pass
        if extra:
            h.update(extra)
        return h

    def _request(self, method: str, path: str, retry: bool = True, **kwargs) -> requests.Response:
        url = self.config.GATEWAY + path
        kwargs.setdefault("timeout", self.DEFAULT_TIMEOUT)

        extra_headers = kwargs.pop("extra_headers", None)
        max_attempts = (self.MAX_RETRIES + 1) if retry else 1

        self.last_request_debug = {
            "method": method,
            "url": url,
            "path": path,
            "body": kwargs.get("json"),
        }

        # Minimum, se kterým má smysl volání vůbec začínat.
        MIN_TIMEOUT = 0.2
        pozadovany_timeout = kwargs["timeout"]

        attempts_log = []
        for attempt in range(max_attempts):
            zbyva = self._zbyva_do_deadline()
            if zbyva is not None:
                if zbyva <= MIN_TIMEOUT:
                    self.last_request_debug["attempts"] = attempts_log
                    raise requests.Timeout(
                        f"Vypršel časový strop pro volání {path} "
                        f"(zbývalo {max(zbyva, 0):.2f}s).")
                # Timeout pokusu se vejde do zbývajícího času.
                kwargs["timeout"] = max(MIN_TIMEOUT, min(pozadovany_timeout, zbyva - 0.05))

            hdrs = self._headers(extra_headers)
            kwargs["headers"] = hdrs
            safe_hdrs = {
                k: (v[:40] + "..." if k == "Authorization" and len(v) > 40 else v)
                for k, v in hdrs.items()
            }
            jwt_debug = self._decode_jwt_debug(hdrs.get("Authorization", ""))
            attempt_t0 = time.monotonic()
            try:
                resp = self.session.request(method, url, **kwargs)
                attempt_elapsed = round((time.monotonic() - attempt_t0) * 1000)
                self.last_status = resp.status_code

                is_last = attempt == max_attempts - 1

                token_err = self._has_token_error(resp)

                attempt_info = {
                    "attempt": attempt + 1,
                    "status": resp.status_code,
                    "elapsed_ms": attempt_elapsed,
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
                    resp_hdrs = dict(resp.headers)
                    if resp_hdrs:
                        attempt_info["response_headers"] = {
                            k: v for k, v in resp_hdrs.items()
                            if k.lower() not in ("set-cookie",)
                        }
                else:
                    try:
                        resp_body = resp.json()
                        attempt_info["response_preview"] = str(resp_body)[:300]
                    except Exception:
                        pass
                attempts_log.append(attempt_info)

                if token_err and not is_last:
                    delay = self.RETRY_BACKOFF[min(attempt, len(self.RETRY_BACKOFF) - 1)]
                    if not self._muze_opakovat(delay):
                        logger.warning("%s (HTTP %d) %s – opakování by přeteklo "
                                       "časový strop, vracím odpověď",
                                       token_err, resp.status_code, path)
                        break
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
                if not self._muze_opakovat(delay):
                    logger.warning("HTTP %d %s – opakování by přeteklo časový "
                                   "strop, vracím odpověď", resp.status_code, path)
                    break
                logger.warning(
                    "HTTP %d %s (pokus %d/%d) – čekám %.1fs a opakuji",
                    resp.status_code, path, attempt + 1, max_attempts, delay
                )

                if resp.status_code in (401, 403):
                    self._reset_session()

                time.sleep(delay)

            except (requests.ConnectionError, requests.Timeout) as e:
                attempts_log.append({
                    "attempt": attempt + 1,
                    "error": f"{type(e).__name__}: {e}",
                    "headers": safe_hdrs,
                })
                delay = self.RETRY_BACKOFF[min(attempt, len(self.RETRY_BACKOFF) - 1)]
                if attempt == max_attempts - 1 or not self._muze_opakovat(delay):
                    self.last_request_debug["headers"] = safe_hdrs
                    self.last_request_debug["attempts"] = attempts_log
                    raise
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

    def get(self, path, params=None, timeout=None):
        kw = {"params": params}
        if timeout is not None:
            kw["timeout"] = timeout
        return self._request("GET", path, **kw)

    def post(self, path, body=None, timeout=None):
        kw = {"json": body}
        if timeout is not None:
            kw["timeout"] = timeout
        return self._request("POST", path, **kw)

    def patch(self, path, body=None, params=None, **kwargs):
        return self._request("PATCH", path, json=body, params=params, **kwargs)

    def put(self, path, body=None, params=None, **kwargs):
        return self._request("PUT", path, json=body, params=params, **kwargs)

    def delete(self, path, body=None):
        return self._request("DELETE", path, json=body)

    def get_external(self, url: str, timeout: int = 30,
                      params: dict = None, headers: dict = None) -> requests.Response:
        """GET an arbitrary external URL using the same mTLS session (no gateway prefix)."""
        hdrs = {"Accept": "application/json", "Accept-Language": "cs"}
        if headers:
            hdrs.update(headers)
        resp = self.session.get(url, headers=hdrs, params=params,
                                timeout=timeout, verify=True)
        self.last_status = resp.status_code
        try:
            self.last_response = resp.json()
        except Exception:
            self.last_response = resp.text
        return resp

    def request_external(self, method: str, url: str, timeout: int = 30,
                          params: dict = None, headers: dict = None,
                          json_body: dict = None) -> requests.Response:
        """Generic external (non-gateway) mTLS request."""
        hdrs = {"Accept": "application/json", "Accept-Language": "cs"}
        if headers:
            hdrs.update(headers)
        resp = self.session.request(method, url, headers=hdrs, params=params,
                                     json=json_body, timeout=timeout, verify=True)
        self.last_status = resp.status_code
        try:
            self.last_response = resp.json()
        except Exception:
            self.last_response = resp.text
        return resp


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

    KRP_CISELNIKY = ["pohlavi", "stat", "druh_dokladu", "zdravotni_pojistovna", "country_service_context"]

    def ciselnik(self, nazev_ciselniku, ucel="LECBA"):
        """KRP v2.0.2: POST /api/v2/ciselnik/{nazev} – načtení číselníku."""
        return self.c.post(
            f"{self.BASE}/api/v2/ciselnik/{nazev_ciselniku}",
            {"zadostInfo": {"datum": self._now(), "ucel": ucel,
                            "zadostId": str(uuid.uuid4())}},
        )

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
        if aifo:
            data["aifo"] = aifo
        if ulozka_id:
            data["ulozkaId"] = ulozka_id
        if ulozka_ref is not None:
            data["ulozkaRef"] = ulozka_ref
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
        if datum:
            data["datum"] = datum
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/historie_pojisteni",
                           self._envelope(ucel, data))

    def historie_registrujicich_lekaru(self, rid, datum=None, ucel="LECBA"):
        data = {"rid": rid}
        if datum:
            data["datum"] = datum
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
        if ulozka_id:
            data["ulozkaId"] = ulozka_id
        if ulozka_ref is not None:
            data["ulozkaRef"] = ulozka_ref
        return self.c.post(f"{self.BASE}/api/v2/pacient/zruseni/zadost",
                           self._envelope(ucel, data))

    def ztotozneni_zadost(self, file_bytes: bytes, filename: str = "ztotozneni.csv",
                          ucel="LECBA", registrovat_odber: bool = False):
        """Submit a batch identification request via multipart/form-data file upload.

        Brána KRP očekává XML dávku dle ``PZS_Import_pacienti_v1.xsd``
        (kořen ``<Davka>`` s elementy ``<Pacient>``). Vstup může být CSV, JSON
        nebo už hotové XML – formát se detekuje automaticky a převede na XML."""
        if isinstance(file_bytes, (bytes, bytearray)):
            raw = file_bytes.decode("utf-8-sig")
        else:
            raw = str(file_bytes)
        base = (filename or "davka").rsplit(".", 1)[0] or "davka"
        xml_text = self.to_davka_xml(raw)
        out_name = base + ".xml"

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
        files = {"file": (out_name, xml_text.encode("utf-8"), "application/xml")}
        resp = self.c.session.post(url, headers=headers, data=form_data,
                                   files=files, timeout=60)
        self.c.last_status = resp.status_code
        try:
            self.c.last_response = resp.json()
        except Exception:
            self.c.last_response = resp.text
        return resp

    def ztotozneni_vykonani(self, id_zadosti, ucel="LECBA"):
        """POZOR: endpoint /ztotoznihromadne/vykonani NENÍ v dokumentaci API KRP
        pro PZS (wiki uvádí jen HromadneZtotozni + VyhledejVysledekHromadnehoZtotozneni);
        ve swaggeru má odpověď schéma s příponou „Interní". Pro PZS flow není
        potřeba – zpracování dávky spouští KRP automaticky po podání žádosti."""
        return self.c.post(f"{self.BASE}/api/v2/pacient/ztotoznihromadne/vykonani",
                           self._envelope(ucel, {"idZadosti": id_zadosti}))

    def ztotozneni_vysledky(self, id_zadosti, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/ztotoznihromadne/vysledky",
                           self._envelope(ucel, {"idZadosti": id_zadosti}))

    def ztotozneni_vysledky_soubor(self, id_zadosti, ucel="LECBA"):
        """Stažení výsledků jako souboru (base64Data). Nedokumentované chování:
        base64Data je ZIP archiv obsahující KRP_ZTOTOZNENI_<id>.JSON."""
        return self.c.post(f"{self.BASE}/api/v2/pacient/ztotoznihromadne/vysledky/soubor",
                           self._envelope(ucel, {"idZadosti": id_zadosti}))

    def ztotozneni_stav(self, id_zadosti, ucel="LECBA") -> dict:
        """Jeden dotaz na stav asynchronního hromadného ztotožnění.

        Hromadné ztotožnění je dle dokumentace ASYNCHRONNÍ: žádost vrátí jen
        hromadneZtotozneniID a KRP dávku zpracovává na pozadí – nic se
        „nevrací samo", stav je nutné opakovaně zjišťovat přes /vysledky.

        Vrací normalizovaný slovník:
          dokonceno       – hromadneZtotozneniDokonceno (None = neznámo)
          data_v_souboru  – True → výsledky nejsou v JSON, stáhnout přes
                            /vysledky/soubor (base64 ZIP s JSON uvnitř)
          pocet_zaznamu   – počet záznamů v souborHromadnehoZtotozneni
          zaznamy         – samotné záznamy (pokud jsou v odpovědi)
          http_status, raw
        """
        resp = self.ztotozneni_vysledky(id_zadosti, ucel=ucel)
        out = {"dokonceno": None, "data_v_souboru": None, "pocet_zaznamu": 0,
               "zaznamy": [], "http_status": getattr(resp, "status_code", 0),
               "raw": None}
        try:
            data = resp.json()
        except Exception:
            out["raw"] = getattr(resp, "text", "")[:500]
            return out
        out["raw"] = data
        od = data.get("odpovedData") or {}
        if isinstance(od, dict):
            out["dokonceno"] = od.get("hromadneZtotozneniDokonceno")
            out["data_v_souboru"] = od.get("dataVSouboru")
            zaznamy = od.get("souborHromadnehoZtotozneni") or []
            out["zaznamy"] = zaznamy
            out["pocet_zaznamu"] = len(zaznamy)
        return out

    def ztotozneni_cekat_na_vysledky(self, id_zadosti, ucel="LECBA",
                                      max_wait_s: float = 300,
                                      interval_s: float = 10) -> dict:
        """Polluje /vysledky, dokud hromadneZtotozneniDokonceno != True
        (nebo do vypršení max_wait_s). Vrací poslední stav ze
        :meth:`ztotozneni_stav` doplněný o počet pokusů a celkový čas."""
        t0 = time.monotonic()
        pokusy = 0
        while True:
            pokusy += 1
            stav = self.ztotozneni_stav(id_zadosti, ucel=ucel)
            stav["pokusu"] = pokusy
            stav["cekano_s"] = round(time.monotonic() - t0, 1)
            if stav["dokonceno"] is True:
                return stav
            if time.monotonic() - t0 + interval_s > max_wait_s:
                stav["timeout"] = True
                return stav
            time.sleep(interval_s)

    @staticmethod
    def csv_sablona() -> str:
        """CSV šablona pro hromadné ztotožnění.

        ``sourceId`` = vlastní (interní) identifikátor pacienta v systému PZS –
        vrací se zpět ve výsledcích, takže podle něj spárujete RID. Doporučeno
        vždy vyplnit (ÚZIS portál ho vyžaduje). Číslo dokladu musí být numerické.
        """
        return (
            "sourceId;jmeno;prijmeni;rodneCislo;datumNarozeni;cisloDokladu;typDokladu;datumUmrti\r\n"
            "PAC-001;Jan;Novák;8501011234;1985-01-01;;;\r\n"
            "PAC-002;Marie;Svobodová;;1990-05-15;;;\r\n"
        )

    @staticmethod
    def _davka_xml_from_patients(patients: list) -> str:
        """Sestaví XML dávku ``<Davka>`` ze seznamu pacientů s kanonickými klíči:
        ``sourceId, jmeno, prijmeni, rodneCislo, datumNarozeni, datumUmrti,
        zemeNarozeniKod, mistoNarozeniText, doklad{typ,cislo}, adresa{ulice,
        cisloDomovni, cisloOrientacniHodnota, obecNazev, psc}``.

        Pořadí elementů v ``<Pacient>`` je dáno XSD sekvencí a musí být
        dodrženo: Doklad, SourceId, Jmeno, Prijmeni, Adresa, DatumUmrti,
        DatumNarozeni, ZemeNarozeniKod, MistoNarozeniText, RodneCislo."""
        from xml.sax.saxutils import escape

        def s(v):
            return ("" if v is None else str(v)).strip()

        lines = ['<?xml version="1.0" encoding="utf-8"?>',
                 '<Davka xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">']

        def _el(tag, val, indent="    "):
            return f"{indent}<{tag}>{escape(str(val))}</{tag}>"

        for p in patients:
            source_id = s(p.get("sourceId"))
            jmeno = s(p.get("jmeno"))
            prijmeni = s(p.get("prijmeni"))
            rc = s(p.get("rodneCislo"))
            dn = s(p.get("datumNarozeni"))
            du = s(p.get("datumUmrti"))
            zeme = s(p.get("zemeNarozeniKod"))
            misto = s(p.get("mistoNarozeniText"))
            doklad = p.get("doklad") or {}
            d_typ = s(doklad.get("typ"))
            d_cislo = s(doklad.get("cislo"))
            adr = p.get("adresa") or {}
            a_ulice = s(adr.get("ulice"))
            a_cd = s(adr.get("cisloDomovni"))
            a_co = s(adr.get("cisloOrientacniHodnota"))
            a_obec = s(adr.get("obecNazev"))
            a_psc = s(adr.get("psc"))

            if not any([source_id, jmeno, prijmeni, rc, dn, du, zeme, misto,
                        d_typ, d_cislo, a_ulice, a_cd, a_co, a_obec, a_psc]):
                continue

            lines.append("  <Pacient>")
            # Doklad – Cislo je xs:unsignedLong, tedy jen číselné doklady
            if d_typ and d_cislo and d_cislo.isdigit():
                lines.append("    <Doklad>")
                lines.append(_el("Typ", d_typ, "      "))
                lines.append(_el("Cislo", d_cislo, "      "))
                lines.append("    </Doklad>")
            if source_id:
                lines.append(_el("SourceId", source_id))
            if jmeno:
                lines.append(_el("Jmeno", jmeno))
            if prijmeni:
                lines.append(_el("Prijmeni", prijmeni))
            # Adresa – XSD vyžaduje VŠECHNY prvky; vložíme jen je-li kompletní.
            # (Pozn.: oficiální XSD Adresa neobsahuje prvek „Stat".)
            if all([a_ulice, a_cd, a_co, a_obec, a_psc]):
                lines.append("    <Adresa>")
                lines.append(_el("Ulice", a_ulice, "      "))
                lines.append(_el("CisloDomovni", a_cd, "      "))
                lines.append(_el("CisloOrientacniHodnota", a_co, "      "))
                lines.append(_el("ObecNazev", a_obec, "      "))
                lines.append(_el("Psc", a_psc, "      "))
                lines.append("    </Adresa>")
            if du:
                lines.append(_el("DatumUmrti", du))
            if dn:
                lines.append(_el("DatumNarozeni", dn))
            if zeme:
                lines.append(_el("ZemeNarozeniKod", zeme))
            if misto:
                lines.append(_el("MistoNarozeniText", misto))
            if rc:
                lines.append(_el("RodneCislo", rc))
            lines.append("  </Pacient>")

        lines.append("</Davka>")
        return "\r\n".join(lines) + "\r\n"

    @staticmethod
    def csv_to_davka_xml(csv_text: str) -> str:
        """Převede CSV (oddělovač ``;``) na XML dávku ``<Davka>`` dle
        ``PZS_Import_pacienti_v1.xsd``.

        Sloupce (case-insensitive): ``sourceId``, ``jmeno``, ``prijmeni``,
        ``rodneCislo``, ``datumNarozeni`` (YYYY-MM-DD), ``datumUmrti``,
        ``cisloDokladu`` + ``typDokladu``, ``zemeNarozeniKod``,
        ``mistoNarozeniText``, příp. adresa (``ulice``, ``cisloDomovni``,
        ``cisloOrientacniHodnota``, ``obecNazev``, ``psc``)."""
        import csv as _csv
        import io

        reader = _csv.DictReader(io.StringIO(csv_text), delimiter=";")
        patients = []
        for raw_row in reader:
            row = {(k or "").strip().lower(): (v or "").strip()
                   for k, v in raw_row.items() if k is not None}
            if not any(row.values()):
                continue

            def g(*names):
                for n in names:
                    if row.get(n):
                        return row[n]
                return ""

            patients.append({
                "sourceId": g("sourceid", "source_id", "id"),
                "jmeno": g("jmeno"),
                "prijmeni": g("prijmeni"),
                "rodneCislo": g("rodnecislo", "rodne_cislo"),
                "datumNarozeni": g("datumnarozeni", "datum_narozeni"),
                "datumUmrti": g("datumumrti", "datum_umrti"),
                "zemeNarozeniKod": g("zemenarozenikod", "zeme_narozeni_kod"),
                "mistoNarozeniText": g("mistonarozenitext", "misto_narozeni_text"),
                "doklad": {"typ": g("typdokladu", "typ_dokladu"),
                           "cislo": g("cislodokladu", "cislo_dokladu", "cislodoklad")},
                "adresa": {"ulice": g("ulice"), "cisloDomovni": g("cislodomovni"),
                           "cisloOrientacniHodnota": g("cisloorientacnihodnota", "cisloorientacni"),
                           "obecNazev": g("obecnazev", "obec"), "psc": g("psc")},
            })
        return KRP._davka_xml_from_patients(patients)

    @staticmethod
    def json_to_davka_xml(json_data) -> str:
        """Převede JSON na XML dávku ``<Davka>`` dle ``PZS_Import_pacienti_v1.xsd``.

        Akceptuje pole pacientů ``[{...}]`` nebo objekt s klíčem ``polozky`` /
        ``pacienti`` / ``Pacient`` / ``Davka.Pacient``. Klíče jsou
        case-insensitive (``Jmeno``, ``RodneCislo``, vnořený ``Doklad``
        {``CisloDokladu``,``TypDokladu``}, ``Adresa`` …). Pozn.: oficiální XSD
        Adresa neobsahuje „Stat"; adresa se zařadí jen je-li kompletní
        (Ulice, CisloDomovni, CisloOrientacniHodnota, ObecNazev, Psc)."""
        import json as _json

        data = json_data
        if isinstance(data, (str, bytes, bytearray)):
            data = _json.loads(data)

        def _low(d):
            return {(k or "").strip().lower(): v for k, v in d.items()} \
                if isinstance(d, dict) else {}

        # Rozbalení na seznam pacientů
        if isinstance(data, dict):
            picked = None
            for k in ("polozky", "pacienti", "patients", "items", "pacient",
                      "Pacient", "Pacienti"):
                v = data.get(k)
                if isinstance(v, list):
                    picked = v
                    break
            if picked is None:
                dv = data.get("Davka") or data.get("davka")
                if isinstance(dv, dict) and isinstance(dv.get("Pacient"), list):
                    picked = dv["Pacient"]
                elif isinstance(dv, list):
                    picked = dv
            data = picked if picked is not None else [data]
        if not isinstance(data, list):
            data = [data]

        patients = []
        for obj in data:
            if not isinstance(obj, dict):
                continue
            low = _low(obj)

            def gv(*names):
                for n in names:
                    val = low.get(n)
                    if val not in (None, "", [], {}):
                        return val
                return ""

            dl = _low(gv("doklad") if isinstance(gv("doklad"), dict) else {})
            al = _low(gv("adresa") if isinstance(gv("adresa"), dict) else {})

            patients.append({
                "sourceId": gv("sourceid", "source_id", "id"),
                "jmeno": gv("jmeno"),
                "prijmeni": gv("prijmeni"),
                "rodneCislo": gv("rodnecislo", "rodne_cislo"),
                "datumNarozeni": gv("datumnarozeni", "datum_narozeni"),
                "datumUmrti": gv("datumumrti", "datum_umrti"),
                "zemeNarozeniKod": gv("zemenarozenikod", "zeme_narozeni_kod"),
                "mistoNarozeniText": gv("mistonarozenitext", "misto_narozeni_text"),
                "doklad": {
                    "typ": dl.get("typdokladu") or dl.get("typ") or dl.get("typdoklad") or "",
                    "cislo": dl.get("cislodokladu") or dl.get("cislo") or dl.get("cislodoklad") or "",
                },
                "adresa": {
                    "ulice": al.get("ulice") or "",
                    "cisloDomovni": al.get("cislodomovni") or "",
                    "cisloOrientacniHodnota": al.get("cisloorientacnihodnota") or al.get("cisloorientacni") or "",
                    "obecNazev": al.get("obecnazev") or al.get("obec") or "",
                    "psc": al.get("psc") or "",
                },
            })
        return KRP._davka_xml_from_patients(patients)

    @staticmethod
    def to_davka_xml(text) -> str:
        """Detekuje formát vstupu (XML / JSON / CSV) a vrátí XML dávku ``<Davka>``.
        XML projde beze změny, JSON i CSV se převedou dle XSD."""
        raw = text
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8-sig")
        stripped = (raw or "").lstrip()
        if stripped.startswith("<"):
            return raw
        if stripped.startswith("[") or stripped.startswith("{"):
            return KRP.json_to_davka_xml(raw)
        return KRP.csv_to_davka_xml(raw)

    # Oficiální XSD schéma dávky pro hromadné ztotožnění (ÚZIS/NCEZ,
    # Manuál EZ pro PZS → API KRP, příloha PZS_Import_pacienti_v1.xsd).
    IMPORT_XSD = (
        '<?xml version="1.0" encoding="utf-8"?>\r\n'
        '<xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified" '
        'xmlns:xs="http://www.w3.org/2001/XMLSchema">\r\n'
        '  <xs:element name="Davka">\r\n'
        '    <xs:complexType>\r\n'
        '      <xs:sequence>\r\n'
        '        <xs:element maxOccurs="unbounded" name="Pacient">\r\n'
        '          <xs:complexType>\r\n'
        '            <xs:sequence>\r\n'
        '              <xs:element minOccurs="0" name="Doklad">\r\n'
        '                <xs:complexType>\r\n'
        '                  <xs:sequence>\r\n'
        '                    <xs:element name="Typ" type="xs:string" />\r\n'
        '                    <xs:element name="Cislo" type="xs:unsignedLong" />\r\n'
        '                  </xs:sequence>\r\n'
        '                </xs:complexType>\r\n'
        '              </xs:element>\r\n'
        '              <xs:element minOccurs="0" name="SourceId" type="xs:string" />\r\n'
        '              <xs:element minOccurs="0" name="Jmeno" type="xs:string" />\r\n'
        '              <xs:element minOccurs="0" name="Prijmeni" type="xs:string" />\r\n'
        '              <xs:element minOccurs="0" name="Adresa">\r\n'
        '                <xs:complexType>\r\n'
        '                  <xs:sequence>\r\n'
        '                    <xs:element name="Ulice" type="xs:string" />\r\n'
        '                    <xs:element name="CisloDomovni" type="xs:string" />\r\n'
        '                    <xs:element name="CisloOrientacniHodnota" type="xs:string" />\r\n'
        '                    <xs:element name="ObecNazev" type="xs:string" />\r\n'
        '                    <xs:element name="Psc" type="xs:string" />\r\n'
        '                  </xs:sequence>\r\n'
        '                </xs:complexType>\r\n'
        '              </xs:element>\r\n'
        '              <xs:element minOccurs="0" name="DatumUmrti" type="xs:date" />\r\n'
        '              <xs:element minOccurs="0" name="DatumNarozeni" type="xs:date" />\r\n'
        '              <xs:element minOccurs="0" name="ZemeNarozeniKod" type="xs:string" />\r\n'
        '              <xs:element minOccurs="0" name="MistoNarozeniText" type="xs:string" />\r\n'
        '              <xs:element minOccurs="0" name="RodneCislo" type="xs:string" />\r\n'
        '            </xs:sequence>\r\n'
        '          </xs:complexType>\r\n'
        '        </xs:element>\r\n'
        '      </xs:sequence>\r\n'
        '    </xs:complexType>\r\n'
        '  </xs:element>\r\n'
        '</xs:schema>\r\n'
    )

    @staticmethod
    def import_xsd() -> str:
        """Vrátí XSD schéma dávky hromadného ztotožnění (PZS_Import_pacienti_v1.xsd)."""
        return KRP.IMPORT_XSD

    # Kanonický vzorek pacientů (klíče dle XSD PZS_Import_pacienti_v1.xsd).
    # 1. pacient plně vyplněný (Doklad + kompletní Adresa), 2. minimální.
    SABLONA_PACIENTI = [
        {
            "SourceId": "PAC-001",
            "Jmeno": "Mračena",
            "Prijmeni": "Mrakomorová",
            "RodneCislo": "7161264528",
            "DatumNarozeni": "1971-07-26",
            "Doklad": {"TypDokladu": "OP", "CisloDokladu": "222333069"},
            "Adresa": {
                "Ulice": "Sokolská",
                "CisloDomovni": "490",
                "CisloOrientacniHodnota": "31",
                "ObecNazev": "Praha",
                "Psc": "12000",
            },
        },
        {
            "SourceId": "PAC-002",
            "Jmeno": "Jiří",
            "Prijmeni": "Plos",
            "RodneCislo": "520111076",
            "DatumNarozeni": "1952-01-11",
        },
    ]

    @staticmethod
    def json_sablona() -> str:
        """Vzorové JSON pole pacientů (klíče dle XSD), které po převodu plní
        ``PZS_Import_pacienti_v1.xsd`` – vč. kompletní Adresy a Dokladu."""
        import json as _json
        return _json.dumps(KRP.SABLONA_PACIENTI, ensure_ascii=False, indent=2) + "\n"

    @staticmethod
    def xml_sablona() -> str:
        """Vzorová XML dávka ``<Davka>`` (validní proti PZS_Import_pacienti_v1.xsd),
        demonstrující všechny podporované elementy (Doklad, Adresa, SourceId…)."""
        return KRP.json_to_davka_xml(KRP.SABLONA_PACIENTI)

    @staticmethod
    def csv_to_records(csv_text: str) -> list[dict]:
        """Parse a CSV (semicolon-separated) into patient records."""
        import csv
        import io
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
        import csv
        import io
        if not records:
            return ""
        fields = ["sourceId", "jmeno", "prijmeni", "rodneCislo", "datumNarozeni",
                   "rid", "substavZtotozneni", "subskripceID",
                   "cisloDokladu", "typDokladu", "datumUmrti"]
        out = io.StringIO()
        w = csv.DictWriter(out, fieldnames=fields, delimiter=";",
                           extrasaction="ignore", lineterminator="\r\n")
        w.writeheader()
        for r in records:
            flat = dict(r)
            if "sourceId" not in flat:
                for k in ("SourceId", "sourceID", "SourceID", "source_id"):
                    if r.get(k) not in (None, ""):
                        flat["sourceId"] = r[k]
                        break
            doklady = r.get("doklady")
            if isinstance(doklady, list) and doklady:
                flat["cisloDokladu"] = doklady[0].get("cislo", "")
                flat["typDokladu"] = doklady[0].get("typDokladu", "")
            w.writerow(flat)
        return out.getvalue()

    def notifikace_vyhledat(self, kanal_typ, subjekt_id=None, subjekt_typ=None, ucel="LECBA"):
        data = {"kanalTyp": kanal_typ}
        if subjekt_id:
            data["subjektId"] = subjekt_id
        if subjekt_typ:
            data["subjektTyp"] = subjekt_typ
        return self.c.post(f"{self.BASE}/api/v2/notifikace/vyhledat/odber",
                           self._envelope(ucel, data))

    def notifikace_zalozit(self, nastaveni, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zalozit/odber",
                           self._envelope(ucel, nastaveni))

    def notifikace_zrusit(self, id_subskripce=None, subjekt_id=None, ucel="LECBA"):
        data = {}
        if id_subskripce:
            data["idSubskripce"] = id_subskripce
        if subjekt_id:
            data["subjektId"] = subjekt_id
        return self.c.delete(f"{self.BASE}/api/v2/notifikace/zrusit/odber",
                             self._envelope(ucel, data))


class DocasneUloziste:
    BASE = "/docasneUloziste"
    QUICK_TIMEOUT = 8
    QUICK_RETRY_BACKOFF = [0.5]
    QUICK_JSU_SCOPES = [None]

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
        params = kwargs.pop("params", None)
        timeout = kwargs.pop("timeout", 30)
        retry_backoff = kwargs.pop("retry_backoff", self.RETRY_BACKOFF)
        max_alt_kids = kwargs.pop("max_alt_kids", None)
        jsu_scopes = kwargs.pop("jsu_scopes", None)
        debug_url = requests.Request(method, url, params=params).prepare().url if params else url

        self.last_request_debug = {
            "method": method,
            "url": debug_url,
            "path": path,
            "body": body,
            "params": params,
            "timeout": timeout,
        }

        alt_kids = self.c.auth.get_alt_kids()
        if max_alt_kids:
            alt_kids = alt_kids[:max_alt_kids]
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
        primary_retries = len(retry_backoff)
        for attempt in range(primary_retries + 1):
            assertion = self.c.auth.build_assertion(extra_headers=primary_jwt_hdrs)
            headers = self._build_headers(assertion)
            last_headers = headers
            last_kid_name = primary_kid

            resp, err = self._try_request(method, url, headers, body, timeout, params=params)
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
                delay = retry_backoff[attempt]
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

            # params se MUSÍ předat i při kid fallbacku – jinak se ztratí
            # query parametry (např. ZmenZasilku ?Id=&VerzeRadku=) a DÚ
            # vrací E01002 „Parametr 'Identifikace zásilky' musí být zadán".
            resp, err = self._try_request(method, url, headers, body, timeout,
                                           params=params)
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
            fb = self._jsu_fallback(method, url, body, timeout, tried_variants, scopes=jsu_scopes, params=params)
            if fb is not None:
                return fb

        if last_headers:
            self.last_request_debug["kid_variant"] = (
                f"{last_kid_name} (poslední – neúspěšný)")
            self.last_request_debug["headers"] = self._safe_headers(last_headers)

        if last_resp is None:
            errors = [v.get("error") for v in tried_variants if v.get("error")]
            if errors:
                self.last_request_debug["error"] = errors[-1]
            else:
                self.last_request_debug["error"] = "DÚ neodpovědělo v časovém limitu"
            logger.error("DÚ: všechny pokusy selhaly bez HTTP odpovědi: %s",
                         self.last_request_debug["error"])
            return None

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

    def _try_request(self, method, url, headers, body, timeout, params=None):
        try:
            if method == "GET":
                r = self.c.session.request("GET", url, headers=headers,
                                           params=params, timeout=timeout)
            else:
                r = self.c.session.request(method, url, headers=headers,
                                           json=body, params=params, timeout=timeout)
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

    def _jsu_fallback(self, method, url, body, timeout, tried_variants, scopes=None, params=None):
        """Try direct JSU token exchange when Gateway auth fails for DÚ."""
        logger.info("DÚ: všechny kid varianty selhaly s token errorém – "
                     "zkouším přímý JSU token exchange")

        DU_SCOPES = scopes or [None, "docasneUloziste", "DU"]
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
                            "GET", url, headers=headers, params=params, timeout=timeout)
                    else:
                        resp = self.c.session.request(
                            method, url, headers=headers, json=body, params=params,
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
        return self._du_request(
            "GET",
            f"{self.BASE}/api/v1/Zasilka/DejZasilku/{zasilka_id}",
            timeout=self.QUICK_TIMEOUT,
            retry_backoff=self.QUICK_RETRY_BACKOFF,
            max_alt_kids=1,
            jsu_scopes=self.QUICK_JSU_SCOPES,
        )

    def vyhledej_zasilku(self, datum_od, datum_do, pacient=None, page=1, size=25):
        body = {"datumOd": datum_od, "datumDo": datum_do, "strankovani": {"page": page, "size": size}}
        if pacient:
            body["pacient"] = pacient
        return self._du_request(
            "POST",
            f"{self.BASE}/api/v1/Zasilka/VyhledejZasilku",
            body=body,
            timeout=self.QUICK_TIMEOUT,
            retry_backoff=self.QUICK_RETRY_BACKOFF,
            max_alt_kids=1,
            jsu_scopes=self.QUICK_JSU_SCOPES,
        )

    def uloz_zasilku(self, zasilka):
        return self._du_request("POST", f"{self.BASE}/api/v1/Zasilka/UlozZasilku", body=zasilka)

    def zmen_zasilku(self, zasilka_id, verze_radku, zasilka):
        return self._du_request(
            "PUT",
            f"{self.BASE}/api/v1/Zasilka/ZmenZasilku",
            body=zasilka,
            params={"Id": zasilka_id, "VerzeRadku": verze_radku},
        )

    def zneplatni_zasilku(self, zasilka_id, verze_radku):
        return self._du_request(
            "PATCH",
            f"{self.BASE}/api/v1/Zasilka/ZneplatniZasilku",
            params={"Id": zasilka_id, "VerzeRadku": verze_radku},
        )

    def potvrd_vyzvednuti_zasilky(self, zasilka_id, verze_radku):
        return self._du_request(
            "PATCH",
            f"{self.BASE}/api/v1/Zasilka/PotvrdVyzvednutiZasilky",
            params={"Id": zasilka_id, "VerzeRadku": verze_radku},
        )

    def zpochybni_zasilku(self, zasilka_id, verze_radku, duvod=None):
        # ZpochybniZasilku – přidáno v Popisu API DÚ v1.2 (publikováno 5. 6. 2026).
        # Příjemce zpochybní obsah/doručení zásilky; důvod je volitelný (dle kontraktu).
        body = {"duvod": duvod} if duvod else None
        return self._du_request(
            "PATCH",
            f"{self.BASE}/api/v1/Zasilka/ZpochybniZasilku",
            params={"Id": zasilka_id, "VerzeRadku": verze_radku},
            body=body,
        )


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
                           {"zadostInfo": {"datum": self._now(), "ucel": ucel,
                                           "zadostId": str(uuid.uuid4())}})

    def notifikace_stav(self, kanal_typ, subjekt_id=None, subjekt_typ=None, ucel="OVERENI"):
        data = {"kanalTyp": kanal_typ}
        if subjekt_id:
            data["subjektId"] = subjekt_id
        if subjekt_typ:
            data["subjektTyp"] = subjekt_typ
        return self.c.post(f"{self.BASE}/api/v2/notifikace/stav",
                           self._envelope(ucel, data))

    def notifikace_zalozit(self, nastaveni, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zalozit",
                           self._envelope(ucel, nastaveni))

    def notifikace_zrusit(self, data, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zrusit",
                           self._envelope(ucel, data))


class KRPZS:
    """Kmenový registr poskytovatelů zdravotních služeb – PZS API v2."""
    BASE = "/krpzs"

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

    def hledat_ico(self, ico: str, ucel="OVERENI"):
        return self.c.post(
            f"{self.BASE}/api/v2/Poskytovatel/hledat/ico",
            self._envelope(ucel, {"ico": ico}),
        )

    def hledat_nazev(self, nazev: str, ucel="OVERENI"):
        return self.c.post(
            f"{self.BASE}/api/v2/Poskytovatel/hledat/nazev",
            self._envelope(ucel, {"nazev": nazev}),
        )

    def hledat_misto(self, mesto: str = None, ulice: str = None,
                      psc: str = None, kraj: str = None, kraj_kod: str = None,
                      ucel="OVERENI"):
        """Vyhledání poskytovatele podle místa poskytování.

        Dle kontraktu (VyhledaniPZSPodleMistaPoskytovani, v2.0.2+) má
        zadostData JEDINÝ parametr ``krajKod`` (identifikátor kraje jako
        ID nebo NUTS/LAU, např. CZ042) – na T2 v2.0.3 je POVINNÝ (jinak
        HTTP 400 'The krajKod field is required'). Parametry mesto/ulice/
        psc/kraj v kontraktu nejsou (ponechány jen pro zpětnou
        kompatibilitu volajících, služba je ignoruje)."""
        data = {}
        if mesto:
            data["mesto"] = mesto
        if ulice:
            data["ulice"] = ulice
        if psc:
            data["psc"] = psc
        if kraj:
            data["kraj"] = kraj
        if kraj_kod:
            data["krajKod"] = kraj_kod
        return self.c.post(
            f"{self.BASE}/api/v2/Poskytovatel/hledat/misto",
            self._envelope(ucel, data),
        )

    def nastavit_url_pro_notifikace(self, ico: str, url: str, ucel="OVERENI"):
        """v2.0.2: nastavení URL pro notifikace poskytovatele."""
        return self.c.post(
            f"{self.BASE}/api/v2/Poskytovatel/nastavit/urlpronotifikace",
            self._envelope(ucel, {"ico": ico, "url": url}),
        )

    def ciselnik(self, nazev_ciselniku, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/ciselnik/{nazev_ciselniku}",
                           {"zadostInfo": {"datum": self._now(), "ucel": ucel,
                                           "zadostId": str(uuid.uuid4())}})

    def reklamuj_udaj(self, reklamace_data, ucel="OVERENI"):
        return self.c.post(f"{self.BASE}/api/v2/Poskytovatel/reklamuj/udaj",
                           self._envelope(ucel, reklamace_data))

    def notifikace_vyhledat_odber(self, data, ucel="OVERENI"):
        """v2.0.2: vyhledat odběry notifikací KRPZS."""
        return self.c.post(f"{self.BASE}/api/v2/notifikace/vyhledat/odber",
                           self._envelope(ucel, data))

    def notifikace_zalozit_odber(self, data, ucel="OVERENI"):
        """v2.0.2: založit odběr notifikací KRPZS."""
        return self.c.post(f"{self.BASE}/api/v2/notifikace/zalozit/odber",
                           self._envelope(ucel, data))

    def notifikace_zrusit_odber(self, data, ucel="OVERENI"):
        """v2.0.2: zrušit odběr notifikací KRPZS (DELETE)."""
        return self.c.delete(f"{self.BASE}/api/v2/notifikace/zrusit/odber",
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

    def sluzby_ez(self, kod=None, nazev=None, sort="nazev", order="asc", page=0, size=100):
        params = {"Sort": sort, "Order": order, "Page": page, "Size": size}
        if kod:
            params["Kod"] = kod
        if nazev:
            params["Nazev"] = nazev
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/SluzbyEZ", params=params)

    def sluzba_ez_detail(self, item_id: int):
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/SluzbyEZ/{item_id}")

    def typy_dokumentaci(self, kod=None, nazev=None, sort="nazev", order="asc", page=0, size=100):
        params = {"Sort": sort, "Order": order, "Page": page, "Size": size}
        if kod:
            params["Kod"] = kod
        if nazev:
            params["Nazev"] = nazev
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/TypyDokumentaci", params=params)

    def typ_dokumentace_detail(self, item_id: int):
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/TypyDokumentaci/{item_id}")


class SZZ:
    """Sdílený zdravotní záznam – PZS API.

    Od T2 v1.0.9: GET-by-RID nahrazeno POST /vyhledat | /detail | /pdf s tělem.
    Pro zpětnou kompatibilitu s PROD v1.0.6: výchozí metody zkusí nejprve nový POST,
    a při HTTP 404/405 se vrátí ke starému GET volání.
    """
    BASE = "/sdilenyZdravotniZaznam"

    def __init__(self, client: SEZClient):
        self.c = client

    @staticmethod
    def _vyhledat_body(rid, jen_platne=None, sort=None, order=None, page=None, size=None):
        body = {"rid": rid}
        if jen_platne is not None:
            body["jenPlatne"] = jen_platne
        if sort is not None:
            body["sort"] = sort
        if order is not None:
            body["order"] = order
        if page is not None:
            body["page"] = page
        if size is not None:
            body["size"] = size
        return body

    def _try_post_then_get(self, post_path: str, body: dict, get_path: str):
        """v1.0.9 first (POST), fallback to v1.0.6 (GET) on 404/405."""
        r = self.c.post(post_path, body)
        if r.status_code in (404, 405):
            return self.c.get(get_path)
        return r

    def emergentni_zaznam(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/emergentniZaznam/{rid}",
        )

    def emergentni_zaznam_pdf(self, rid):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/pdf",
            {"rid": rid},
            f"{self.BASE}/api/v1/emergentniZaznam/{rid}/pdf",
        )

    def alergie(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/alergie/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/emergentniZaznam/alergie/{rid}",
        )

    def vytvor_alergii(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/alergie", body)

    def krevni_skupina(self, rid):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina/detail",
            {"rid": rid},
            f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina/{rid}",
        )

    def vytvor_krevni_skupinu(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina", body)

    def nezadouci_prihody(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody/{rid}",
        )

    def vytvor_nezadouci_prihodu(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody", body)

    def nezadouci_reakce(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce/{rid}",
        )

    def vytvor_nezadouci_reakci(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce", body)

    def nezadouci_ucinky(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky/{rid}",
        )

    def vytvor_nezadouci_ucinek(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky", body)

    def nezadouci_udalosti(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti/{rid}",
        )

    def vytvor_nezadouci_udalost(self, body):
        return self.c.post(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti", body)

    def lecive_pripravky(self, rid, jen_platne=None, sort=None, order=None):
        return self._try_post_then_get(
            f"{self.BASE}/api/v1/lecivePripravky/vyhledat",
            self._vyhledat_body(rid, jen_platne, sort, order),
            f"{self.BASE}/api/v1/lecivePripravky/{rid}",
        )

    def vytvor_lecivy_pripravek(self, body):
        return self.c.post(f"{self.BASE}/api/v1/lecivePripravky", body)

    def zdravotni_zaznamy(self, body):
        return self.c.post(f"{self.BASE}/api/v1/zdravotniZaznamy", body)

    def zdravotni_zaznamy_vyhledat(self, body):
        return self.c.post(f"{self.BASE}/api/v1/zdravotniZaznamy/vyhledat", body)

    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v1/ciselniky")

    def ciselnik_polozky(self, kod):
        """v1.0.9: položky číselníku."""
        return self.c.get(f"{self.BASE}/api/v1/ciselniky/{kod}/polozky")

    # --- Lifecycle: Update (PUT) ---

    def update_alergii(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/alergie/{id}", body, **kw)

    def update_krevni_skupinu(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/krevniSkupina/{id}", body, **kw)

    def update_nezadouci_prihodu(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciPrihody/{id}", body, **kw)

    def update_nezadouci_reakci(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciReakce/{id}", body, **kw)

    def update_nezadouci_ucinek(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUcinky/{id}", body, **kw)

    def update_nezadouci_udalost(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/emergentniZaznam/nezadouciUdalosti/{id}", body, **kw)

    def update_lecivy_pripravek(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/lecivePripravky/{id}", body, **kw)

    def update_zdravotni_zaznam(self, id, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.put(f"{self.BASE}/api/v1/zdravotniZaznamy/{id}", body, **kw)

    # --- Lifecycle: Generic action (zneplatnit/obnovit/zpochybnit) ---

    def _lifecycle_action(self, entity_path, id, action, body, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
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
    """ELP v1 – zachováno pro zpětnou kompatibilitu."""
    BASE = "/elektronickePosudky"

    def __init__(self, client: SEZClient):
        self.c = client

    # -- Číselníky (swagger v1.0.7) --
    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v1/ciselniky")

    def ciselnik_polozky(self, kod: str):
        return self.c.get(f"{self.BASE}/api/v1/ciselniky/{kod}/polozky")

    def vytvor_posudek(self, posudek):
        return self.c.post(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni", posudek)

    def vyhledej_posudky(self, body):
        return self.c.post(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/vyhledat", body)

    def detail_posudku(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}")

    def list_posudky(self, **params):
        qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        url = f"{self.BASE}/api/v1/posudky/ridicskeOpravneni"
        if qs:
            url += f"?{qs}"
        return self.c.get(url)

    def historie(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/historie")

    def pdf(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/pdf")

    def pdftest(self, posudek_id):
        return self.c.get(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/pdftest")

    def zneplatnit(self, posudek_id, etag=None):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.patch(f"{self.BASE}/api/v1/posudky/ridicskeOpravneni/{posudek_id}/zneplatnit", {}, **kw)


class ELPv2:
    """ELP v2.0 – Elektronické posudky pro řidičská oprávnění (nové rozhraní)."""
    BASE = "/elektronickePosudky"

    def __init__(self, client: SEZClient):
        self.c = client

    # -- Číselníky --
    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v2/ciselniky")

    def ciselnik_polozky(self, kod: str):
        return self.c.get(f"{self.BASE}/api/v2/ciselniky/{kod}/polozky")

    # -- CRUD Posudky ŘO --
    def vytvor(self, body: dict):
        return self.c.post(f"{self.BASE}/api/v2/posudky/ridicskeOpravneni", body)

    def vyhledej(self, body: dict):
        return self.c.post(f"{self.BASE}/api/v2/posudky/ridicskeOpravneni/vyhledat", body)

    def detail(self, posudek_id: str):
        return self.c.get(f"{self.BASE}/api/v2/posudky/ridicskeOpravneni/{posudek_id}")

    def historie(self, posudek_id: str):
        return self.c.get(f"{self.BASE}/api/v2/posudky/ridicskeOpravneni/{posudek_id}/historie")

    def pdf(self, posudek_id: str):
        return self.c.get(f"{self.BASE}/api/v2/posudky/ridicskeOpravneni/{posudek_id}/pdf")

    def zneplatnit(self, posudek_id: str, etag: str = ""):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.patch(
            f"{self.BASE}/api/v2/posudky/ridicskeOpravneni/{posudek_id}/zneplatnit", {}, **kw)

    # -- Oprávnění --
    def over_opravneni(self, body: dict):
        return self.c.post(
            f"{self.BASE}/api/v2/posudky/ridicskeOpravneni/zalozeni/opravneni", body)


class ELPv3:
    """ELP v3.0.1 – Elektronické posudky pro řidičská oprávnění (path /api/v3)."""
    BASE = "/elektronickePosudky"

    def __init__(self, client: SEZClient):
        self.c = client

    # -- Číselníky --
    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v3/ciselniky")

    def ciselnik_polozky(self, kod: str):
        return self.c.get(f"{self.BASE}/api/v3/ciselniky/{kod}/polozky")

    # -- CRUD Posudky ŘO --
    def vytvor(self, body: dict):
        return self.c.post(f"{self.BASE}/api/v3/posudky/ridicskeOpravneni", body)

    def vyhledej(self, body: dict):
        return self.c.post(f"{self.BASE}/api/v3/posudky/ridicskeOpravneni/vyhledat", body)

    def detail(self, posudek_id: str):
        return self.c.get(f"{self.BASE}/api/v3/posudky/ridicskeOpravneni/{posudek_id}")

    def historie(self, posudek_id: str):
        return self.c.get(f"{self.BASE}/api/v3/posudky/ridicskeOpravneni/{posudek_id}/historie")

    def pdf(self, posudek_id: str):
        return self.c.get(f"{self.BASE}/api/v3/posudky/ridicskeOpravneni/{posudek_id}/pdf")

    def zneplatnit(self, posudek_id: str, etag: str = ""):
        kw = {}
        if etag:
            kw["extra_headers"] = {"If-Match": etag}
        return self.c.patch(
            f"{self.BASE}/api/v3/posudky/ridicskeOpravneni/{posudek_id}/zneplatnit", {}, **kw)

    # -- Oprávnění --
    def over_opravneni(self, body: dict):
        return self.c.post(
            f"{self.BASE}/api/v3/posudky/ridicskeOpravneni/zalozeni/opravneni", body)


class EZadanky:
    BASE = "/eZadanky"

    def __init__(self, client: SEZClient):
        self.c = client

    def uloz_zadanku(self, zadanka):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/UlozZadanku", zadanka)

    def vyhledej_zadanku(self, body):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/VyhledejZadanku", body)

    def vyhledej_aktivni(self, body):
        return self.c.post(f"{self.BASE}/api/v1/eZadanka/VyhledejAktivniZadanku", body)

    def nacti_zadanku(self, zadanka_id):
        return self.c.get(f"{self.BASE}/api/v1/eZadanka/NactiZadanku/{zadanka_id}")

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

    def diagnose(self) -> dict:
        """Probe each endpoint to determine auth status without side effects."""
        results = []
        dummy_uuid = "00000000-0000-0000-0000-000000000001"
        dummy_verze = "AAAAAAA="

        probes = [
            ("StornujZadanku", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/StornujZadanku",
             {"id": dummy_uuid, "verzeRadku": dummy_verze,
              "duvodStornaZadanky": {"kod": "1", "verze": "1.0.0"}}),
            ("VyhledejZadanku", "POST",
             f"{self.BASE}/api/v1/eZadanka/VyhledejZadanku",
             {"strankovani": {"page": 1, "size": 1}}),
            ("VyhledejAktivniZadanku", "POST",
             f"{self.BASE}/api/v1/eZadanka/VyhledejAktivniZadanku",
             {"strankovani": {"page": 1, "size": 1}}),
            ("NactiZadanku", "GET",
             f"{self.BASE}/api/v1/eZadanka/NactiZadanku/{dummy_uuid}", None),
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
            ("UpravZadanku", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/UpravZadanku",
             {"id": dummy_uuid, "verzeRadku": dummy_verze,
              "upravenyPacient": "0",
              "upravenaPriorita": {"kod": "routine", "verze": "5.0.2"}}),
            ("VratZadankuDoObehu", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/VratZadankuDoObehu",
             {"id": dummy_uuid, "verzeRadku": dummy_verze,
              "duvodVraceniZadanky": {"kod": "1", "verze": "1.0.0"}}),
            ("ZaznacNeproveditelnostZadanky", "PATCH",
             f"{self.BASE}/api/v1/eZadanka/ZaznacNeproveditelnostZadanky",
             {"id": dummy_uuid, "verzeRadku": dummy_verze,
              "duvodNeproveditelnostiZadanky": {"kod": "1", "verze": "1.0.0"}}),
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


class Terminologie:
    """Terminologický server (TermX) – FHIR R4.

    Swagger (v1.0.5 i v1.1.0): servers ``/terminologie`` – operace jsou
    PŘÍMO pod ním (``/terminologie/ValueSet/$expand``), BEZ mezisegmentu
    ``/fhir``. Starší nasazení TermX na T2 přijímalo i cesty
    ``/terminologie/fhir/...``; po upgrade (v1.1.0) na ně backend vrací
    HTTP 406 „could not find matching enabled interaction". Prefix se
    proto AUTODETEKUJE: primárně ``/terminologie`` dle swaggeru, při
    404/406 fallback na legacy ``/terminologie/fhir`` – funkční varianta
    se zapamatuje pro další volání.

    Režimy:

    * ``public=False`` (default) – přes SEZ API Gateway s mTLS + JWT
      assertion (stejný flow jako ostatní SEZ služby).
    * ``public=True`` – přímý mirror ``https://termx-api-t2-pub.csez.cz/fhir/...``
      (jen mTLS, bez JWT, bez gateway).

    Všechny metody vrací ``requests.Response`` (FHIR JSON v ``application/fhir+json``).
    """

    BASE = "/terminologie"
    # Pořadí pokusů: dle swaggeru (bez /fhir), pak legacy s /fhir.
    GATEWAY_PREFIXES = ("/terminologie", "/terminologie/fhir")
    GATEWAY_PREFIX = "/terminologie"  # zpětná kompatibilita (výchozí prefix)
    PUBLIC_BASE_DEFAULT = "https://termx-api-t2-pub.csez.cz/fhir"

    FHIR_GET_HEADERS = {
        "Accept": "application/fhir+json",
    }
    FHIR_WRITE_HEADERS = {
        "Accept": "application/fhir+json",
        "Content-Type": "application/fhir+json",
    }

    def __init__(self, client: SEZClient, public: bool = False,
                 public_base: str = None):
        self.c = client
        self.public = public
        self.public_base = (public_base or self.PUBLIC_BASE_DEFAULT).rstrip("/")
        # Autodetekovaný funkční gateway prefix (None = zatím neověřeno)
        self._gateway_prefix = None

    @property
    def base_url(self) -> str:
        if self.public:
            return self.public_base
        return f"{self.c.config.GATEWAY}{self._gateway_prefix or self.GATEWAY_PREFIXES[0]}"

    @staticmethod
    def _je_spatny_prefix(resp) -> bool:
        """406/404 s OperationOutcome „could not find matching enabled
        interaction" = špatný base path (změna /fhir mezi verzemi TermX)."""
        if resp is None or resp.status_code not in (404, 406):
            return False
        try:
            text = resp.text or ""
        except Exception:
            return True
        return ("could not find matching enabled interaction" in text
                 or resp.status_code == 404)

    def _clean(self, params):
        if not params:
            return None
        out = {}
        for k, v in params.items():
            if v is None:
                continue
            # FHIR vyžaduje boolean jako lower-case string (true/false), ne True/False
            if isinstance(v, bool):
                out[k] = "true" if v else "false"
            else:
                out[k] = v
        return out or None

    def _request(self, method: str, op_path: str, *,
                  params: dict = None, body: dict = None, timeout: int = 30):
        """Provede FHIR request. ``op_path`` je vždy bez gateway prefixu
        (např. ``/metadata`` či ``/ValueSet/$expand``). Gateway prefix se
        autodetekuje mezi ``/terminologie`` (swagger) a legacy
        ``/terminologie/fhir``."""
        params = self._clean(params)
        write = method.upper() in ("POST", "PUT", "PATCH")
        hdrs = self.FHIR_WRITE_HEADERS if write else self.FHIR_GET_HEADERS

        if self.public:
            url = self.public_base + op_path
            return self.c.request_external(
                method, url, timeout=timeout,
                params=params, headers=hdrs, json_body=body,
            )

        prefixes = ([self._gateway_prefix] if self._gateway_prefix
                     else list(self.GATEWAY_PREFIXES))
        resp = None
        for i, prefix in enumerate(prefixes):
            # 406/404 (špatný prefix) není v RETRY_CODES, fallback je okamžitý;
            # standardní retry na token chyby zůstává zachováno.
            resp = self.c._request(
                method, prefix + op_path,
                params=params, json=body,
                extra_headers=hdrs, timeout=timeout,
            )
            posledni = i == len(prefixes) - 1
            if not posledni and self._je_spatny_prefix(resp):
                logger.info("TermX: prefix %s vrací %s – zkouším %s",
                             prefix, resp.status_code, prefixes[i + 1])
                continue
            if resp.status_code < 400 and self._gateway_prefix is None:
                self._gateway_prefix = prefix
                if prefix != self.GATEWAY_PREFIXES[0]:
                    logger.info("TermX: autodetekován legacy prefix %s", prefix)
            return resp
        return resp

    # ------------------------------------------------------------------
    # Whole System Interactions
    # ------------------------------------------------------------------

    def metadata(self):
        """``GET /metadata`` – CapabilityStatement serveru.

        Pozn.: ve swaggeru v1.1.0 už není uveden (zůstává funkční jako
        standardní FHIR interakce)."""
        return self._request("GET", "/metadata")

    def manifest(self, *, lastUpdate: str = None, effectiveDate: str = None):
        """``GET /manifest`` – manifest obsahu terminologického serveru.

        Přidáno ve swaggeru Terminologie v1.1.0 (apio.csez.gov.cz).
        Volitelné filtry ``lastUpdate`` a ``effectiveDate`` (datum)."""
        return self._request("GET", "/manifest",
                             params={"lastUpdate": lastUpdate,
                                     "effectiveDate": effectiveDate})

    # ------------------------------------------------------------------
    # ValueSet
    # ------------------------------------------------------------------

    def valueset_read(self, id: str):
        return self._request("GET", f"/ValueSet/{id}")

    def valueset_search(self, **params):
        return self._request("GET", "/ValueSet", params=params)

    def valueset_search_post(self, **params):
        return self._request("POST", "/ValueSet/_search", params=params)

    def valueset_create(self, body: dict):
        return self._request("POST", "/ValueSet", body=body)

    def valueset_update(self, id: str, body: dict):
        return self._request("PUT", f"/ValueSet/{id}", body=body)

    def valueset_expand(self, *, url: str = None, id: str = None,
                         valueSetVersion: str = None, **extra):
        params = {"url": url, "valueSetVersion": valueSetVersion, **extra}
        if id:
            return self._request("GET", f"/ValueSet/{id}/$expand", params=params)
        return self._request("GET", "/ValueSet/$expand", params=params)

    def valueset_validate_code(self, *, code: str, url: str = None, id: str = None,
                                 system: str = None, systemVersion: str = None,
                                 display: str = None, **extra):
        params = {"code": code, "url": url, "system": system,
                   "systemVersion": systemVersion, "display": display, **extra}
        if id:
            return self._request("GET", f"/ValueSet/{id}/$validate-code", params=params)
        return self._request("GET", "/ValueSet/$validate-code", params=params)

    def valueset_sync(self, *, resources: str = None, id: str = None):
        params = {"resources": resources}
        if id:
            return self._request("GET", f"/ValueSet/{id}/$sync", params=params)
        return self._request("GET", "/ValueSet/$sync", params=params)

    # ------------------------------------------------------------------
    # CodeSystem
    # ------------------------------------------------------------------

    def codesystem_read(self, id: str):
        return self._request("GET", f"/CodeSystem/{id}")

    def codesystem_search(self, **params):
        return self._request("GET", "/CodeSystem", params=params)

    def codesystem_search_post(self, **params):
        return self._request("POST", "/CodeSystem/_search", params=params)

    def codesystem_create(self, body: dict):
        return self._request("POST", "/CodeSystem", body=body)

    def codesystem_update(self, id: str, body: dict):
        return self._request("PUT", f"/CodeSystem/{id}", body=body)

    def codesystem_lookup(self, *, code: str, system: str = None, id: str = None,
                            version: str = None, property: str = None, **extra):
        params = {"code": code, "system": system, "version": version,
                   "property": property, **extra}
        if id:
            return self._request("GET", f"/CodeSystem/{id}/$lookup", params=params)
        return self._request("GET", "/CodeSystem/$lookup", params=params)

    def codesystem_validate_code(self, *, code: str, url: str = None, id: str = None,
                                   system: str = None, version: str = None,
                                   display: str = None, **extra):
        params = {"code": code, "url": url, "system": system,
                   "version": version, "display": display, **extra}
        if id:
            return self._request("GET", f"/CodeSystem/{id}/$validate-code", params=params)
        return self._request("GET", "/CodeSystem/$validate-code", params=params)

    def codesystem_subsumes(self, *, codeA: str, codeB: str, system: str = None,
                              id: str = None, version: str = None):
        params = {"codeA": codeA, "codeB": codeB, "system": system, "version": version}
        if id:
            return self._request("GET", f"/CodeSystem/{id}/$subsumes", params=params)
        return self._request("GET", "/CodeSystem/$subsumes", params=params)

    def codesystem_find_matches(self, *, system: str = None, id: str = None,
                                  property: str = None, exact: bool = False, **extra):
        params = {"system": system, "property": property,
                   "exact": "true" if exact else "false", **extra}
        if id:
            return self._request("GET", f"/CodeSystem/{id}/$find-matches", params=params)
        return self._request("GET", "/CodeSystem/$find-matches", params=params)

    def codesystem_compare(self, *, id: str = None, body: dict = None, **params):
        if body is not None:
            if id:
                return self._request("POST", f"/CodeSystem/{id}/$compare", body=body)
            return self._request("POST", "/CodeSystem/$compare", body=body)
        if id:
            return self._request("GET", f"/CodeSystem/{id}/$compare", params=params)
        return self._request("GET", "/CodeSystem/$compare", params=params)

    def codesystem_sync(self, *, resources: str = None, id: str = None):
        params = {"resources": resources}
        if id:
            return self._request("GET", f"/CodeSystem/{id}/$sync", params=params)
        return self._request("GET", "/CodeSystem/$sync", params=params)

    # ------------------------------------------------------------------
    # ConceptMap
    # ------------------------------------------------------------------

    def conceptmap_read(self, id: str):
        return self._request("GET", f"/ConceptMap/{id}")

    def conceptmap_search(self, **params):
        return self._request("GET", "/ConceptMap", params=params)

    def conceptmap_search_post(self, **params):
        return self._request("POST", "/ConceptMap/_search", params=params)

    def conceptmap_update(self, id: str, body: dict):
        return self._request("PUT", f"/ConceptMap/{id}", body=body)

    def conceptmap_translate(self, *, code: str = None, sourceCode: str = None,
                               system: str = None, url: str = None, id: str = None,
                               targetCode: str = None, targetSystem: str = None,
                               sourceCoding: str = None,
                               sourceCodeableConcept: str = None,
                               targetCoding: str = None,
                               targetCodeableConcept: str = None,
                               target: str = None, **extra):
        """``GET /ConceptMap[/{id}]/$translate``.

        Dle swaggeru (v1.0.5 i v1.1.0) se zdrojový kód posílá jako
        ``sourceCode`` (ne ``code``) a cílový systém jako ``targetSystem``.
        Aliasy ``code`` → ``sourceCode`` a ``target`` → ``targetSystem``
        jsou zachovány pro zpětnou kompatibilitu volajících.
        """
        params = {"url": url,
                   "sourceCode": sourceCode or code,
                   "system": system,
                   "sourceCoding": sourceCoding,
                   "sourceCodeableConcept": sourceCodeableConcept,
                   "targetCode": targetCode,
                   "targetSystem": targetSystem or target,
                   "targetCoding": targetCoding,
                   "targetCodeableConcept": targetCodeableConcept,
                   **extra}
        if id:
            return self._request("GET", f"/ConceptMap/{id}/$translate", params=params)
        return self._request("GET", "/ConceptMap/$translate", params=params)

    def conceptmap_sync(self, *, resources: str = None, id: str = None):
        params = {"resources": resources}
        if id:
            return self._request("GET", f"/ConceptMap/{id}/$sync", params=params)
        return self._request("GET", "/ConceptMap/$sync", params=params)

    # ------------------------------------------------------------------
    # StructureMap
    # ------------------------------------------------------------------

    def structuremap_read(self, id: str):
        return self._request("GET", f"/StructureMap/{id}")

    def structuremap_search(self, **params):
        return self._request("GET", "/StructureMap", params=params)

    def structuremap_search_post(self, **params):
        return self._request("POST", "/StructureMap/_search", params=params)

    def structuremap_create(self, body: dict):
        return self._request("POST", "/StructureMap", body=body)

    def structuremap_transform(self, *, source: str = None, id: str = None,
                                 body: dict = None):
        params = {"source": source}
        if id:
            return self._request("POST", f"/StructureMap/{id}/$transform",
                                  params=params, body=body)
        return self._request("POST", "/StructureMap/$transform",
                              params=params, body=body)

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------

    def provenance_search(self, **params):
        return self._request("GET", "/Provenance", params=params)

    def provenance_search_post(self, **params):
        return self._request("POST", "/Provenance/_search", params=params)


# Krátký alias, který odpovídá názvu serveru v dokumentaci
TermX = Terminologie


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

    # ========================================================================
    # v1.0.6: Nové endpointy
    # ========================================================================

    # --- Search ---
    def search_hash(self, body):
        """v1.0.6: Vyhledat dokument podle hashe."""
        return self.c.post(f"{self.BASE}/api/search/hash", self._auth_wrap(body))

    def search_metadata(self, body):
        """v1.0.6: Vyhledat dokument podle metadat."""
        return self.c.post(f"{self.BASE}/api/search/metadata", self._auth_wrap(body))

    # --- Certificates (od v1.0.7 přesunuto pod /content a /validate) ---
    def get_certificate(self, id_):
        """v1.0.7: Detail certifikátu (přesunuto z /api/certificates/certificate/{id})."""
        return self.c.get(f"{self.BASE}/api/content/certificate/{id_}")

    def validate_certificate(self, body):
        """v1.0.7: Validace certifikátu (přesunuto z /api/certificates/validatecertificate)."""
        return self.c.post(f"{self.BASE}/api/validate/certificate",
                           self._auth_wrap(body))

    # --- Content / Package ---
    def content_package(self, id_):
        """v1.0.6: Obsah balíčku."""
        return self.c.get(f"{self.BASE}/api/content/package/{id_}")

    # --- v1.0.7: Proxy timestamp (sync + async) ---
    def stamp_proxy_timestamp(self, body):
        """v1.0.7: Vyžádat časové razítko přes externí TSA proxy."""
        return self.c.post(f"{self.BASE}/api/stamp/proxytimestamp", self._auth_wrap(body))

    def stamp_proxy_timestamp_async(self, body):
        """v1.0.7: Async varianta proxy timestamp."""
        return self.c.post(f"{self.BASE}/api/stampasync/proxytimestamp", self._auth_wrap(body))

    # ========================================================================
    # v1.0.6: Async varianty (nereblokující – server vrátí ID úlohy)
    # ========================================================================

    def sign_document_async(self, body):
        return self.c.post(f"{self.BASE}/api/signasync/document", self._auth_wrap(body))

    def sign_hash_async(self, body):
        return self.c.post(f"{self.BASE}/api/signasync/hash", self._auth_wrap(body))

    def stamp_document_async(self, body):
        return self.c.post(f"{self.BASE}/api/stampasync/document", self._auth_wrap(body))

    def stamp_hash_async(self, body):
        return self.c.post(f"{self.BASE}/api/stampasync/hash", self._auth_wrap(body))

    def validate_document_async(self, body):
        return self.c.post(f"{self.BASE}/api/validateasync/document", self._auth_wrap(body))

    def list_certificates_async(self, body):
        return self.c.post(f"{self.BASE}/api/listasync/certificates", body)

    def create_document_async(self, body):
        return self.c.post(f"{self.BASE}/api/createasync/document", body)

    def create_xades_async(self, body):
        return self.c.post(f"{self.BASE}/api/createasync/xades", body)

    def info_document_async(self, id_):
        return self.c.get(f"{self.BASE}/api/infoasync/document/{id_}")

    def info_component_async(self, id_):
        return self.c.get(f"{self.BASE}/api/infoasync/component/{id_}")

    def content_component_async(self, id_):
        return self.c.get(f"{self.BASE}/api/contentasync/component/{id_}")

    def content_package_async(self, id_):
        return self.c.get(f"{self.BASE}/api/contentasync/package/{id_}")

    def content_report_async(self, body):
        return self.c.post(f"{self.BASE}/api/contentasync/report", body)

    def external_report_async(self, body):
        return self.c.post(f"{self.BASE}/api/externalasync/report", body)

    def get_certificate_async(self, id_):
        """v1.0.7: Detail certifikátu async (přesunuto z /api/certificatesasync/certificate)."""
        return self.c.get(f"{self.BASE}/api/contentasync/certificate/{id_}")

    def validate_certificate_async(self, body):
        """v1.0.7: Validace certifikátu async (přesunuto z /api/certificatesasync/validatecertificate)."""
        return self.c.post(f"{self.BASE}/api/validateasync/certificate",
                           self._auth_wrap(body))


# ===========================================================================
# EZCA2 – Správa certifikátů v1.0.2 (samostatná služba na T2 gateway)
# Cesta: /ezca2Certifikaty/api/v1/... (gateway prefix dle swagger servers[0].url)
# Slouží PZS k vystavení/obnově/preregistraci/revokaci EZCA II certifikátu.
# ===========================================================================
class EZCA2SpravaCertifikatu:
    """EZCA II Správa certifikátů – REST API pro životní cyklus systémových certů."""

    BASE = "/ezca2Certifikaty"
    # EZCA II administrace (vystavení/obnova/revokace…) bývá na backendu pomalá –
    # delší upstream timeout platí POUZE pro tuto službu, nikde jinde.
    TIMEOUT = 180

    def __init__(self, client: SEZClient):
        self.c = client

    def _get(self, path, params=None):
        return self.c.get(path, params=params, timeout=self.TIMEOUT)

    def _post(self, path, body=None):
        return self.c.post(path, body, timeout=self.TIMEOUT)

    def _put(self, path, body=None):
        return self.c.put(path, body, timeout=self.TIMEOUT)

    # --- Lifecycle (POST) ---
    def vystavit(self, body: dict):
        """Vytvoří požadavek na vydání nového EZCA II systémového cert."""
        return self._post(f"{self.BASE}/api/v1/vystavit", body)

    def preregistrovat(self, body: dict):
        """Vystaví nový EZCA II cert na základě stávajícího EZCA I."""
        return self._post(f"{self.BASE}/api/v1/preregistrovat", body)

    def obnovit(self, body: dict):
        """PUT – vytvoří požadavek na obnovu certifikátu EZCA II."""
        return self._put(f"{self.BASE}/api/v1/obnovit", body)

    def revokovat(self, body: dict):
        """Vytvoří požadavek na revokaci certifikátu."""
        return self._post(f"{self.BASE}/api/v1/revokovat", body)

    # --- Stavy + stažení (GET) ---
    # Pozn.: dle swagger v1.0.4 se používají query parametry IczId / SerioveCislo /
    # ExterniIdentifikator (ne requestId/certificateId). ExterniIdentifikator
    # vyplňuje pouze nadřazený systém PZS; při přímém volání PZS se IČO přebírá
    # z client_id a hodnota se ignoruje.
    def stav(self, icz_id=None, externi_identifikator=None):
        params = {}
        if icz_id:
            params["IczId"] = icz_id
        if externi_identifikator:
            params["ExterniIdentifikator"] = externi_identifikator
        return self._get(f"{self.BASE}/api/v1/stav", params=params or None)

    def stahnout(self, seriove_cislo, externi_identifikator=None):
        params = {"SerioveCislo": seriove_cislo}
        if externi_identifikator:
            params["ExterniIdentifikator"] = externi_identifikator
        return self._get(f"{self.BASE}/api/v1/stahnout", params=params)

    def detail(self, icz_id=None, seriove_cislo=None, externi_identifikator=None):
        params = {}
        if icz_id:
            params["IczId"] = icz_id
        if seriove_cislo:
            params["SerioveCislo"] = seriove_cislo
        if externi_identifikator:
            params["ExterniIdentifikator"] = externi_identifikator
        return self._get(f"{self.BASE}/api/v1/detail", params=params or None)

    def seznam(self, typ_seznamu=None, hledany_nazev=None, stranka=None,
               velikost_stranky=None, seradit_podle=None, smer_razeni=None,
               externi_identifikator=None):
        """Seznam certifikátů pro aktuální subjekt (volitelné filtry).

        v1.0.4: přidáno stránkování (VelikostStranky) a řazení
        (SeraditPodle / SmerRazeni).
          TypSeznamu  : Platne | Stazene | Revokovane | Expirovane
          SeraditPodle: Id|IczId|NazevSluzby|SerioveCislo|PlatnostOd|PlatnostDo|
                        DatumStazeni|ExterniIdentifikator|NazevSubjektu|Uid|Sablona
          SmerRazeni  : Vzestupne | Sestupne
        """
        params = {}
        if typ_seznamu:
            params["TypSeznamu"] = typ_seznamu
        if hledany_nazev:
            params["HledanyNazev"] = hledany_nazev
        if stranka is not None:
            params["Stranka"] = stranka
        if velikost_stranky is not None:
            params["VelikostStranky"] = velikost_stranky
        if seradit_podle:
            params["SeraditPodle"] = seradit_podle
        if smer_razeni:
            params["SmerRazeni"] = smer_razeni
        if externi_identifikator:
            params["ExterniIdentifikator"] = externi_identifikator
        return self._get(f"{self.BASE}/api/v1/seznam", params=params or None)

    def crl_list(self, externi_identifikator=None, stat=None, datum_od=None,
                 seriove_cislo=None):
        """Seznam revokovaných certifikátů.

        v1.0.4: přidány volitelné filtry ExterniIdentifikator / Stat /
        DatumOd (date-time) / SerioveCislo.
        """
        params = {}
        if externi_identifikator:
            params["ExterniIdentifikator"] = externi_identifikator
        if stat:
            params["Stat"] = stat
        if datum_od:
            params["DatumOd"] = datum_od
        if seriove_cislo:
            params["SerioveCislo"] = seriove_cislo
        return self._get(f"{self.BASE}/api/v1/crl-list", params=params or None)

    def seznam_chyb(self):
        """Seznam možných chyb (číselník)."""
        return self._get(f"{self.BASE}/api/v1/seznam-chyb")

    # --- Health endpointy (mimo /api/v1) ---
    def health(self):
        """Health check (uvádí stav závislých služeb)."""
        return self._get(f"{self.BASE}/health")

    def simple_health(self):
        """Lehký health check pro K8s liveness probe."""
        return self._get(f"{self.BASE}/simple-health")

    def detail_health(self):
        """Detailní health check (dependencies + DB)."""
        return self._get(f"{self.BASE}/detail-health")


class EZCAValidace:
    """EZCA Validace v1.0.0 – online/offline validace dokumentů (ELP).

    Swagger: ``apio.csez.gov.cz/apidoc`` → EZCAValidace_v1.0.0.json
    (servers ``/ezcaValidace``). Jediná byznys operace je
    ``POST /api/v1/dokumenty/validate``:

    * online  – validace podle ``dokumentId`` + ``dokumentHash``
    * offline – validace podle ``dokumentId`` + ``datumVystaveni`` +
      ``datumNarozeni`` + ``prijmeni``

    Odpověď: ``{platnyDokument, dokumentNalezen, detail}``.
    """

    BASE = "/ezcaValidace"

    def __init__(self, client: SEZClient):
        self.c = client

    def validate(self, body: dict):
        """POST /api/v1/dokumenty/validate – obecná validace (tělo dle swaggeru)."""
        return self.c.post(f"{self.BASE}/api/v1/dokumenty/validate", body)

    def validate_online(self, dokument_id: str, dokument_hash: str,
                        typ_dokumentu: str = "elp"):
        """Online validace podle hashe dokumentu (SHA-512 hex)."""
        return self.validate({
            "typValidace": "online",
            "typDokumentu": typ_dokumentu,
            "dokumentId": dokument_id,
            "dokumentHash": dokument_hash,
        })

    def validate_offline(self, dokument_id: str, datum_vystaveni: str,
                         datum_narozeni: str, prijmeni: str,
                         typ_dokumentu: str = "elp"):
        """Offline validace podle data vystavení, data narození a příjmení."""
        return self.validate({
            "typValidace": "offline",
            "typDokumentu": typ_dokumentu,
            "dokumentId": dokument_id,
            "datumVystaveni": datum_vystaveni,
            "datumNarozeni": datum_narozeni,
            "prijmeni": prijmeni,
        })

    # --- Health endpointy (mimo /api/v1) ---
    def health(self):
        return self.c.get(f"{self.BASE}/health")

    def simple_health(self):
        return self.c.get(f"{self.BASE}/simple-health")

    def detail_health(self):
        return self.c.get(f"{self.BASE}/detail-health")


# ===========================================================================
# KRP v3.0.0 – BREAKING: bez diakritiky v atributech, podtržítka v cestách,
# DatumNarozeni změněno z date-time na date pro MatkaNovorozence.
# Verze v1 byla vypnuta 14. 8. 2026, provoz a podpora v2 se dle plánu NCEZ
# (stránka „Kmenový registr pacientů“) ukončuje – nové integrace patří na v3.
# ===========================================================================
class KRPv3:
    """KRP v3.0.0 – Kmenový registr pacientů (nový tvar URL)."""

    BASE = "/krp"

    def __init__(self, client: SEZClient):
        self.c = client

    # --- Číselníky (POST) ---
    def ciselnik(self, nazev: str, body: dict | None = None):
        return self.c.post(f"{self.BASE}/api/v3/ciselnik/{nazev}", body or {})

    # --- Hledání (POST, žádné GET-by-RID, vše v body) ---
    def hledat_rid(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/rid", body)

    def hledat_jmeno_prijmeni_rc(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/jmeno_prijmeni_rc", body)

    def hledat_jmeno_prijmeni_datum_narozeni(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/jmeno_prijmeni_datum_narozeni", body)

    def hledat_jmeno_prijmeni_cp(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/jmeno_prijmeni_cp", body)

    def hledat_cizinec_cp(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/cizinec_cp", body)

    def hledat_doklady(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/doklady", body)

    def hledat_niabsi(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/niabsi", body)

    def hledat_uni(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/uni", body)

    def hledat_aifoulozenka(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/aifoulozenka", body)

    def historie_pojisteni(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/historie_pojisteni", body)

    def historie_lekaru(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/historie_registrujicich_lekaru", body)

    def mapovani_rid(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/mapovani_rid", body)

    # --- Správa pacienta ---
    def zalozit(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/zalozit/pacient", body)

    def zmenit(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/zmenit/pacient", body)

    def reklamuj_udaj(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/reklamuj/udaj", body)

    def slouceni(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/slouceni/zadost", body)

    def rozdeleni(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/rozdeleni/zadost", body)

    def zruseni(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/zruseni/zadost", body)

    # --- DRID ---
    def generovat_docasny_rid(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/generovat/docasny_rid", body)

    def priradit_docasny_rid(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/priradit/docasny_rid", body)

    # --- Hromadné ztotožnění ---
    @staticmethod
    def _now():
        from datetime import date
        return date.today().isoformat()

    def ztotozneni_zadost(self, file_bytes, filename="ztotozneni.csv",
                          ucel="LECBA", registrovat_odber=False):
        """KRP v3 hromadné ztotožnění – multipart/form-data upload XML dávky
        (<Davka> dle PZS_Import_pacienti_v1.xsd). Vstup CSV/JSON/XML se převede
        automaticky na XML (stejně jako u v2)."""
        if isinstance(file_bytes, (bytes, bytearray)):
            raw = file_bytes.decode("utf-8-sig")
        else:
            raw = str(file_bytes)
        base = (filename or "davka").rsplit(".", 1)[0] or "davka"
        xml_text = KRP.to_davka_xml(raw)
        url = self.c.config.GATEWAY + f"{self.BASE}/api/v3/pacient/ztotoznihromadne/zadost"
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
        files = {"file": (base + ".xml", xml_text.encode("utf-8"), "application/xml")}
        resp = self.c.session.post(url, headers=headers, data=form_data,
                                   files=files, timeout=60)
        self.c.last_status = resp.status_code
        try:
            self.c.last_response = resp.json()
        except Exception:
            self.c.last_response = resp.text
        return resp

    # zpětná kompatibilita (JSON varianta – některé starší volání)
    def hrom_zadost(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/ztotoznihromadne/zadost", body)

    def hrom_vysledky(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/ztotoznihromadne/vysledky", body)

    def hrom_vysledky_soubor(self, body):
        return self.c.post(f"{self.BASE}/api/v3/pacient/ztotoznihromadne/vysledky/soubor", body)

    # --- Notifikace ---
    def notifikace_vyhledat(self, body):
        return self.c.post(f"{self.BASE}/api/v3/notifikace/vyhledat/odber", body)

    def notifikace_zalozit(self, body):
        return self.c.post(f"{self.BASE}/api/v3/notifikace/zalozit/odber", body)

    def notifikace_zrusit(self, body):
        return self.c.delete(f"{self.BASE}/api/v3/notifikace/zrusit/odber", body)


# ===========================================================================
# Adaptér KRP v3 na rozhraní KRP v2 pro ztotožňování pacienta.
# KRP v2 metody staví obálku zadostInfo samy, v3 přijímá celé tělo – díky
# adaptéru může interní ztotožnění přejít na v3 bez zásahu do logiky výběru
# vyhledávací metody. Důvod přechodu: NCEZ vypnul v1 (14. 8. 2026) a ukončuje
# provoz i podporu v2.
# ===========================================================================
class KRPZtotozneniV3:
    """KRP v3 se stejnými metodami, jaké používá ztotožnění u verze v2."""

    BASE = "/krp"
    VERZE = "v3"

    def __init__(self, client: SEZClient):
        self.c = client

    @staticmethod
    def _envelope(ucel, data):
        from datetime import date
        return {
            "zadostInfo": {
                "datum": date.today().isoformat(),
                "ucel": ucel,
                "zadostId": str(uuid.uuid4()),
            },
            "zadostData": data,
        }

    def ciselnik(self, nazev_ciselniku, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v3/ciselnik/{nazev_ciselniku}",
                           self._envelope(ucel, {}))

    def hledat_rid(self, rid, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/rid",
                           self._envelope(ucel, {"rid": rid}))

    def hledat_jmeno_rc(self, jmeno, prijmeni, rc, ucel="LECBA"):
        data = {"rodneCislo": rc}
        if jmeno:
            data["jmeno"] = jmeno
        if prijmeni:
            data["prijmeni"] = prijmeni
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/jmeno_prijmeni_rc",
                           self._envelope(ucel, data))

    def hledat_jmeno_cp(self, jmeno, prijmeni, cislo_pojistence, ucel="LECBA"):
        return self.c.post(
            f"{self.BASE}/api/v3/pacient/hledat/jmeno_prijmeni_cp",
            self._envelope(ucel, {"jmeno": jmeno, "prijmeni": prijmeni,
                                   "cisloPojistence": cislo_pojistence}))

    def hledat_jmeno_dn(self, jmeno, prijmeni, datum_narozeni,
                        statni_obcanstvi=None, ucel="LECBA"):
        data = {"jmeno": jmeno, "prijmeni": prijmeni,
                "datumNarozeni": datum_narozeni}
        if statni_obcanstvi:
            data["statniObcanstvi"] = statni_obcanstvi
        return self.c.post(
            f"{self.BASE}/api/v3/pacient/hledat/jmeno_prijmeni_datum_narozeni",
            self._envelope(ucel, data))

    def hledat_cizinec_cp(self, cislo_pojistence, statni_obcanstvi=None, ucel="LECBA"):
        data = {"cisloPojistence": cislo_pojistence}
        if statni_obcanstvi:
            data["statniObcanstvi"] = statni_obcanstvi
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/cizinec_cp",
                           self._envelope(ucel, data))

    def hledat_uni(self, ucel="LECBA", **kwargs):
        data = {k: v for k, v in kwargs.items() if v is not None}
        return self.c.post(f"{self.BASE}/api/v3/pacient/hledat/uni",
                           self._envelope(ucel, data))


# ===========================================================================
# SZZ v2.0.1 – Sdílený zdravotní záznam (BREAKING – samostatné moduly
# pro Prevence a Screeningy + emergentní záznam ve v2 shodný se v1).
# Implementace doplňuje SZZ (v1) – obě verze se používají paralelně.
# ===========================================================================
class SZZv2:
    """SZZ v2.0.1 – samostatné moduly /prevence a /screeningy + emergentní záznam v2."""

    BASE = "/sdilenyZdravotniZaznam"

    # Známé typy v modulu /prevence (každý má CRUD: POST, vyhledat, PUT, PATCH /obnovit/zneplatnit/zpochybnit)
    PREVENCE_TYPY = [
        "kardiovaskularniRizika",
        "ockovaniHpv",
        "preventivniProhlidky",            # všeob. praktický lékař
        "preventivniProhlidkyGynekologie", # gynekolog
        "preventivniProhlidkyPldd",        # praktický lékař pro děti a dorost
    ]

    # Známé typy v modulu /screeningy
    # Pozn.: HPV screening děložního hrdla je ve swaggeru v2.0.1 veden s dvojitým
    # "D" – /screeningy/karcinomDDeloznihoHrdlaHpv (překlep v API, ale reálná
    # cesta). Jednoduché "karcinomDeloznihoHrdlaHpv" přijímáme jako alias.
    SCREENINGY_TYPY = [
        "aneurysmaAbdominalniAortyUsg",
        "karcinomDDeloznihoHrdlaHpv",
        "karcinomDeloznihoHrdlaCytologie",
        "karcinomDeloznihoHrdlaExpertniKolposkopie",
        "karcinomPlicLdct",
        "karcinomProstatyMri",
        "karcinomProstatyPsa",
        "karcinomPrsuBiopsie",
        "karcinomPrsuMamografie",
        "kolorektalniKarcinomToks",
    ]

    # Aliasy typů → cesta dle swaggeru
    SCREENINGY_ALIASY = {
        "karcinomDeloznihoHrdlaHpv": "karcinomDDeloznihoHrdlaHpv",
    }

    # Emergentní záznam v2 – stejná podmnožina jako v1 (alergie bez CasZjisteni)
    EMERGENTNI_TYPY = [
        "alergie", "krevniSkupina", "nezadouciPrihody",
        "nezadouciReakce", "nezadouciUcinky", "nezadouciUdalosti",
    ]

    def __init__(self, client: SEZClient):
        self.c = client

    # --- Číselníky ---
    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v2/ciselniky")

    def ciselnik_polozky(self, kod):
        return self.c.get(f"{self.BASE}/api/v2/ciselniky/{kod}/polozky")

    def ciselniky_reindex(self, body=None):
        return self.c.post(f"{self.BASE}/api/v2/ciselniky/reindex", body or {})

    # --- Generický CRUD pro prevence/screeningy/emergentní záznam ---
    def _crud(self, modul: str, typ: str):
        """Vrátí slovník metod pro daný modul/typ."""
        base = f"{self.BASE}/api/v2/{modul}/{typ}"
        return {
            "vytvor": lambda body: self.c.post(base, body),
            "vyhledat": lambda body: self.c.post(f"{base}/vyhledat", body),
            "uprav": lambda id_, body: self.c.put(f"{base}/{id_}", body),
            "obnovit": lambda id_, body=None: self.c.patch(f"{base}/{id_}/obnovit", body or {}),
            "zneplatnit": lambda id_, body=None: self.c.patch(f"{base}/{id_}/zneplatnit", body or {}),
            "zpochybnit": lambda id_, body=None: self.c.patch(f"{base}/{id_}/zpochybnit", body or {}),
        }

    def prevence(self, typ: str):
        if typ not in self.PREVENCE_TYPY:
            raise ValueError(f"Neznámý typ prevence: {typ}. Povolené: {self.PREVENCE_TYPY}")
        return self._crud("prevence", typ)

    def screening(self, typ: str):
        typ = self.SCREENINGY_ALIASY.get(typ, typ)
        if typ not in self.SCREENINGY_TYPY:
            raise ValueError(f"Neznámý screening: {typ}. Povolené: {self.SCREENINGY_TYPY}")
        return self._crud("screeningy", typ)

    def emergentni(self, typ: str):
        if typ not in self.EMERGENTNI_TYPY:
            raise ValueError(f"Neznámý emergentní typ: {typ}. Povolené: {self.EMERGENTNI_TYPY}")
        return self._crud("emergentniZaznam", typ)

    # --- Souhrnné vyhledávání všech prevencí / screeningů pacienta ---
    def prevence_vyhledat_souhrn(self, body):
        """POST /api/v2/prevence/vyhledat – všechny prevence pacienta podle RID."""
        return self.c.post(f"{self.BASE}/api/v2/prevence/vyhledat", body)

    def screeningy_vyhledat_souhrn(self, body):
        """POST /api/v2/screeningy/vyhledat – všechny screeningy pacienta podle RID."""
        return self.c.post(f"{self.BASE}/api/v2/screeningy/vyhledat", body)

    def emergentni_vyhledat_souhrn(self, body):
        """POST /api/v2/emergentniZaznam/vyhledat – všechny emergentní záznamy pacienta."""
        return self.c.post(f"{self.BASE}/api/v2/emergentniZaznam/vyhledat", body)

    def emergentni_pdf(self, body):
        """POST /api/v2/emergentniZaznam/pdf – PDF souhrn emergentního záznamu."""
        return self.c.post(f"{self.BASE}/api/v2/emergentniZaznam/pdf", body)

    # --- Lecive pripravky (CRUD bez podkategorií) ---
    def lecive_pripravky_vytvor(self, body):
        """POST /api/v2/lecivePripravky – nový záznam léčivého přípravku."""
        return self.c.post(f"{self.BASE}/api/v2/lecivePripravky", body)

    def lecive_pripravky_vyhledat(self, body):
        """POST /api/v2/lecivePripravky/vyhledat – seznam léčivých přípravků pacienta."""
        return self.c.post(f"{self.BASE}/api/v2/lecivePripravky/vyhledat", body)

    def lecive_pripravky_uprav(self, id_: str, body):
        """PUT /api/v2/lecivePripravky/{id} – aktualizace záznamu."""
        return self.c.put(f"{self.BASE}/api/v2/lecivePripravky/{id_}", body)

    def lecive_pripravky_obnovit(self, id_: str, body=None):
        """PATCH /api/v2/lecivePripravky/{id}/obnovit."""
        return self.c.patch(f"{self.BASE}/api/v2/lecivePripravky/{id_}/obnovit", body or {})

    def lecive_pripravky_zneplatnit(self, id_: str, body=None):
        """PATCH /api/v2/lecivePripravky/{id}/zneplatnit."""
        return self.c.patch(f"{self.BASE}/api/v2/lecivePripravky/{id_}/zneplatnit", body or {})

    def lecive_pripravky_zpochybnit(self, id_: str, body=None):
        """PATCH /api/v2/lecivePripravky/{id}/zpochybnit."""
        return self.c.patch(f"{self.BASE}/api/v2/lecivePripravky/{id_}/zpochybnit", body or {})


# ===========================================================================
# SZZ v3.0.0 – Sdílený zdravotní záznam (Standard EZ SZZ 3.0, 29. 7. 2026).
# Proti v2: cesty /api/v3, pět nových screeningů (koloskopie, vstupní PSA,
# navazující urologické a bioptické vyšetření, pneumologické vyšetření),
# opravený překlep v HPV screeningu děložního hrdla a nová položka
# `samoplatce` u všech preventivních i screeningových vyšetření.
# v2 zůstává dostupná paralelně.
# ===========================================================================
class SZZv3:
    """SZZ v3.0.0 – /api/v3 s moduly /prevence, /screeningy, /emergentniZaznam."""

    BASE = "/sdilenyZdravotniZaznam"
    VERZE_API = "3.0.0"
    VERZE_STANDARDU = "3.0"

    PREVENCE_TYPY = [
        "kardiovaskularniRizika",
        "ockovaniHpv",
        "preventivniProhlidky",            # všeob. praktický lékař
        "preventivniProhlidkyGynekologie",  # gynekolog
        "preventivniProhlidkyPldd",        # praktický lékař pro děti a dorost
    ]

    # Screeningy dle Standardu SZZ 3.0, kap. 6. Nové proti v2 jsou koloskopie,
    # vstupní PSA, navazující urologické a bioptické vyšetření prostaty
    # a pneumologické vyšetření u karcinomu plic.
    SCREENINGY_TYPY = [
        "aneurysmaAbdominalniAortyUsg",
        "karcinomDeloznihoHrdlaCytologie",
        "karcinomDeloznihoHrdlaExpertniKolposkopie",
        "karcinomDeloznihoHrdlaHpv",
        "karcinomPlicLdct",
        "karcinomPlicPneumologickeVysetreni",
        "karcinomProstatyBioptickeVysetreni",
        "karcinomProstatyMri",
        "karcinomProstatyPsa",
        "karcinomProstatyUrologickeVysetreni",
        "karcinomProstatyVstupniPsa",
        "karcinomPrsuBiopsie",
        "karcinomPrsuMamografie",
        "kolorektalniKarcinomKoloskopie",
        "kolorektalniKarcinomToks",
    ]

    # Ve v2 byl HPV screening veden s dvojitým "D" (karcinomDDeloznihoHrdlaHpv);
    # v3 je překlep opravený, starý zápis přijímáme jako alias.
    SCREENINGY_ALIASY = {
        "karcinomDDeloznihoHrdlaHpv": "karcinomDeloznihoHrdlaHpv",
    }

    EMERGENTNI_TYPY = [
        "alergie", "krevniSkupina", "nezadouciPrihody",
        "nezadouciReakce", "nezadouciUcinky", "nezadouciUdalosti",
    ]

    # Rozsahy číselných hodnot dle přílohy Validace ve SZZ v3.0
    # (atribut → min, max, počet desetinných míst). Slouží jako klientská
    # pojistka a podklad pro formuláře; závaznou kontrolu dělá server.
    ROZSAHY = {
        "ntProbnp": (0, 100000, 0),
        "vyska": (10, 300, 3),
        "vaha": (0, 400, 3),
        "obvodPasu": (10, 400, 3),
        "hladinaToksUgG": (0, 500, 2),
        "vysledekBbps": (0, 9, 0),
        "hladinaPsa": (1000, 12000, 2),
        "objemProstaty": (0, 1000, 2),
        "psaDenzita": (0, 10, 2),
        "psaVelocita": (0, 10, 2),
        "pocetLetZanechaniKoureni": (0, 120, 1),
    }

    # Maximální délka volných textů (poznámky, popisy) dle validací v3.
    MAX_TEXT = 300

    # Číselníky, které v3 přinesla nad rámec v2.
    NOVE_CISELNIKY = [
        "szz-ucast-karcinom-plic",
        "szz-ucast-karcinom-prostaty",
        "szz-ucast-ve-screeningu-aaa",
        "gastro-typ-koloskopie",
        "gastro-kompletnost-koloskopie",
        "gastro-patologie-nalez",
        "gastro-zaver",
        "urologie-klinicke-vysetreni",
        "urologie-dalsi-vysetreni",
        "urologie-typ-biopsie",
        "urologie-vysledek-biopt-vys",
        "pneumologie-koureni",
        "pneumologie-fyzikalni-vysetreni",
        "pneumologie-rtg-plic",
        "pneumologie-funkcni-vysetreni",
    ]

    def __init__(self, client: SEZClient):
        self.c = client

    # --- Číselníky ---
    def ciselniky(self):
        return self.c.get(f"{self.BASE}/api/v3/ciselniky")

    def ciselnik_polozky(self, kod):
        return self.c.get(f"{self.BASE}/api/v3/ciselniky/{kod}/polozky")

    def ciselniky_reindex(self, body=None):
        return self.c.post(f"{self.BASE}/api/v3/ciselniky/reindex", body or {})

    # --- Generický CRUD pro prevence/screeningy/emergentní záznam ---
    def _crud(self, modul: str, typ: str):
        base = f"{self.BASE}/api/v3/{modul}/{typ}"
        return {
            "vytvor": lambda body: self.c.post(base, body),
            "vyhledat": lambda body: self.c.post(f"{base}/vyhledat", body),
            "uprav": lambda id_, body: self.c.put(f"{base}/{id_}", body),
            "obnovit": lambda id_, body=None: self.c.patch(f"{base}/{id_}/obnovit", body or {}),
            "zneplatnit": lambda id_, body=None: self.c.patch(f"{base}/{id_}/zneplatnit", body or {}),
            "zpochybnit": lambda id_, body=None: self.c.patch(f"{base}/{id_}/zpochybnit", body or {}),
        }

    def prevence(self, typ: str):
        if typ not in self.PREVENCE_TYPY:
            raise ValueError(f"Neznámý typ prevence: {typ}. Povolené: {self.PREVENCE_TYPY}")
        return self._crud("prevence", typ)

    def screening(self, typ: str):
        typ = self.SCREENINGY_ALIASY.get(typ, typ)
        if typ not in self.SCREENINGY_TYPY:
            raise ValueError(f"Neznámý screening: {typ}. Povolené: {self.SCREENINGY_TYPY}")
        return self._crud("screeningy", typ)

    def emergentni(self, typ: str):
        if typ not in self.EMERGENTNI_TYPY:
            raise ValueError(f"Neznámý emergentní typ: {typ}. Povolené: {self.EMERGENTNI_TYPY}")
        return self._crud("emergentniZaznam", typ)

    # --- Souhrnná vyhledávání ---
    def prevence_vyhledat_souhrn(self, body):
        return self.c.post(f"{self.BASE}/api/v3/prevence/vyhledat", body)

    def screeningy_vyhledat_souhrn(self, body):
        return self.c.post(f"{self.BASE}/api/v3/screeningy/vyhledat", body)

    def emergentni_vyhledat_souhrn(self, body):
        return self.c.post(f"{self.BASE}/api/v3/emergentniZaznam/vyhledat", body)

    def emergentni_pdf(self, body):
        return self.c.post(f"{self.BASE}/api/v3/emergentniZaznam/pdf", body)

    def zdravotni_zaznamy_vyhledat(self, body):
        """POST /api/v3/zdravotniZaznamy/vyhledat – všechny výsledky prevencí
        i screeningů pacienta jedním dotazem (novinka v3)."""
        return self.c.post(f"{self.BASE}/api/v3/zdravotniZaznamy/vyhledat", body)

    # --- Léčivé přípravky ---
    def lecive_pripravky_vytvor(self, body):
        return self.c.post(f"{self.BASE}/api/v3/lecivePripravky", body)

    def lecive_pripravky_vyhledat(self, body):
        return self.c.post(f"{self.BASE}/api/v3/lecivePripravky/vyhledat", body)

    def lecive_pripravky_uprav(self, id_: str, body):
        return self.c.put(f"{self.BASE}/api/v3/lecivePripravky/{id_}", body)

    def lecive_pripravky_obnovit(self, id_: str, body=None):
        return self.c.patch(f"{self.BASE}/api/v3/lecivePripravky/{id_}/obnovit", body or {})

    def lecive_pripravky_zneplatnit(self, id_: str, body=None):
        return self.c.patch(f"{self.BASE}/api/v3/lecivePripravky/{id_}/zneplatnit", body or {})

    def lecive_pripravky_zpochybnit(self, id_: str, body=None):
        return self.c.patch(f"{self.BASE}/api/v3/lecivePripravky/{id_}/zpochybnit", body or {})

    # --- Klientská kontrola dat ---
    @classmethod
    def zkontroluj(cls, telo: dict) -> list:
        """Projde tělo požadavku proti rozsahům z přílohy Validace SZZ 3.0
        a vrátí seznam výhrad. Nejde o náhradu serverové validace – smyslem je
        odhalit zjevně chybnou hodnotu ještě před odesláním do produkce."""
        vyhrady = []
        if not isinstance(telo, dict):
            return ["Tělo požadavku není objekt."]

        for klic, hodnota in telo.items():
            if klic in cls.ROZSAHY and isinstance(hodnota, (int, float)) \
                    and not isinstance(hodnota, bool):
                minimum, maximum, desetinna = cls.ROZSAHY[klic]
                if not (minimum <= hodnota <= maximum):
                    vyhrady.append(
                        f"{klic}: hodnota {hodnota} je mimo rozsah "
                        f"{minimum}–{maximum}.")
                elif desetinna == 0 and float(hodnota) != int(hodnota):
                    vyhrady.append(f"{klic}: očekává se celé číslo.")
                else:
                    zbytek = str(float(hodnota)).split(".")[1].rstrip("0")
                    if desetinna and len(zbytek) > desetinna:
                        vyhrady.append(
                            f"{klic}: nejvýše {desetinna} desetinná místa.")
            elif isinstance(hodnota, str) and len(hodnota) > cls.MAX_TEXT \
                    and klic in ("poznamka", "popis", "davkovani", "genotypyHpvTestu"):
                vyhrady.append(
                    f"{klic}: text přesahuje {cls.MAX_TEXT} znaků "
                    f"({len(hodnota)}).")

        if "samoplatce" in telo and not isinstance(telo["samoplatce"], bool):
            vyhrady.append("samoplatce: očekává se true/false.")
        return vyhrady


# ===========================================================================
# Registr oprávnění NCPeH v1.0.7 – samostatná služba pro přeshraniční
# zdravotnictví (CMS/NCPeH). Pro běžné tuzemské PZS není potřeba, ale
# klient + endpointy zpřístupňujeme pro úplnost.
# ===========================================================================
class RegistrOpravneniNcpeh:
    """RO NCPeH v1.0.7 – přeshraniční oprávnění pro NCPeH (StátEHP ↔ Pacient)."""

    BASE = "/registrOpravneniNcpeh"

    def __init__(self, client: SEZClient):
        self.c = client

    def over(self, params: dict | None = None):
        """GET /api/v1/Opravneni/Over – v 1.0.7 nepřijímá IdSluzbyEZ ani role
        (vždy SZZ + Pacient ↔ StátEHP)."""
        return self.c.get(f"{self.BASE}/api/v1/Opravneni/Over", params=params)

    def sluzby_ez(self, params=None):
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/SluzbyEZ", params=params)

    def sluzba_ez(self, id_):
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/SluzbyEZ/{id_}")

    def typy_dokumentaci(self, params=None):
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/TypyDokumentaci", params=params)

    def typ_dokumentace(self, id_):
        return self.c.get(f"{self.BASE}/api/v1/Ciselniky/TypyDokumentaci/{id_}")


# ===========================================================================
# SÚKL – eRecept / CÚER a Databáze léčivých přípravků (DLP)
# ---------------------------------------------------------------------------
# eRecept je samostatný systém SÚKL (SOAP web services, verze rozhraní 202501A,
# dokumentace na epreskripce.gov.cz). Vyžaduje registraci SW u SÚKL + certifikát.
# Bez těchto přístupů běží integrace v režimu SIMULACE (viz simulační engine
# v sez_api/app.py). DLP jsou veřejná otevřená data (opendata.sukl.cz).
# ===========================================================================

SUKL_ENVIRONMENTS = {
    "T2": {
        "name": "SÚKL Test",
        "info": "epreskripce.gov.cz – testovací prostředí (registrace SW u SÚKL nutná)",
    },
    "PROD": {
        "name": "SÚKL Produkce",
        "info": "epreskripce.gov.cz – produkční prostředí eRecept / CÚER",
    },
}


class SUKLDLP:
    """Databáze léčivých přípravků SÚKL – veřejná otevřená data (opendata.sukl.cz).

    Líné stažení + rozbalení + cache CSV; fulltext lookup nad indexem v paměti.
    Když stažení selže (offline), použije vestavěné vzorky z configu
    (`self.status()['zdroj'] == 'sample'`).
    """

    # Sdílená cache napříč instancemi (index se stahuje jednou za proces).
    _index: list | None = None
    _source: str | None = None
    _loaded_at: float = 0.0
    _error: str | None = None
    # Skutečně použitá URL balíku (po autodetekci z katalogu).
    _url: str = ""

    # Kandidátní názvy sloupců (schéma DLP se mezi verzemi liší) – zkusí se po
    # řadě. První v seznamu je název podle datového rozhraní DLP
    # (opendata.sukl.cz/soubory/DLP_datove_rozhrani<datum>.csv).
    _COLS = {
        "kod": ["KOD_SUKL", "KODSUKL", "KOD"],
        "nazev": ["NAZEV", "NÁZEV", "NAZ"],
        "sila": ["SILA", "SÍLA"],
        "forma": ["FORMA", "LEKOVA_FORMA", "F"],
        "baleni": ["BALENI", "DOPLNEK_NAZ", "VELIKOST_BALENI", "DOPLNEK"],
        "atc": ["ATC_WHO", "ATC", "ATCWHO"],
        "ucinna_latka": ["LL", "NAZEV_LATKY", "UCINNA_LATKA", "LATKA", "SLOZENI"],
        "cesta": ["CESTA", "CESTA_PODANI"],
        "drzitel": ["DRZ", "DRZITEL", "DRZITEL_ROZHODNUTI", "NAZEV_DRZITELE"],
        "stav_registrace": ["REG", "STAV_REG", "STAV_REGISTRACE", "STAV"],
        "vydej": ["VYDEJ", "ZPUSOB_VYDEJE"],
    }

    # Soubory s přípravky v archivu, v pořadí preference. Archiv obsahuje ~30
    # CSV (data i číselníky), takže se nesmí brát první podle pořadí v ZIPu.
    _DATOVE_SOUBORY = ("dlp_lecivepripravky", "lecivepripravky", "dlp_lecive")

    # Číselníky v témže archivu: pole -> (soubor, sloupec s kódem, sloupec s názvem).
    # V CSV s přípravky jsou jen zkratky (držitel "ZNB", výdej "R").
    _CISELNIKY = {
        "drzitel": ("dlp_organizace", "ZKR_ORG", "NAZEV"),
        "stav_registrace": ("dlp_stavyreg", "REG", "NAZEV"),
        "vydej": ("dlp_vydej", "VYDEJ", "NAZEV"),
    }

    # Číselníky léčivých látek – sloupec LL obsahuje kódy oddělené čárkou
    # ("12,223"), názvy jsou v samostatných souborech.
    _CISELNIKY_LATEK = (
        ("dlp_lecivelatky", "KOD_LATKY", "NAZEV"),
        ("dlp_latky", "KOD_LATKY", "NAZEV"),
    )

    def __init__(self, client: SEZClient = None):
        self.c = client

    # --- načtení indexu ---------------------------------------------------
    def _load_samples(self, error: str | None = None):
        from sez_api import config as _cfg
        SUKLDLP._index = [dict(x) for x in getattr(_cfg, "SUKL_DLP_SAMPLE", [])]
        SUKLDLP._source = "sample"
        SUKLDLP._loaded_at = time.time()
        SUKLDLP._error = error
        SUKLDLP._url = ""
        return SUKLDLP._index

    @staticmethod
    def _csv_rows(data: bytes) -> list[list[str]]:
        """Dekóduje CSV z balíku DLP (cp1250, oddělovač ';')."""
        import csv
        import io
        for enc in ("cp1250", "utf-8-sig", "utf-8"):
            try:
                text = data.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = data.decode("cp1250", errors="replace")
        return list(csv.reader(io.StringIO(text), delimiter=";"))

    @classmethod
    def _vyber_soubor(cls, names: list) -> str | None:
        """Vybere CSV s léčivými přípravky podle preference, ne podle pořadí
        v archivu (jinak se načte první číselník, např. dlp_atc.csv)."""
        for vzor in cls._DATOVE_SOUBORY:
            for n in names:
                if vzor in n.lower():
                    return n
        return names[0] if names else None

    @classmethod
    def _zjisti_url(cls, url: str) -> tuple:
        """Pro hodnotu "auto" najde v katalogu odkaz na aktuální balík – SÚKL
        publikuje balík s datem v názvu (SOD<datum>/DLP<datum>.zip), takže
        pevně zadaná URL po každé aktualizaci přestane platit.

        Vrací (url, chyba).
        """
        if (url or "").strip().lower() != "auto":
            return url, None

        import re
        from sez_api import config as _cfg
        katalog = getattr(_cfg, "SUKL_DLP_KATALOG", "")
        if not katalog:
            return "", "SUKL_DLP_KATALOG není nastavena"
        try:
            resp = requests.get(katalog, timeout=30)
            resp.raise_for_status()
        except Exception as exc:
            return "", f"katalog DLP nedostupný: {str(exc)[:150]}"
        odkazy = re.findall(
            r"https?://[^\"'\s]+/soubory/SOD\d{8}/DLP\d{8}\.zip", resp.text)
        if not odkazy:
            return "", "v katalogu DLP nebyl nalezen odkaz na balík"
        # Datum je součástí názvu, takže nejnovější balík je lexikograficky poslední.
        return sorted(set(odkazy))[-1], None

    def _doplnit_ciselniky(self, zf, records: list) -> None:
        """Přeloží zkratky (držitel, stav registrace, výdej) na názvy z číselníků
        v témže archivu. Původní kód zůstává v poli <pole>_kod."""
        for pole, (soubor, kl_kod, kl_nazev) in self._CISELNIKY.items():
            mapa = self._nacti_ciselnik(zf, soubor, kl_kod, kl_nazev)
            if not mapa:
                continue
            for r in records:
                kod = (r.get(pole) or "").strip()
                if not kod:
                    continue
                r[pole + "_kod"] = kod
                if kod in mapa:
                    r[pole] = mapa[kod]

    def _doplnit_latky(self, zf, records: list) -> None:
        """Přeloží kódy léčivých látek ze sloupce LL na názvy. Kódy zůstávají
        v poli ucinna_latka_kod."""
        mapa: dict = {}
        for zaklad, kl_kod, kl_nazev in self._CISELNIKY_LATEK:
            for kod, nazev in self._nacti_ciselnik(zf, zaklad, kl_kod, kl_nazev).items():
                mapa.setdefault(kod, nazev)
        if not mapa:
            return
        for r in records:
            hodnota = (r.get("ucinna_latka") or "").strip()
            if not hodnota:
                continue
            kody = [k.strip() for k in hodnota.split(",") if k.strip()]
            nazvy = [mapa.get(k, k) for k in kody]
            if nazvy != kody:
                r["ucinna_latka_kod"] = hodnota
                r["ucinna_latka"] = ", ".join(nazvy)

    def _nacti_ciselnik(self, zf, zaklad: str, kl_kod: str, kl_nazev: str) -> dict:
        name = next((n for n in zf.namelist() if zaklad in n.lower()), None)
        if not name:
            return {}
        try:
            rows = self._csv_rows(zf.read(name))
        except Exception:
            return {}
        if not rows:
            return {}
        header = [c.strip().upper() for c in rows[0]]
        if (kl_kod not in header) or (kl_nazev not in header):
            return {}
        i_kod, i_naz = header.index(kl_kod), header.index(kl_nazev)
        out = {}
        for r in rows[1:]:
            if len(r) > max(i_kod, i_naz) and r[i_kod].strip():
                out[r[i_kod].strip()] = r[i_naz].strip()
        return out

    def _norm_row(self, header: list, row: list) -> dict:
        raw = {header[i].strip().upper(): (row[i].strip() if i < len(row) else "")
               for i in range(len(header))}
        out = {}
        for field, candidates in self._COLS.items():
            out[field] = ""
            for cand in candidates:
                if cand in raw and raw[cand]:
                    out[field] = raw[cand]
                    break
        return out

    def _ensure_index(self, force: bool = False):
        if SUKLDLP._index is not None and not force:
            return SUKLDLP._index

        from sez_api import config as _cfg
        import io
        import zipfile

        url = getattr(_cfg, "SUKL_DLP_URL", "")
        if not url:
            return self._load_samples("SUKL_DLP_URL není nastavena")

        url, chyba = self._zjisti_url(url)
        if not url:
            return self._load_samples(chyba or "URL balíku DLP se nepodařilo zjistit")

        try:
            resp = requests.get(url, timeout=60)
            resp.raise_for_status()
            data = resp.content
            records: list[dict] = []

            def _parse_csv_bytes(b: bytes):
                rows = self._csv_rows(b)
                if not rows:
                    return
                header = rows[0]
                for r in rows[1:]:
                    if r:
                        records.append(self._norm_row(header, r))

            if url.lower().endswith(".zip") or data[:2] == b"PK":
                zf = zipfile.ZipFile(io.BytesIO(data))
                target = self._vyber_soubor(zf.namelist())
                if target:
                    _parse_csv_bytes(zf.read(target))
                self._doplnit_ciselniky(zf, records)
                self._doplnit_latky(zf, records)
            else:
                _parse_csv_bytes(data)

            records = [r for r in records if r.get("kod") or r.get("nazev")]
            if not records:
                return self._load_samples("DLP dataset neobsahuje očekávaná data")

            SUKLDLP._index = records
            SUKLDLP._source = "opendata"
            SUKLDLP._loaded_at = time.time()
            SUKLDLP._error = None
            SUKLDLP._url = url
            logger.info("SÚKL DLP načteno: %d přípravků z %s", len(records), url)
            return SUKLDLP._index
        except Exception as exc:
            logger.warning("SÚKL DLP stažení selhalo (%s) – fallback na vzorky", exc)
            return self._load_samples(str(exc)[:200])

    # --- veřejné API ------------------------------------------------------
    def status(self) -> dict:
        from sez_api import config as _cfg
        idx = self._ensure_index()
        return {
            "zdroj": SUKLDLP._source,
            "pocet": len(idx or []),
            "nacteno": SUKLDLP._loaded_at,
            "chyba": SUKLDLP._error,
            # url = balík, ze kterého se data skutečně načetla (u "auto" zjištěný
            # z katalogu); url_konfigurace = co je nastaveno v konfiguraci.
            "url": SUKLDLP._url or getattr(_cfg, "SUKL_DLP_URL", ""),
            "url_konfigurace": getattr(_cfg, "SUKL_DLP_URL", ""),
            "katalog": getattr(_cfg, "SUKL_DLP_KATALOG", ""),
        }

    def reload(self) -> dict:
        self._ensure_index(force=True)
        return self.status()

    def hledat(self, nazev: str = None, sukl_kod: str = None,
               atc: str = None, limit: int = 50) -> dict:
        idx = self._ensure_index()
        q_naz = (nazev or "").strip().lower()
        q_kod = (sukl_kod or "").strip().lower()
        q_atc = (atc or "").strip().lower()

        def _match(r):
            if q_kod and q_kod not in (r.get("kod", "").lower()):
                return False
            if q_atc and q_atc not in (r.get("atc", "").lower()):
                return False
            if q_naz:
                hay = (r.get("nazev", "") + " " + r.get("ucinna_latka", "")).lower()
                if q_naz not in hay:
                    return False
            return True

        matches = [r for r in idx if _match(r)] if (q_naz or q_kod or q_atc) else list(idx)
        total = len(matches)
        return {
            "zdroj": SUKLDLP._source,
            "pocet": total,
            "limit": limit,
            "vysledky": matches[:limit],
        }

    def detail(self, sukl_kod: str) -> dict:
        idx = self._ensure_index()
        kod = (sukl_kod or "").strip().lower()
        for r in idx:
            if r.get("kod", "").lower() == kod:
                return {"zdroj": SUKLDLP._source, "nalezeno": True, "pripravek": r}
        return {"zdroj": SUKLDLP._source, "nalezeno": False, "pripravek": None}


class SUKLeRecept:
    """eRecept / CÚER (SÚKL) – builder request obálek a odesílání.

    LIVE režim (nakonfigurován endpoint + registrační ID) posílá request na
    reálné SOAP rozhraní; jinak vrací marker `{"_simulace": True, ...}`, který
    zpracuje simulační engine ve vrstvě app.py.
    """

    def __init__(self, client: SEZClient = None):
        self.c = client

    # --- pomocné ----------------------------------------------------------
    def _cfg(self):
        from sez_api import config as _cfg
        return _cfg

    def mode(self) -> str:
        return self._cfg().sukl_mode(SEZConfig.ENVIRONMENT)

    def _hlavicka(self, kontext: dict | None = None) -> dict:
        cfg = self._cfg()
        h = {
            "verzeRozhrani": cfg.SUKL_INTERFACE_VERSION,
            "identifikaceVyrobce": cfg.SUKL_VYROBCE,
            "registracniId": cfg.SUKL_REG_ID or None,
            "casVytvoreni": _iso_now(),
            "idKorelace": str(uuid.uuid4()),
        }
        if kontext:
            h["kontext"] = kontext
        return h

    def build_envelope(self, operace: str, telo: dict,
                       kontext: dict | None = None) -> dict:
        return {
            "operace": operace,
            "hlavicka": self._hlavicka(kontext),
            "telo": telo or {},
        }

    def odeslat(self, operace: str, telo: dict, kontext: dict | None = None) -> dict:
        """LIVE: POST na endpoint. SIM: vrátí marker pro app.py sim engine."""
        env = self.build_envelope(operace, telo, kontext)
        cfg = self._cfg()
        endpoint = cfg.sukl_erecept_endpoint(SEZConfig.ENVIRONMENT)
        if self.mode() == "LIVE" and endpoint:
            try:
                resp = requests.post(
                    endpoint,
                    json=env,
                    timeout=30,
                    cert=self._live_cert(),
                    headers={"Content-Type": "application/json",
                             "SOAPAction": operace},
                )
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text[:2000]}
                return {"_simulace": False, "operace": operace,
                        "http_status": resp.status_code, "request": env,
                        "response": body}
            except Exception as exc:
                return {"_simulace": False, "operace": operace,
                        "chyba": str(exc)[:300], "request": env}
        return {"_simulace": True, "operace": operace, "request": env}

    # Cache PFX→PEM (per cesta), aby se cert nerozbaloval při každém requestu.
    _pem_cache: dict = {}

    def _pfx_to_pem(self, path: str, password: str):
        """Rozbalí PFX/P12 do dočasných PEM souborů (cert+klíč) pro requests mTLS."""
        key = (path, bool(password))
        if key in SUKLeRecept._pem_cache and all(os.path.exists(p) for p in SUKLeRecept._pem_cache[key]):
            return SUKLeRecept._pem_cache[key]
        pwd = password.encode() if isinstance(password, str) and password else None
        with open(path, "rb") as f:
            data = f.read()
        try:
            k, cert, cas = pkcs12.load_key_and_certificates(data, pwd)
        except ValueError:
            k, cert, cas = pkcs12.load_key_and_certificates(base64.b64decode(data), pwd)
        tmp = tempfile.mkdtemp(prefix="sukl_")
        cert_path = os.path.join(tmp, "sukl_cert.pem")
        key_path = os.path.join(tmp, "sukl_key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
            for ca in (cas or []):
                f.write(ca.public_bytes(Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(k.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        SUKLeRecept._pem_cache[key] = (cert_path, key_path)
        return cert_path, key_path

    def _live_cert(self):
        """mTLS certifikát pro eRecept. Priorita: explicitní SUKL_CERT_PATH (PFX),
        jinak certifikát aktivního CSEZ/EZCA klienta (krajska_zdravotni.pfx apod.)."""
        cfg = self._cfg()
        if cfg.SUKL_CERT_PATH:
            try:
                return self._pfx_to_pem(cfg.SUKL_CERT_PATH, cfg.SUKL_CERT_PASSWORD)
            except Exception as exc:
                logger.warning("SÚKL cert %s nelze načíst: %s", cfg.SUKL_CERT_PATH, exc)
        # Fallback: použij mTLS certifikát již načteného klienta (SEZAuth.tls_cert)
        if self.c is not None and getattr(self.c, "auth", None) is not None:
            try:
                return self.c.auth.tls_cert
            except Exception:
                pass
        return None

    # --- prioritní služby -------------------------------------------------
    def predepsat(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("ZalozeniEReceptu", telo, kontext)

    def vydej(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("ZalozeniVydeje", telo, kontext)

    def rlpo(self, telo: dict, kontext: dict | None = None) -> dict:
        """Rušení/oprava předpisu nebo výdeje (RLPO)."""
        return self.odeslat("RLPO", telo, kontext)

    def nahled_erecept(self, id_erecept: str, kontext: dict | None = None) -> dict:
        return self.odeslat("NahledNaERecept", {"idERecept": id_erecept}, kontext)

    # --- neprioritní služby ----------------------------------------------
    def lekovy_zaznam(self, rid: str = None, rc: str = None,
                      kontext: dict | None = None) -> dict:
        telo = {}
        if rid:
            telo["rid"] = rid
        if rc:
            telo["rodneCislo"] = rc
        return self.odeslat("ZobrazeniLekovehoZaznamu", telo, kontext)

    def zaloz_elektronicky_zaznam(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("ZalozeniElektronickehoZaznamu", telo, kontext)

    # --- CÚER doplňkové ---------------------------------------------------
    def doplatky_limit_pojistence(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("NacistDoplatkyLimitPojistence", telo, kontext)

    def seznam_doplatku_pojistence(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("NacistSeznamDoplatkuPojistence", telo, kontext)

    def zmen_poznamku_vydeje(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("ZmenitPoznamkuVydeje", telo, kontext)

    # --- ePoukaz ----------------------------------------------------------
    def zaloz_epoukaz(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("ZalozeniEPoukazu", telo, kontext)

    def nahled_epoukaz(self, id_epoukaz: str, kontext: dict | None = None) -> dict:
        return self.odeslat("NahledNaEPoukaz", {"idEPoukaz": id_epoukaz}, kontext)

    # --- eOčkování --------------------------------------------------------
    def zaloz_ockovani(self, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat("ZalozeniOckovani", telo, kontext)

    def nahled_ockovani(self, rid: str, kontext: dict | None = None) -> dict:
        return self.odeslat("NahledNaOckovani", {"rid": rid}, kontext)

    def diagnose(self) -> dict:
        cfg = self._cfg()
        env = SEZConfig.ENVIRONMENT
        cert = self._live_cert()
        cert_src = "SUKL_CERT_PATH" if cfg.SUKL_CERT_PATH else (
            "CSEZ/EZCA klient" if cert else "(žádný)")
        return {
            "enabled": cfg.SUKL_ENABLED,
            "mode": self.mode(),
            "verzeRozhrani": cfg.SUKL_INTERFACE_VERSION,
            "endpoint": cfg.sukl_erecept_endpoint(env) or "(nenastaveno – simulace)",
            "registracniId": bool(cfg.SUKL_REG_ID),
            "certifikat": bool(cert),
            "certifikatZdroj": cert_src,
            "vyrobce": cfg.SUKL_VYROBCE,
            "prostredi": env,
        }


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


_PFX_PEM_CACHE: dict = {}


def _load_pfx_pem(path: str, password: str):
    """Rozbalí PFX/P12 do dočasných PEM (cert+klíč) pro requests mTLS. Cachováno."""
    key = (path, bool(password))
    if key in _PFX_PEM_CACHE and all(os.path.exists(p) for p in _PFX_PEM_CACHE[key]):
        return _PFX_PEM_CACHE[key]
    pwd = password.encode() if isinstance(password, str) and password else None
    with open(path, "rb") as f:
        data = f.read()
    try:
        k, cert, cas = pkcs12.load_key_and_certificates(data, pwd)
    except ValueError:
        k, cert, cas = pkcs12.load_key_and_certificates(base64.b64decode(data), pwd)
    tmp = tempfile.mkdtemp(prefix="uzis_")
    cert_path = os.path.join(tmp, "cert.pem")
    key_path = os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
        for ca in (cas or []):
            f.write(ca.public_bytes(Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(k.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    _PFX_PEM_CACHE[key] = (cert_path, key_path)
    return cert_path, key_path


# ===========================================================================
# ÚZIS ČR – NZIS (Národní zdravotnický informační systém)
# ---------------------------------------------------------------------------
# NRPZS = veřejné REST API (nrpzs.uzis.cz/api/v1) – reálně + offline fallback.
# Národní zdravotnické registry (NZR) / hlášení do NZIS = cert-authenticated
# (EREG/EZCA) → simulace, dokud není nakonfigurován endpoint + certifikát.
# ===========================================================================

UZIS_ENVIRONMENTS = {
    "T2": {"name": "ÚZIS Test", "info": "NZIS testovací prostředí (přístup na základě certifikátu ÚZIS/EREG)"},
    "PROD": {"name": "ÚZIS Produkce", "info": "NZIS produkční prostředí ÚZIS ČR"},
}


class UZISNrpzs:
    """Národní registr poskytovatelů zdravotních služeb – veřejné REST API ÚZIS.

    Volá nrpzs.uzis.cz/api/v1; při nedostupnosti použije vestavěné vzorky
    (`status()['zdroj'] == 'sample'`). Filtrování probíhá i lokálně.
    """

    _cache: list | None = None
    _source: str | None = None
    _error: str | None = None

    def __init__(self, client: SEZClient = None):
        self.c = client

    def _base(self) -> str:
        from sez_api import config as _cfg
        return getattr(_cfg, "UZIS_NRPZS_URL", "https://nrpzs.uzis.cz/api/v1").rstrip("/")

    def _samples(self) -> list:
        from sez_api import config as _cfg
        return [dict(x) for x in getattr(_cfg, "UZIS_NRPZS_SAMPLE", [])]

    def _fetch_all(self, force: bool = False) -> list:
        if UZISNrpzs._cache is not None and not force:
            return UZISNrpzs._cache
        url = self._base() + "/mista-poskytovani"
        try:
            resp = requests.get(url, params={"limit": 5000}, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            rows = data if isinstance(data, list) else data.get("data") or data.get("items") or []
            rows = [self._norm(r) for r in rows if isinstance(r, dict)]
            if not rows:
                raise ValueError("prázdná odpověď NRPZS")
            UZISNrpzs._cache = rows
            UZISNrpzs._source = "nrpzs"
            UZISNrpzs._error = None
            logger.info("NRPZS načteno: %d míst poskytování", len(rows))
        except Exception as exc:
            logger.warning("NRPZS API nedostupné (%s) – fallback na vzorky", exc)
            UZISNrpzs._cache = self._samples()
            UZISNrpzs._source = "sample"
            UZISNrpzs._error = str(exc)[:200]
        return UZISNrpzs._cache

    @staticmethod
    def _norm(r: dict) -> dict:
        """Best-effort mapování polí NRPZS (schéma se může lišit napříč verzemi)."""
        def g(*keys):
            for k in keys:
                for variant in (k, k.upper(), k.lower(), k.capitalize()):
                    if variant in r and r[variant] not in (None, ""):
                        return r[variant]
            return ""
        return {
            "icz": g("ZdravotnickeZarizeniId", "icz", "ZarizeniId", "id"),
            "ico": g("Ico", "ico"),
            "nazev": g("NazevZarizeni", "nazev", "Nazev", "PoskytovatelNazev"),
            "obec": g("Obec", "obec", "Mesto"),
            "kraj": g("Kraj", "kraj", "KrajNazev"),
            "psc": g("Psc", "psc"),
            "obor": g("OborPece", "obor", "Obor"),
            "forma": g("FormaPece", "forma", "Forma"),
            "druh": g("DruhPece", "druh", "Druh"),
            "adresa": g("Adresa", "adresa", "Ulice"),
            "web": g("Web", "web", "WebovaStranka"),
            "_raw": r,
        }

    def hledat(self, nazev=None, ico=None, obec=None, kraj=None, obor=None, limit=50) -> dict:
        rows = self._fetch_all()
        q = {"nazev": (nazev or "").lower(), "ico": (ico or "").lower(),
             "obec": (obec or "").lower(), "kraj": (kraj or "").lower(),
             "obor": (obor or "").lower()}

        def match(r):
            if q["nazev"] and q["nazev"] not in str(r.get("nazev", "")).lower():
                return False
            if q["ico"] and q["ico"] not in str(r.get("ico", "")).lower():
                return False
            if q["obec"] and q["obec"] not in str(r.get("obec", "")).lower():
                return False
            if q["kraj"] and q["kraj"] not in str(r.get("kraj", "")).lower():
                return False
            if q["obor"] and q["obor"] not in str(r.get("obor", "")).lower():
                return False
            return True

        any_q = any(q.values())
        matches = [r for r in rows if match(r)] if any_q else list(rows)
        return {"zdroj": UZISNrpzs._source, "pocet": len(matches),
                "limit": limit, "vysledky": matches[:limit]}

    def detail(self, ico_or_icz: str) -> dict:
        rows = self._fetch_all()
        key = (ico_or_icz or "").strip().lower()
        for r in rows:
            if key in (str(r.get("ico", "")).lower(), str(r.get("icz", "")).lower()):
                return {"zdroj": UZISNrpzs._source, "nalezeno": True, "poskytovatel": r}
        return {"zdroj": UZISNrpzs._source, "nalezeno": False, "poskytovatel": None}

    def ciselnik(self, nazev: str) -> dict:
        from sez_api import config as _cfg
        # Zkus reálný číselník NRPZS, jinak vzorky.
        try:
            resp = requests.get(self._base() + f"/ciselniky/{nazev}", timeout=10)
            resp.raise_for_status()
            return {"zdroj": "nrpzs", "polozky": resp.json()}
        except Exception:
            data = getattr(_cfg, "UZIS_CISELNIKY_SAMPLE", {})
            return {"zdroj": "sample", "polozky": data.get(nazev, [])}

    def status(self) -> dict:
        rows = self._fetch_all()
        return {"zdroj": UZISNrpzs._source, "pocet": len(rows),
                "chyba": UZISNrpzs._error, "url": self._base()}

    def reload(self) -> dict:
        self._fetch_all(force=True)
        return self.status()


class UZIS:
    """ÚZIS NZIS – Národní zdravotnické registry (NZR) a hlášení.

    Builder obálek + odeslání. LIVE (nakonfigurován endpoint + cert) posílá na
    reálné restAPI EREG; jinak vrací marker `{"_simulace": True, ...}` pro sim engine.
    """

    def __init__(self, client: SEZClient = None):
        self.c = client

    def _cfg(self):
        from sez_api import config as _cfg
        return _cfg

    def mode(self) -> str:
        return self._cfg().uzis_mode(SEZConfig.ENVIRONMENT)

    def katalog_registru(self) -> list:
        return list(self._cfg().UZIS_NZR_KATALOG)

    def _hlavicka(self, kontext: dict | None = None) -> dict:
        h = {
            "casVytvoreni": _iso_now(),
            "idKorelace": str(uuid.uuid4()),
            "system": "SEZ API Web (mirapavlicek/sezapi)",
        }
        if kontext:
            h["kontext"] = kontext
        return h

    def build_envelope(self, registr: str, operace: str, telo: dict,
                       kontext: dict | None = None) -> dict:
        return {"registr": registr, "operace": operace,
                "hlavicka": self._hlavicka(kontext), "telo": telo or {}}

    def _live_cert(self):
        cfg = self._cfg()
        if cfg.UZIS_CERT_PATH:
            try:
                return _load_pfx_pem(cfg.UZIS_CERT_PATH, cfg.UZIS_CERT_PASSWORD)
            except Exception as exc:
                logger.warning("ÚZIS cert %s nelze načíst: %s", cfg.UZIS_CERT_PATH, exc)
        if self.c is not None and getattr(self.c, "auth", None) is not None:
            try:
                return self.c.auth.tls_cert
            except Exception:
                pass
        return None

    def odeslat(self, registr: str, operace: str, telo: dict,
                kontext: dict | None = None) -> dict:
        env = self.build_envelope(registr, operace, telo, kontext)
        cfg = self._cfg()
        endpoint = cfg.uzis_nzr_endpoint(SEZConfig.ENVIRONMENT)
        if self.mode() == "LIVE" and endpoint:
            try:
                resp = requests.post(endpoint, json=env, timeout=30,
                                     cert=self._live_cert(),
                                     headers={"Content-Type": "application/json"})
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text[:2000]}
                return {"_simulace": False, "registr": registr, "operace": operace,
                        "http_status": resp.status_code, "request": env, "response": body}
            except Exception as exc:
                return {"_simulace": False, "registr": registr, "operace": operace,
                        "chyba": str(exc)[:300], "request": env}
        return {"_simulace": True, "registr": registr, "operace": operace, "request": env}

    def hlasit(self, registr: str, telo: dict, kontext: dict | None = None) -> dict:
        return self.odeslat(registr, "Hlaseni", telo, kontext)

    def stav_hlaseni(self, registr: str, id_hlaseni: str, kontext: dict | None = None) -> dict:
        return self.odeslat(registr, "StavHlaseni", {"idHlaseni": id_hlaseni}, kontext)

    def diagnose(self) -> dict:
        cfg = self._cfg()
        env = SEZConfig.ENVIRONMENT
        cert = self._live_cert()
        return {
            "enabled": cfg.UZIS_ENABLED,
            "mode": self.mode(),
            "nrpzs_url": cfg.UZIS_NRPZS_URL,
            "ereg_base": cfg.uzis_ereg_base(env),
            "apidoc": cfg.UZIS_APIDOC,
            "dasta_url": getattr(cfg, "UZIS_DASTA_URL", ""),
            "nzr_endpoint": cfg.uzis_nzr_endpoint(env) or "(nenastaveno – simulace)",
            "certifikat": bool(cert),
            "pocet_registru": len(cfg.UZIS_NZR_KATALOG),
            "prostredi": env,
        }


class UZISObsazenostLuzek:
    """ÚZIS eReg REST API – NRPZS / ObsazenostLůžek (Národní dispečink lůžkové péče).

    Rozhraní dle Metodiky hlášení obsazenosti lůžek v1.2 (ÚZIS).
    Base: api.uzis.cz/registr/nrpzs/v1 (prod) / apitest.uzis.cz (test).
    Dokumentace: apidoc.uzis.cz/Registr/NRPZS. Přístup vyžaduje systémový
    certifikát ÚZIS/EREG → GET číselníky mají offline fallback z configu,
    POST VolnaLuzka běží v simulaci, dokud není cert + endpoint.
    """

    PATH = "/registr/nrpzs/v1"

    def __init__(self, client: SEZClient = None):
        self.c = client

    def _cfg(self):
        from sez_api import config as _cfg
        return _cfg

    def _base(self) -> str:
        return self._cfg().uzis_ereg_base(SEZConfig.ENVIRONMENT).rstrip("/") + self.PATH

    def _live_cert(self):
        cfg = self._cfg()
        if cfg.UZIS_CERT_PATH:
            try:
                return _load_pfx_pem(cfg.UZIS_CERT_PATH, cfg.UZIS_CERT_PASSWORD)
            except Exception as exc:
                logger.warning("ÚZIS cert %s nelze načíst: %s", cfg.UZIS_CERT_PATH, exc)
        if self.c is not None and getattr(self.c, "auth", None) is not None:
            try:
                return self.c.auth.tls_cert
            except Exception:
                pass
        return None

    def _get(self, path: str, fallback_key: str | None = None) -> dict:
        """GET na eReg API (mTLS); při nedostupnosti fallback na číselník z configu."""
        url = self._base() + path
        try:
            resp = requests.get(url, timeout=12, cert=self._live_cert(),
                                headers={"Accept": "application/json"})
            resp.raise_for_status()
            return {"zdroj": "ereg", "polozky": resp.json()}
        except Exception as exc:
            data = self._cfg().UZIS_LUZKA_CISELNIKY.get(fallback_key, []) if fallback_key else []
            logger.warning("ÚZIS eReg %s nedostupné (%s) – fallback", path, str(exc)[:120])
            return {"zdroj": "sample", "polozky": data, "chyba": str(exc)[:160]}

    def nacti_formy_pece(self):
        return self._get("/ObsazenostLuzek/NactiFormyPece", "formy_pece")

    def nacti_obory_pece(self):
        return self._get("/ObsazenostLuzek/NactiOboryPece", "obory_pece")

    def nacti_vybaveni(self):
        return self._get("/ObsazenostLuzek/NactiVybaveni", "vybaveni")

    def nacti_skupiny_pacientu(self):
        return self._get("/ObsazenostLuzek/NactiSkupinyPacientu", "skupiny_pacientu")

    def nacti_zdravotnicka_zarizeni(self):
        return self._get("/ObsazenostLuzek/NactiZdravotnickeZarizeni", None)

    def probe(self) -> dict:
        url = self._base() + "/Status/Probe"
        try:
            resp = requests.get(url, timeout=8, cert=self._live_cert())
            return {"ok": resp.status_code == 200, "http_status": resp.status_code}
        except Exception as exc:
            return {"ok": False, "chyba": str(exc)[:160]}

    def hlas_volna_luzka(self, telo: dict) -> dict:
        """POST /ObsazenostLuzek/VolnaLuzka. LIVE s cert+endpointem, jinak sim marker."""
        cfg = self._cfg()
        url = self._base() + "/ObsazenostLuzek/VolnaLuzka"
        payload = {
            "ico": telo.get("ico", ""),
            "pcz": telo.get("pcz", ""),
            "pcdp": telo.get("pcdp", ""),
            "datumHlaseni": telo.get("datumHlaseni") or _iso_now(),
            "kodOborPece": telo.get("kodOborPece"),
            "kodFormaPece": telo.get("kodFormaPece"),
            "kodVybaveni": telo.get("kodVybaveni"),
            "kodSkupinaPacientu": telo.get("kodSkupinaPacientu"),
            "pocetVolnychLuzek": int(telo.get("pocetVolnychLuzek", 0) or 0),
            "celkovyPocetLuzek": int(telo.get("celkovyPocetLuzek", 0) or 0),
        }
        # Živě jen když je nakonfigurován reálný eReg endpoint (jiný než default veřejný apitest).
        live = cfg.UZIS_ENABLED and (cfg.UZIS_NZR_ENDPOINT or cfg.UZIS_NZR_ENDPOINT_TEST or cfg.UZIS_CERT_PATH)
        if live:
            try:
                resp = requests.post(url, json=payload, timeout=20,
                                     cert=self._live_cert(),
                                     headers={"Content-Type": "application/json"})
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text[:1000]}
                return {"_simulace": False, "http_status": resp.status_code,
                        "request": payload, "response": body}
            except Exception as exc:
                return {"_simulace": False, "chyba": str(exc)[:300], "request": payload}
        return {"_simulace": True, "request": payload}
