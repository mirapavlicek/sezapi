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


class SEZConfig:
    GATEWAY = "https://gwy-ext-sec-t2.csez.cz"
    TOKEN_AUDIENCE = "https://jsuint-auth-t2.csez.cz/connect/token"
    ASSERTION_VALIDITY_SECONDS = 55


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

    def build_assertion(self) -> str:
        now = int(time.time())
        payload = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.config.TOKEN_AUDIENCE,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self.config.ASSERTION_VALIDITY_SECONDS,
        }
        headers = {"kid": self._kid}
        return jwt.encode(payload, self._signing_key, algorithm="RS256", headers=headers)

    def cleanup(self):
        import shutil
        if hasattr(self, "_tmp_dir") and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def __del__(self):
        self.cleanup()


class SEZClient:
    """HTTP klient pro SEZ API Gateway s automatickým retry."""

    def __init__(self, auth: SEZAuth):
        self.auth = auth
        self.config = auth.config
        self.session = requests.Session()
        self.session.cert = auth.tls_cert
        self.session.verify = True
        self.last_status = 0
        self.last_response = None

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
        kwargs["headers"] = self._headers(extra_headers)

        resp = self.session.request(method, url, **kwargs)
        self.last_status = resp.status_code

        if resp.status_code == 401 and retry:
            logger.warning("401 – generuji novou assertion a opakuji")
            kwargs["headers"] = self._headers(extra_headers)
            resp = self.session.request(method, url, **kwargs)
            self.last_status = resp.status_code

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

    def patch(self, path, body=None, params=None):
        return self._request("PATCH", path, json=body, params=params)

    def put(self, path, body=None):
        return self._request("PUT", path, json=body)

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

    def hledat_rid(self, rid, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/rid", self._envelope(ucel, {"rid": rid}))

    def hledat_jmeno_rc(self, jmeno, prijmeni, rc, ucel="LECBA"):
        return self.c.post(f"{self.BASE}/api/v2/pacient/hledat/jmeno_prijmeni_rc",
                           self._envelope(ucel, {"jmeno": jmeno, "prijmeni": prijmeni, "rodneCislo": rc}))


class DocasneUloziste:
    BASE = "/docasneUloziste"

    def __init__(self, client: SEZClient):
        self.c = client

    def dej_zasilku(self, zasilka_id):
        return self.c.get(f"{self.BASE}/api/v1/Zasilka/DejZasilku/{zasilka_id}")

    def vyhledej_zasilku(self, datum_od, datum_do, pacient=None, page=1, size=25):
        body = {"datumOd": datum_od, "datumDo": datum_do, "strankovani": {"page": page, "size": size}}
        if pacient:
            body["pacient"] = pacient
        return self.c.post(f"{self.BASE}/api/v1/Zasilka/VyhledejZasilku", body)

    def uloz_zasilku(self, zasilka):
        return self.c.post(f"{self.BASE}/api/v1/Zasilka/UlozZasilku", zasilka)


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


class Notifikace:
    BASE = "/notifikace"

    def __init__(self, client: SEZClient):
        self.c = client

    def ping(self):
        return self.c.get(f"{self.BASE}/api/v1/notifikace/ping")

    def odeslat(self, notifikace):
        return self.c.post(f"{self.BASE}/api/v1/notifikace/odeslat", notifikace)

    def vyhledat(self, id_prijemce, od_data, page=1, size=25):
        return self.c.get(f"{self.BASE}/api/v1/notifikace/vyhledat",
                          params={"idPrijemce": id_prijemce, "odData": od_data, "page": page, "size": size})

    def katalog_kanalu(self, page=1, size=25):
        return self.c.get(f"{self.BASE}/api/v1/kanaly/katalog", params={"page": page, "size": size})

    def katalog_sablon(self, page=1, size=25):
        return self.c.get(f"{self.BASE}/api/v1/sablony/katalog", params={"page": page, "size": size})

    def katalog_zdroju(self, page=1, size=25):
        return self.c.get(f"{self.BASE}/api/v1/zdroje/katalog", params={"page": page, "size": size})
