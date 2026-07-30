"""
Úložiště klientských certifikátů (PKCS#12) pro SEZ API.

Slouží k převzetí ostrého certifikátu z centrální distribuce: certifikát
přijde jako base64 v JSON, tady se zvaliduje, uloží a zařadí do provozu.

Vlastnosti důležité pro ostrý provoz:

* **Validace před uložením** – PKCS#12 musí jít otevřít zadaným heslem a
  obsahovat privátní klíč i certifikát; neplatný (expirovaný / ještě
  nezačínající) se bez ``vynutit`` odmítne.
* **Atomický zápis** – soubor se zapíše do temp a přesune přes ``os.replace``,
  takže běžící proces nikdy nečte poloviční certifikát.
* **Záloha a rollback** – předchozí verze se odkládá do podadresáře
  ``historie``, takže se lze vrátit, když nový certifikát brána odmítne.
* **Práva 0600** – certifikát i soubor s heslem jsou čitelné jen pro
  uživatele procesu; heslo se nikde nevrací ani neloguje.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.extensions import SubjectKeyIdentifier

logger = logging.getLogger("sez_api.certstore")

# Kolik předchozích verzí se drží v historii.
MAX_HISTORIE = 10

_PREFIX_DATA_URL = re.compile(r"^data:[^;]*;base64,", re.I)


class CertChyba(ValueError):
    """Certifikát nelze převzít (nevalidní vstup, heslo, platnost)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def dekoduj_pfx(pfx_base64: str) -> bytes:
    """Dekóduje PKCS#12 z base64. Tolerantní ke zabalení, které přidávají
    distribuční nástroje: data URL prefix, zalomené řádky, mezery."""
    if not pfx_base64 or not pfx_base64.strip():
        raise CertChyba("Pole s certifikátem (pfxBase64) je prázdné.")
    text = _PREFIX_DATA_URL.sub("", pfx_base64.strip())
    text = "".join(text.split())
    # Chybějící zarovnání "=" na násobek 4 doplníme, jinak base64 selže.
    text += "=" * (-len(text) % 4)
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertChyba(f"Certifikát není platný base64: {exc}") from exc
    if not data:
        raise CertChyba("Dekódovaný certifikát je prázdný.")
    return data


def _kid_z_certifikatu(cert) -> str:
    """Fallback identifikátor klíče, když distribuce nepošle UID z EZCA."""
    try:
        ski = cert.extensions.get_extension_for_class(SubjectKeyIdentifier)
        return ski.value.digest.hex()
    except Exception:
        return cert.fingerprint(SHA256()).hex()


def _platnost(cert) -> tuple:
    """(platny_od, platny_do) v UTC – s podporou starších verzí cryptography."""
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return (cert.not_valid_before.replace(tzinfo=timezone.utc),
                cert.not_valid_after.replace(tzinfo=timezone.utc))


def zkontroluj_pfx(pfx: bytes, password: str, *, vynutit: bool = False) -> dict:
    """Otevře PKCS#12 a vrátí popis certifikátu.

    ``vynutit=True`` přijme i certifikát mimo dobu platnosti (potřeba jen při
    předstihové distribuci, kdy ještě nezačala platnost).
    """
    pwd = password.encode() if isinstance(password, str) else (password or None)
    try:
        key, cert, _ca = pkcs12.load_key_and_certificates(pfx, pwd)
    except Exception as exc:
        raise CertChyba(
            "PKCS#12 nelze otevřít – zkontrolujte heslo a formát souboru "
            f"({type(exc).__name__}).") from exc
    if cert is None:
        raise CertChyba("PKCS#12 neobsahuje certifikát.")
    if key is None:
        raise CertChyba(
            "PKCS#12 neobsahuje privátní klíč – pro mTLS i podpis JWT je nutný.")

    platny_od, platny_do = _platnost(cert)
    ted = _now()
    dny = (platny_do - ted).days
    if not vynutit:
        if ted < platny_od:
            raise CertChyba(
                f"Certifikát začíná platit až {platny_od.date().isoformat()}. "
                "Pro předstihové nasazení použijte vynutitNeplatny=true.")
        if ted > platny_do:
            raise CertChyba(
                f"Certifikát vypršel {platny_do.date().isoformat()}.")

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serialNumber": format(cert.serial_number, "x"),
        "platnyOd": platny_od.isoformat(),
        "platnyDo": platny_do.isoformat(),
        "dnyDoExpirace": dny,
        "fingerprintSha256": cert.fingerprint(SHA256()).hex(),
        "kid": _kid_z_certifikatu(cert),
    }


class CertStore:
    """Adresář s aktivním certifikátem a historií předchozích verzí."""

    def __init__(self, dir_path: str | os.PathLike, prostredi: str = "PROD"):
        self.dir = Path(dir_path)
        self.prostredi = prostredi

    # --- cesty ------------------------------------------------------------
    @property
    def zaklad(self) -> str:
        return self.prostredi.lower()

    @property
    def pfx_path(self) -> Path:
        return self.dir / f"{self.zaklad}.p12"

    @property
    def pass_path(self) -> Path:
        return self.dir / f"{self.zaklad}.p12.pass"

    @property
    def meta_path(self) -> Path:
        return self.dir / f"{self.zaklad}.json"

    @property
    def historie_dir(self) -> Path:
        return self.dir / "historie"

    # --- čtení ------------------------------------------------------------
    def existuje(self) -> bool:
        return self.pfx_path.is_file()

    def heslo(self) -> str:
        """Heslo k aktivnímu certifikátu (pro sestavení klienta)."""
        if not self.pass_path.is_file():
            return ""
        return self.pass_path.read_text(encoding="utf-8").strip()

    def metadata(self) -> dict:
        if not self.meta_path.is_file():
            return {}
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Metadata certifikátu nelze přečíst: %s", exc)
            return {}

    def info(self) -> dict:
        """Popis aktivního certifikátu; při chybějícím souboru {}."""
        if not self.existuje():
            return {}
        meta = dict(self.metadata())
        try:
            popis = zkontroluj_pfx(self.pfx_path.read_bytes(), self.heslo(),
                                   vynutit=True)
            meta.update(popis)
        except CertChyba as exc:
            meta["chyba"] = str(exc)
        meta.setdefault("prostredi", self.prostredi)
        meta["cesta"] = str(self.pfx_path)
        return meta

    def historie(self) -> list:
        """Zálohy od nejnovější."""
        if not self.historie_dir.is_dir():
            return []
        polozky = []
        for meta_file in sorted(self.historie_dir.glob(f"{self.zaklad}-*.json"),
                                reverse=True):
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            data["zaloha"] = meta_file.stem
            polozky.append(data)
        return polozky

    # --- zápis ------------------------------------------------------------
    def _zapis_atomicky(self, cesta: Path, data: bytes) -> None:
        """Zapíše soubor tak, aby jej běžící proces nikdy neviděl rozepsaný."""
        cesta.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(cesta.parent), prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, cesta)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _zaloh(self) -> dict | None:
        """Odloží aktivní certifikát do historie. Vrací metadata zálohy."""
        if not self.existuje():
            return None
        znacka = _now().strftime("%Y%m%dT%H%M%SZ")
        self.historie_dir.mkdir(parents=True, exist_ok=True)
        meta = self.info()
        meta["zalohovanoV"] = _now().isoformat()
        zaloha_pfx = self.historie_dir / f"{self.zaklad}-{znacka}.p12"
        self._zapis_atomicky(zaloha_pfx, self.pfx_path.read_bytes())
        self._zapis_atomicky(self.historie_dir / f"{self.zaklad}-{znacka}.p12.pass",
                             self.heslo().encode())
        self._zapis_atomicky(self.historie_dir / f"{self.zaklad}-{znacka}.json",
                             json.dumps(meta, ensure_ascii=False, indent=2).encode())
        self._prorez_historii()
        return meta

    def _prorez_historii(self) -> None:
        zalohy = sorted(self.historie_dir.glob(f"{self.zaklad}-*.p12"), reverse=True)
        for stara in zalohy[MAX_HISTORIE:]:
            for pripona in (".p12", ".p12.pass", ".json"):
                cesta = stara.with_name(stara.stem + pripona)
                try:
                    cesta.unlink(missing_ok=True)
                except OSError as exc:
                    logger.warning("Starou zálohu %s nelze smazat: %s", cesta, exc)

    def uloz(self, pfx: bytes, password: str, *, popis: dict,
             client_id: str = "", cert_uid: str = "",
             poznamka: str = "", zdroj: str = "") -> dict:
        """Zazálohuje stávající certifikát a uloží nový. Vrací (metadata)."""
        predchozi = self._zaloh()
        meta = dict(popis)
        meta.update({
            "prostredi": self.prostredi,
            "clientId": client_id or (predchozi or {}).get("clientId", ""),
            "certUid": cert_uid or popis.get("kid", ""),
            "poznamka": poznamka,
            "zdroj": zdroj,
            "nahranoV": _now().isoformat(),
            "cesta": str(self.pfx_path),
        })
        self._zapis_atomicky(self.pfx_path, pfx)
        self._zapis_atomicky(self.pass_path, (password or "").encode())
        self._zapis_atomicky(self.meta_path,
                             json.dumps(meta, ensure_ascii=False, indent=2).encode())
        logger.info("Certifikát %s uložen: subject=%s platnost do %s",
                    self.prostredi, meta.get("subject"), meta.get("platnyDo"))
        return meta

    def rollback(self, zaloha: str = "") -> dict:
        """Vrátí certifikát z historie (výchozí = nejnovější záloha)."""
        if not self.historie_dir.is_dir():
            raise CertChyba("Historie certifikátů je prázdná – není kam se vrátit.")
        if zaloha:
            pfx = self.historie_dir / f"{zaloha}.p12"
            if not pfx.is_file():
                raise CertChyba(f"Záloha '{zaloha}' neexistuje.")
        else:
            zalohy = sorted(self.historie_dir.glob(f"{self.zaklad}-*.p12"),
                            reverse=True)
            if not zalohy:
                raise CertChyba("Historie certifikátů je prázdná – není kam se vrátit.")
            pfx = zalohy[0]

        pass_file = pfx.with_name(pfx.stem + ".p12.pass")
        heslo = pass_file.read_text(encoding="utf-8").strip() if pass_file.is_file() else ""
        data = pfx.read_bytes()
        popis = zkontroluj_pfx(data, heslo, vynutit=True)

        meta_file = pfx.with_name(pfx.stem + ".json")
        puvodni = {}
        if meta_file.is_file():
            try:
                puvodni = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception:
                puvodni = {}

        return self.uloz(data, heslo, popis=popis,
                         client_id=puvodni.get("clientId", ""),
                         cert_uid=puvodni.get("certUid", ""),
                         poznamka=f"rollback ze zálohy {pfx.stem}",
                         zdroj="rollback")
