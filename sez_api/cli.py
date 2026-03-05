"""
CLI entry point pro SEZ API.
Spustí webové rozhraní nebo provede rychlý test připojení.
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="sez-api",
        description="SEZ API klient – webové rozhraní pro Sdílené elektronické zdravotnictví",
    )
    sub = parser.add_subparsers(dest="command")

    serve_cmd = sub.add_parser("serve", help="Spustí webové rozhraní (výchozí)")
    serve_cmd.add_argument("--host", default=None, help="Adresa serveru (výchozí: 0.0.0.0)")
    serve_cmd.add_argument("--port", type=int, default=None, help="Port (výchozí: 8004)")
    serve_cmd.add_argument("--reload", action="store_true", help="Automatický reload při změnách")

    sub.add_parser("ping", help="Rychlý test připojení ke všem službám")
    sub.add_parser("version", help="Zobrazí verzi")

    args = parser.parse_args()
    command = args.command or "serve"

    if command == "version":
        from sez_api import __version__
        print(f"sez-api {__version__}")
        return

    if command == "ping":
        _ping()
        return

    _serve(args)


def _serve(args):
    import uvicorn
    from sez_api import config as cfg

    host = getattr(args, "host", None) or cfg.HOST
    port = getattr(args, "port", None) or cfg.PORT
    reload = getattr(args, "reload", False)

    print(f"SEZ API Web UI: http://{host}:{port}")
    print(f"  Client ID: {cfg.CLIENT_ID}")
    print(f"  Gateway:   {cfg.GATEWAY}")
    print(f"  Certifikát: {cfg.P12_PATH}")
    print()

    uvicorn.run("sez_api.app:app", host=host, port=port, reload=reload)


def _ping():
    from sez_api import config as cfg
    cfg.validate()

    from sez_api.client import (
        SEZAuth, SEZClient,
        KRP, KRZP, DocasneUloziste, SZZ, ELP, EZadanky, Notifikace, EZCA2,
    )

    print(f"Připojuji se k {cfg.GATEWAY}...")
    auth = SEZAuth(
        client_id=cfg.CLIENT_ID,
        p12_path=cfg.P12_PATH,
        p12_password=cfg.P12_PASSWORD,
        cert_uid=cfg.CERT_UID or None,
    )
    client = SEZClient(auth)

    checks = [
        ("Notifikace", lambda: Notifikace(client).ping()),
        ("KRP",        lambda: KRP(client).hledat_rid("7653800856")),
        ("SZZ",        lambda: SZZ(client).alergie("7706120004")),
        ("ELP",        lambda: ELP(client).vyhledej_posudky({"strankovani": {"page": 0, "size": 1}})),
        ("eZadanky",   lambda: EZadanky(client).dej_token()),
        ("EZCA2",      lambda: EZCA2(client).simple_health()),
        ("KRZP",       lambda: KRZP(client).hledat_jmeno("Novák", "Jan")),
    ]

    ok = 0
    for name, fn in checks:
        try:
            r = fn()
            status = r.status_code
            mark = "OK" if status == 200 else f"WARN ({status})"
            if status == 200:
                ok += 1
        except Exception as e:
            mark = f"FAIL ({e})"
        print(f"  {name:15s} {mark}")

    print(f"\n{ok}/{len(checks)} služeb dostupných")
    auth.cleanup()
    sys.exit(0 if ok == len(checks) else 1)


if __name__ == "__main__":
    main()
