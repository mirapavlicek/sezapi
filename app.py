#!/usr/bin/env python3
"""
Zpětná kompatibilita – deleguje na sez_api.app.
Preferovaný způsob spuštění: sez-api serve  nebo  uvicorn sez_api.app:app
"""

from sez_api.app import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn
    from sez_api import config as cfg
    print(f"SEZ API Web UI: http://{cfg.HOST}:{cfg.PORT}")
    uvicorn.run("sez_api.app:app", host=cfg.HOST, port=cfg.PORT, reload=True)
