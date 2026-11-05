"""Entrada del panel local Tools LatamGCP."""

import argparse
import json
import threading
import webbrowser
from urllib.request import urlopen

from interfaz.server import APP_ID, make_server
from managed_store import ManagedStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--open", action="store_true")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    url = f"http://127.0.0.1:{args.port}"
    try:
        server = make_server(args.port, ManagedStore())
    except OSError:
        try:
            with urlopen(url + "/api/health", timeout=2) as response:
                healthy = json.load(response).get("app") == APP_ID
        except Exception:
            healthy = False
        if not healthy:
            raise SystemExit("El puerto está ocupado por otra aplicación")
        if args.open:
            webbrowser.open(url)
        return
    print("Tools LatamGCP local: " + url, flush=True)
    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
