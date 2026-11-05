"""Verifica el entorno antes de arrancar el panel (solo lectura, no guarda nada)."""
import shutil
import subprocess
import sys


def main():
    ok = True
    if sys.version_info < (3, 10):
        print(f"[X] Python {sys.version.split()[0]}: se requiere 3.10 o superior")
        ok = False
    else:
        print(f"[OK] Python {sys.version.split()[0]}")
    gcloud = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if not gcloud:
        print("[X] gcloud no esta en el PATH. Instala Google Cloud SDK y reabre la terminal.")
        return 1
    print(f"[OK] gcloud: {gcloud}")
    result = subprocess.run([gcloud, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
                            capture_output=True, text=True, timeout=60)
    accounts = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(accounts) != 1:
        print("[X] Se requiere exactamente una cuenta activa de gcloud. Ejecuta: gcloud auth login")
        ok = False
    else:
        print(f"[OK] Cuenta activa: {accounts[0]}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
