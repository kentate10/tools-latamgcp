# Instrucciones para Codex / agentes

Este repo es un panel LOCAL de vulnerabilidades sobre GCP (solo lectura). Antes de tocar nada lee `README.md` y `app/HANDOFF.md`.

## Si el usuario pide "instala/haz funcional esto"
1. Verifica Python 3.10+ (`python --version`). Si falta: `winget install Python.Python.3.12`.
2. Verifica Google Cloud SDK (`gcloud --version`). Si falta: `winget install Google.CloudSDK`, reabrir terminal.
3. Pide al usuario que ejecute el mismo `gcloud auth login` con SU cuenta corporativa (es interactivo en el navegador; no lo hagas por el).
4. `cd app` y `python check_env.py` (debe dar todo [OK]).
5. `python -m unittest discover -s . -p "test_*.py"` (deben pasar todas).
6. `python run_local.py --open` y abrir http://127.0.0.1:8765.

## Reglas que no se rompen
- Cero Prisma. GCP solo lectura. Servidor solo en 127.0.0.1.
- Nunca guardar tokens, llaves ni credenciales en disco, repo o navegador. El token sale de `gcloud auth print-access-token`, en memoria.
- Un error de permisos (403) jamas se muestra como "0 hallazgos".
- No usar datos locales (CSV, JSON, snapshots) como fuente: todo en vivo desde GCP.
- No commitear `app/evidence/`, ni `gcp_*.json`, ni `inventario*.json` (ver `.gitignore`).
- No modificar permisos IAM ni crear recursos en GCP sin aprobacion explicita.

## Si algo falla
- 403 en un modulo: faltan permisos de la cuenta del usuario, no es bug. Ver README, seccion Permisos.
- "no autorizada" tras reiniciar: refrescar la pagina (token CSRF nuevo).
- Actualizar: `git pull` y reiniciar `start.cmd`.
