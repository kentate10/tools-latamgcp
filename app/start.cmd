@echo off
setlocal
cd /d "%~dp0"
set "PYTHON="
for %%P in (python.exe py.exe) do if not defined PYTHON for /f "delims=" %%I in ('where %%P 2^>nul') do if not defined PYTHON set "PYTHON=%%I"
if not defined PYTHON (
  echo No se encontro Python 3.10+. Ver README.md de la raiz del repo.
  exit /b 1
)
"%PYTHON%" check_env.py || exit /b 1
"%PYTHON%" run_local.py --open
