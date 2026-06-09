@echo off
cd /d "%~dp0"
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe tui\app.py %*
) else (
    python tui\app.py %*
)
