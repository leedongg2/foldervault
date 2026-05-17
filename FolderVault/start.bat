@echo off
setlocal
title FolderVault
cd /d "%~dp0"

echo ============================================
echo   FolderVault - Folder Security
echo ============================================
echo.

REM --- Check Python ---
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed.
    echo Install Python 3.9+ from https://www.python.org
    echo.
    pause
    exit /b 1
)

REM --- Create virtual environment on first run ---
if not exist ".venv\Scripts\pythonw.exe" (
    echo [1/2] First run - setting up environment. Please wait...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    echo.
    echo [2/2] Installing security libraries...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install libraries. Check your internet connection.
        pause
        exit /b 1
    )
    echo.
    echo Setup complete.
    echo.
)

REM --- Launch the app (no console window) ---
start "" ".venv\Scripts\pythonw.exe" "folder_vault.py"
exit /b 0
