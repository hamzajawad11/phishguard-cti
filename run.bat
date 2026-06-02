@echo off
REM ============================================================
REM   PhishGuard - one-click launcher
REM   Double-click this file to start the CTI dashboard.
REM ============================================================
setlocal

REM Always run from the folder this script lives in
cd /d "%~dp0"

set "PORT=8000"
set "PYTHON=.venv\Scripts\python.exe"

REM --- First run only: create the virtual environment + install deps ---
if not exist "%PYTHON%" (
    echo [PhishGuard] First run - creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 python -m venv .venv
    echo [PhishGuard] Installing dependencies ^(one time only^)...
    "%PYTHON%" -m pip install --upgrade pip
    "%PYTHON%" -m pip install -r requirements.txt
)

if not exist "%PYTHON%" (
    echo [PhishGuard] ERROR: could not find or create the Python environment.
    echo            Make sure Python 3 is installed and on your PATH.
    pause
    exit /b 1
)

echo.
echo [PhishGuard] Starting server at http://127.0.0.1:%PORT%
echo [PhishGuard] Close this window or press Ctrl+C to stop.
echo.

REM Open the dashboard in the default browser once the server has had time to start
start "" /min cmd /c "ping -n 4 127.0.0.1 >nul & start http://127.0.0.1:%PORT%/"

REM Run the server in the foreground so the log stays visible in this window
"%PYTHON%" -m uvicorn app.main:app --host 127.0.0.1 --port %PORT%

echo.
echo [PhishGuard] Server stopped.
pause
endlocal
