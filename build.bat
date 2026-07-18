@echo off
setlocal

cd /d "%~dp0"
set "CGO_ENABLED=0"

where go >nul 2>nul
if errorlevel 1 (
    echo Error: Go was not found in PATH.
    endlocal
    exit /b 1
)

go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
if errorlevel 1 (
    echo Build failed.
    endlocal
    exit /b 1
)

echo Build complete: xray.exe
endlocal
exit /b 0
