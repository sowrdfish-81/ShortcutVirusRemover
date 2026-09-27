@echo off
rem builds the single setup exe with WiX 3.14. Put the WiX binaries in tools\wix or have candle.exe on PATH.
setlocal
cd /d %~dp0

set WIX=%~dp0tools\wix\
if not exist "%WIX%candle.exe" (
    for /f "delims=" %%i in ('where candle.exe 2^>nul') do set WIX=%%~dpi
)
if not exist "%WIX%candle.exe" (
    echo WiX toolset not found. Download WiX 3.14 and put its binaries in tools\wix.
    exit /b 1
)

if not exist dist\ShortcutVirusRemover.exe call build.bat || exit /b 1
if not exist obj mkdir obj

"%WIX%candle.exe" -arch x64 -dAppExe="%~dp0dist\ShortcutVirusRemover.exe" -out obj\Product.wixobj installer\Product.wxs || exit /b 1
"%WIX%light.exe" -out obj\ShortcutVirusRemover.msi obj\Product.wixobj || exit /b 1
"%WIX%candle.exe" -out obj\Bundle.wixobj installer\Bundle.wxs || exit /b 1
"%WIX%light.exe" -out dist\ShortcutVirusRemover-Setup.exe obj\Bundle.wixobj -ext "%WIX%WixBalExtension.dll" || exit /b 1

echo Done: dist\ShortcutVirusRemover-Setup.exe
endlocal
