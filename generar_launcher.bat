@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

echo ===============================================
echo GENERADOR DE EJECUTABLE LIVIANO (LAUNCHER)
echo ===============================================
echo.
echo Este ejecutable:
echo - Usará las librerías del sistema
echo - Será ultra liviano (menos de 1MB)
echo - Tendrá inicio instantáneo
echo - Instalará dependencias si faltan
echo.

echo 1. Verificando Python...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python no esta instalado
    echo Instale Python desde python.org
    echo Asegúrese de marcar "Add Python to PATH"
    pause
    exit /b 1
)

echo 2. Instalando PyInstaller...
python -m pip install --upgrade pyinstaller

echo 3. Verificando archivos necesarios...
if not exist "launcher.py" (
    echo ERROR: No se encuentra launcher.py
    pause
    exit /b 1
)

echo 4. Limpiando builds anteriores...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
if exist "*.spec" del /q "*.spec"

echo 5. Creando launcher liviano...
pyinstaller --noconfirm ^
    --onefile ^
    --windowed ^
    --name "SistemaResultados" ^
    --icon "img/kiosco.ico" ^
    --exclude-module pandas ^
    --exclude-module PIL ^
    --exclude-module Pillow ^
    --exclude-module openpyxl ^
    --exclude-module numpy ^
    --exclude-module watchdog ^
    launcher.py

if %ERRORLEVEL% neq 0 (
    echo ERROR: Fallo la creación del launcher
    pause
    exit /b 1
)

echo 6. Verificando launcher...
if not exist "dist\SistemaResultados.exe" (
    echo ERROR: No se generó el launcher
    pause
    exit /b 1
)

echo 7. Creando paquete de distribución...
if exist "Sistema_Resultados" rmdir /s /q "Sistema_Resultados"
mkdir "Sistema_Resultados"

echo 8. Copiando archivos...
copy "dist\SistemaResultados.exe" "Sistema_Resultados\" >nul
copy "resultados_sistema.py" "Sistema_Resultados\" >nul
copy "config_manager.py" "Sistema_Resultados\" >nul
copy "config_form.py" "Sistema_Resultados\" >nul
copy "loading_screen.py" "Sistema_Resultados\" >nul
copy "config.db" "Sistema_Resultados\" >nul
if exist "license.lic" copy "license.lic" "Sistema_Resultados\" >nul

if not exist "Sistema_Resultados\img" mkdir "Sistema_Resultados\img"
xcopy "img\*.*" "Sistema_Resultados\img\" /E /I /Y >nul

echo 9. Creando instrucciones...
echo SISTEMA DE RESULTADOS - VERSION LIVIANA > "Sistema_Resultados\INSTRUCCIONES.txt"
echo ========================================= >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo. >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo REQUISITOS: >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo - Windows 10/11 >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo - Python 3.8 o superior >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo. >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo PRIMERA EJECUCION: >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo 1. Instalar Python desde python.org >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo 2. IMPORTANTE: Marcar "Add Python to PATH" durante la instalación >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo 3. Ejecutar SistemaResultados.exe >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo. >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo VENTAJAS: >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo - Usa las librerías del sistema >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo - Ultra liviano y rápido >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo - Instala dependencias automáticamente >> "Sistema_Resultados\INSTRUCCIONES.txt"
echo - Compatible con cualquier Python 3.8+ >> "Sistema_Resultados\INSTRUCCIONES.txt"

echo 10. Limpiando archivos temporales...
rmdir /s /q "build" 2>nul
rmdir /s /q "dist" 2>nul
del /q "*.spec" 2>nul

echo.
echo ===============================================
echo LAUNCHER GENERADO EXITOSAMENTE
echo ===============================================
echo.
echo El sistema se encuentra en:
echo Sistema_Resultados\SistemaResultados.exe
echo.
echo CARACTERISTICAS:
echo - Launcher ultra liviano
echo - Usa librerías del sistema
echo - Instala dependencias automáticamente
echo - Compatible con cualquier Python 3.8+
echo.
pause
