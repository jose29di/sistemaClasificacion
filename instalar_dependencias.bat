@echo off
chcp 65001 >nul 2>&1
cls

echo ===============================================
echo INSTALADOR DE DEPENDENCIAS - SISTEMA RESULTADOS
echo ===============================================
echo.
echo Este script instalara todas las dependencias necesarias
echo para que el Sistema de Resultados funcione correctamente.
echo.
echo DEPENDENCIAS A INSTALAR:
echo - pandas (procesamiento de datos Excel)
echo - pillow (manejo de imagenes)
echo - openpyxl (lectura/escritura Excel)
echo - watchdog (monitoreo de archivos)
echo.
pause

echo.
echo ===============================================
echo VERIFICANDO PYTHON
echo ===============================================

python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python no esta instalado en el sistema
    echo.
    echo SOLUCION:
    echo 1. Descargar Python desde: https://www.python.org/downloads/
    echo 2. Durante la instalacion, marcar "Add Python to PATH"
    echo 3. Reiniciar el sistema
    echo 4. Ejecutar este script nuevamente
    echo.
    pause
    exit /b 1
)

python --version
echo Python encontrado correctamente.
echo.

echo ===============================================
echo ACTUALIZANDO PIP
echo ===============================================
python -m pip install --upgrade pip
echo.

echo ===============================================
echo INSTALANDO DEPENDENCIAS
echo ===============================================

echo Instalando pandas...
python -m pip install pandas
if %ERRORLEVEL% neq 0 (
    echo ERROR: Fallo la instalacion de pandas
    pause
    exit /b 1
)

echo Instalando Pillow...
python -m pip install Pillow
if %ERRORLEVEL% neq 0 (
    echo ERROR: Fallo la instalacion de Pillow
    pause
    exit /b 1
)

echo Instalando openpyxl...
python -m pip install openpyxl
if %ERRORLEVEL% neq 0 (
    echo ERROR: Fallo la instalacion de openpyxl
    pause
    exit /b 1
)

echo Instalando watchdog...
python -m pip install watchdog
if %ERRORLEVEL% neq 0 (
    echo ERROR: Fallo la instalacion de watchdog
    pause
    exit /b 1
)

echo.
echo ===============================================
echo VERIFICANDO INSTALACION
echo ===============================================

echo Verificando pandas...
python -c "import pandas; print('pandas:', pandas.__version__)" 2>nul
if %ERRORLEVEL% neq 0 (
    echo pandas: FALLO
    set ERRORS=1
) else (
    echo pandas: OK
)

echo Verificando PIL/Pillow...
python -c "from PIL import Image; print('Pillow: OK')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo Pillow: FALLO
    set ERRORS=1
) else (
    echo Pillow: OK
)

echo Verificando openpyxl...
python -c "import openpyxl; print('openpyxl:', openpyxl.__version__)" 2>nul
if %ERRORLEVEL% neq 0 (
    echo openpyxl: FALLO
    set ERRORS=1
) else (
    echo openpyxl: OK
)

echo Verificando watchdog...
python -c "import watchdog; print('watchdog: OK')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo watchdog: FALLO
    set ERRORS=1
) else (
    echo watchdog: OK
)

echo Verificando tkinter...
python -c "import tkinter; print('tkinter: OK')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo tkinter: FALLO (incluido con Python)
    set ERRORS=1
) else (
    echo tkinter: OK
)

echo Verificando sqlite3...
python -c "import sqlite3; print('sqlite3: OK')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo sqlite3: FALLO (incluido con Python)
    set ERRORS=1
) else (
    echo sqlite3: OK
)

echo.
if defined ERRORS (
    echo ===============================================
    echo INSTALACION COMPLETADA CON ERRORES
    echo ===============================================
    echo Algunas dependencias no se instalaron correctamente.
    echo Revise los errores anteriores y ejecute el script nuevamente.
) else (
    echo ===============================================
    echo INSTALACION COMPLETADA EXITOSAMENTE
    echo ===============================================
    echo Todas las dependencias se instalaron correctamente.
    echo El Sistema de Resultados esta listo para usar.
)

echo.
pause
