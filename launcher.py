import os
import sys
import subprocess
from tkinter import messagebox
import tkinter as tk
import datetime


def log_error(mensaje):
    """Guarda un mensaje en el archivo de log"""
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'launcher_log.txt')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"\n[{timestamp}] {mensaje}")
    except:
        pass  # Si no podemos escribir el log, continuamos sin él


def mostrar_error(titulo, mensaje):
    """Muestra un mensaje de error en una ventana"""
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(titulo, mensaje)
    root.destroy()


def verificar_python():
    """Verifica que Python esté instalado y disponible"""
    try:
        # Intentar primero con python
        subprocess.run(
            ["python", "--version"],
            check=True,
            capture_output=True,
            text=True
        )
        log_error("Usando comando 'python'")
        return "python"
    except Exception:
        try:
            # Si falla, intentar con py
            subprocess.run(
                ["py", "--version"],
                check=True,
                capture_output=True,
                text=True
            )
            log_error("Usando comando 'py'")
            return "py"
        except Exception:
            log_error("No se encontró Python")
            return None

def mostrar_error(titulo, mensaje):
    """Muestra un mensaje de error en una ventana"""
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal
    messagebox.showerror(titulo, mensaje)
    root.destroy()

def verificar_dependencia(dep, python_cmd):
    """Verifica si una dependencia está instalada ejecutando python -c 'import...'"""
    try:
        # Mapeo de nombres de paquetes a sus módulos de importación
        import_names = {
            "pandas": "pandas",
            "Pillow": "PIL",
            "openpyxl": "openpyxl",
            "watchdog": "watchdog",
            "pywin32": "win32api"  # pywin32 se importa como win32api
        }
        
        module_name = import_names.get(dep, dep)
        
        # Intentar importar usando python -c
        result = subprocess.run(
            [python_cmd, "-c", f"import {module_name}"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            log_error(f"{dep} está disponible")
            return True
        else:
            log_error(f"{dep} no está disponible")
            return False
            
    except Exception as e:
        log_error(f"Error verificando {dep}: {str(e)}")
        return False

def main():
    try:
        log_error("Iniciando launcher...")
        
        # Verificar Python
        log_error("Verificando instalación de Python...")
        python_cmd = verificar_python()
        if not python_cmd:
            msg = "Python no está instalado o no está en el PATH"
            log_error(f"Error: {msg}")
            mostrar_error("Error de Python", 
                        msg + "\nPor favor, instale Python desde python.org")
            return

        # Obtener la ruta absoluta del directorio donde está el launcher
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        script_path = "resultados_sistema.py"
        ruta_completa = os.path.join(base_dir, script_path)
        
        log_error(f"Directorio base: {base_dir}")
        log_error(f"Buscando script: {ruta_completa}")
        
        if not os.path.exists(ruta_completa):
            msg = f"No se encuentra el archivo: {ruta_completa}"
            log_error(f"Error: {msg}")
            mostrar_error("Error", msg)
            return

        # Verificar que las dependencias estén disponibles
        log_error("Verificando dependencias...")
        dependencies = ["pandas", "Pillow", "openpyxl", "watchdog", "pywin32"]
        missing_deps = []
        
        for dep in dependencies:
            if not verificar_dependencia(dep, python_cmd):
                missing_deps.append(dep)
        
        if missing_deps:
            msg = "Faltan las siguientes dependencias:\n" + "\n".join(missing_deps)
            log_error(f"Error: {msg}")
            mostrar_error("Error de Dependencias", msg + 
                         "\n\nEjecute instalar_dependencias.bat primero")
            return
        
        # Intentar ejecutar el script
        log_error("Preparando ejecución del script...")
        
        # Bucle principal para mantener el programa ejecutándose
        while True:
            try:
                log_error(f"Iniciando nueva ejecución con {python_cmd}...")
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"

                process = subprocess.Popen(
                    [python_cmd, ruta_completa],
                    cwd=base_dir,
                    env=env
                )

                # Esperar a que el proceso termine
                process.wait()

                # Leer el código de salida de la base de datos
                try:
                    from config_manager import ConfigManager
                    config_db_path = os.path.join(base_dir, "config.db")
                    config_manager = ConfigManager(config_db_path)
                    config = config_manager.get_all_config()
                    exit_code = int(config.get("EXIT_CODE", "999"))  # Código por defecto 999
                    log_error(f"Código de salida configurado: {exit_code}")
                except Exception as e:
                    log_error(f"Error leyendo código de salida: {e}")
                    exit_code = 999  # Usar código por defecto si hay error

                # Si el proceso termina con el código de salida configurado, salir del launcher
                if process.returncode == exit_code:
                    log_error(f"Programa cerrado por el usuario con código {exit_code}")
                    break
                # Si terminó normalmente (código 0 o 1), volver a ejecutar
                elif process.returncode in [0, 1]:
                    log_error("Esperando a que la instancia anterior se cierre...")
                    import time
                    time.sleep(2)  # Esperar 2 segundos antes de reiniciar
                    log_error("Reiniciando el programa...")
                    continue
                else:
                    log_error(f"Error inesperado (código {process.returncode})")
                    mostrar_error("Error", "El programa se cerró de forma inesperada")
                    break

            except Exception as e:
                log_error(f"Error al ejecutar: {str(e)}")
                mostrar_error("Error al ejecutar", str(e))
                break
            
    except subprocess.CalledProcessError:
        mostrar_error(
            "Error de Python",
            "Python no está instalado o no está en el PATH.\n\n" +
            "1. Instale Python desde python.org\n" +
            "2. Marque la opción 'Add Python to PATH' durante la instalación"
        )
        
    except Exception as e:
        mostrar_error("Error", f"Error inesperado: {str(e)}")

if __name__ == "__main__":
    main()
