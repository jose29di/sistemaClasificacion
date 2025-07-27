#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Punto de entrada principal del Sistema de Resultados
Este archivo orquesta el flujo completo del sistema.
"""

import sys
import os
import traceback

# Agregar el directorio actual al path para importaciones
if "." not in sys.path:
    sys.path.insert(0, ".")

try:
    from loading_screen import LoadingScreen
    from config_manager import ConfigManager
    from resultados_sistema import init_sistema_resultados, main as run_resultados

    def main():
        """Función principal que orquesta todo el flujo del sistema"""
        try:
            # 0. Inicializar sistema de resultados (rutas, licencia, etc.)
            print("Inicializando sistema...")
            init_success = init_sistema_resultados()
            if not init_success:
                print("ERROR: No se pudo inicializar el sistema")
                sys.exit(1)  # 1. Mostrar pantalla de carga
            loading = LoadingScreen()
            loading.show()

            # 2. Agregar actualización de progreso
            loading.update_status("Verificando configuración...")

            # 3. Verificar si existe configuración
            config_manager = ConfigManager()
            has_config = config_manager.is_configured()

            if not has_config:
                loading.update_status("Configuración requerida...")
                loading.hide()

                # Abrir formulario de configuración ANTES de iniciar el sistema principal
                import tkinter as tk
                from config_form import show_config_form

                # Crear una ventana temporal para el formulario
                temp_root = tk.Tk()
                temp_root.withdraw()  # Ocultar la ventana temporal

                # Mostrar formulario de configuración
                success = show_config_form(None)  # Sin parent para evitar conflictos

                # Cerrar ventana temporal
                temp_root.destroy()

                if not success:
                    print("Configuración cancelada. Saliendo...")
                    sys.exit(0)

            # 4. Finalizar carga
            loading.update_status("Iniciando sistema...")
            loading.hide()

            # 5. Ejecutar sistema de resultados
            print("Ejecutando sistema de resultados...")
            run_resultados()

        except Exception as e:
            print(f"ERROR en main(): {e}")
            traceback.print_exc()
            sys.exit(1)

    if __name__ == "__main__":
        main()

except ImportError as e:
    print(f"ERROR: Falta dependencia: {e}")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)
