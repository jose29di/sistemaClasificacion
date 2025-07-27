"""
Gestor de configuración con SQLite para el sistema de resultados.
Maneja la lectura, escritura y validación de configuraciones.
"""

import sqlite3
import os
import sys
from typing import Dict, Optional, Any


class ConfigManager:
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Detectar directorio base correctamente
            if getattr(sys, "frozen", False):
                # Si es ejecutable
                base_dir = os.path.dirname(sys.executable)
            else:
                # Si es script
                base_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(base_dir, "config.db")
        else:
            self.db_path = db_path

        self.base_dir = os.path.dirname(self.db_path)
        self._init_db()

    def _init_db(self):
        """Inicializa la base de datos si no existe"""
        if not os.path.exists(self.db_path):
            self._create_default_config()

    def _create_default_config(self):
        """Crea la configuración por defecto"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Crear tabla si no existe
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS configuracion (
                clave TEXT PRIMARY KEY,
                valor TEXT,
                descripcion TEXT,
                tipo TEXT DEFAULT 'text'
            )
        """
        )

        # Configuración por defecto
        default_config = [
            ("EVENTO", "Evento de pruebas", "Nombre del evento", "text"),
            (
                "TITULO",
                "Sistema de resultados preliminares",
                "Título del sistema",
                "text",
            ),
            (
                "CARRUSEL",
                "¡Bienvenidos al evento! Consulta tu resultado preliminar aquí.",
                "Mensaje del carrusel",
                "textarea",
            ),
            ("LOGO", "logo.png", "Ruta del logo", "file"),
            ("PUBLICIDAD", "fondo.png", "Imagen de fondo publicitaria", "file"),
            ("RUTA_COMPETIDORES", "Resultados.xls", "Ruta del archivo Excel", "file"),
            ("HOJA_COMPETIDORES", "INSCRIPTOS", "Nombre de la hoja Excel", "text"),
            ("ANCHO", "100", "Ancho del logo en píxeles", "number"),
            ("BARRA", "OFF", "Mostrar barra de título", "combo"),
            (
                "OCULTAR_COLUMNAS",
                "CHIP,SAL,LLEGA,CEDULA,EDAD",
                "Columnas a ocultar",
                "textarea",
            ),
            (
                "RESULTADOS_COLUMNAS",
                "POS,DORSAL,NOMBRES,APELLIDOS,TIEMPO",
                "Columnas de resultados",
                "textarea",
            ),
            ("OCULTAR_PESTANAS", "General", "Pestañas a ocultar", "textarea"),
            ("TIMEOUT_RESULT", "10", "Tiempo de muestra del resultado", "number"),
            ("EXIT_CODE", "9999", "Código de salida especial", "text"),
            ("CONFIG_CODE", "00000", "Código secreto para configuración", "password"),
        ]

        cursor.executemany(
            """
            INSERT OR REPLACE INTO configuracion (clave, valor, descripcion, tipo)
            VALUES (?, ?, ?, ?)
        """,
            default_config,
        )

        conn.commit()
        conn.close()

    def get_config(self, key: str, default: str = "") -> str:
        """Obtiene un valor de configuración"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT valor FROM configuracion WHERE clave = ?", (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else default

    def get_all_config(self) -> Dict[str, str]:
        """Obtiene toda la configuración"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT clave, valor FROM configuracion")
        result = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return result

    def get_config_with_metadata(self) -> Dict[str, Dict[str, str]]:
        """Obtiene la configuración con metadatos"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT clave, valor, descripcion, tipo FROM configuracion")
        result = {}
        for row in cursor.fetchall():
            result[row[0]] = {"valor": row[1], "descripcion": row[2], "tipo": row[3]}
        conn.close()
        return result

    def set_config(self, key: str, value: str):
        """Establece un valor de configuración"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO configuracion (clave, valor)
            VALUES (?, ?)
        """,
            (key, value),
        )
        conn.commit()
        conn.close()

    def update_config(self, config_dict: Dict[str, str]):
        """Actualiza múltiples valores de configuración"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for key, value in config_dict.items():
            cursor.execute(
                """
                INSERT OR REPLACE INTO configuracion (clave, valor)
                VALUES (?, ?)
            """,
                (key, value),
            )

        conn.commit()
        conn.close()

    def get_file_path(self, filename: str) -> str:
        """Obtiene la ruta completa de un archivo"""
        if not filename:
            return ""

        # Si es una ruta absoluta, devolverla como está
        if os.path.isabs(filename):
            return filename

        # Si es una ruta relativa, combinarla con el directorio base
        return os.path.join(self.base_dir, filename)

    def is_configured(self) -> bool:
        """Verifica si el sistema está configurado"""
        try:
            config = self.get_all_config()
            required_keys = ["EVENTO", "TITULO", "RUTA_COMPETIDORES"]
            return all(key in config and config[key].strip() for key in required_keys)
        except:
            return False

    def validate_config(self) -> Dict[str, str]:
        """Valida la configuración y devuelve errores si los hay"""
        errors = {}
        config = self.get_all_config()

        # Validar campos obligatorios
        required_fields = {
            "EVENTO": "El nombre del evento es obligatorio",
            "TITULO": "El título del sistema es obligatorio",
            "RUTA_COMPETIDORES": "La ruta del archivo Excel es obligatoria",
        }

        for field, message in required_fields.items():
            if not config.get(field, "").strip():
                errors[field] = message

        # Validar archivos existentes
        file_fields = ["LOGO", "PUBLICIDAD", "RUTA_COMPETIDORES"]
        for field in file_fields:
            if config.get(field):
                file_path = self.get_file_path(config[field])
                if not os.path.exists(file_path):
                    errors[field] = f"El archivo {config[field]} no existe"

        # Validar números
        number_fields = ["ANCHO", "TIMEOUT_RESULT"]
        for field in number_fields:
            value = config.get(field, "")
            if value and not value.isdigit():
                errors[field] = f"El valor de {field} debe ser un número"

        return errors
