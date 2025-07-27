"""
Pantalla de carga para el sistema de resultados.
Muestra una interfaz profesional mientras se inicializa el sistema.
"""

import tkinter as tk
import tkinter.ttk as ttk
import threading
import time


class LoadingScreen:
    def __init__(self, title="Sistema de Resultados", message="Iniciando..."):
        self.root = tk.Tk()
        self.root.title(title)
        self.root.overrideredirect(True)  # Sin bordes
        self.root.attributes("-topmost", True)
        self.root.configure(bg="#2c3e50")

        # Centrar ventana
        width, height = 400, 300
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.setup_ui()
        self.is_running = False
        self.progress_thread = None

    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Frame principal
        main_frame = tk.Frame(self.root, bg="#2c3e50")
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        # Título
        title_label = tk.Label(
            main_frame,
            text="SISTEMA DE RESULTADOS",
            font=("Segoe UI", 18, "bold"),
            fg="#ecf0f1",
            bg="#2c3e50",
        )
        title_label.pack(pady=(0, 20))

        # Subtítulo
        subtitle_label = tk.Label(
            main_frame,
            text="Gestión de Clasificaciones Deportivas",
            font=("Segoe UI", 12),
            fg="#bdc3c7",
            bg="#2c3e50",
        )
        subtitle_label.pack(pady=(0, 30))

        # Mensaje de estado
        self.status_label = tk.Label(
            main_frame,
            text="Iniciando sistema...",
            font=("Segoe UI", 10),
            fg="#3498db",
            bg="#2c3e50",
        )
        self.status_label.pack(pady=(0, 20))

        # Barra de progreso
        self.progress_bar = ttk.Progressbar(
            main_frame,
            mode="indeterminate",
            length=300,
            style="Custom.Horizontal.TProgressbar",
        )
        self.progress_bar.pack(pady=(0, 20))

        # Información adicional
        info_label = tk.Label(
            main_frame,
            text="Cargando configuración y recursos...",
            font=("Segoe UI", 9),
            fg="#7f8c8d",
            bg="#2c3e50",
        )
        info_label.pack(pady=(0, 10))

        # Configurar estilo de la barra de progreso
        style = ttk.Style()
        style.configure(
            "Custom.Horizontal.TProgressbar",
            background="#3498db",
            troughcolor="#34495e",
            borderwidth=0,
            lightcolor="#3498db",
            darkcolor="#2980b9",
        )

    def show(self):
        """Muestra la pantalla de carga"""
        self.is_running = True
        self.progress_bar.start(10)
        self.root.update()

    def update_status(self, message):
        """Actualiza el mensaje de estado"""
        self.status_label.config(text=message)
        self.root.update()

    def hide(self):
        """Oculta la pantalla de carga"""
        self.is_running = False
        self.progress_bar.stop()
        self.root.withdraw()

    def destroy(self):
        """Destruye la ventana de carga"""
        self.is_running = False
        if self.progress_bar:
            self.progress_bar.stop()
        self.root.destroy()

    def run_with_progress(self, tasks):
        """
        Ejecuta una lista de tareas mostrando el progreso
        tasks: lista de tuplas (función, mensaje)
        """
        self.show()

        for task_func, message in tasks:
            self.update_status(message)
            time.sleep(0.5)  # Simular tiempo de carga

            if callable(task_func):
                task_func()

            time.sleep(0.5)

        self.hide()


def show_loading_with_tasks(tasks, title="Sistema de Resultados"):
    """
    Función de conveniencia para mostrar loading con tareas
    """
    loading = LoadingScreen(title)
    loading.run_with_progress(tasks)
    loading.destroy()


def test_loading():
    """Función de prueba para la pantalla de carga"""

    def task1():
        print("Ejecutando tarea 1...")
        time.sleep(1)

    def task2():
        print("Ejecutando tarea 2...")
        time.sleep(1)

    def task3():
        print("Ejecutando tarea 3...")
        time.sleep(1)

    tasks = [
        (task1, "Verificando licencia..."),
        (task2, "Cargando configuración..."),
        (task3, "Inicializando interfaz..."),
    ]

    show_loading_with_tasks(tasks, "Sistema de Resultados - Prueba")


if __name__ == "__main__":
    test_loading()
