"""
Formulario de configuración para el sistema de resultados.
Interfaz moderna y completa para configurar todos los parámetros.
"""

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox, scrolledtext
import os
from config_manager import ConfigManager


class ConfigForm:
    def __init__(self, parent=None):
        self.parent = parent
        self.config_manager = ConfigManager()
        self.fields = {}
        self.is_configured = False

        # Crear ventana principal
        self.root = tk.Toplevel(parent) if parent else tk.Tk()
        self.root.title("CONFIGURACION DEL SISTEMA")
        self.root.geometry("900x800")
        self.root.resizable(True, True)
        self.root.configure(bg="#f8f9fa")

        # Optimizaciones para pantallas táctiles
        self.root.attributes("-topmost", True)  # Mantener al frente

        # Hacer botones más grandes para touch
        self.touch_button_height = 50
        self.touch_button_font_size = 12

        # Centrar ventana
        self.center_window()  # Configurar ventana
        if parent:
            self.root.transient(parent)
            try:
                self.root.grab_set()
            except Exception:
                pass  # Si falla grab_set, continuar sin él

        self.root.focus_set()

        # Protocolo para cerrar ventana
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)

        self.setup_ui()
        self.load_config()

    def center_window(self):
        """Centra la ventana en la pantalla"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Header
        header_frame = tk.Frame(self.root, bg="#3498db", height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="CONFIGURACION DEL SISTEMA",
            font=("Segoe UI", 20, "bold"),
            fg="white",
            bg="#3498db",
        )
        title_label.pack(expand=True)

        subtitle_label = tk.Label(
            header_frame,
            text="Configure todos los parámetros del sistema",
            font=("Segoe UI", 12),
            fg="#ecf0f1",
            bg="#3498db",
        )
        subtitle_label.pack()

        # Frame principal con scroll
        main_frame = tk.Frame(self.root, bg="#f8f9fa")
        main_frame.pack(fill="both", expand=True, padx=20, pady=(20, 0))

        # Canvas y scrollbar para scroll
        canvas = tk.Canvas(main_frame, bg="#f8f9fa", highlightthickness=0)

        # Scrollbar más ancha para pantallas táctiles
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)

        # Configurar estilo del scrollbar para touch
        style = ttk.Style()
        style.configure("Touch.Vertical.TScrollbar", width=20)  # Más ancho
        scrollbar.configure(style="Touch.Vertical.TScrollbar")

        scrollable_frame = tk.Frame(canvas, bg="#f8f9fa")

        scrollable_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Contenido del formulario
        self.create_form_sections(scrollable_frame)

        # Botones inferiores - fuera del scroll
        self.create_buttons(self.root)

        # Soporte para scroll con rueda del mouse
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<MouseWheel>", _on_mousewheel)

        # Soporte para navegación táctil (touch)
        self.setup_touch_scroll(canvas)

    def setup_touch_scroll(self, canvas):
        """Configura el scroll táctil para pantallas touch"""
        # Variables para rastrear el movimiento táctil
        self.touch_start_y = 0
        self.last_touch_y = 0
        self.touch_is_scrolling = False
        self.scroll_momentum = 0

        def on_touch_start(event):
            """Inicio del toque en pantalla táctil"""
            self.touch_start_y = event.y
            self.last_touch_y = event.y
            self.touch_is_scrolling = False
            self.scroll_momentum = 0
            canvas.focus_set()  # Enfocar el canvas para recibir eventos

        def on_touch_move(event):
            """Movimiento del dedo en pantalla táctil"""
            if abs(event.y - self.touch_start_y) > 10:  # Umbral de movimiento
                self.touch_is_scrolling = True

            if self.touch_is_scrolling:
                # Calcular la diferencia de movimiento
                delta_y = self.last_touch_y - event.y
                self.last_touch_y = event.y

                # Aplicar scroll suave
                scroll_units = max(1, abs(delta_y) // 10)  # Sensibilidad
                direction = 1 if delta_y > 0 else -1

                canvas.yview_scroll(direction * scroll_units, "units")

        def on_touch_end(event):
            """Fin del toque en pantalla táctil"""
            if self.touch_is_scrolling:
                # Aplicar inercia al scroll
                total_movement = event.y - self.touch_start_y
                if abs(total_movement) > 50:  # Si hubo movimiento significativo
                    self.apply_scroll_momentum(canvas, total_movement)

            self.touch_is_scrolling = False

        def on_button_press(event):
            """Manejo de clic/toque inicial"""
            on_touch_start(event)

        def on_button_motion(event):
            """Manejo de arrastre con botón presionado"""
            on_touch_move(event)

        def on_button_release(event):
            """Manejo de liberación del clic/toque"""
            on_touch_end(event)

        # Vincular eventos para mouse (compatibilidad)
        canvas.bind("<ButtonPress-1>", on_button_press)
        canvas.bind("<B1-Motion>", on_button_motion)
        canvas.bind("<ButtonRelease-1>", on_button_release)

        # Vincular eventos táctiles específicos (si están disponibles)
        try:
            canvas.bind("<TouchBegin>", on_touch_start)
            canvas.bind("<TouchMove>", on_touch_move)
            canvas.bind("<TouchEnd>", on_touch_end)
        except:
            pass  # Los eventos táctiles podrían no estar disponibles

        # Scroll mejorado con teclas de dirección
        def on_key_press(event):
            if event.keysym == "Up":
                canvas.yview_scroll(-3, "units")
            elif event.keysym == "Down":
                canvas.yview_scroll(3, "units")
            elif event.keysym == "Page_Up":
                canvas.yview_scroll(-10, "units")
            elif event.keysym == "Page_Down":
                canvas.yview_scroll(10, "units")

        canvas.bind("<Key>", on_key_press)
        canvas.focus_set()  # Permitir que el canvas reciba eventos de teclado

    def apply_scroll_momentum(self, canvas, movement):
        """Aplica inercia al scroll para un efecto más suave"""
        momentum_steps = min(10, abs(movement) // 20)
        direction = -1 if movement > 0 else 1

        def scroll_step(step):
            if step > 0:
                canvas.yview_scroll(direction * 2, "units")
                # Programar el siguiente paso con delay decreciente
                delay = max(50, 200 - step * 15)
                canvas.after(delay, lambda: scroll_step(step - 1))

        if momentum_steps > 0:
            scroll_step(momentum_steps)

    def create_form_sections(self, parent):
        """Crea las secciones del formulario dinámicamente desde la base de datos"""
        # Obtener configuración con metadatos
        config_with_metadata = self.config_manager.get_config_with_metadata()

        # Agrupaciones de campos por sección
        sections = {
            "INFO GENERAL": ["EVENTO", "TITULO", "CARRUSEL"],
            "ARCHIVOS Y RECURSOS": ["LOGO", "PUBLICIDAD", "RUTA_COMPETIDORES"],
            "CONFIGURACION DE DATOS": [
                "HOJA_COMPETIDORES",
                "OCULTAR_COLUMNAS",
                "RESULTADOS_COLUMNAS",
                "OCULTAR_PESTANAS",
            ],
            "CONFIGURACION DE INTERFAZ": [
                "ANCHO",
                "BARRA",
                "TIMEOUT_RESULT",
                "EXIT_CODE",
            ],
            "SEGURIDAD": ["CONFIG_CODE"],
        }

        section_colors = {
            "INFO GENERAL": "#e74c3c",
            "ARCHIVOS Y RECURSOS": "#9b59b6",
            "CONFIGURACION DE DATOS": "#27ae60",
            "CONFIGURACION DE INTERFAZ": "#f39c12",
            "SEGURIDAD": "#e67e22",
        }

        # Crear secciones con sus campos
        for section_name, field_keys in sections.items():
            # Crear encabezado de sección
            self.create_section(
                parent, section_name, section_colors.get(section_name, "#34495e")
            )

            # Crear campos de la sección
            for key in field_keys:
                if key in config_with_metadata:
                    meta = config_with_metadata[key]
                    self.create_dynamic_field(parent, key, meta)

        # Crear campos adicionales que no estén en las secciones
        other_fields = []
        for key in config_with_metadata.keys():
            found = False
            for field_keys in sections.values():
                if key in field_keys:
                    found = True
                    break
            if not found:
                other_fields.append(key)

        if other_fields:
            self.create_section(parent, "OTROS", "#95a5a6")
            for key in other_fields:
                meta = config_with_metadata[key]
                self.create_dynamic_field(parent, key, meta)

    def create_dynamic_field(self, parent, key, meta):
        """Crea un campo dinámicamente basado en los metadatos"""
        descripcion = meta.get("descripcion", key)
        tipo = meta.get("tipo", "text")
        valor = meta.get("valor", "")  # Obtener el valor actual

        # Si la descripción es None o vacía, usar el nombre de la clave
        if descripcion is None or descripcion == "None" or descripcion == "":
            descripcion = key

        if tipo == "password":
            self.create_password_field(parent, f"{descripcion}:", key, str(valor))
        elif tipo == "file":
            self.create_file_field(
                parent, f"{descripcion}:", key, [("Todos", "*.*")], str(valor)
            )
        elif tipo == "textarea":
            self.create_textarea_field(
                parent, f"{descripcion}:", key, height=4, placeholder=str(valor)
            )
        elif tipo == "number":
            self.create_number_field(
                parent, f"{descripcion}:", key, placeholder=str(valor)
            )
        elif tipo == "combo":
            # Para combos, usar valores por defecto
            if key == "BARRA":
                self.create_combo_field(
                    parent, f"{descripcion}:", key, ["ON", "OFF"], str(valor)
                )
            else:
                self.create_text_field(parent, f"{descripcion}:", key, str(valor))
        else:  # text por defecto
            # Campos especiales que necesitan selector de archivos
            if key in ["RUTA_COMPETIDORES", "LOGO", "PUBLICIDAD"]:
                file_types = []
                if key == "RUTA_COMPETIDORES":
                    file_types = [("Excel", "*.xlsx;*.xls")]
                elif key == "LOGO":
                    file_types = [("Imágenes", "*.png;*.jpg;*.jpeg;*.gif")]
                elif key == "PUBLICIDAD":
                    file_types = [("Imágenes", "*.png;*.jpg;*.jpeg;*.gif")]

                self.create_file_field(
                    parent, f"{descripcion}:", key, file_types, str(valor)
                )
            else:
                self.create_text_field(parent, f"{descripcion}:", key, str(valor))

    def create_section(self, parent, title, color):
        """Crea una sección con título"""
        section_frame = tk.Frame(parent, bg=color, height=40)
        section_frame.pack(fill="x", pady=(20, 0))
        section_frame.pack_propagate(False)

        title_label = tk.Label(
            section_frame,
            text=title,
            font=("Segoe UI", 14, "bold"),
            fg="white",
            bg=color,
        )
        title_label.pack(expand=True)

    def create_text_field(self, parent, label_text, key, placeholder=""):
        """Crea un campo de texto simple"""
        frame = tk.Frame(parent, bg="#f8f9fa")
        frame.pack(fill="x", pady=5)

        label = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg="#f8f9fa",
            width=25,
            anchor="w",
        )
        label.pack(side="left")

        entry = tk.Entry(frame, font=("Segoe UI", 10), width=50)
        entry.pack(side="left", padx=(10, 0), fill="x", expand=True)

        if placeholder:
            entry.insert(0, placeholder)
            entry.config(fg="gray")

            def on_focus_in(event):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.config(fg="black")

            def on_focus_out(event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.config(fg="gray")

            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)

        self.fields[key] = entry

    def create_password_field(self, parent, label_text, key, placeholder=""):
        """Crea un campo de contraseña (texto oculto)"""
        frame = tk.Frame(parent, bg="#f8f9fa")
        frame.pack(fill="x", pady=5)

        label = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg="#f8f9fa",
            width=25,
            anchor="w",
        )
        label.pack(side="left")

        entry = tk.Entry(frame, font=("Segoe UI", 10), width=50, show="*")
        entry.pack(side="left", padx=(10, 0), fill="x", expand=True)

        if placeholder:
            entry.insert(0, placeholder)
            entry.config(fg="gray", show="")

            def on_focus_in(event):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.config(fg="black", show="*")

            def on_focus_out(event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.config(fg="gray", show="")

            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
            entry.placeholder = placeholder

        self.fields[key] = entry

    def create_textarea_field(self, parent, label_text, key, height=4, placeholder=""):
        """Crea un campo de texto multilínea"""
        frame = tk.Frame(parent, bg="#f8f9fa")
        frame.pack(fill="x", pady=5)

        label = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg="#f8f9fa",
            width=25,
            anchor="w",
        )
        label.pack(side="left", anchor="n")

        text_widget = scrolledtext.ScrolledText(
            frame, font=("Segoe UI", 10), width=50, height=height
        )
        text_widget.pack(side="left", padx=(10, 0), fill="x", expand=True)

        # Insertar valor inicial si existe
        if placeholder:
            text_widget.insert(1.0, placeholder)

        self.fields[key] = text_widget

    def create_file_field(self, parent, label_text, key, file_types, initial_value=""):
        """Crea un campo de archivo con botón de selección"""
        frame = tk.Frame(parent, bg="#f8f9fa")
        frame.pack(fill="x", pady=5)

        label = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg="#f8f9fa",
            width=25,
            anchor="w",
        )
        label.pack(side="left")

        entry = tk.Entry(frame, font=("Segoe UI", 10), width=40)
        entry.pack(side="left", padx=(10, 5), fill="x", expand=True)

        # Insertar valor inicial
        if initial_value:
            entry.insert(0, initial_value)

        def select_file():
            file_path = filedialog.askopenfilename(
                title=f"Seleccionar {label_text}",
                filetypes=file_types + [("Todos los archivos", "*.*")],
            )
            if file_path:
                entry.delete(0, tk.END)
                entry.insert(0, file_path)

        button = tk.Button(
            frame,
            text="SELECCIONAR",
            command=select_file,
            bg="#3498db",
            fg="white",
            font=("Segoe UI", self.touch_button_font_size, "bold"),
            height=2,  # Mayor altura para touch
            padx=15,
            pady=8,
            relief="flat",
            borderwidth=0,
            cursor="hand2",
        )
        button.pack(side="right")

        self.fields[key] = entry

    def create_number_field(
        self, parent, label_text, key, min_val=0, max_val=100, placeholder=""
    ):
        """Crea un campo numérico con spinbox"""
        frame = tk.Frame(parent, bg="#f8f9fa")
        frame.pack(fill="x", pady=5)

        label = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg="#f8f9fa",
            width=25,
            anchor="w",
        )
        label.pack(side="left")

        spinbox = tk.Spinbox(
            frame, from_=min_val, to=max_val, font=("Segoe UI", 10), width=20
        )
        spinbox.pack(side="left", padx=(10, 0))

        # Insertar valor inicial
        if placeholder:
            spinbox.delete(0, tk.END)
            spinbox.insert(0, placeholder)

        self.fields[key] = spinbox

    def create_combo_field(self, parent, label_text, key, values, initial_value=""):
        """Crea un campo de selección con combobox"""
        frame = tk.Frame(parent, bg="#f8f9fa")
        frame.pack(fill="x", pady=5)

        label = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg="#f8f9fa",
            width=25,
            anchor="w",
        )
        label.pack(side="left")

        combo = ttk.Combobox(
            frame, values=values, font=("Segoe UI", 10), width=20, state="readonly"
        )
        combo.pack(side="left", padx=(10, 0))

        # Establecer valor inicial
        if initial_value:
            combo.set(initial_value)

        self.fields[key] = combo

    def create_buttons(self, parent):
        """Crea los botones del formulario"""
        button_frame = tk.Frame(parent, bg="#f8f9fa", height=70)
        button_frame.pack(fill="x", pady=10)
        button_frame.pack_propagate(False)

        # Frame interno para centrar y organizar botones
        inner_frame = tk.Frame(button_frame, bg="#f8f9fa")
        inner_frame.pack(expand=True, fill="both", padx=20, pady=15)

        # Botón Restaurar Defaults (izquierda)
        default_btn = tk.Button(
            inner_frame,
            text="RESTAURAR DEFAULTS",
            command=self.restore_defaults,
            bg="#f39c12",
            fg="white",
            font=("Segoe UI", self.touch_button_font_size, "bold"),
            padx=25,
            pady=15,
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            height=2,  # Altura adecuada para touch
        )
        default_btn.pack(side="left")

        # Frame para botones de acción (derecha)
        action_frame = tk.Frame(inner_frame, bg="#f8f9fa")
        action_frame.pack(side="right")

        # Botón Cancelar
        cancel_btn = tk.Button(
            action_frame,
            text="CANCELAR",
            command=self.cancel,
            bg="#e74c3c",
            fg="white",
            font=("Segoe UI", self.touch_button_font_size, "bold"),
            padx=25,
            pady=15,
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            height=2,  # Altura adecuada para touch
        )
        cancel_btn.pack(side="right", padx=(0, 15))

        # Botón Guardar
        save_btn = tk.Button(
            action_frame,
            text="GUARDAR Y CONTINUAR",
            command=self.save_and_continue,
            bg="#27ae60",
            fg="white",
            font=("Segoe UI", self.touch_button_font_size, "bold"),
            padx=25,
            pady=15,
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            height=2,  # Altura adecuada para touch
        )
        save_btn.pack(side="right")

    def load_config(self):
        """Carga la configuración actual en los campos"""
        config = self.config_manager.get_all_config()

        for key, widget in self.fields.items():
            value = config.get(key, "")

            if isinstance(widget, scrolledtext.ScrolledText):
                widget.delete(1.0, tk.END)
                widget.insert(1.0, value)
            elif isinstance(widget, ttk.Combobox):
                widget.set(value)
            else:
                widget.delete(0, tk.END)
                widget.insert(0, value)

    def get_field_value(self, key):
        """Obtiene el valor de un campo"""
        widget = self.fields.get(key)
        if not widget:
            return ""

        if isinstance(widget, scrolledtext.ScrolledText):
            value = widget.get(1.0, tk.END).strip()
        elif isinstance(widget, ttk.Combobox):
            value = widget.get()
        else:
            value = widget.get()

        # Eliminar placeholder si está presente
        if hasattr(widget, "placeholder") and value == widget.placeholder:
            return ""

        return value

    def validate_form(self):
        """Valida el formulario"""
        errors = []

        # Campos obligatorios
        required_fields = {
            "EVENTO": "Nombre del Evento",
            "TITULO": "Título del Sistema",
            "RUTA_COMPETIDORES": "Archivo Excel",
        }

        for key, name in required_fields.items():
            value = self.get_field_value(key)
            if not value.strip():
                errors.append(f"El campo '{name}' es obligatorio")

        # Validar archivos
        file_fields = ["LOGO", "PUBLICIDAD", "RUTA_COMPETIDORES"]
        for key in file_fields:
            value = self.get_field_value(key)
            if value and not os.path.exists(value):
                errors.append(f"El archivo '{value}' no existe")

        # Validar números
        number_fields = ["ANCHO", "TIMEOUT_RESULT"]
        for key in number_fields:
            value = self.get_field_value(key)
            if value and not value.isdigit():
                errors.append(f"El campo '{key}' debe ser un número válido")

        return errors

    def save_and_continue(self):
        """Guarda la configuración y continúa"""
        errors = self.validate_form()

        if errors:
            messagebox.showerror("Errores de Validación", "\n".join(errors))
            return

        # Guardar configuración
        config_data = {}
        for key in self.fields:
            config_data[key] = self.get_field_value(key)

        try:
            self.config_manager.update_config(config_data)
            self.is_configured = True
            messagebox.showinfo("Éxito", "Configuración guardada correctamente")
            # Cerrar la ventana correctamente
            self.close_window()
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar: {str(e)}")

    def restore_defaults(self):
        """Restaura los valores por defecto"""
        if messagebox.askyesno("Confirmar", "¿Restaurar valores por defecto?"):
            self.config_manager._create_default_config()
            self.load_config()
            messagebox.showinfo("Éxito", "Valores por defecto restaurados")

    def cancel(self):
        """Cancela la configuración"""
        if messagebox.askyesno("Confirmar", "¿Salir sin guardar cambios?"):
            self.close_window()

    def close_window(self):
        """Cierra la ventana correctamente"""
        try:
            if self.root:
                self.root.quit()  # Termina el mainloop
                self.root.destroy()  # Destruye la ventana
        except Exception:
            pass

    def on_window_close(self):
        """Maneja el cierre de ventana con la X"""
        self.cancel()

    def show_modal(self):
        """Muestra el formulario como modal"""
        # Asegurar que la ventana esté visible
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

        # Si hay parent, usar wait_window, sino usar mainloop
        if self.parent:
            try:
                self.root.wait_window(self.root)
            except Exception:
                # Si wait_window falla, usar mainloop
                self.root.mainloop()
        else:
            self.root.mainloop()

        return self.is_configured

    def show(self):
        """Método de compatibilidad - muestra el formulario"""
        return self.show_modal()


def show_config_form(parent=None):
    """Función de conveniencia para mostrar el formulario"""
    try:
        # Crear el formulario directamente
        form = ConfigForm(parent)
        result = form.show_modal()
        return result
    except Exception as e:
        print(f"Error en show_config_form: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Prueba del formulario
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal

    configured = show_config_form()
    print(f"Configurado: {configured}")

    root.destroy()
