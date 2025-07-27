import sys
import os
import ctypes
import uuid
import hmac
import hashlib
import tempfile
import subprocess
import winreg

import pandas as pd
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.font as tkfont
import threading
import queue
import time
from tkinter import filedialog, messagebox, scrolledtext, StringVar, IntVar, BooleanVar
from tkinter import Spinbox
from tkinter import messagebox as msgbox  # Alias para usar msgbox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# Intentar importar Pillow para logos
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None

# Variables globales para mantener referencias de imágenes
logo_img_ref = None
fondo_img_ref = None
keypad_fondo_img_ref = None

# Variables globales para datos PIL precargados
logo_pil_img = None
fondo_pil_img = None
keypad_fondo_pil_img = None

# --- Mutex para instancia única ---
MUTEX_NAME = "ResultadosKioskSingletonMutex"
h_mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
last_error = ctypes.windll.kernel32.GetLastError()
if last_error == 183:  # ERROR_ALREADY_EXISTS
    # Ya hay otra instancia
    splash = tk.Tk()
    splash.overrideredirect(True)
    w, h = 350, 120
    sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
    splash.after(
        1000,
        lambda: (
            ctypes.windll.kernel32.ReleaseMutex(h_mutex) if h_mutex else None,
            ctypes.windll.kernel32.CloseHandle(h_mutex) if h_mutex else None,
            sys.exit(1),
        ),
    )
    splash.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    frm = ttk.Frame(splash, padding=10)
    frm.pack(expand=True, fill="both")
    ttk.Label(
        frm, text="La aplicación ya se está ejecutando", font=("Segoe UI", 12)
    ).pack(pady=(0, 10))
    pb = ttk.Progressbar(frm, mode="indeterminate")
    pb.pack(fill="x")
    pb.start(20)
    splash.after(2000, splash.destroy)
    splash.mainloop()
    sys.exit(0)


# --- Manejo global de errores no capturados ---
def show_unhandled_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    import traceback

    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print("ERROR INESPERADO:\n", tb)
    try:
        tk.Tk().withdraw()
        messagebox.showerror("Error Inesperado", f"{exc_type.__name__}: {exc_value}")
    except Exception:
        pass
    sys.exit(1)


sys.excepthook = show_unhandled_exception

# --- Impresión avanzada en Windows (pywin32) ---
try:
    import win32print
    import win32ui
    import win32con
    import pywintypes
    from win32api import GetSystemMetrics
except ImportError:
    win32print = None
    win32ui = None
    win32con = None
    pywintypes = None
    GetSystemMetrics = None
    print(
        "Advertencia: 'pywin32' no está instalado. "
        "Las opciones de impresión avanzadas no estarán disponibles."
    )

# --- Validación de licencia ---
LICENSE_FILE = "license.lic"
MASTER_KEY = b"bGljZW5jaWE="


def get_volume_serial(drive="C:\\"):
    buf1 = ctypes.create_unicode_buffer(1024)
    buf2 = ctypes.create_unicode_buffer(1024)
    serial = ctypes.c_uint()
    maxlen = ctypes.c_uint()
    flags = ctypes.c_uint()
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive),
        buf1,
        ctypes.sizeof(buf1),
        ctypes.byref(serial),
        ctypes.byref(maxlen),
        ctypes.byref(flags),
        buf2,
        ctypes.sizeof(buf2),
    )
    if not ok:
        raise ctypes.WinError()
    return serial.value


def get_machine_id():
    vol = get_volume_serial()
    mac = uuid.getnode()
    return f"{vol:08X}-{mac:012X}".encode()


def check_license():
    if not os.path.exists(LICENSE_FILE):
        tk.Tk().withdraw()
        messagebox.showerror("Licencia", "Falta el archivo license.lic.")
        sys.exit(1)
    lic = open(LICENSE_FILE, "r").read().strip()
    mid = get_machine_id()
    exp = hmac.new(MASTER_KEY, mid, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(exp, lic):
        tk.Tk().withdraw()
        messagebox.showerror(
            "Licencia inválida", "La licencia no es válida para este equipo."
        )
        sys.exit(1)


check_license()


def init_sistema_resultados():
    """Inicializa el sistema de resultados para ser llamado desde main.py"""
    global BASE_DIR
    print(f"Sistema inicializado desde: {BASE_DIR}")
    return True


# --- Configuración global ---
if getattr(sys, "frozen", False):
    # Si es ejecutable, usa la carpeta del ejecutable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Si es script, usa la carpeta del script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SPECIAL = {"DNS", "DNF", "DSQ"}
SPECIAL_DESC = {
    "DNS": "No se presentó / No chip",
    "DNF": "No finalizó / Retiro",
    "DSQ": "No califica",
}

df_inscritos = pd.DataFrame()
dfs = {}
premios_grouped = pd.DataFrame()
ocultar_columns = []
resultados_columns = []
ocultar_tabs = []

EVENTO = TITULO = LOGO_PATH = EXCEL_PATH = SHEET_NAME = PUBLICIDAD_PATH = ""
TIMEOUT_RESULT = 5
EXIT_CODE = ""
BARRA = "ON"
ANCHO_LOGO = 80
CARRUSEL_MSG = ""


def read_config():
    """Lee la configuración desde config.db usando ConfigManager"""
    try:
        from config_manager import ConfigManager

        config_db_path = os.path.join(BASE_DIR, "config.db")
        config_manager = ConfigManager(config_db_path)
        config = config_manager.get_all_config()
        print(f"OK: Configuracion cargada desde {config_db_path}")
        return config
    except Exception as e:
        print(f"ERROR: Error leyendo configuracion: {e}")
        return {}


cfg = read_config()
EVENTO = cfg.get("EVENTO", "")
TITULO = cfg.get("TITULO", "")

# Inicializar ruta de publicidad por defecto
publicidad_config = cfg.get("PUBLICIDAD", "")
print(f"DEBUG GLOBAL - publicidad_config de BD: '{publicidad_config}'")
if publicidad_config:
    if os.path.isabs(publicidad_config) and os.path.exists(publicidad_config):
        PUBLICIDAD_PATH = publicidad_config
        print(f"DEBUG GLOBAL - Usando ruta absoluta: {PUBLICIDAD_PATH}")
    else:
        possible_paths = [
            os.path.join(BASE_DIR, publicidad_config),
            os.path.join(BASE_DIR, "img", publicidad_config),
            os.path.join(BASE_DIR, os.path.basename(publicidad_config)),
        ]
        print(f"DEBUG GLOBAL - Buscando en rutas: {possible_paths}")
        PUBLICIDAD_PATH = ""
        for path in possible_paths:
            print(f"DEBUG GLOBAL - Probando ruta: {path} - Existe: {os.path.exists(path)}")
            if os.path.exists(path):
                PUBLICIDAD_PATH = path
                break
        if not PUBLICIDAD_PATH:
            PUBLICIDAD_PATH = os.path.join(BASE_DIR, "img", "fondo.png")
            print(f"DEBUG GLOBAL - Usando fondo por defecto: {PUBLICIDAD_PATH}")
else:
    PUBLICIDAD_PATH = os.path.join(BASE_DIR, "img", "fondo.png")
    print(f"DEBUG GLOBAL - Sin config, usando fondo por defecto: {PUBLICIDAD_PATH}")

print(f"DEBUG GLOBAL - PUBLICIDAD_PATH final: '{PUBLICIDAD_PATH}'")

# Manejo inteligente de la ruta del logo
logo_config = cfg.get("LOGO", "")
if logo_config:
    if os.path.isabs(logo_config) and os.path.exists(logo_config):
        # Si es ruta absoluta y existe, usarla directamente
        LOGO_PATH = logo_config
    else:
        # Si no, buscar en BASE_DIR o img/
        possible_paths = [
            os.path.join(BASE_DIR, logo_config),
            os.path.join(BASE_DIR, "img", logo_config),
            os.path.join(BASE_DIR, os.path.basename(logo_config)),
        ]
        LOGO_PATH = ""
        for path in possible_paths:
            if os.path.exists(path):
                LOGO_PATH = path
                break
        if not LOGO_PATH:
            LOGO_PATH = os.path.join(BASE_DIR, "img", "logo.png")  # Logo por defecto
else:
    LOGO_PATH = os.path.join(BASE_DIR, "img", "logo.png")  # Logo por defecto

ANCHO_LOGO = int(cfg.get("ANCHO", "80"))
EXCEL_PATH = cfg.get("RUTA_COMPETIDORES", "")
SHEET_NAME = cfg.get("HOJA_COMPETIDORES", "INSCRIPTOS")
TIMEOUT_RESULT = int(cfg.get("TIMEOUT_RESULT", "5"))
EXIT_CODE = cfg.get("EXIT_CODE", "")
BARRA = cfg.get("BARRA", "ON").upper()

# Manejo inteligente de la ruta de publicidad
publicidad_config = cfg.get("PUBLICIDAD", "")
if publicidad_config:
    if os.path.isabs(publicidad_config) and os.path.exists(publicidad_config):
        # Si es ruta absoluta y existe, usarla directamente
        PUBLICIDAD_PATH = publicidad_config
    else:
        # Si no, buscar en BASE_DIR o img/
        possible_paths = [
            os.path.join(BASE_DIR, publicidad_config),
            os.path.join(BASE_DIR, "img", publicidad_config),
            os.path.join(BASE_DIR, os.path.basename(publicidad_config)),
        ]
        PUBLICIDAD_PATH = ""
        for path in possible_paths:
            if os.path.exists(path):
                PUBLICIDAD_PATH = path
                break
        if not PUBLICIDAD_PATH:
            PUBLICIDAD_PATH = os.path.join(
                BASE_DIR, "img", "fondo.png"
            )  # Fondo por defecto
else:
    PUBLICIDAD_PATH = os.path.join(BASE_DIR, "img", "fondo.png")  # Fondo por defecto


ocultar_columns = [
    c.strip().upper() for c in cfg.get("OCULTAR_COLUMNAS", "").split(",") if c.strip()
]
resultados_columns = [
    c.strip().upper()
    for c in cfg.get(
        "RESULTADOS_COLUMNAS", "POS,DORSAL,NOMBRES,APELLIDOS,TIEMPO"
    ).split(",") if c.strip()
]
ocultar_tabs = [
    t.strip().upper() for t in cfg.get("OCULTAR_PESTANAS", "").split(",") if t.strip()
]


def ajustar_ancho_columnas(tree: ttk.Treeview, padding: int = 10):
    """
    Ajusta el ancho de cada columna de un Treeview al ancho máximo de su contenido.
    :param tree: instancia de ttk.Treeview ya poblada.
    :param padding: espacio extra (en píxeles) que se añade a cada columna.
    """
    # Obtenemos el font del estilo actual del Treeview
    style_name = tree.cget("style") or "Treeview"
    font_descr = tree.tk.call("ttk::style", "lookup", style_name, "-font")
    font = tkfont.Font(tree, font=font_descr)

    for col in tree["columns"]:
        # ancho del encabezado
        max_width = font.measure(col)
        # ancho de cada celda
        for item in tree.get_children():
            text = str(tree.set(item, col))
            w = font.measure(text)
            if w > max_width:
                max_width = w
        # fijamos ancho + padding
        tree.column(col, width=max_width + padding)


# --- Funciones de procesamiento de tiempo y clasificación ---
def format_time_str(ts: str) -> str:
    """
    Formatea la columna TIEMPO como cadena, dejando sólo 3
    dígitos después del separador decimal (',' o '.').
    """
    s = str(ts)
    # Si es uno de los códigos especiales, lo devolvemos tal cual
    if s in SPECIAL:
        return s
    # Detectamos si lleva coma como separador
    if "," in s:
        left, right = s.split(",", 1)
        # rellenamos o cortamos a 3 dígitos
        right = (right + "000")[:3]
        return f"{left},{right}"
    # Si lleva punto como separador
    if "." in s:
        left, right = s.split(".", 1)
        right = (right + "000")[:3]
        return f"{left}.{right}"
    # si no tiene decimal, lo dejamos entero
    return s


def simple_choice_dialog(parent, title, opciones):
    """
    Muestra un Toplevel a pantalla completa con una Listbox de elementos grandes
    para selección táctil. Devuelve el índice escogido (int) o None si cancela.
    """
    dlg = tk.Toplevel(parent)
    dlg.withdraw()  # Ocultar mientras se configura
    dlg.title(title)
    dlg.attributes("-fullscreen", True)
    dlg.attributes("-topmost", True)
    dlg.configure(bg="black")
    dlg.transient(parent)
    dlg.protocol("WM_DELETE_WINDOW", lambda: None)  # Ignorar cierre con X

    # Frame centralizado
    frm = tk.Frame(dlg, bg="white", bd=4, relief="raised")
    frm.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)

    # Título grande
    ttk.Label(frm, text=title, font=("Segoe UI", 24, "bold"), background="white").pack(
        pady=(20, 10)
    )

    # Listbox con fuente grande
    lb = tk.Listbox(
        frm,
        font=("Segoe UI", 20),
        activestyle="none",
        selectbackground="#337ab7",
        selectforeground="white",
        height=len(opciones),
    )
    for opt in opciones:
        lb.insert(tk.END, opt)
    lb.pack(expand=True, fill="both", padx=20, pady=10)
    lb.select_set(0)
    lb.focus()

    # Botones grandes
    btns = tk.Frame(frm, bg="white")
    btns.pack(pady=(10, 20))

    choice = {"idx": None}
    dialog_active = {"value": True}

    def on_ok():
        if not dialog_active["value"]:
            return
        dialog_active["value"] = False
        sel = lb.curselection()
        if sel:
            choice["idx"] = sel[0]
        dlg.grab_release()
        dlg.destroy()

    def on_cancel():
        if not dialog_active["value"]:
            return
        dialog_active["value"] = False
        dlg.grab_release()
        dlg.destroy()

    ttk.Button(btns, text="OK", command=on_ok, style="TButton").pack(
        side="left", ipadx=20, ipady=10, padx=20
    )

    ttk.Button(btns, text="Cancelar", command=on_cancel, style="TButton").pack(
        side="left", ipadx=20, ipady=10, padx=20
    )

    # Mostrar diálogo y hacerlo modal
    dlg.deiconify()
    dlg.focus_force()
    dlg.grab_set()

    # Esperar a que se cierre
    parent.wait_window(dlg)

    return choice["idx"]


def tiempo_a_delta(val):
    try:
        return pd.to_timedelta(str(val))
    except Exception:
        return pd.NaT


def clasificacion_general(df):
    df2 = df.copy()
    df2["__td"] = df2["TIEMPO"].map(tiempo_a_delta)
    valid = df2[df2["__td"].notna()].sort_values("__td")
    invalid = df2[df2["__td"].isna()]
    valid.insert(0, "POS", range(1, len(valid) + 1))
    invalid.insert(0, "POS", [""] * len(invalid))
    return pd.concat([valid, invalid], ignore_index=True).drop("__td", axis=1)


def clasificar_con_encabezados(df, col):
    out = []
    if col not in df.columns:
        return pd.DataFrame()
    for key in sorted(df[col].dropna().unique()):
        hdr = {c: c for c in df.columns}
        hdr["POS"] = "POS"
        out.append(hdr)
        sub = df[df[col] == key].copy()
        sub["__td"] = sub["TIEMPO"].map(tiempo_a_delta)
        valid = sub[sub["__td"].notna()].sort_values("__td")
        invalid = sub[sub["__td"].isna()]
        pos = 1
        for _, r in valid.iterrows():
            d = r.drop("__td").to_dict()
            d["POS"] = pos
            pos += 1
            out.append(d)
        for _, r in invalid.iterrows():
            d = r.drop("__td").to_dict()
            d["POS"] = ""
            out.append(d)
    return pd.DataFrame(out)


# --- Funciones de impresión de tickets ---
def listar_impresoras_windows():
    printers = []
    if win32print is None:
        return printers
    try:
        path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                printers.append(winreg.EnumKey(key, i))
    except Exception:
        pass
    return printers


def formatear_ticket_linea(texto, ancho, centrar=False):
    return texto.center(ancho)[:ancho] if centrar else texto.ljust(ancho)[:ancho]


def aplicar_negrita_escpos():
    return b"\x1b\x45\x01"


def desactivar_negrita_escpos():
    return b"\x1b\x45\x00"


def imprimir_directo_ticket(texto, impresora, usar_negrita, reducir_fuente):
    if win32print is None:
        messagebox.showwarning("Impresión", "pywin32 no disponible.")
        return
    h = win32print.OpenPrinter(impresora)
    win32print.StartDocPrinter(h, 1, ("Ticket", None, "RAW"))
    win32print.StartPagePrinter(h)
    if usar_negrita.get():
        win32print.WritePrinter(h, aplicar_negrita_escpos())
    fuente = b"\x1bM\x01" if reducir_fuente.get() else b"\x1bM\x00"
    win32print.WritePrinter(h, fuente + texto.encode("utf-8"))
    win32print.WritePrinter(h, b"\n" * 6 + b"\x1dV\x00")
    if usar_negrita.get():
        win32print.WritePrinter(h, desactivar_negrita_escpos())
    win32print.EndPagePrinter(h)
    win32print.EndDocPrinter(h)
    win32print.ClosePrinter(h)


def generar_texto_premios(premios_data, modo, ancho, centrar, cols):
    lines = []
    cat = None
    for _, row in premios_data.iterrows():
        vals = [row.get(c, "") for c in cols]
        is_hdr = all(str(vals[i]) == cols[i] for i in range(len(cols)))
        is_desc = (
            isinstance(vals[0], str) and vals[0] and all(v == "" for v in vals[1:])
        )
        if modo == "Ticket":
            if is_desc and not is_hdr:
                cat = vals[0]
                lines.append("")
                lines.append(
                    formatear_ticket_linea(f"== {cat.upper()} ==", ancho, centrar)
                )
                lines.append(formatear_ticket_linea("-" * ancho, ancho, centrar))
            elif not is_hdr and cat:
                pos = row.get("POS", "")
                dor = row.get("DORSAL", "")
                ti = row.get("TIEMPO", "")
                ti = ti.split(",")[0] + "," + ti.split(",")[1][:2] if "," in ti else ti
                nom = row.get("NOMBRES", "")
                ape = row.get("APELLIDOS", "")
                lines.append(
                    formatear_ticket_linea(f"POS: {pos}  DORSAL: {dor}", ancho, centrar)
                )
                lines.append(formatear_ticket_linea(f"TIEMPO: {ti}", ancho, centrar))
                lines.append(
                    formatear_ticket_linea(f"NOMBRE: {nom} {ape}", ancho, centrar)
                )
                lines.append("")
        else:
            if is_desc and not is_hdr:
                lines.append(f"\n--- {vals[0]} ---")
            elif is_hdr:
                hdr = " | ".join(c.ljust(15) for c in cols)
                lines.append(hdr)
                lines.append("-" * len(hdr))
            else:
                lines.append(" | ".join(str(v).ljust(15) for v in vals))
    return "\n".join(lines)


def imprimir_premios():
    if premios_grouped.empty:
        messagebox.showwarning("Imprimir", "No hay premios generados.")
        return

    pv = tk.Toplevel(root)
    pv.title("Vista previa e impresión")
    pv.geometry("800x600")
    pv.attributes("-topmost", True)  # <-- Agrega esto

    st = ttk.Style(pv)
    st.configure("Preview.TButton", font=("Segoe UI", 12), padding=10)

    ta = scrolledtext.ScrolledText(pv, font=("Courier New", 8))
    ta.pack(expand=True, fill="both", padx=10, pady=(10, 5))

    sf = ttk.Frame(pv)
    sf.pack(pady=10)
    printers = listar_impresoras_windows()
    sel_imp = StringVar(pv, value=printers[0] if printers else "")
    ttk.Label(sf, text="Impresora:").pack(side="left", padx=5)
    cb_imp = ttk.Combobox(
        sf, textvariable=sel_imp, values=printers, width=40, state="readonly"
    )
    cb_imp.pack(side="left", padx=5)

    modo_var = StringVar(pv, value="Normal")
    ttk.Label(sf, text="Modo:").pack(side="left", padx=(20, 5))
    cb_modo = ttk.Combobox(
        sf,
        textvariable=modo_var,
        values=["Normal", "Ticket"],
        width=10,
        state="readonly",
    )
    cb_modo.pack(side="left")

    ancho_var = IntVar(pv, value=42)
    ttk.Label(sf, text="Ancho cols:").pack(side="left", padx=(20, 5))
    eb = ttk.Entry(sf, textvariable=ancho_var, width=5)
    eb.pack(side="left")

    centrar_var = BooleanVar(pv)
    reducir_var = BooleanVar(pv)
    negrita_var = BooleanVar(pv)
    ttk.Checkbutton(sf, text="Centrar texto", variable=centrar_var).pack(
        side="left", padx=5
    )
    ttk.Checkbutton(sf, text="Fuente pequeña", variable=reducir_var).pack(
        side="left", padx=5
    )
    ttk.Checkbutton(sf, text="Negrita", variable=negrita_var).pack(side="left", padx=5)

    def update_prev(*_):
        txt = generar_texto_premios(
            premios_grouped,
            modo_var.get(),
            ancho_var.get(),
            centrar_var.get(),
            resultados_columns,
        )
        ta.config(state="normal")
        ta.delete("1.0", tk.END)
        ta.insert("1.0", txt)
        ta.config(state="disabled")

    modo_var.trace_add("write", update_prev)
    ancho_var.trace_add("write", update_prev)
    centrar_var.trace_add("write", update_prev)
    reducir_var.trace_add("write", update_prev)
    negrita_var.trace_add("write", update_prev)

    bf = ttk.Frame(pv)
    bf.pack(pady=10)

    def do_print():
        cb_imp.update_idletasks()
        im = sel_imp.get()
        if not im:
            messagebox.showwarning("Impresión", "Selecciona una impresora.")
            return
        m = modo_var.get()
        a = ancho_var.get()
        c = centrar_var.get()
        txt = generar_texto_premios(premios_grouped, m, a, c, resultados_columns)
        if m == "Ticket":
            imprimir_directo_ticket(txt, im, negrita_var, reducir_var)
            messagebox.showinfo("Impresión", "Ticket enviado.")
            pv.destroy()
            return
        fd, tmp = tempfile.mkstemp(suffix=".txt", text=True)
        os.write(fd, txt.encode("utf-8"))
        os.close(fd)
        subprocess.Popen(
            ["notepad.exe", "/p", tmp], creationflags=subprocess.DETACHED_PROCESS
        )
        messagebox.showinfo("Impresión", "Enviado a impresora.")
        pv.destroy()

    ttk.Button(bf, text="🖨 Imprimir", style="Preview.TButton", command=do_print).pack(
        side="left", padx=10
    )
    ttk.Button(bf, text="CANCELAR", style="Preview.TButton", command=pv.destroy).pack(
        side="left"
    )
    update_prev()


def show_modern_keypad(parent, on_submit):
    keypad = tk.Toplevel(parent)
    keypad.attributes("-fullscreen", True)
    keypad.attributes("-topmost", True)
    keypad.transient(parent)
    keypad.grab_set()
    keypad.configure(bg="black")  # Fondo por defecto

    frm = tk.Frame(keypad, bg="black", bd=0)
    frm.place(relx=0.5, rely=0.5, anchor="center")

    # Usar imagen de publicidad como fondo del keypad
    print(f"DEBUG - fondo_img_ref en keypad: {fondo_img_ref}")
    print(f"DEBUG - keypad_fondo_img_ref en keypad: {keypad_fondo_img_ref}")

    # Priorizar la imagen de publicidad, luego la específica del keypad
    imagen_fondo = fondo_img_ref if fondo_img_ref else keypad_fondo_img_ref

    if imagen_fondo:
        label_fondo = tk.Label(keypad, image=imagen_fondo)
        label_fondo.place(x=0, y=0, relwidth=1, relheight=1)
        frm.lift()  # Mantener el frame al frente
        print("DEBUG - Imagen de fondo aplicada al keypad")
    else:
        print("DEBUG - No hay imagen de fondo disponible para el keypad")

    style = ttk.Style(frm)
    style.theme_use("default")
    style.configure(
        "ModernKp.TButton",
        font=("Segoe UI", 28, "bold"),
        foreground="white",
        background="#222",
        borderwidth=0,
        focusthickness=3,
        focuscolor="#00BFFF",
        padding=20,
        relief="flat",
    )
    style.map(
        "ModernKp.TButton",
        background=[("active", "#444"), ("pressed", "#00BFFF")],
        foreground=[("active", "white"), ("pressed", "white")],
    )
    style.configure(
        "ModernKp.TLabel",
        background="black",
        foreground="white",
        font=("Segoe UI", 22, "bold"),
        padding=10,
    )

    var = tk.StringVar(master=keypad)
    ttk.Label(frm, text="Ingrese su dorsal", style="ModernKp.TLabel").grid(
        row=0, column=0, columnspan=3, pady=(10, 5)
    )
    entry = tk.Entry(
        frm,
        textvariable=var,
        font=("Segoe UI", 28, "bold"),
        justify="center",
        fg="#00BFFF",
        bg="black",
        relief="flat",
        width=6,
        insertbackground="white",
    )
    entry.grid(row=1, column=0, columnspan=3, pady=(5, 20), ipadx=10, ipady=10)
    entry.focus()

    def submit():
        keypad.grab_release()
        keypad.destroy()
        on_submit(var.get().strip())

    entry.bind("<Return>", lambda e: submit())

    keys = [
        ("1", 2, 0),
        ("2", 2, 1),
        ("3", 2, 2),
        ("4", 3, 0),
        ("5", 3, 1),
        ("6", 3, 2),
        ("7", 4, 0),
        ("8", 4, 1),
        ("9", 4, 2),
        ("0", 5, 1),
    ]
    for txt, r, c in keys:
        ttk.Button(
            frm,
            text=txt,
            style="ModernKp.TButton",
            command=lambda x=txt: var.set(var.get() + x),
            width=3,
        ).grid(row=r, column=c, padx=10, pady=10, ipadx=10, ipady=10)
    ttk.Button(
        frm,
        text="←",
        style="ModernKp.TButton",
        command=lambda: var.set(var.get()[:-1]),
        width=3,
    ).grid(row=5, column=0, padx=10, pady=10, ipadx=10, ipady=10)
    ttk.Button(frm, text="OK", style="ModernKp.TButton", command=submit, width=3).grid(
        row=5, column=2, padx=10, pady=10, ipadx=10, ipady=10
    )


def show_updating_overlay(parent):
    """Muestra un overlay con el mensaje 'Actualizando datos...'"""
    win = tk.Toplevel(parent)
    win.withdraw()  # Ocultar mientras se configura
    win.overrideredirect(True)
    win.configure(bg="#000000")
    win.attributes("-alpha", 0.8)
    win.attributes("-topmost", True)

    # Asegurar que la ventana ocupe toda la pantalla
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    win.geometry(f"{sw}x{sh}+0+0")

    # Frame central con el mensaje
    frm = tk.Frame(win, bg="#000000", bd=2, relief="raised")
    frm.place(relx=0.5, rely=0.5, anchor="center")

    # Mensaje con estilo
    lbl = tk.Label(
        frm,
        text="Actualizando datos...",
        font=("Segoe UI", 24, "bold"),
        fg="#FFFFFF",
        bg="#000000",
        padx=40,
        pady=20,
    )
    lbl.pack()

    # Barra de progreso indeterminada
    pb = ttk.Progressbar(frm, mode="indeterminate", length=300)
    pb.pack(pady=(0, 20))
    pb.start(15)

    # Mostrar la ventana y asegurar que esté al frente
    win.deiconify()
    win.lift()
    win.focus_force()
    win.grab_set()

    # Actualizar la ventana para asegurar que se muestre correctamente
    win.update_idletasks()

    return win


def show_error_overlay(parent, message):
    win = tk.Toplevel(parent)
    win.overrideredirect(True)
    win.configure(bg="white")
    win.attributes("-alpha", 1.0)
    win.attributes("-topmost", True)
    win.grab_set()
    frm = tk.Frame(win, bg="white", bd=2, relief="ridge")
    frm.place(relx=0.5, rely=0.5, anchor="center")
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{sw}x{sh}+0+0")
    # Icono de advertencia
    ico = tk.Label(frm, text="!", fg="black", bg="white", font=("Segoe UI", 22, "bold"))
    ico.pack(pady=(10, 5))
    # Mensaje en rojo y centrado
    lbl = tk.Label(
        frm,
        text=message,
        fg="red",
        bg="white",
        font=("Segoe UI", 16, "bold"),
        wraplength=400,
        justify="center",
        anchor="center"
    )
    lbl.pack(padx=20, pady=(0, 20), fill="x")
    def close_overlay():
        try:
            win.grab_release()
        except Exception:
            pass
        win.destroy()
    btn = tk.Button(frm, text="OK", font=("Segoe UI", 16, "bold"), width=10, command=close_overlay)
    btn.pack(pady=(0, 20))
    parent.wait_window(win)


def show_result_window(parent, row):
    def get_pos(df_cl, row, categoria=None, grupo=None, sexo=None):
        # Busca por DORSAL y, si hay varios, por NOMBRES y APELLIDOS
        sel = df_cl[(df_cl["DORSAL"] == row["DORSAL"]) & (df_cl["POS"] != "POS")]
        if categoria and "CATEGORIA" in df_cl.columns:
            sel2 = sel[sel["CATEGORIA"] == categoria]
            if not sel2.empty:
                sel = sel2
        if grupo and "GRUPO" in df_cl.columns:
            sel2 = sel[sel["GRUPO"] == grupo]
            if not sel2.empty:
                sel = sel2
        if sexo and "SEXO" in df_cl.columns:
            sel2 = sel[sel["SEXO"] == sexo]
            if not sel2.empty:
                sel = sel2
        # Si hay varios con el mismo dorsal, filtra por nombre y apellido
        if len(sel) > 1 and "NOMBRES" in df_cl.columns and "APELLIDOS" in df_cl.columns:
            sel2 = sel[
                (sel["NOMBRES"] == row.get("NOMBRES", ""))
                & (sel["APELLIDOS"] == row.get("APELLIDOS", ""))
            ]
            if not sel2.empty:
                sel = sel2
        pos = sel["POS"].iloc[0] if not sel.empty else ""
        return pos if pos else "#"

    d = row["DORSAL"]
    categoria = row.get("CATEGORIA", "")
    grupo = row.get("GRUPO", "")
    sexo = row.get("SEXO", "")

    p1 = get_pos(dfs["General"], row)
    p2 = get_pos(dfs["Por Categoría"], row, categoria=categoria)
    p3 = get_pos(dfs["Por Grupo"], row, grupo=grupo)
    p4 = get_pos(dfs["Por Sexo"], row, sexo=sexo)
    win = tk.Toplevel(parent)
    win.title("Resultado")
    win.attributes("-topmost", True)  # <-- Agrega esto
    if BARRA == "OFF":
        win.overrideredirect(True)
        win.state("zoomed")
    else:
        win.geometry("450x600")
        win.update()
        x = (win.winfo_screenwidth() - win.winfo_width()) // 2
        y = (win.winfo_screenheight() - win.winfo_height()) // 2
        win.geometry(f"+{x}+{y}")
    if TIMEOUT_RESULT > 0:
        win.after(TIMEOUT_RESULT * 1000, win.destroy)
    raw = row["TIEMPO"]
    tk.Label(
        win, text=str(raw), font=("Segoe UI", 32, "bold"), fg="white", bg="#003366"
    ).pack(fill="x", pady=(0, 5))
    if raw in SPECIAL:
        tk.Label(
            win,
            text=SPECIAL_DESC[raw],
            font=("Segoe UI", 16, "italic"),
            fg="yellow",
            bg="#003366",
        ).pack(fill="x", pady=(0, 10))
    card = tk.Frame(win, bg="white", bd=2, relief="groove")
    card.pack(padx=20, pady=10, fill="both", expand=True)
    tk.Label(
        card,
        text=row.get("NOMBRES", "").upper(),
        font=("Segoe UI", 24, "bold"),
        fg="#3F51B5",
        bg="white",
    ).pack(pady=(20, 0))
    tk.Label(
        card,
        text=row.get("APELLIDOS", "").upper(),
        font=("Segoe UI", 24, "bold"),
        fg="#3F51B5",
        bg="white",
    ).pack(pady=(0, 20))

    def sep():
        ttk.Separator(card, orient="horizontal").pack(fill="x", pady=5)

    for lbl, val, pos in [
        ("General", "", f"#{p1}"),
        ("Categoría", row.get("CATEGORIA", ""), f"#{p2}"),
        ("Grupo", row.get("GRUPO", ""), f"#{p3}"),
        ("Sexo", row.get("SEXO", ""), f"#{p4}"),
    ]:
        tk.Label(
            card, text=f"{lbl}: Pos: {pos}", font=("Segoe UI", 16, "bold"), bg="white"
        ).pack(anchor="center")
        if val:
            tk.Label(card, text=val, font=("Segoe UI", 14), bg="white").pack(
                anchor="center"
            )
        sep()
    for fld in ("CIUDAD", "EQUIPO"):
        v = row.get(fld, "")
        if v:
            tk.Label(
                card,
                text=f"{fld.capitalize()}: {v}",
                font=("Segoe UI", 12, "italic"),
                fg="#666",
                bg="white",
            ).pack(pady=(5, 0))
    st = ttk.Style(win)
    st.configure("Close.TButton", font=("Segoe UI", 18, "bold"), padding=12)
    ttk.Button(win, text="Cerrar", style="Close.TButton", command=win.destroy).pack(
        pady=20
    )


class ExcelMonitor(FileSystemEventHandler):
    def __init__(self, path):
        super().__init__()
        self.path = os.path.abspath(path)

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.path:
            root.after(200, lambda: actualizar_datos_excel(self.path))


actualizando_datos = False  # Bandera global


def actualizar_datos_excel(path):
    global actualizando_datos
    actualizando_datos = True
    resultado = queue.Queue()
    overlay = show_updating_overlay(root)

    # Asegurar que el overlay esté visible
    overlay.update()
    root.update_idletasks()

    def worker():
        try:
            while True:
                try:
                    ext = os.path.splitext(path)[1].lower()
                    eng = "xlrd" if ext == ".xls" else "openpyxl"
                    df = pd.read_excel(
                        path, engine=eng, sheet_name=SHEET_NAME, dtype=str
                    )
                    df["DORSAL"] = df["DORSAL"].astype(str).str.strip()
                    resultado.put(("success", df))
                    break
                except PermissionError:
                    time.sleep(0.5)
                except Exception as e:
                    resultado.put(("error", str(e)))
                    break
        except Exception as e:
            resultado.put(("error", str(e)))

    def check_thread():
        try:
            status, data = resultado.get_nowait()
            try:
                if status == "success":
                    try:
                        global df_inscritos
                        df_inscritos = data.copy()
                        for col in df_inscritos.columns:
                            df_inscritos[col] = df_inscritos[col].astype(str)
                        df_inscritos["TIEMPO"] = df_inscritos["TIEMPO"].apply(
                            format_time_str
                        )
                        dfs.clear()
                        dfs.update(
                            {
                                "General": clasificacion_general(df_inscritos),
                                "Por Categoría": clasificar_con_encabezados(
                                    df_inscritos, "CATEGORIA"
                                ),
                                "Por Grupo": clasificar_con_encabezados(
                                    df_inscritos, "GRUPO"
                                ),
                                "Por Sexo": clasificar_con_encabezados(
                                    df_inscritos, "SEXO"
                                ),
                            }
                        )
                        actualizar_tabs()
                        print(
                            f"DEBUG: Actualización exitosa. Registros cargados: {len(df_inscritos)}"
                        )
                    except Exception as e:
                        messagebox.showerror(
                            "Error", f"Error procesando datos:\n{str(e)}"
                        )
                else:
                    messagebox.showerror(
                        "Error", f"No se pudo acceder al archivo.\n{data}"
                    )
            finally:
                try:
                    overlay.destroy()
                except Exception:
                    pass
                actualizando_datos = False
        except queue.Empty:
            root.after(100, check_thread)
        except Exception as e:
            # Si ocurre un error inesperado, aseguramos liberar todo
            try:
                overlay.destroy()
            except Exception:
                pass
            actualizando_datos = False
            messagebox.showerror(
                "Error", f"Error inesperado en actualización de datos:\n{e}"
            )

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    root.after(100, check_thread)


def cargar_excel(path):
    global df_inscritos, dfs
    try:
        ext = os.path.splitext(path)[1].lower()
        eng = "xlrd" if ext == ".xls" else "openpyxl"
        df_inscritos = pd.read_excel(path, sheet_name=SHEET_NAME, engine=eng, dtype=str)
    except Exception as e:
        show_error_overlay(root, f"No puedo cargar:\n{e}")
        return
    df_inscritos["TIEMPO"] = df_inscritos["TIEMPO"].astype(str).apply(format_time_str)
    dfs.clear()
    dfs.update(
        {
            "General": clasificacion_general(df_inscritos),
            "Por Categoría": clasificar_con_encabezados(df_inscritos, "CATEGORIA"),
            "Por Grupo": clasificar_con_encabezados(df_inscritos, "GRUPO"),
            "Por Sexo": clasificar_con_encabezados(df_inscritos, "SEXO"),
        }
    )
    actualizar_tabs()


def restart_program():
    """Reinicia el programa actual"""
    try:
        import subprocess
        import sys

        print("Reiniciando el sistema...")

        # Cerrar ventana principal si existe
        global root
        if root:
            root.quit()
            root.destroy()

        # Obtener el ejecutable y argumentos actuales
        python = sys.executable
        script = sys.argv[0]

        # Si estamos ejecutando desde un .exe (PyInstaller)
        if getattr(sys, "frozen", False):
            # Ejecutable compilado
            subprocess.Popen([sys.executable] + sys.argv[1:])
        else:
            # Script de Python
            subprocess.Popen([python, script] + sys.argv[1:])

        # Salir del programa actual
        sys.exit(0)

    except Exception as e:
        print(f"ERROR reiniciando programa: {e}")
        # Si falla el reinicio, al menos cerrar el programa actual
        sys.exit(1)


def open_config_form():
    """Abre el formulario de configuración"""
    global cfg, root, BARRA
    try:
        # Minimizar temporalmente la ventana principal para evitar conflictos
        was_fullscreen = False
        was_override_redirect = False

        if root:
            # Verificar estado actual
            try:
                was_fullscreen = root.attributes("-fullscreen")
            except Exception:
                was_fullscreen = False

            # Verificar si tiene override redirect
            try:
                was_override_redirect = root.overrideredirect()
            except Exception:
                was_override_redirect = False

            root.withdraw()  # Ocultar ventana principal temporalmente

        try:
            from config_form import show_config_form

            # Mostrar formulario sin parent para evitar problemas de Toplevel
            success = show_config_form(None)
        except ImportError as e:
            msgbox.showerror(
                "Error", f"No se pudo cargar el formulario de configuración: {e}"
            )
            success = False
        except Exception as e:
            msgbox.showerror("Error", f"Error al abrir configuración: {e}")
            success = False

        # Restaurar ventana principal
        if root:
            try:
                root.deiconify()  # Mostrar ventana principal de nuevo
                root.lift()  # Traer al frente
                root.focus_force()  # Forzar foco

                # Restaurar el estado según la configuración BARRA
                if BARRA == "OFF":
                    # Sin barra: usar override redirect y zoomed
                    root.overrideredirect(True)
                    root.state("zoomed")
                else:
                    # Con barra: configuración normal
                    root.overrideredirect(False)
                    try:
                        root.attributes("-fullscreen", True)
                    except Exception:
                        root.state("zoomed")

                # Forzar actualización de la ventana
                root.update_idletasks()
                root.update()

            except Exception as restore_error:
                print(f"Error restaurando ventana: {restore_error}")
                # Como último recurso, solo mostrar la ventana
                root.deiconify()
                root.state("zoomed")

        if success:
            # Mostrar mensaje y reiniciar programa
            # Cerrar ventana principal antes del mensaje
            if root:
                root.withdraw()

            # Preguntar si quiere reiniciar ahora
            restart = msgbox.askyesno(
                "Configuración Guardada",
                "Configuración guardada exitosamente.\n\n"
                "Para aplicar todos los cambios es necesario reiniciar el sistema.\n\n"
                "¿Reiniciar ahora?",
                icon="question",
            )

            if restart:
                # Reiniciar el programa
                restart_program()
            else:
                # Si no quiere reiniciar, restaurar ventana
                if root:
                    root.deiconify()
                    if BARRA == "OFF":
                        root.overrideredirect(True)
                        root.state("zoomed")
                    else:
                        root.overrideredirect(False)
                        try:
                            root.attributes("-fullscreen", True)
                        except Exception:
                            root.state("zoomed")
        else:
            # Mostrar mensaje de cancelación
            msgbox.showwarning("Configuración", "Configuración cancelada.")

    except Exception as e:
        # Restaurar ventana principal en caso de error
        if root:
            root.deiconify()
            root.lift()
            root.focus_force()

        msgbox.showerror("Error", f"Error abriendo configuración: {e}")


def process_dorsal(d):
    global actualizando_datos
    if actualizando_datos:
        show_error_overlay(
            root,
            "Espere, los datos están actualizándose. Intente de nuevo en unos segundos."
        )
        # Liberar el flag por si quedó trabado
        actualizando_datos = False
        return

    """
    Lógica de búsqueda de dorsal con manejo de duplicados:
    - Si no encuentra, muestra error.
    - Si encuentra uno, lo muestra directamente.
    - Si encuentra varios, llama al diálogo de elección.
    - Si es el código secreto, abre el formulario de configuración.
    """
    # Verificar si es el código secreto para configuración
    try:
        from config_manager import ConfigManager

        config_manager = ConfigManager()
        config_code = config_manager.get_config("CONFIG_CODE", "00000")
    except Exception:
        config_code = "00000"  # Valor por defecto si hay error

    # Asegurarse que el dorsal sea string y sin espacios
    d = str(d).strip()

    # Verificar códigos especiales
    if d == config_code:  # Código de configuración
        open_config_form()
        return

    if EXIT_CODE and d == str(EXIT_CODE):  # Código de salida
        root.quit()
        root.destroy()
        exit_code = int(EXIT_CODE)
        sys.exit(exit_code)  # Usar el código configurado

    # Buscar el dorsal
    sel = df_inscritos[df_inscritos["DORSAL"] == d]
    if sel.empty:
        show_error_overlay(root, "Dorsal no encontrado.")
        return

    if len(sel) == 1:
        # Un solo resultado: mostrarlo directamente
        show_result_window(root, sel.iloc[0])
        return

    # Varios resultados: mostrar diálogo de selección
    opciones = [
        f"{r['NOMBRES']} {r['APELLIDOS']} — Tiempo: {r['TIEMPO']}"
        for _, r in sel.iterrows()
    ]
    idx = simple_choice_dialog(
        root, f"{len(opciones)} resultados para dorsal {d}", opciones
    )
    if idx is not None:
        show_result_window(root, sel.iloc[idx])


def mostrar_en_tab(df, tab, style_base):
    """
    Muestra un DataFrame en una pestaña de Tkinter con un Treeview,
    ocultando las columnas indicadas y ajustando automáticamente
    el ancho de cada columna al contenido.
    """
    # Limpia la pestaña
    for w in tab.winfo_children():
        w.destroy()
    if df.empty:
        return

    # Contenedor y scrollbars
    cont = tk.Frame(tab)
    cont.pack(expand=True, fill="both")
    vs = ttk.Scrollbar(cont, orient="vertical")
    vs.pack(side="right", fill="y")
    hs = ttk.Scrollbar(cont, orient="horizontal")
    hs.pack(side="bottom", fill="x")

    # Determinar columnas a mostrar
    cols = ["POS"] if "POS" in df.columns else []
    for c in df.columns:
        if c != "POS" and c.upper() not in ocultar_columns:
            cols.append(c)

    # Crear el Treeview
    tree = ttk.Treeview(
        cont,
        columns=cols,
        show="headings",
        style=f"{style_base}.Treeview",
        yscrollcommand=vs.set,
        xscrollcommand=hs.set,
    )
    vs.config(command=tree.yview)
    hs.config(command=tree.xview)

    # Configurar encabezados y anchuras provisionales
    for c in cols:
        tree.heading(c, text=c, anchor="center")
        tree.column(c, width=(200 if c == "TIEMPO" else 140), anchor="center")

    # Configurar estilo para la fila de cabecera interna
    tree.tag_configure(
        "headerrow", background=colors[style_base], font=("Segoe UI", 16, "bold")
    )

    # Insertar datos
    for idx, r in enumerate(df.iterrows()):
        _, row = r
        tags = ("headerrow",) if row.get("POS", "") == "POS" else ()
        # Intercalar color solo para filas de datos (no encabezado interno)
        if not tags:
            tags += ("evenrow",) if idx % 2 == 0 else ("oddrow",)
        tree.insert("", tk.END, values=[row.get(c, "") for c in cols], tags=tags)

    # Configurar colores intercalados
    tree.tag_configure("evenrow", background="#f7fafd")  # Color suave 1
    tree.tag_configure("oddrow", background="#e9f1fb")  # Color suave 2
    tree.tag_configure(
        "headerrow", background=colors[style_base], font=("Segoe UI", 16, "bold")
    )

    # Empaquetar y ajustar anchos
    tree.pack(expand=True, fill="both")
    tree.update_idletasks()
    ajustar_ancho_columnas(tree, padding=20)

    # Doble clic para keypad
    tree.bind("<Double-Button-1>", lambda e: show_modern_keypad(root, process_dorsal))

    # Scroll táctil mediante arrastre
    def _on_press(event):
        tree._drag_start_y = event.y
        tree._drag_accum = 0

    def _on_drag(event):
        if not hasattr(tree, "_drag_start_y"):
            tree._drag_start_y = event.y
            tree._drag_accum = 0
        dy = event.y - tree._drag_start_y
        tree._drag_accum += dy
        step = 6
        while abs(tree._drag_accum) >= step:
            direction = -1 if tree._drag_accum > 0 else 1
            tree.yview_scroll(direction, "units")
            tree._drag_accum -= step * (1 if tree._drag_accum > 0 else -1)
        tree._drag_start_y = event.y

    tree.bind("<ButtonPress-1>", _on_press)
    tree.bind("<B1-Motion>", _on_drag)


def actualizar_tabs():
    tab_map = [
        ("General", tab_general),
        ("Por Categoría", tab_categoria),
        ("Por Grupo", tab_grupo),
        ("Por Sexo", tab_sexo),
        ("Resultados", tab_premios),
    ]
    for t in notebook.tabs():
        notebook.forget(t)
    for name, frm in tab_map:
        if name.upper() not in ocultar_tabs:
            notebook.add(frm, text=name)
    if "GENERAL" not in ocultar_tabs:
        mostrar_en_tab(dfs["General"], tab_general, "General")
    if "POR CATEGORÍA" not in ocultar_tabs:
        mostrar_en_tab(dfs["Por Categoría"], tab_categoria, "Por Categoría")
    if "POR GRUPO" not in ocultar_tabs:
        mostrar_en_tab(dfs["Por Grupo"], tab_grupo, "Por Grupo")
    if "POR SEXO" not in ocultar_tabs:
        mostrar_en_tab(dfs["Por Sexo"], tab_sexo, "Por Sexo")
    if "RESULTADOS" not in ocultar_tabs:
        actualizar_premios_tab()


def actualizar_premios_tab():
    for w in tab_premios.winfo_children():
        w.destroy()
    frm = tk.Frame(tab_premios, bg="white", pady=10)
    frm.pack(fill="x")
    tk.Label(frm, text="Base:", font=("Segoe UI", 12), bg="white").pack(
        side="left", padx=(10, 2)
    )
    cb = ttk.Combobox(frm, values=list(dfs.keys()), state="readonly", width=18)
    cb.current(0)
    cb.pack(side="left", padx=10)
    tk.Label(frm, text="Premiar primeros:", font=("Segoe UI", 12), bg="white").pack(
        side="left", padx=(10, 2)
    )
    en = Spinbox(frm, from_=1, to=100, width=7, font=("Segoe UI", 14), justify="center")
    en.delete(0, "end")
    en.insert(0, "3")
    en.pack(side="left", padx=10)
    ttk.Button(
        frm, text="Generar lista", command=lambda: genera_premios(cb.get(), en.get())
    ).pack(side="left", padx=10)
    ttk.Button(frm, text="Exportar a Excel", command=exportar_excel).pack(
        side="right", padx=10
    )
    ttk.Button(frm, text="Imprimir", command=imprimir_premios).pack(side="right")
    canvas = tk.Canvas(tab_premios)
    vsb = ttk.Scrollbar(tab_premios, orient="vertical", command=canvas.yview)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    canvas.configure(yscrollcommand=vsb.set)

    def _on_press_c(event):
        canvas.scan_mark(event.x, event.y)

    def _on_drag_c(event):
        canvas.scan_dragto(event.x, event.y, gain=1)

    canvas.bind("<ButtonPress-1>", _on_press_c)
    canvas.bind("<B1-Motion>", _on_drag_c)

    cont = tk.Frame(canvas)
    canvas.create_window((0, 0), window=cont, anchor="nw")
    cont.bind(
        "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    tab_premios._cont = cont


def genera_premios(base, n_str):
    try:
        N = max(0, int(n_str))
    except ValueError:
        messagebox.showerror("Entrada inválida", "Ingresa entero válido.")
        return
    dfb = dfs.get(base, pd.DataFrame())
    out = []
    agrup = {"Por Categoría": "CATEGORIA", "Por Grupo": "GRUPO", "Por Sexo": "SEXO"}
    if base == "General":
        valid = dfb[dfb["POS"].apply(lambda x: str(x).isdigit())].copy()
        valid["POS"] = valid["POS"].astype(int)
        sel = valid.sort_values("POS").head(N)
        hdr = {c: "" for c in resultados_columns}
        hdr[resultados_columns[0]] = "GENERAL"
        out.append(hdr)
        out.append({c: c for c in resultados_columns})
        for _, r in sel.iterrows():
            out.append({c: r[c] for c in resultados_columns})
    else:
        col = agrup[base]
        valid = dfb[dfb["POS"].apply(lambda x: str(x).isdigit())].copy()
        valid["POS"] = valid["POS"].astype(int)
        for val in df_inscritos[col].dropna().unique():
            sub = valid[valid[col] == val]
            if sub.empty:
                continue
            hdr = {c: "" for c in resultados_columns}
            hdr[resultados_columns[0]] = str(val)
            out.append(hdr)
            out.append({c: c for c in resultados_columns})
            for _, r in sub.sort_values("POS").head(N).iterrows():
                out.append({c: r[c] for c in resultados_columns})
    global premios_grouped
    premios_grouped = pd.DataFrame(out)
    cont = tab_premios._cont
    for w in cont.winfo_children():
        w.destroy()
    for _, row in premios_grouped.iterrows():
        vals = [row[c] for c in resultados_columns]
        is_hdr = all(str(vals[i]) == resultados_columns[i] for i in range(len(vals)))
        is_desc = (
            isinstance(vals[0], str) and vals[0] and all(v == "" for v in vals[1:])
        )
        if is_desc:
            tk.Label(
                cont, text=vals[0], font=("Segoe UI", 16, "bold"), bg="#ddd", anchor="w"
            ).pack(fill="x", pady=(10, 0))
        elif is_hdr:
            frm_hdr = tk.Frame(cont, bg="white")
            frm_hdr.pack(fill="x")
            for c in resultados_columns:
                tk.Label(
                    frm_hdr,
                    text=c,
                    font=("Segoe UI", 14, "bold"),
                    width=15,
                    anchor="center",
                ).pack(side="left", expand=True, fill="x")
            tk.Label(frm_hdr, text="", width=15).pack(
                side="left", expand=True, fill="x"
            )
        else:
            frm_row = tk.Frame(cont, bg="white")
            frm_row.pack(fill="x")
            for v in vals:
                tk.Label(
                    frm_row,
                    text=str(v),
                    font=("Segoe UI", 12),
                    width=15,
                    anchor="center",
                ).pack(side="left", expand=True, fill="x")


def exportar_excel():
    if premios_grouped.empty:
        messagebox.showwarning("Exportar", "No hay datos")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")]
    )
    if not path:
        return
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        premios_grouped.to_excel(w, index=False, header=False)
    messagebox.showinfo("Exportar", f"Guardado en:\n{path}")


def show_updating_overlay(parent):
    """Muestra un overlay semi-transparente con mensaje de actualización"""
    overlay = tk.Toplevel(parent)
    overlay.transient(parent)
    overlay.overrideredirect(True)
    overlay.attributes("-topmost", True, "-alpha", 0.7)

    # Centrar en la pantalla
    screen_width = parent.winfo_screenwidth()
    screen_height = parent.winfo_screenheight()
    overlay.geometry(f"{screen_width}x{screen_height}+0+0")

    # Configurar fondo y estilo
    overlay.configure(bg="black")

    # Frame central para el mensaje
    frame = tk.Frame(overlay, bg="black", bd=2, relief="solid")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    # Mensaje principal
    label = tk.Label(
        frame,
        text="Actualizando datos...",
        font=("Arial", 24, "bold"),
        fg="white",
        bg="black",
        pady=20,
        padx=40,
    )
    label.pack()

    # Mensaje secundario
    sub_label = tk.Label(
        frame,
        text="Por favor espere mientras se procesan los cambios",
        font=("Arial", 12),
        fg="light gray",
        bg="black",
        pady=10,
    )
    sub_label.pack()

    overlay.update()
    return overlay


# --- Modifica la función donde cargas el Excel ---
def cargar_excel_con_overlay(path, root):

    overlay = show_updating_overlay(root)

    def intentar_cargar():
        try:
            # Aquí va tu código original para cargar el Excel, por ejemplo:
            df = pd.read_excel(path)
            overlay.destroy()
            # Aquí sigue el flujo normal de tu programa, por ejemplo:
            actualizar_tabs()
        except PermissionError:
            # Si el archivo está bloqueado, reintenta en 2 segundos
            root.after(2000, intentar_cargar)
        except Exception as e:
            overlay.destroy()
            messagebox.showerror("Error", f"No puedo cargar:\n{e}")

    intentar_cargar()


# --- Usa esta función donde antes cargabas el Excel ---
# Por ejemplo, reemplaza:
# df = pd.read_excel(path)
# por:
# cargar_excel_con_overlay(path, root)

# --- Arranque ---
# --- Las siguientes variables se inicializarán en main() ---
# cfg = read_config()
# EVENTO = cfg.get("EVENTO", "")
# TITULO = cfg.get("TITULO", "")
# LOGO_PATH = os.path.join(BASE_DIR, os.path.basename(cfg.get("LOGO", "")))
# ANCHO_LOGO = int(cfg.get("ANCHO", "80"))
# EXCEL_PATH = cfg.get("RUTA_COMPETIDORES", "")
# SHEET_NAME = cfg.get("HOJA_COMPETIDORES", "INSCRIPTOS")
# TIMEOUT_RESULT = int(cfg.get("TIMEOUT_RESULT", "5"))
# EXIT_CODE = cfg.get("EXIT_CODE", "")
# BARRA = cfg.get("BARRA", "ON").upper()
# PUBLICIDAD_PATH = os.path.join(BASE_DIR, os.path.basename(cfg.get("PUBLICIDAD", "")))

# Valores por defecto
cfg = {}
EVENTO = ""
TITULO = ""
LOGO_PATH = ""
ANCHO_LOGO = 80
EXCEL_PATH = ""
SHEET_NAME = "INSCRIPTOS"
TIMEOUT_RESULT = 5
EXIT_CODE = ""
BARRA = "ON"
PUBLICIDAD_PATH = ""


ocultar_columns = []
resultados_columns = []
ocultar_tabs = []

CARRUSEL_MSG = ""

# Colores para estilos de Treeview
colors = {
    "General": "#add8e6",
    "Por Categoría": "#d1f2d1",
    "Por Grupo": "#fff4a3",
    "Por Sexo": "#f8d7da",
}

# Variables globales para el carrusel
carrusel_canvas = None
text_id = None


# Variables globales para las imágenes
def move_text():
    """Función para mover el texto del carrusel"""
    global carrusel_canvas, text_id
    if (
        "carrusel_canvas" in globals()
        and carrusel_canvas
        and "text_id" in globals()
        and text_id
    ):
        try:
            carrusel_canvas.update_idletasks()
            bbox = carrusel_canvas.bbox(text_id)
            if bbox:  # Verificar que bbox no sea None
                x1, y1, x2, y2 = bbox
                ancho_canvas = carrusel_canvas.winfo_width()
                if x2 < 0:
                    # Si el texto salió completamente, lo regresa a la derecha
                    carrusel_canvas.coords(text_id, ancho_canvas, 20)
                else:
                    carrusel_canvas.move(text_id, -2, 0)  # velocidad
                carrusel_canvas.after(12, move_text)  # velocidad de refresco
        except tk.TclError:
            # El widget fue destruido, detener el carrusel
            pass


def resize_canvas(event):
    """Función para redimensionar el canvas del carrusel"""
    global carrusel_canvas, text_id
    if carrusel_canvas and text_id:
        carrusel_canvas.coords(text_id, carrusel_canvas.winfo_width(), 20)


def preload_image_data():
    """Precarga los datos de las imágenes (PIL) antes de crear la interfaz"""
    global logo_pil_img, fondo_pil_img, keypad_fondo_pil_img

    print("Precargando datos de imágenes...")

    # Precargar datos del logo
    if Image and LOGO_PATH and os.path.exists(LOGO_PATH):
        try:
            img = Image.open(LOGO_PATH)
            wpercent = ANCHO_LOGO / float(img.size[0])
            hsize = int((float(img.size[1]) * wpercent))
            logo_pil_img = img.resize((ANCHO_LOGO, hsize), Image.Resampling.LANCZOS)
            print("Datos del logo precargados exitosamente")
        except Exception as e:
            print(f"Error precargando datos del logo: {e}")
            logo_pil_img = None
    else:
        logo_pil_img = None

    # Precargar datos del fondo/publicidad
    print(f"DEBUG - Ruta publicidad: {PUBLICIDAD_PATH}")
    print(f"DEBUG - Existe archivo publicidad: {os.path.exists(PUBLICIDAD_PATH)}")
    if Image and os.path.exists(PUBLICIDAD_PATH):
        try:
            fondo_pil_img = Image.open(PUBLICIDAD_PATH)
            print("Datos del fondo precargados exitosamente")
        except Exception as e:
            print(f"Error precargando datos del fondo: {e}")
            fondo_pil_img = None
    else:
        fondo_pil_img = None
        print(
            "No se pudo precargar fondo de publicidad (Image no disponible o archivo no existe)"
        )

    # Precargar datos del fondo del keypad
    keypad_fondo_path = os.path.join(BASE_DIR, "img", "fondo.png")
    print(f"DEBUG - Ruta fondo keypad: {keypad_fondo_path}")
    print(f"DEBUG - Existe archivo fondo keypad: {os.path.exists(keypad_fondo_path)}")
    if Image and os.path.exists(keypad_fondo_path):
        try:
            keypad_fondo_pil_img = Image.open(keypad_fondo_path)
            print("Datos del fondo keypad precargados exitosamente")
        except Exception as e:
            print(f"Error precargando datos del fondo keypad: {e}")
            keypad_fondo_pil_img = None
    else:
        keypad_fondo_img_ref = None
        print(
            "No se pudo precargar fondo del keypad (Image no disponible o archivo no existe)"
        )


def create_tkinter_images(master_window):
    """Crea las imágenes Tkinter usando los datos PIL precargados"""
    global logo_img_ref, fondo_img_ref, keypad_fondo_img_ref

    print("Creando imágenes Tkinter...")

    # Crear imagen Tkinter del logo
    if ImageTk and logo_pil_img:
        try:
            logo_img_ref = ImageTk.PhotoImage(logo_pil_img, master=master_window)
            print("Imagen Tkinter del logo creada exitosamente")
        except Exception as e:
            print(f"Error creando imagen Tkinter del logo: {e}")
            logo_img_ref = None
    else:
        logo_img_ref = None

    # Crear imagen Tkinter del fondo
    if ImageTk and fondo_pil_img:
        try:
            sw, sh = (
                master_window.winfo_screenwidth(),
                master_window.winfo_screenheight(),
            )
            print(f"DEBUG - Redimensionando fondo a: {sw}x{sh}")
            fondo_resized = fondo_pil_img.resize((sw, sh), Image.Resampling.LANCZOS)
            fondo_img_ref = ImageTk.PhotoImage(fondo_resized, master=master_window)
            print("Imagen Tkinter del fondo creada exitosamente")
        except Exception as e:
            print(f"Error creando imagen Tkinter del fondo: {e}")
            fondo_img_ref = None
    else:
        fondo_img_ref = None
        print(
            f"DEBUG - No se puede crear fondo Tkinter: ImageTk={ImageTk is not None}, fondo_pil_img={fondo_pil_img is not None}"
        )

    # Crear imagen Tkinter del fondo del keypad
    if ImageTk and keypad_fondo_pil_img:
        try:
            sw, sh = (
                master_window.winfo_screenwidth(),
                master_window.winfo_screenheight(),
            )
            keypad_resized = keypad_fondo_pil_img.resize(
                (sw, sh), Image.Resampling.LANCZOS
            )
            keypad_fondo_img_ref = ImageTk.PhotoImage(
                keypad_resized, master=master_window
            )
            print("Imagen Tkinter del fondo keypad creada exitosamente")
        except Exception as e:
            print(f"Error creando imagen Tkinter del fondo keypad: {e}")
            keypad_fondo_img_ref = None
    else:
        keypad_fondo_img_ref = None


def main():
    """Función principal - carga configuración y ejecuta interfaz"""
    global observer, cfg, EVENTO, TITULO, LOGO_PATH, EXCEL_PATH, SHEET_NAME
    global TIMEOUT_RESULT, EXIT_CODE, BARRA, ANCHO_LOGO, PUBLICIDAD_PATH
    global ocultar_columns, resultados_columns, ocultar_tabs, CARRUSEL_MSG
    global root, notebook, tab_general, tab_categoria, tab_grupo, tab_sexo, tab_premios
    global carrusel_canvas, text_id

    # Cargar configuración al iniciar
    cfg = read_config()
    EVENTO = cfg.get("EVENTO", "")
    TITULO = cfg.get("TITULO", "")

    # Debug: confirmar valores de encabezado
    print(f"DEBUG - EVENTO: '{EVENTO}'")
    print(f"DEBUG - TITULO: '{TITULO}'")

    # Manejo inteligente de la ruta del logo
    logo_config = cfg.get("LOGO", "")
    if logo_config:
        if os.path.isabs(logo_config) and os.path.exists(logo_config):
            LOGO_PATH = logo_config
        else:
            possible_paths = [
                os.path.join(BASE_DIR, logo_config),
                os.path.join(BASE_DIR, "img", logo_config),
                os.path.join(BASE_DIR, os.path.basename(logo_config)),
            ]
            LOGO_PATH = ""
            for path in possible_paths:
                if os.path.exists(path):
                    LOGO_PATH = path
                    break
            if not LOGO_PATH:
                LOGO_PATH = os.path.join(BASE_DIR, "img", "logo.png")
    else:
        LOGO_PATH = os.path.join(BASE_DIR, "img", "logo.png")

    ANCHO_LOGO = int(cfg.get("ANCHO", "80"))
    EXCEL_PATH = cfg.get("RUTA_COMPETIDORES", "")
    SHEET_NAME = cfg.get("HOJA_COMPETIDORES", "INSCRIPTOS")
    TIMEOUT_RESULT = int(cfg.get("TIMEOUT_RESULT", "5"))
    EXIT_CODE = cfg.get("EXIT_CODE", "999")  # Código por defecto si no está configurado
    BARRA = cfg.get("BARRA", "ON").upper()

    # Debug: confirmar código de salida
    print(f"DEBUG - EXIT_CODE configurado: '{EXIT_CODE}'")

    # Actualizar ruta de publicidad con la configuración más reciente
    publicidad_config = cfg.get("PUBLICIDAD", "")
    print(f"DEBUG MAIN - publicidad_config de BD: '{publicidad_config}'")
    if publicidad_config:
        if os.path.isabs(publicidad_config) and os.path.exists(publicidad_config):
            PUBLICIDAD_PATH = publicidad_config
        else:
            possible_paths = [
                os.path.join(BASE_DIR, publicidad_config),
                os.path.join(BASE_DIR, "img", publicidad_config),
                os.path.join(BASE_DIR, os.path.basename(publicidad_config)),
            ]
            PUBLICIDAD_PATH = ""
            for path in possible_paths:
                if os.path.exists(path):
                    PUBLICIDAD_PATH = path
                    break
            if not PUBLICIDAD_PATH:
                PUBLICIDAD_PATH = os.path.join(BASE_DIR, "img", "fondo.png")
    else:
        PUBLICIDAD_PATH = os.path.join(BASE_DIR, "img", "fondo.png")

    # Debug: confirmar ruta de publicidad
    print(f"DEBUG - PUBLICIDAD_PATH: '{PUBLICIDAD_PATH}'")
    print(f"DEBUG - Existe archivo publicidad: {os.path.exists(PUBLICIDAD_PATH)}")

    ocultar_columns = [
        c.strip().upper()
        for c in cfg.get("OCULTAR_COLUMNAS", "").split(",")
        if c.strip()
    ]
    resultados_columns = [
        c.strip().upper()
        for c in cfg.get(
            "RESULTADOS_COLUMNAS", "POS,DORSAL,NOMBRES,APELLIDOS,TIEMPO"
        ).split(",")
        if c.strip()
    ]
    ocultar_tabs = [
        t.strip().upper()
        for t in cfg.get("OCULTAR_PESTANAS", "").split(",")
        if t.strip()
    ]

    CARRUSEL_MSG = cfg.get("CARRUSEL", "")

    # Precargar datos de imágenes antes de crear la interfaz
    preload_image_data()

    # Crear ventana principal
    root = tk.Tk()
    root.title(f"{EVENTO} | {TITULO}")
    root.attributes("-topmost", True)  # <-- Siempre al frente

    # Configurar fondo después de que la ventana esté lista
    root.configure(bg="black")  # Fondo por defecto

    # Función para cerrar el sistema completamente
    def cerrar_sistema():
        """Función para cerrar el sistema de manera definitiva"""
        global observer
        print("Cerrando sistema...")

        # Detener observador de archivos
        if observer:
            try:
                observer.stop()
                observer.join()
            except Exception:
                pass

        # Cerrar ventana principal
        if root:
            try:
                root.quit()  # Terminar mainloop
                root.destroy()  # Destruir ventana
            except Exception:
                pass

        # Salir del programa completamente
        import sys

        sys.exit(0)

    if BARRA == "OFF":
        root.overrideredirect(True)
        root.state("zoomed")
        root.protocol("WM_DELETE_WINDOW", lambda: None)
    else:
        root.geometry("1024x700")
        root.state("normal")
        root.protocol("WM_DELETE_WINDOW", cerrar_sistema)

    # Crear las imágenes Tkinter después de que la ventana principal esté lista
    create_tkinter_images(root)

    style = ttk.Style(root)
    style.theme_use("default")
    for k, v in colors.items():
        style.configure(f"{k}.Treeview", rowheight=54, font=("Segoe UI", 14))
        style.configure(
            f"{k}.Treeview.Heading",
            font=("Segoe UI", 16, "bold"),
            background=v,
            foreground="black",
        )
        style.map(
            f"{k}.Treeview.Heading",
            background=[("active", v), ("!active", v)],
            foreground=[("active", "black"), ("!active", "black")],
        )

    style.configure("Search.TButton", font=("Segoe UI", 18, "bold"), padding=12)

    topf = tk.Frame(root, bg="white")
    # Logo del evento - usar imagen precargada
    if logo_img_ref:
        logo_label = tk.Label(topf, image=logo_img_ref, bg="white")
        logo_label.pack(side="left", padx=10, pady=5)

    tk.Label(
        topf, text=EVENTO, font=("Segoe UI", 20, "bold"), bg="white", fg="#0300A7"
    ).pack(side="left", padx=10)
    tk.Label(
        topf,
        text=TITULO,
        font=("Segoe UI", 17),
        bg="white",
        fg="#FF0000"
    ).pack(side="left")
    ttk.Button(
        topf,
        text="BUSCAR",
        style="Search.TButton",
        command=lambda: show_modern_keypad(root, process_dorsal),
    ).pack(side="right", padx=10, pady=5)

    # IMPORTANTE: Empaquetar el frame del encabezado en la parte superior
    topf.pack(side="top", fill="x", padx=5, pady=5)

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")
    tab_general = ttk.Frame(notebook)
    tab_categoria = ttk.Frame(notebook)
    tab_grupo = ttk.Frame(notebook)
    tab_sexo = ttk.Frame(notebook)
    tab_premios = ttk.Frame(notebook)

    if os.path.exists(EXCEL_PATH):
        cargar_excel(EXCEL_PATH)
        obs = Observer()
        obs.schedule(
            ExcelMonitor(EXCEL_PATH),
            os.path.dirname(EXCEL_PATH) or ".",
            recursive=False,
        )
        obs.daemon = True
        obs.start()
        observer = obs
    else:
        messagebox.showwarning("Config", f"No existe Excel en:\n{EXCEL_PATH}")

    # --- Carrusel inferior con desplazamiento suave ---
    if CARRUSEL_MSG:
        carrusel_frame = tk.Frame(root, bg="black", height=40)
        carrusel_frame.pack(side="bottom", fill="x")
        carrusel_canvas = tk.Canvas(
            carrusel_frame, bg="black", height=40, highlightthickness=0
        )
        carrusel_canvas.pack(fill="both", expand=True)

        font_carrusel = ("Segoe UI", 18, "bold")
        separador = "   •   "
        texto_carrusel = (
            CARRUSEL_MSG + separador + CARRUSEL_MSG
        )  # Doble para efecto continuo

        text_id = carrusel_canvas.create_text(
            carrusel_canvas.winfo_width(),
            20,
            text=texto_carrusel,
            font=font_carrusel,
            fill="white",
            anchor="w",
        )

        carrusel_canvas.bind("<Configure>", resize_canvas)

        # Iniciar el carrusel después de un delay para asegurar que esté listo
        def start_carrusel():
            if "carrusel_canvas" in globals() and "text_id" in globals():
                move_text()

        root.after(100, start_carrusel)

    # Mostrar fondo precargado si existe
    print(f"DEBUG - fondo_img_ref: {fondo_img_ref}")
    if fondo_img_ref:
        label_fondo = tk.Label(root, image=fondo_img_ref)
        label_fondo.place(x=0, y=0, relwidth=1, relheight=1)
        # Mantener otros widgets al frente
        topf.lift()
        if "carrusel_frame" in locals():
            # Elevar el frame del carrusel, no el canvas
            carrusel_frame.lift()
        notebook.lift()
        print("DEBUG - Imagen de fondo aplicada")
    else:
        print("DEBUG - No hay imagen de fondo para mostrar")

    # Iniciar el loop principal
    root.mainloop()

    # Cleanup al salir
    if observer:
        observer.stop()
        observer.join()


def run_resultados():
    """Función principal de entrada del sistema de resultados"""
    init_sistema_resultados()
    main()


# Punto de entrada principal cuando se ejecuta directamente
if __name__ == "__main__":
    run_resultados()
