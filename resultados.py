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
from tkinter import filedialog, messagebox, scrolledtext, StringVar, IntVar, BooleanVar
from tkinter import Spinbox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Intentar importar Pillow para logos
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None

# --- Mutex para instancia única ---
MUTEX_NAME = "ResultadosKioskSingletonMutex"
h_mutex = ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX_NAME)
if ctypes.windll.kernel32.GetLastError() == 183:
    # Ya hay otra instancia
    splash = tk.Tk()
    splash.overrideredirect(True)
    w, h = 350, 120
    sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
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
        "Advertencia: 'pywin32' no está instalado. Las opciones de impresión avanzadas no estarán disponibles."
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

# --- Configuración global ---
if getattr(sys, "frozen", False):
    # Si es ejecutable, usa la carpeta del ejecutable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Si es script, usa la carpeta del script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(BASE_DIR, "config_kiosk.txt")
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

EVENTO = TITULO = LOGO_PATH = EXCEL_PATH = SHEET_NAME = ""
TIMEOUT_RESULT = 5
EXIT_CODE = ""
BARRA = "ON"
ANCHO_LOGO = 80


def read_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"{CONFIG_FILE} no encontrado.")
    cfg = {}
    key = None
    with open(CONFIG_FILE, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if ln.endswith(":"):
                key = ln[:-1].upper()
            elif key:
                cfg[key] = ln
                key = None
    return cfg


cfg = read_config()
EVENTO = cfg.get("EVENTO", "")
TITULO = cfg.get("TITULO", "")
LOGO_PATH = os.path.join(BASE_DIR, os.path.basename(cfg.get("LOGO", "")))
ANCHO_LOGO = int(cfg.get("ANCHO", "80"))
EXCEL_PATH = cfg.get("RUTA_COMPETIDORES", "")
SHEET_NAME = cfg.get("HOJA_COMPETIDORES", "INSCRIPTOS")
TIMEOUT_RESULT = int(cfg.get("TIMEOUT_RESULT", "5"))
EXIT_CODE = cfg.get("EXIT_CODE", "")
BARRA = cfg.get("BARRA", "ON").upper()
# NUEVO: Lee la ruta de la imagen publicitaria
PUBLICIDAD_PATH = os.path.join(BASE_DIR, os.path.basename(cfg.get("PUBLICIDAD", "")))


ocultar_columns = [
    c.strip().upper() for c in cfg.get("OCULTAR_COLUMNAS", "").split(",") if c.strip()
]
resultados_columns = [
    c.strip().upper()
    for c in cfg.get(
        "RESULTADOS_COLUMNAS", "POS,DORSAL,NOMBRES,APELLIDOS,TIEMPO"
    ).split(",")
    if c.strip()
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
    dlg.title(title)
    dlg.attributes("-fullscreen", True)
    dlg.attributes("-topmost", True)  # <-- Agrega esto
    dlg.configure(bg="black")
    dlg.transient(parent)
    dlg.grab_set()

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

    def on_ok():
        sel = lb.curselection()
        if sel:
            choice["idx"] = sel[0]
        dlg.destroy()

    def on_cancel():
        dlg.destroy()

    ttk.Button(btns, text="OK", command=on_ok, style="TButton").pack(
        side="left", ipadx=20, ipady=10, padx=20
    )

    ttk.Button(btns, text="Cancelar", command=on_cancel, style="TButton").pack(
        side="left", ipadx=20, ipady=10, padx=20
    )

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
    ttk.Button(
        bf, text="❌ Cancelar", style="Preview.TButton", command=pv.destroy
    ).pack(side="left")
    update_prev()


def show_modern_keypad(parent, on_submit):
    keypad = tk.Toplevel(parent)
    keypad.attributes("-fullscreen", True)
    keypad.attributes("-topmost", True)
    keypad.transient(parent)
    keypad.grab_set()

    # --- Fondo publicitario en el keypad (usa fondo.png) ---
    FONDO_KEYPAD_PATH = os.path.join(BASE_DIR, "fondo.png")
    if Image and ImageTk and os.path.exists(FONDO_KEYPAD_PATH):
        sw, sh = keypad.winfo_screenwidth(), keypad.winfo_screenheight()
        try:
            fondo_img = Image.open(FONDO_KEYPAD_PATH)
            fondo_img = fondo_img.resize((sw, sh), Image.Resampling.LANCZOS)
            fondo_tk = ImageTk.PhotoImage(fondo_img)
            label_fondo = tk.Label(keypad, image=fondo_tk)
            label_fondo.place(x=0, y=0, relwidth=1, relheight=1)
            keypad._fondo_img = fondo_tk  # Previene garbage collection
        except Exception as e:
            print(f"Error cargando imagen de fondo en keypad: {e}")
            keypad.configure(bg="black")
    else:
        keypad.configure(bg="black")

    frm = tk.Frame(keypad, bg="black", bd=0)
    frm.place(relx=0.5, rely=0.5, anchor="center")

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


def show_error_overlay(parent, message):
    win = tk.Toplevel(parent)
    win.overrideredirect(True)
    win.configure(bg="black")
    win.attributes("-alpha", 1.0)
    win.attributes("-topmost", True)  # <-- Agrega esto
    win.grab_set()
    frm = tk.Frame(win, bg="#f5f5f5", bd=2, relief="ridge")
    frm.place(relx=0.5, rely=0.5, anchor="center")
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{sw}x{sh}+0+0")
    ico = tk.Label(frm, bitmap="warning", bg="#f5f5f5")
    ico.pack(pady=(20, 10))
    style = ttk.Style(frm)
    style.configure(
        "Err.TLabel",
        background="#f5f5f5",
        foreground="red",
        font=("Segoe UI", 16, "bold"),
    )
    style.configure("Err.TButton", font=("Segoe UI", 18, "bold"), padding=12)
    lbl = ttk.Label(
        frm,
        text=message,
        style="Err.TLabel",
        wraplength=360,
        anchor="center",
        justify="center",
    )
    lbl.pack(padx=20, pady=(0, 20), fill="x")
    btn = ttk.Button(frm, text="OK", style="Err.TButton", command=win.destroy)
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
            root.after(200, lambda: cargar_excel(self.path))


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


def process_dorsal(d):
    """
    Lógica de búsqueda de dorsal con manejo de duplicados:
    - Si no encuentra, muestra error.
    - Si encuentra uno, lo muestra directamente.
    - Si encuentra varios, llama al diálogo de elección.
    """
    if d == EXIT_CODE:
        root.destroy()
        return

    sel = df_inscritos[df_inscritos["DORSAL"] == d]
    if sel.empty:
        show_error_overlay(root, "Dorsal no encontrado.")
        return

    if len(sel) == 1:
        # Un solo resultado: lo mostramos directamente
        show_result_window(root, sel.iloc[0])
    else:
        # Varios resultados: construimos la lista de opciones
        opciones = [
            f"{r['NOMBRES']} {r['APELLIDOS']} — Tiempo: {r['TIEMPO']}"
            for _, r in sel.iterrows()
        ]
        idx = simple_choice_dialog(
            root, f"{len(opciones)} resultados para dorsal {d}", opciones
        )
        if idx is not None:
            show_result_window(root, sel.iloc[idx])
        # si el usuario cancela, no hacemos nada


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


# --- Agrega esta función cerca del inicio del archivo ---
def show_updating_overlay(parent):
    overlay = tk.Toplevel(parent)
    overlay.overrideredirect(True)
    overlay.attributes("-topmost", True)
    overlay.geometry(f"{parent.winfo_screenwidth()}x{parent.winfo_screenheight()}+0+0")
    overlay.configure(bg="black")
    label = tk.Label(
        overlay,
        text="Actualizando datos...",
        font=("Segoe UI", 36, "bold"),
        fg="white",
        bg="black",
    )
    label.place(relx=0.5, rely=0.5, anchor="center")
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
            cargar_datos_en_ui(df)
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
cfg = read_config()
EVENTO = cfg.get("EVENTO", "")
TITULO = cfg.get("TITULO", "")
LOGO_PATH = os.path.join(BASE_DIR, os.path.basename(cfg.get("LOGO", "")))
ANCHO_LOGO = int(cfg.get("ANCHO", "80"))
EXCEL_PATH = cfg.get("RUTA_COMPETIDORES", "")
SHEET_NAME = cfg.get("HOJA_COMPETIDORES", "INSCRIPTOS")
TIMEOUT_RESULT = int(cfg.get("TIMEOUT_RESULT", "5"))
EXIT_CODE = cfg.get("EXIT_CODE", "")
BARRA = cfg.get("BARRA", "ON").upper()
# NUEVO: Lee la ruta de la imagen publicitaria
PUBLICIDAD_PATH = os.path.join(BASE_DIR, os.path.basename(cfg.get("PUBLICIDAD", "")))


ocultar_columns = [
    c.strip().upper() for c in cfg.get("OCULTAR_COLUMNAS", "").split(",") if c.strip()
]
resultados_columns = [
    c.strip().upper()
    for c in cfg.get(
        "RESULTADOS_COLUMNAS", "POS,DORSAL,NOMBRES,APELLIDOS,TIEMPO"
    ).split(",")
    if c.strip()
]
ocultar_tabs = [
    t.strip().upper() for t in cfg.get("OCULTAR_PESTANAS", "").split(",") if t.strip()
]

CARRUSEL_MSG = cfg.get("CARRUSEL", "")

root = tk.Tk()
root.title(f"{EVENTO} | {TITULO}")
root.attributes("-topmost", True)  # <-- Siempre al frente

# --- Fondo publicitario o fondo negro por defecto ---
if Image and ImageTk and os.path.exists(PUBLICIDAD_PATH):
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    try:
        fondo_img = Image.open(PUBLICIDAD_PATH)
        fondo_img = fondo_img.resize((sw, sh), Image.Resampling.LANCZOS)
        fondo_tk = ImageTk.PhotoImage(fondo_img)
        label_fondo = tk.Label(root, image=fondo_tk)
        label_fondo.place(x=0, y=0, relwidth=1, relheight=1)
        root._fondo_img = fondo_tk  # Previene garbage collection
    except Exception as e:
        print(f"Error cargando imagen de fondo: {e}")
else:
    root.configure(bg="black")

if BARRA == "OFF":
    root.overrideredirect(True)
    root.state("zoomed")
    root.protocol("WM_DELETE_WINDOW", lambda: None)
else:
    root.geometry("1024x700")
    root.state("normal")
    root.protocol(
        "WM_DELETE_WINDOW", lambda: (observer and observer.stop(), root.destroy())
    )

style = ttk.Style(root)
style.theme_use("default")
colors = {
    "General": "#add8e6",
    "Por Categoría": "#d1f2d1",
    "Por Grupo": "#fff4a3",
    "Por Sexo": "#f8d7da",
}
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
topf.pack(fill="x")
if Image and ImageTk and os.path.exists(LOGO_PATH):
    img = Image.open(LOGO_PATH)
    wpercent = ANCHO_LOGO / float(img.size[0])
    hsize = int((float(img.size[1]) * wpercent))
    img = img.resize((ANCHO_LOGO, hsize), Image.Resampling.LANCZOS)
    logo = ImageTk.PhotoImage(img)
    tk.Label(topf, image=logo, bg="white").pack(side="left", padx=10, pady=5)
tk.Label(
    topf, text=EVENTO, font=("Segoe UI", 20, "bold"), bg="white", fg="#0300A7"
).pack(side="left", padx=10)
tk.Label(topf, text=TITULO, font=("Segoe UI", 17), bg="white", fg="#FF0000").pack(
    side="left"
)
ttk.Button(
    topf,
    text="🔍 Busca",
    style="Search.TButton",
    command=lambda: show_modern_keypad(root, process_dorsal),
).pack(side="right", padx=10, pady=5)

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
        ExcelMonitor(EXCEL_PATH), os.path.dirname(EXCEL_PATH) or ".", recursive=False
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

    def move_text():
        carrusel_canvas.update_idletasks()
        x1, y1, x2, y2 = carrusel_canvas.bbox(text_id)
        ancho_canvas = carrusel_canvas.winfo_width()
        if x2 < 0:
            # Si el texto salió completamente, lo regresa a la derecha
            carrusel_canvas.coords(text_id, ancho_canvas, 20)
        else:
            carrusel_canvas.move(
                text_id, -2, 0
            )  # <--- AQUÍ: valor negativo = velocidad
        carrusel_canvas.after(12, move_text)  # <--- AQUÍ: menor número = más rápido

    def resize_canvas(event):
        carrusel_canvas.coords(text_id, carrusel_canvas.winfo_width(), 20)

    carrusel_canvas.bind("<Configure>", resize_canvas)
    move_text()

root.mainloop()

if observer:
    observer.stop()
    observer.join()
