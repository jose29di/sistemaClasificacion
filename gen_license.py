#!/usr/bin/env python3
"""
License generator for ResultadosKiosk.
Genera un archivo license.lic único para la máquina.
"""

import ctypes
import uuid
import hmac
import hashlib
import sys
import os

MASTER_KEY = b"bGljZW5jaWE="
OUT_FILE = "license.lic"


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
    """
    Combina el serial de volumen con la MAC para
    producir un identificador único de máquina.
    """
    vol = get_volume_serial()
    mac = uuid.getnode()
    return f"{vol:08X}-{mac:012X}".encode()


def gen_license(machine_id: bytes) -> str:
    """
    Genera HMAC-SHA256 usando MASTER_KEY y machine_id.
    """
    return hmac.new(MASTER_KEY, machine_id, hashlib.sha256).hexdigest()


def main():
    try:
        mid = get_machine_id()
    except Exception as e:
        print(f"Error al obtener ID de máquina: {e}")
        sys.exit(1)

    lic = gen_license(mid)
    with open(OUT_FILE, "w") as f:
        f.write(lic)
    print(f"Licencia generada y guardada en {OUT_FILE}")
    print(f"Machine ID: {mid.decode()}")
    print(f"License key: {lic}")


if __name__ == "__main__":
    main()
