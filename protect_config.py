# -*- coding: utf-8 -*-
"""config.json 的 DPAPI 加密保护。

encrypt: 读取 config.json，用 Windows DPAPI（当前用户）加密为 config.json.dpapi，
         该密文可安全提交到 Git——没有本机当前账户无法解开。
decrypt: 把 config.json.dpapi 还原为 config.json（用于恢复）。
"""
import ctypes
import ctypes.wintypes as wt
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLAIN = HERE / "config.json"
CIPHER = HERE / "config.json.dpapi"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _protect(data: bytes, protect: bool) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _blob(data)
    blob_out = DATA_BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def encrypt() -> str:
    if not PLAIN.exists():
        return "config.json 不存在，跳过"
    CIPHER.write_bytes(_protect(PLAIN.read_bytes(), True))
    return f"已加密: {PLAIN.name} -> {CIPHER.name} ({CIPHER.stat().st_size} bytes)"


def decrypt() -> str:
    if not CIPHER.exists():
        return "config.json.dpapi 不存在，无法恢复"
    PLAIN.write_bytes(_protect(CIPHER.read_bytes(), False))
    return f"已恢复: {CIPHER.name} -> {PLAIN.name}"


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "encrypt"
    print(encrypt() if cmd == "encrypt" else decrypt())
