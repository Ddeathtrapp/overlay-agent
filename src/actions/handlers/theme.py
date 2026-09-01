"""toggle_dark_mode — Tier 0.

Design test (§7): an attacker who can invoke this at will can flip the
system between light and dark theme. No data exposure, no persistence
change beyond a cosmetic DWORD, trivially reversible by invoking it again.
Acceptable at any moment, by construction.

§0.1 substitutes this action for `toggle_night_light`, which has no clean
Windows API. `AppsUseLightTheme` is a documented-by-convention registry
DWORD that every Windows theming tool reads and writes; there is nothing
comparable for night light.
"""
from __future__ import annotations

import ctypes
import winreg

_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"

_HWND_BROADCAST = 0xFFFF
_WM_SETTINGCHANGE = 0x001A
_SMTO_ABORTIFHUNG = 0x0002

_SendMessageTimeoutW = ctypes.windll.user32.SendMessageTimeoutW
_SendMessageTimeoutW.argtypes = [
    ctypes.c_void_p,   # HWND
    ctypes.c_uint,      # Msg
    ctypes.c_void_p,   # wParam
    ctypes.c_wchar_p,  # lParam
    ctypes.c_uint,      # fuFlags
    ctypes.c_uint,      # uTimeout
    ctypes.POINTER(ctypes.c_void_p),  # lpdwResult
]
_SendMessageTimeoutW.restype = ctypes.c_void_p


def toggle_dark_mode() -> None:
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, _KEY_PATH, 0, winreg.KEY_READ | winreg.KEY_WRITE
    ) as key:
        current, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        new_value = 0 if current else 1
        winreg.SetValueEx(key, "AppsUseLightTheme", 0, winreg.REG_DWORD, new_value)
        winreg.SetValueEx(key, "SystemUsesLightTheme", 0, winreg.REG_DWORD, new_value)

    result = ctypes.c_void_p()
    _SendMessageTimeoutW(
        _HWND_BROADCAST,
        _WM_SETTINGCHANGE,
        0,
        "ImmersiveColorSet",
        _SMTO_ABORTIFHUNG,
        1000,
        ctypes.byref(result),
    )
