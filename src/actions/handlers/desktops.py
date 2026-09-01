"""open_new_desktop — Tier 0.

Design test (§7): an attacker who can invoke this at will can spam new
virtual desktops. Annoying, trivially reversible (close the desktop), no
data exposure, no privilege change. Acceptable at any moment.

§9 rules out `IVirtualDesktopManager`: it is undocumented COM and breaks
across Windows builds. The Win+Ctrl+D keystroke is the stable surface, so
it is synthesized directly via `SendInput`.
"""
from __future__ import annotations

import ctypes

_INPUT_KEYBOARD = 1
_KEYEVENTF_KEYUP = 0x0002

_VK_LWIN = 0x5B
_VK_CONTROL = 0x11
_VK_D = 0x44


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),  # ULONG_PTR, sized for 32/64-bit
    ]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", ctypes.c_ulong),
        ("wParamL", ctypes.c_short),
        ("wParamH", ctypes.c_ushort),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [
        ("ki", _KEYBDINPUT),
        ("mi", _MOUSEINPUT),
        ("hi", _HARDWAREINPUT),
    ]


class _INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("u", _INPUTUNION),
    ]


_SendInput = ctypes.windll.user32.SendInput
_SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(_INPUT), ctypes.c_int]
_SendInput.restype = ctypes.c_uint


def _key(vk: int, key_up: bool) -> _INPUT:
    inp = _INPUT()
    inp.type = _INPUT_KEYBOARD
    inp.ki = _KEYBDINPUT(
        wVk=vk,
        wScan=0,
        dwFlags=_KEYEVENTF_KEYUP if key_up else 0,
        time=0,
        dwExtraInfo=None,
    )
    return inp


def open_new_desktop() -> None:
    # Press in order, release in reverse, one SendInput call for the whole
    # sequence so no other input can interleave between press and release.
    sequence = (
        _key(_VK_LWIN, key_up=False),
        _key(_VK_CONTROL, key_up=False),
        _key(_VK_D, key_up=False),
        _key(_VK_D, key_up=True),
        _key(_VK_CONTROL, key_up=True),
        _key(_VK_LWIN, key_up=True),
    )
    array = (_INPUT * len(sequence))(*sequence)
    sent = _SendInput(len(sequence), array, ctypes.sizeof(_INPUT))
    if sent != len(sequence):
        raise ctypes.WinError()
