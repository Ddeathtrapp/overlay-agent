"""shutdown_pc / restart_pc — Tier 2, irreversible.

Design test (§7): an attacker who can invoke either of these at any moment
can take the machine down or force a reboot on the spot — lost unsaved
work, interrupted whatever the user was doing, no undo. That is exactly why
these are Tier 2: dispatch (see dispatch/cli.py) refuses to call this
handler at all until a policy engine exists to gate it with confirmation
and a rate limit (§5, §9). The handler itself stays correct and complete so
Phase 2 has something to gate.

§9 forbids `subprocess(["shutdown.exe", "/s"])` — that reintroduces a shell
invocation for no benefit. `InitiateSystemShutdownExW` requires
`SeShutdownPrivilege` to be enabled on the process token first, which is
not held by default.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY = 0x0008
_SE_PRIVILEGE_ENABLED = 0x00000002

_SHTDN_REASON_MAJOR_OTHER = 0x00000000
_SHTDN_REASON_MINOR_OTHER = 0x00000000
_SHTDN_REASON_FLAG_PLANNED = 0x80000000
_REASON = _SHTDN_REASON_MAJOR_OTHER | _SHTDN_REASON_MINOR_OTHER | _SHTDN_REASON_FLAG_PLANNED


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


_GetCurrentProcess = _kernel32.GetCurrentProcess
_GetCurrentProcess.argtypes = []
_GetCurrentProcess.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_OpenProcessToken = _advapi32.OpenProcessToken
_OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_OpenProcessToken.restype = wintypes.BOOL

_LookupPrivilegeValueW = _advapi32.LookupPrivilegeValueW
_LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(_LUID)]
_LookupPrivilegeValueW.restype = wintypes.BOOL

_AdjustTokenPrivileges = _advapi32.AdjustTokenPrivileges
_AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    ctypes.POINTER(_TOKEN_PRIVILEGES),
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_AdjustTokenPrivileges.restype = wintypes.BOOL

_InitiateSystemShutdownExW = _advapi32.InitiateSystemShutdownExW
_InitiateSystemShutdownExW.argtypes = [
    wintypes.LPWSTR,   # lpMachineName
    wintypes.LPWSTR,   # lpMessage
    wintypes.DWORD,    # dwTimeout
    wintypes.BOOL,     # bForceAppsClosed
    wintypes.BOOL,     # bRebootAfterShutdown
    wintypes.DWORD,    # dwReason
]
_InitiateSystemShutdownExW.restype = wintypes.BOOL


def _enable_shutdown_privilege() -> None:
    token = wintypes.HANDLE()
    if not _OpenProcessToken(
        _GetCurrentProcess(),
        _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        luid = _LUID()
        if not _LookupPrivilegeValueW(None, "SeShutdownPrivilege", ctypes.byref(luid)):
            raise ctypes.WinError(ctypes.get_last_error())

        privileges = _TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = _SE_PRIVILEGE_ENABLED

        ctypes.set_last_error(0)
        if not _AdjustTokenPrivileges(
            token, False, ctypes.byref(privileges), 0, None, None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # AdjustTokenPrivileges returns nonzero ("success") even when it
        # silently grants nothing — ERROR_NOT_ALL_ASSIGNED (1300) only shows
        # up in GetLastError, checked separately per the Win32 docs.
        last_error = ctypes.get_last_error()
        if last_error != 0:
            raise ctypes.WinError(last_error)
    finally:
        _CloseHandle(token)


def _initiate_shutdown(*, reboot: bool) -> None:
    _enable_shutdown_privilege()
    ok = _InitiateSystemShutdownExW(None, None, 0, False, reboot, _REASON)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def shutdown_pc() -> None:
    _initiate_shutdown(reboot=False)


def restart_pc() -> None:
    _initiate_shutdown(reboot=True)
