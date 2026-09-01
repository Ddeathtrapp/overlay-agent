"""Handler-shape tests for the three actions that touch a dangerous API.

These assert the properties that make §0.2 safe, which nothing else guards:
that `open_application` passes a LIST built from the dict VALUE with
`shell=False`, that `open_setting` passes the enum's hardcoded URI rather than
anything derived from input, and that `open_new_desktop` synthesizes exactly
one fixed chord. §0.2 calls for mandatory human review of `open_application`
precisely because a future edit here — `shell=True`, or `Popen([app])` passing
the key as a PATH-searched command name — would look innocuous and break the
security model silently.

`SendInput` belongs in that list too: it is the UI-manipulation API, and
`threat-model.md` §4 T7's mitigation rests on no action parameterizing it.

Nothing real is launched or injected: `Popen`, `os.startfile`, and `SendInput`
are all patched.
"""
from __future__ import annotations

import ctypes
import inspect
from pathlib import Path
from unittest.mock import patch

from _helpers import assert_raises

from actions.handlers import apps, desktops, settings
from actions.params import APPS, SettingPage

SRC = Path(__file__).resolve().parents[1] / "src"


# --- open_application, §0.2 ----------------------------------------------

def test_open_application_passes_a_list_of_the_dict_value() -> None:
    with patch.object(apps.subprocess, "Popen") as popen:
        apps.open_application("notepad")

    popen.assert_called_once()
    (argv,), kwargs = popen.call_args

    assert isinstance(argv, list), "argv must be a list, never a string"
    assert argv == [str(APPS["notepad"])]
    assert kwargs["shell"] is False, "shell=False must be explicit"


def test_open_application_never_passes_the_raw_key() -> None:
    # Passing the key would make it a PATH-searched command name — the exact
    # "a key quietly becomes a command" failure §0.2 warns about.
    with patch.object(apps.subprocess, "Popen") as popen:
        apps.open_application("calculator")

    (argv,), _ = popen.call_args
    assert "calculator" not in argv
    assert Path(argv[0]).is_absolute()
    assert argv[0] == str(APPS["calculator"])


def test_open_application_fails_closed_on_a_key_not_in_the_table() -> None:
    # The handler does its own dict lookup, so it fails closed even if a
    # future caller hands it something the parser never saw. There is no
    # .get(key, key) fall-through to make the key itself executable.
    with patch.object(apps.subprocess, "Popen") as popen:
        assert_raises(KeyError, apps.open_application, "vscode")
    popen.assert_not_called()


# --- open_setting ---------------------------------------------------------

def test_open_setting_passes_the_hardcoded_uri() -> None:
    with patch.object(settings.os, "startfile") as startfile:
        settings.open_setting(SettingPage.DISPLAY)

    startfile.assert_called_once_with("ms-settings:display")


def test_open_setting_never_passes_a_member_name_or_raw_input() -> None:
    for page in SettingPage:
        with patch.object(settings.os, "startfile") as startfile:
            settings.open_setting(page)
        (arg,), _ = startfile.call_args
        assert arg == page.value
        assert arg.startswith("ms-settings:")
        assert arg != page.name


# --- open_new_desktop: the SendInput chord --------------------------------

KEYEVENTF_KEYUP = 0x0002
VK_LWIN, VK_CONTROL, VK_D = 0x5B, 0x11, 0x44

# Press in order, release in reverse. Win+Ctrl+D, and nothing else.
EXPECTED_CHORD = [(VK_LWIN, False), (VK_CONTROL, False), (VK_D, False),
                  (VK_D, True), (VK_CONTROL, True), (VK_LWIN, True)]


def test_open_new_desktop_sends_exactly_the_win_ctrl_d_chord() -> None:
    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        desktops.open_new_desktop()

    send_input.assert_called_once()
    count, array, cb_size = send_input.call_args[0]

    assert count == len(EXPECTED_CHORD)
    assert cb_size == ctypes.sizeof(desktops._INPUT)
    assert [(array[i].ki.wVk, bool(array[i].ki.dwFlags & KEYEVENTF_KEYUP))
            for i in range(count)] == EXPECTED_CHORD
    assert all(array[i].type == 1 for i in range(count)), "keyboard input only"


def test_open_new_desktop_takes_no_parameters() -> None:
    # The chord is fixed at build time. T7's mitigation depends on no action
    # parameterizing keystroke synthesis: `_key` is a general primitive, and a
    # future press_hotkey(chord: HotkeyChord) would satisfy §3 while reaching
    # Win+R. This asserts the fixed-chord property the safety argument rests on.
    assert inspect.signature(desktops.open_new_desktop).parameters == {}


def test_open_new_desktop_fails_closed_on_partial_send() -> None:
    with patch.object(desktops, "_SendInput", return_value=3):
        assert_raises(OSError, desktops.open_new_desktop)


def test_key_primitive_has_exactly_one_caller() -> None:
    # `_key` is module-private and must stay that way. If it acquires a second
    # caller, or is exported, the fixed-chord argument above stops holding.
    for path in SRC.rglob("*.py"):
        if path.name == "desktops.py":
            continue
        assert "_key(" not in path.read_text(encoding="utf-8"), path.name


# --- source-level guards (§8) --------------------------------------------

def test_no_shell_invocation_anywhere_in_src() -> None:
    # A grep-shaped tripwire, deliberately — NOT the security boundary, which
    # is the typed-parameter system. §11.7: "the trivial ones are where
    # shell=True gets pasted in."
    banned = ("shell=True", "shell = True", "os.system", "os.popen",
              "os.spawn", "os.exec", "subprocess.call(", "subprocess.run(",
              "ShellExecute", "eval(", "exec(", "__import__")
    for path in SRC.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in source, f"{path.name} contains {token!r}"


def test_startfile_is_confined_to_open_setting() -> None:
    # os.startfile IS ShellExecuteW — the §8 checklist item "does anything reach
    # ShellExecute" is HIT and safe here, not absent. It is legitimate in
    # exactly one file, on a hardcoded enum value. Anywhere else it is a
    # general-purpose opener, which is `open_url(str)` in a costume.
    users = [p.name for p in SRC.rglob("*.py")
             if "startfile" in p.read_text(encoding="utf-8")]
    assert users == ["settings.py"], f"os.startfile appears in {users}"
