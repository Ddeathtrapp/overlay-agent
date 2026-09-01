"""§3 parameter kinds. Every rejection path is tested, because rejection is
the behaviour the security model depends on (§2.4 — never coerce, never
default, never guess)."""
from __future__ import annotations

from pathlib import Path

from _helpers import assert_raises

from actions.params import (
    APPS,
    BoundedIntParam,
    EnumParam,
    ParamRejected,
    SettingPage,
    WhitelistKeyParam,
)

PAGE = EnumParam("page", SettingPage)
VOLUME = BoundedIntParam("volume", 0, 100)
APP = WhitelistKeyParam("app", APPS)


# --- EnumParam ------------------------------------------------------------

def test_enum_accepts_member_name_any_case() -> None:
    assert PAGE.parse("DISPLAY") is SettingPage.DISPLAY
    assert PAGE.parse("display") is SettingPage.DISPLAY


def test_enum_rejects_unknown_name() -> None:
    assert_raises(ParamRejected, PAGE.parse, "windows_security")


def test_enum_rejects_the_uri_value_itself() -> None:
    # Matching on `.value` would let a raw string address a page by its URI,
    # turning an enum parameter back into a string one.
    assert_raises(ParamRejected, PAGE.parse, "ms-settings:display")


def test_enum_rejects_empty_string() -> None:
    assert_raises(ParamRejected, PAGE.parse, "")


# --- BoundedIntParam ------------------------------------------------------

def test_bounded_int_accepts_within_range_inclusive() -> None:
    assert VOLUME.parse("0") == 0
    assert VOLUME.parse("50") == 50
    assert VOLUME.parse("100") == 100


def test_bounded_int_rejects_out_of_range() -> None:
    assert_raises(ParamRejected, VOLUME.parse, "-1")
    assert_raises(ParamRejected, VOLUME.parse, "101")


def test_bounded_int_rejects_non_integers() -> None:
    for raw in ("", "abc", "50.5", "0x10", "1e2"):
        assert_raises(ParamRejected, VOLUME.parse, raw)


# --- WhitelistKeyParam ----------------------------------------------------

def test_whitelist_returns_the_key_not_the_path() -> None:
    # §0.2: the parameter is a key. The handler resolves it; the ParamSpec
    # never touches a Path.
    result = APP.parse("notepad")
    assert result == "notepad"
    assert not isinstance(result, Path)


def test_whitelist_rejects_unknown_key() -> None:
    assert_raises(ParamRejected, APP.parse, "vscode")


def test_whitelist_rejects_path_and_shell_shaped_input() -> None:
    # None of these are special-cased anywhere; they fail for the only reason
    # any value fails — absence from the table. Recorded so a future "helpful"
    # normalisation step has a test standing in its way.
    for raw in (r"C:\Windows\System32\notepad.exe", "../../evil",
                "notepad & calc", "notepad.exe", "NOTEPAD", ""):
        assert_raises(ParamRejected, APP.parse, raw)


# --- non-string input must still fail CLOSED ------------------------------

def test_every_kind_rejects_non_string_input_as_paramrejected() -> None:
    # Unreachable from argv, which is always str — but in Phase 2 an
    # ActionRequest arrives as parsed JSON where a non-string parameter is
    # ordinary. §2.4 requires "reject and log"; an AttributeError or TypeError
    # escaping parse() is neither, and it would destroy the audit record §6
    # requires be written before execution.
    for spec in (PAGE, VOLUME, APP):
        for raw in (None, 5, 3.7, True, [], {}, object()):
            assert_raises(ParamRejected, spec.parse, raw)


def test_bounded_int_does_not_truncate_floats() -> None:
    # int(3.7) == 3. Silently narrowing an out-of-type value to a valid one is
    # coercion, which §2.4 forbids outright.
    assert_raises(ParamRejected, VOLUME.parse, 3.7)
    assert_raises(ParamRejected, VOLUME.parse, 100.9)


# --- The table itself -----------------------------------------------------

def test_apps_table_is_immutable_at_runtime() -> None:
    # §2.1: the registry is closed at BUILD time. `Final` is a type-checker
    # annotation with no runtime effect, so it alone does not deliver that.
    # SettingPage is an Enum and REGISTRY is a tuple — both immutable by
    # construction; APPS must not be the one mutable source of truth, least of
    # all the table §0.2 calls the highest-risk object in the registry.
    def add_entry() -> None:
        APPS["evil"] = Path(r"C:\evil.exe")  # type: ignore[index]

    assert_raises(TypeError, add_entry)
    assert "evil" not in APPS
    # A mappingproxy exposes no mutators at all, so the table cannot be grown
    # by any route — not just not by assignment.
    for mutator in ("__setitem__", "update", "setdefault", "pop", "clear"):
        assert not hasattr(APPS, mutator), f"APPS exposes {mutator}"

def test_apps_table_is_absolute_existing_paths() -> None:
    for key, path in APPS.items():
        assert isinstance(path, Path), key
        assert path.is_absolute(), key
        assert path.exists(), f"{key} -> {path} is not present on this machine"


def test_setting_pages_exclude_security_surfaces() -> None:
    # §9's excluded pages are excluded by absence from the enum. This asserts
    # the absence directly, so re-adding one fails loudly rather than quietly.
    # APPS and NETWORK joined the list when §9 was updated: Apps is where
    # software is uninstalled, Network is one click from proxy configuration.
    forbidden = {"SECURITY", "WINDOWSSECURITY", "FIREWALL", "UAC",
                 "BITLOCKER", "SIGNIN", "SIGNINOPTIONS", "DEFENDER",
                 "APPS", "NETWORK"}
    assert forbidden.isdisjoint(SettingPage.__members__)
    for page in SettingPage:
        assert page.value.startswith("ms-settings:"), page
