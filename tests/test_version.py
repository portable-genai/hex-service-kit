"""The version is stated twice, so the two statements must agree.

`pyproject.toml` carries the version the build system stamps into distribution metadata, and
`hex_service_kit.__version__` carries the one a running process can read without
`importlib.metadata`. Nothing keeps them in step automatically, and a release has already
shipped with them disagreeing: the bump landed in `pyproject.toml` while `__version__` stayed
where it was.

That release was the fix for an authentication fail-open, which is the worst possible case for
this particular slip. A consumer debugging why an outbound call left without an `Authorization`
header, who reads `__version__` to check whether the fix is present, is told the older number
and concludes it is not. The metadata said one thing, the module said another, and the module
is what a human reaches for.

A version string is a claim about which code you are running. When it is wrong it is not
cosmetic, it is a false negative in exactly the situation where somebody is looking hardest.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import hex_service_kit

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_module_version_matches_the_packaged_version() -> None:
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert hex_service_kit.__version__ == declared, (
        f"pyproject.toml declares {declared!r} but hex_service_kit.__version__ is "
        f"{hex_service_kit.__version__!r}. A release bumped one and not the other, so a caller "
        "reading the module attribute is told it is on a version it is not on. Bump both."
    )


def test_the_version_is_a_release_number_and_not_a_placeholder() -> None:
    # Guards the other direction: a value that parses as agreeing but says nothing, such as an
    # unreplaced template token or a dev suffix that never got cut.
    assert re.fullmatch(r"\d+\.\d+\.\d+", hex_service_kit.__version__), (
        f"__version__ is {hex_service_kit.__version__!r}, which is not a plain release number."
    )
