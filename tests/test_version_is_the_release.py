"""The version this package IMPORTS as is the version it is RELEASED as.

A `__version__` constant that disagrees with the release tag is invisible to every ordinary
check: a lockfile pins a COMMIT, and nothing downstream can see that a constant inside that
commit disagrees with the tag pointing at it. A consumer following the shared-packages
adoption recipe (step 3: print the imported module's `__file__` AND its `__version__`) would
read a release number that is not the code it is running.

Why this check lives in the PACKAGE and not only in a portfolio scan: a portfolio scan can only
see a defect that has already been released and installed somewhere. This fails in the
release's own gate, before there is a tag to be wrong.

`pyproject.toml` is the authority, because it is what the build backend stamps into the
distribution metadata an installer records. `__version__` is a hand-maintained copy of that
number, which is precisely why it drifts.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import hex_service_kit


def _declared_version() -> str:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    return str(tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"])


def test_the_imported_version_is_the_declared_version() -> None:
    declared = _declared_version()
    assert hex_service_kit.__version__ == declared, (
        f"__init__.py exports __version__ = {hex_service_kit.__version__!r} while "
        f"pyproject.toml declares {declared!r}. A consumer proving its adoption by printing the "
        "imported "
        "__version__ would read the wrong release, and the lockfile commit pin cannot show it."
    )


def test_the_declared_version_is_a_release_number() -> None:
    # A version that is not three dotted integers cannot be matched against a `vX.Y.Z` tag by the
    # portfolio check, which would silently stop comparing rather than report a mismatch.
    parts = _declared_version().split(".")
    assert len(parts) == 3 and all(part.isdigit() for part in parts), (
        f"pyproject.toml declares version {_declared_version()!r}, which the lockfile header "
        "tag map and the installed-pin proof both parse as vMAJOR.MINOR.PATCH."
    )
