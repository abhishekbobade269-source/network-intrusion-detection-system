"""Regression test for a real bug found by actually running the Docker
build: `rules_dir`'s default used to be computed by walking up a fixed
number of parent directories from `config.py`'s own location, assuming a
source-tree ("`src/nids/config.py` is 2 parents below the repo root")
layout. That's true for an editable install but false for a real wheel
install (`site-packages/nids/config.py`) — which is exactly how the
Dockerfile installs the app — so the container loaded zero signature
rules with no error at all. Fixed by anchoring to `config.py`'s own
package directory instead of a fragile "project root" guess.
"""

from __future__ import annotations

from pathlib import Path

from nids.config import Settings
from nids.rules.loader import load_rules


def test_default_rules_dir_exists_and_is_package_relative() -> None:
    settings = Settings(_env_file=None)

    assert settings.rules_dir.is_absolute()
    assert settings.rules_dir.is_dir(), (
        f"{settings.rules_dir} does not exist — rules_dir must resolve relative to "
        "the installed nids package, not a source-tree-only 'project root' guess"
    )
    # It must live *inside* the installed nids.rules package, not somewhere
    # derived from an assumption about the surrounding repo/CWD layout.
    import nids.rules as rules_pkg

    assert Path(rules_pkg.__file__).resolve().parent in settings.rules_dir.parents


def test_default_rules_dir_actually_loads_real_rules() -> None:
    settings = Settings(_env_file=None)

    rules = load_rules(settings.rules_dir)

    assert len(rules) >= 5


def test_default_rules_dir_is_independent_of_cwd(tmp_path: Path, monkeypatch) -> None:
    # The bug this guards against only manifested when the process wasn't
    # run from the repo root (e.g. a container's WORKDIR) — assert the
    # default doesn't depend on CWD at all, live or repo-root or not.
    monkeypatch.chdir(tmp_path)

    settings = Settings(_env_file=None)

    assert settings.rules_dir.is_dir()
