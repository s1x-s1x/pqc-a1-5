"""Regression tests for Sweep A, the live-check inventory.

Five reviews have attacked this tool, and every attack became a test here:

* an earlier version found references by scanning text, so a check named only inside a
  **comment** was reported live (V-20);
* the same version reported a check really called through ``getattr(obj, "name")`` as
  **dead** (V-21);
* it exempted **any** method called ``verify``, because the exemption was keyed on the bare
  method name (V-22);
* it forgave an undeclared ``getattr`` literal that never called anything (V6-10b);
* and it treated a *declared* dispatch site as evidence even when the line could never run —
  inside ``if typing.TYPE_CHECKING:`` or inside a function nobody calls (V8-01 / T1 / T2).

The v9 contract, which the tests below pin:

* every definition and call site carries its full lexical scope, nested functions included
  (``Class.method.<locals>.helper``);
* a small constant evaluator understands ``False``/``0``/``while False``/``TYPE_CHECKING``
  (through a resolved, unshadowed import alias) and marks the branch that cannot run;
* reachability is a limited call graph from the declared entries plus the reviewed interface
  bindings, and a nested function is reachable only when something loads its name;
* declarations are verified: they must name exactly one definition, state how they run, and —
  for dispatch — point at a reachable site, so free text is never evidence;
* a reference inside a provably dead branch never counts as a caller, whatever syntax reached
  it;
* exit codes: 1 for unverified evidence (dead, unreachable, unattributed, tests-only,
  undeclared getattr, invalid declaration), 2 for a tool failure, 0 for a clean tree.

Two of the older tests encoded the lenient contract — a synthetic tree with no declared entry,
and a declaration accepted without reachability. Both are updated here, and the original audit
cases stay as counterexample evidence in ``02-审查记录/06-v8审计``.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOL = PROJECT_ROOT / "tools" / "audit_live_checks.py"

PROBES = '''"""Probe definitions planted by the independent review."""
def verify_comment_only_check(value):
    """Only ever mentioned inside a comment elsewhere in the tree."""
    if not value:
        raise ValueError("planted: comment-only check")


def verify_dynamic_dispatch(value):
    """Called for real, but only through getattr with the name as a string."""
    if not value:
        raise ValueError("planted: dynamically dispatched check")


class PlantedHolder:
    """A dead method that can hide behind the tool's interface exemption."""

    def verify(self, value):
        if not value:
            raise ValueError("planted: dead method named verify")
'''

COMMENT_CALL_SITE = "# NOTE: verify_comment_only_check(1) is mentioned here on purpose\n"

DYNAMIC_PROBE = '''def verify_dynamic_dispatch(value):
    """Called for real, but only through getattr with the name as a string."""
    if not value:
        raise ValueError("planted: dynamically dispatched check")
'''

DYNAMIC_CALL_SITE = '''def dispatch(obj):
    """Calls a check for real, but only through getattr with the name as a string."""
    return getattr(obj, "verify_dynamic_dispatch")(obj)
'''


def run_tool(root: Path, *extra: str, tool: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run the sweep against ``root`` and return the completed process.

    ``tool`` defaults to this project's sweep. A probe that patches a declaration table passes
    the copy's own tool, which is how the auditor's cases run: they plant the probe *and* the
    declaration in a throwaway copy and execute that copy's tool.
    """
    return subprocess.run(
        [sys.executable, str(tool or TOOL), "--root", str(root), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def load_tool_module():
    """Import the sweep as a module, so a test can fill a declaration table in-process."""
    spec = importlib.util.spec_from_file_location("audit_live_checks_under_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` resolves string annotations through `sys.modules[cls.__module__]`, so an
    # exec without registering the module first raises AttributeError inside the decorator.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def plant(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write a throwaway tree with ``tls/<name>`` files and return its root."""
    (tmp_path / "tls").mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (tmp_path / "tls" / name).write_text(content, encoding="utf-8")
    return tmp_path


def plant_with_entry(tmp_path: Path, files: dict[str, str], entry: str) -> Path:
    """Same, but with the entry declared so the tree has a root to reach from."""
    root = plant(tmp_path, files)
    return root, entry


# --------------------------------------------------------------- the original three probes


def test_a_check_named_only_in_a_comment_is_dead(tmp_path):
    """V-20: a textual scan counted a comment as a call site."""
    root = plant(tmp_path, {"_probe_checks.py": PROBES, "__init__.py": COMMENT_CALL_SITE})
    completed = run_tool(root, "--entry", "tls/__init__.py::<none>")
    assert completed.returncode == 1, completed.stdout
    assert "DEAD" in completed.stdout
    assert "verify_comment_only_check" in completed.stdout
    assert "live from implementation or drivers : 0" in completed.stdout


def test_a_getattr_dispatched_check_is_live_and_flagged(tmp_path):
    """V-21/V6-10b: a real dispatcher is not DEAD, but an undeclared literal is not proof."""
    root = plant(tmp_path, {"_probe_checks.py": PROBES, "client.py": DYNAMIC_CALL_SITE})
    completed = run_tool(root, "--entry", "tls/client.py::dispatch")
    assert completed.returncode == 1, completed.stdout
    assert "getattr-undeclared" in completed.stdout
    offending = [line for line in completed.stdout.splitlines() if "verify_dynamic_dispatch" in line]
    assert offending, completed.stdout
    assert not any(line.startswith("DEAD") for line in offending), offending
    assert "live only via an undeclared getattr : 1" in completed.stdout


def test_a_declared_getattr_check_at_a_reachable_site_passes(tmp_path):
    """Q3: a dispatcher that really calls the check, declared with source/line evidence."""
    root = plant(
        tmp_path,
        {
            "_probe_checks.py": DYNAMIC_PROBE,
            "client.py": 'import tls._probe_checks as probe\ndef dispatch():\n'
                         '    return getattr(probe, "verify_dynamic_dispatch")(True)\n',
        },
    )
    module = load_tool_module()
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            module, "DISPATCH_SITES", {
                "tls/_probe_checks.py::verify_dynamic_dispatch": ("tls/client.py", 3, "getattr-call")
            }
        )
        monkeypatch.setattr(
            "sys.argv",
            ["audit_live_checks.py", "--root", str(root), "--entry", "tls/client.py::dispatch"],
        )
        assert module.main() == 0
    finally:
        monkeypatch.undo()


def test_a_dead_method_named_verify_is_not_exempt(tmp_path):
    """V-22: the interface exemption used to match any method with that bare name."""
    root = plant(tmp_path, {"_probe_checks.py": PROBES})
    completed = run_tool(root, "--entry", "tls/_probe_checks.py::verify_dynamic_dispatch")
    assert completed.returncode == 1, completed.stdout
    assert "DEAD" in completed.stdout and "PlantedHolder.verify" in completed.stdout


# --------------------------------------------------------------- V8-01: T1 / T2 and friends

T_PROBE = '''"""A check that nothing calls."""


def validate_dead_branch(value):
    if not value:
        raise ValueError("planted: never executed")
'''

T_DECLARATION = '''import typing as _typing
import tls._probe_t as _probe_t


def entry() -> None:
{body}
'''


def _t_tree(tmp_path: Path, body: str, declaration_line: int | None) -> Path:
    return plant(tmp_path, {"_probe_t.py": T_PROBE, "client.py": T_DECLARATION.format(body=body)})


def _write_t_declaration(root: Path, line: int) -> None:
    tool = root / "tools" / "audit_live_checks.py"
    tool.parent.mkdir(parents=True, exist_ok=True)
    source = TOOL.read_text(encoding="utf-8")
    old = "DISPATCH_SITES: dict[str, tuple[str, int, str]] = {}"
    new = (
        "DISPATCH_SITES: dict[str, tuple[str, int, str]] = {\n"
        f'    "tls/_probe_t.py::validate_dead_branch": ("tls/client.py", {line}, "getattr-call"),\n'
        "}"
    )
    assert old in source
    tool.write_text(source.replace(old, new, 1), encoding="utf-8")


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("if False:", "    if False:\n        getattr(_probe_t, \"validate_dead_branch\")(True)\n"),
        ("if 0:", "    if 0:\n        getattr(_probe_t, \"validate_dead_branch\")(True)\n"),
        ("while False:", "    while False:\n        getattr(_probe_t, \"validate_dead_branch\")(True)\n"),
        (
            "if True: ... else:",
            "    if True:\n        pass\n    else:\n"
            "        getattr(_probe_t, \"validate_dead_branch\")(True)\n",
        ),
        (
            "if typing.TYPE_CHECKING:",
            "    if _typing.TYPE_CHECKING:\n"
            "        getattr(_probe_t, \"validate_dead_branch\")(True)\n",
        ),
        (
            "if not not False:",
            "    if _typing.TYPE_CHECKING or False:\n"
            "        getattr(_probe_t, \"validate_dead_branch\")(True)\n",
        ),
    ],
)
def test_a_declared_site_in_a_constant_false_branch_fails(tmp_path, label, body):
    """T1 and its siblings: a branch that cannot run cannot call the check."""
    root = _t_tree(tmp_path, body, None)
    line = next(
        index for index, text in enumerate(
            (root / "tls" / "client.py").read_text(encoding="utf-8").splitlines(), start=1
        ) if "validate_dead_branch" in text
    )
    _write_t_declaration(root, line)
    completed = run_tool(root, "--entry", "tls/client.py::entry",
                         tool=root / "tools" / "audit_live_checks.py")
    assert completed.returncode == 1, f"{label}: {completed.stdout}"
    assert "validate_dead_branch" in completed.stdout
    assert "dead branch" in completed.stdout


def test_a_declared_site_in_an_uncalled_nested_function_fails(tmp_path):
    """T2: defining a nested function does not make its body reachable."""
    root = _t_tree(
        tmp_path,
        "    def _never_called_helper():\n"
        "        getattr(_probe_t, \"validate_dead_branch\")(True)\n",
        None,
    )
    line = next(
        index for index, text in enumerate(
            (root / "tls" / "client.py").read_text(encoding="utf-8").splitlines(), start=1
        ) if "validate_dead_branch" in text
    )
    _write_t_declaration(root, line)
    completed = run_tool(root, "--entry", "tls/client.py::entry",
                         tool=root / "tools" / "audit_live_checks.py")
    assert completed.returncode == 1, completed.stdout
    assert "validate_dead_branch" in completed.stdout
    assert "entry.<locals>._never_called_helper" in completed.stdout


def test_a_called_nested_helper_is_reachable(tmp_path):
    """Positive control for T2: the same helper *called* from a reachable function passes."""
    root = _t_tree(
        tmp_path,
        "    def helper():\n"
        "        return getattr(_probe_t, \"validate_dead_branch\")(True)\n"
        "    helper()\n",
        None,
    )
    line = next(
        index for index, text in enumerate(
            (root / "tls" / "client.py").read_text(encoding="utf-8").splitlines(), start=1
        ) if "validate_dead_branch" in text
    )
    _write_t_declaration(root, line)
    completed = run_tool(root, "--entry", "tls/client.py::entry",
                         tool=root / "tools" / "audit_live_checks.py")
    assert completed.returncode == 0, completed.stdout


def test_a_nested_callback_that_is_only_bound_is_reachable(tmp_path):
    """The drivers pass a nested function as a callback; binding the name is evidence."""
    root = _t_tree(
        tmp_path,
        "    def helper():\n"
        "        return getattr(_probe_t, \"validate_dead_branch\")(True)\n"
        "    register(helper)\n",
        None,
    )
    line = next(
        index for index, text in enumerate(
            (root / "tls" / "client.py").read_text(encoding="utf-8").splitlines(), start=1
        ) if "validate_dead_branch" in text
    )
    _write_t_declaration(root, line)
    completed = run_tool(root, "--entry", "tls/client.py::entry",
                         tool=root / "tools" / "audit_live_checks.py")
    assert completed.returncode == 0, completed.stdout


def test_a_live_branch_under_type_checking_negation_passes(tmp_path):
    """`if not TYPE_CHECKING:` is the live half; the evaluator must keep it live."""
    root = _t_tree(
        tmp_path,
        "    if not _typing.TYPE_CHECKING:\n"
        "        getattr(_probe_t, \"validate_dead_branch\")(True)\n",
        None,
    )
    line = next(
        index for index, text in enumerate(
            (root / "tls" / "client.py").read_text(encoding="utf-8").splitlines(), start=1
        ) if "validate_dead_branch" in text
    )
    _write_t_declaration(root, line)
    completed = run_tool(root, "--entry", "tls/client.py::entry",
                         tool=root / "tools" / "audit_live_checks.py")
    assert completed.returncode == 0, completed.stdout


def test_a_shadowed_type_checking_alias_is_not_pruned(tmp_path):
    """A local named TYPE_CHECKING is not typing's constant, so the branch stays live."""
    root = plant(
        tmp_path,
        {
            "_probe_t.py": T_PROBE,
            "client.py": (
                "import tls._probe_t as _probe_t\n\n\n"
                "def entry(TYPE_CHECKING: bool) -> None:\n"
                "    if TYPE_CHECKING:\n"
                "        getattr(_probe_t, \"validate_dead_branch\")(True)\n"
            ),
        },
    )
    line = next(
        index for index, text in enumerate(
            (root / "tls" / "client.py").read_text(encoding="utf-8").splitlines(), start=1
        ) if "validate_dead_branch" in text
    )
    _write_t_declaration(root, line)
    completed = run_tool(root, "--entry", "tls/client.py::entry",
                         tool=root / "tools" / "audit_live_checks.py")
    assert completed.returncode == 0, completed.stdout


def test_a_reference_in_a_dead_branch_does_not_count_as_live(tmp_path):
    """Item 5 of the plan: the rule is about reachability, not about the getattr syntax."""
    root = plant(
        tmp_path,
        {
            "_probe_checks.py": PROBES,
            "client.py": (
                "def entry() -> None:\n"
                "    if False:\n"
                "        verify_dynamic_dispatch(True)\n"
            ),
        },
    )
    completed = run_tool(root, "--entry", "tls/client.py::entry")
    assert completed.returncode == 1, completed.stdout
    assert "referenced only from unreachable code: 1" in completed.stdout
    assert "dead branch" in completed.stdout


# --------------------------------------------------------------- declarations and entries


def test_an_entry_that_does_not_exist_is_rejected(tmp_path):
    """Item 4: an entry declaration must resolve to exactly one definition."""
    root = plant(tmp_path, {"_probe_checks.py": PROBES})
    completed = run_tool(root, "--entry", "tls/_probe_checks.py::not_defined_here")
    assert completed.returncode == 1, completed.stdout
    assert "INVALID-ENTRY" in completed.stdout


def test_a_declaration_with_the_wrong_module_is_rejected(tmp_path):
    """A declaration must name the module the definition lives in, not a plausible one."""
    root = plant(
        tmp_path,
        {
            "_probe_checks.py": PROBES,
            "client.py": 'import tls._probe_checks as probe\ndef dispatch():\n'
                         '    return getattr(probe, "verify_dynamic_dispatch")(True)\n',
        },
    )
    module = load_tool_module()
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            module, "DISPATCH_SITES", {
                "tls/other.py::verify_dynamic_dispatch": ("tls/client.py", 3, "getattr-call")
            }
        )
        monkeypatch.setattr(
            "sys.argv",
            ["audit_live_checks.py", "--root", str(root), "--entry", "tls/client.py::dispatch"],
        )
        assert module.main() == 1
    finally:
        monkeypatch.undo()


def test_a_declaration_at_the_wrong_line_is_rejected(tmp_path):
    """The declared site has to be the site the AST sees."""
    root = plant(
        tmp_path,
        {
            "_probe_checks.py": PROBES,
            "client.py": 'import tls._probe_checks as probe\ndef dispatch():\n'
                         '    return getattr(probe, "verify_dynamic_dispatch")(True)\n',
        },
    )
    module = load_tool_module()
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            module, "DISPATCH_SITES", {
                "tls/_probe_checks.py::verify_dynamic_dispatch": ("tls/client.py", 9, "getattr-call")
            }
        )
        monkeypatch.setattr(
            "sys.argv",
            ["audit_live_checks.py", "--root", str(root), "--entry", "tls/client.py::dispatch"],
        )
        assert module.main() == 1
    finally:
        monkeypatch.undo()


def test_a_module_reference_cannot_stand_in_for_a_class_method(tmp_path):
    """A free-text claim about a class method is not evidence the class method is called."""
    root = plant(
        tmp_path,
        {
            "lib.py": "class Holder:\n    def verify(self, value):\n        return bool(value)\n",
            "client.py": "import tls.lib as lib\ndef use():\n    return lib.verify(1)\n",
        },
    )
    completed = run_tool(root, "--entry", "tls/client.py::use")
    assert completed.returncode == 1, completed.stdout
    assert "Holder.verify" in completed.stdout


# ------------------------------------------------------------------ unchanged tool contract


def test_a_forecast_tree_passes_with_an_entry(tmp_path):
    """An entirely synthetic tree passes once its entry is declared."""
    (tmp_path / "tls").mkdir(parents=True)
    (tmp_path / "tls" / "a.py").write_text(
        "def _check_thing(x):\n    if not x:\n        raise ValueError('no')\n",
        encoding="utf-8",
    )
    (tmp_path / "tls" / "b.py").write_text(
        "from tls.a import _check_thing\n\n\ndef use() -> None:\n    _check_thing(1)\n",
        encoding="utf-8",
    )
    completed = run_tool(tmp_path, "--entry", "tls/b.py::use")
    assert completed.returncode == 0, completed.stdout
    assert "PASS" in completed.stdout


def test_an_empty_tree_is_a_tool_error_not_a_pass(tmp_path):
    """A sweep that finds nothing must say so; the first version reported PASS."""
    (tmp_path / "tls").mkdir(parents=True)
    completed = run_tool(tmp_path)
    assert completed.returncode == 2
    assert "refusing to report a pass" in completed.stdout


def test_a_missing_tree_is_a_tool_error(tmp_path):
    """No tls/ directory at all is the same class of problem."""
    completed = run_tool(tmp_path)
    assert completed.returncode == 2
    assert "does not exist" in completed.stdout


def test_a_file_with_a_bom_does_not_crash_the_sweep(tmp_path):
    """The first version raised SyntaxError on a BOM, which is a legal Python source."""
    (tmp_path / "tls").mkdir(parents=True)
    (tmp_path / "tls" / "a.py").write_text(
        "def _check_thing(x):\n    if not x:\n        raise ValueError('no')\n",
        encoding="utf-8-sig",
    )
    (tmp_path / "tls" / "b.py").write_text(
        "from tls.a import _check_thing\n\n\ndef use() -> None:\n    _check_thing(1)\n",
        encoding="utf-8",
    )
    completed = run_tool(tmp_path, "--entry", "tls/b.py::use")
    assert completed.returncode == 0, completed.stdout
    assert "PASS" in completed.stdout


def test_a_dead_method_sharing_an_ambiguous_name_is_unattributed(tmp_path):
    """V-22, the deeper form: two classes define `verify`, one is called on a variable."""
    root = plant(
        tmp_path,
        {
            "a.py": "class RealHolder:\n    def verify(self, value):\n        return bool(value)\n",
            "b.py": "class PlantedHolder:\n    def verify(self, value):\n        return bool(value)\n",
            "c.py": "def call(signer, value):\n    return signer.verify(value)\n",
        },
    )
    completed = run_tool(root, "--entry", "tls/c.py::call")
    assert completed.returncode == 1, completed.stdout
    assert "UNATTRIBUTED" in completed.stdout
    assert "RealHolder.verify" in completed.stdout
    assert "PlantedHolder.verify" in completed.stdout


def test_a_sole_implementation_called_on_a_variable_is_unverified(tmp_path):
    """V7-04: a unique name cannot establish the receiver's type."""
    root = plant(
        tmp_path,
        {
            "a.py": "class OnlyHolder:\n    def require_ready(self, value):\n"
                    "        if not value:\n            raise ValueError('no')\n",
            "c.py": "def call(holder, value):\n    return holder.require_ready(value)\n",
        },
    )
    completed = run_tool(root, "--entry", "tls/c.py::call")
    assert completed.returncode == 1, completed.stdout
    assert "of those: sole-implementation variable calls : 1" in completed.stdout
    assert "variable-sole" in completed.stdout


def test_the_real_tree_passes():
    """The invariant this whole file defends: every check here is reachable."""
    completed = run_tool(PROJECT_ROOT)
    assert completed.returncode == 0, completed.stdout
    assert "referenced nowhere                  : 0" in completed.stdout
    assert "referenced only from unreachable code: 0" in completed.stdout
    assert "declared entries" in completed.stdout
