"""Purity contract for sentinel.core.

The deterministic engine must be mechanically portable to another language:
stdlib-only (fixed allowlist), zero I/O, zero network, no subprocess, no
environment access, and no imports from the rest of the sentinel package.
"""
import ast
import io
import re
import tokenize
from pathlib import Path

from sentinel.core.semantics import CORE_ALLOWED_IMPORTS

CORE_DIR = Path(__file__).resolve().parents[1] / "sentinel" / "core"

FORBIDDEN_CALLS = re.compile(
    r"\b(open|exec|eval|compile|input|__import__)\s*\("
    r"|\bPath\s*\("
    r"|\bsubprocess\b|\bsocket\b|\burllib\b|\brequests\b|\byaml\b|\bhttpx?\b",
)


def _code_tokens_only(path: Path) -> str:
    """Source with string literals and comments removed (docstrings included),
    so documentation prose can never trip the I/O lint."""
    src = path.read_text(encoding="utf-8")
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT):
            continue
        out.append(tok.string)
    return " ".join(out)


def core_python_files():
    return sorted(CORE_DIR.glob("*.py"))


def test_core_exists_with_engine():
    names = {p.name for p in core_python_files()}
    assert {"__init__.py", "schema.py", "evaluator.py", "semantics.py"} <= names


def test_core_imports_within_allowlist():
    for path in core_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:  # relative import inside core is fine
                    assert (node.module or "").split(".")[0] in {
                        "", *CORE_ALLOWED_IMPORTS
                    } or node.module in {"schema", "semantics", "evaluator"}
                    continue
                mods = [(node.module or ".").split(".")[0]]
            else:
                continue
            for mod in mods:
                assert mod in CORE_ALLOWED_IMPORTS, (
                    f"{path.name}: forbidden import '{mod}' - core must stay "
                    "pure stdlib (see semantics.CORE_ALLOWED_IMPORTS)")


def test_core_has_no_io_or_third_party_calls():
    for path in core_python_files():
        code = _code_tokens_only(path)
        hit = FORBIDDEN_CALLS.search(code)
        assert not hit, f"{path.name}: forbidden I/O call in executable code: {hit!r}"


def test_core_does_not_import_sentinel_package():
    for path in core_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                assert not (node.module or "").startswith("sentinel"), (
                    f"{path.name}: core must not import sentinel package internals")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("sentinel"), (
                        f"{path.name}: core must not import sentinel package internals")
