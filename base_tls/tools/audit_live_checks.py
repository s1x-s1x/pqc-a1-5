"""Sweep A: are the security checks in this tree reachable?

Four reviews of this repository each found the same class of defect  -- a check that exists,
is correct, and is not on the path a handshake actually takes. The clearest instance was
`verify_hybrid_certificate_verify`: a strict scheme-identifier check that **nothing called
at all**. A test suite cannot see that, because every test compares this implementation
against itself.

This script is the mechanical half of the answer to "does that class still exist here": it
collects every check-like definition under ``tls/`` and asks whether anything *reachable*
references it.

Why v9 is stricter than v8. The v8 version validated that a declared dispatch site existed in
the AST  -- module alias, exact line, immediate invocation  -- but not that the site could ever
run. An independent review planted the declared call inside ``if typing.TYPE_CHECKING:`` and
inside a function nobody calls, and the sweep passed both (their V8-01 / T1 / T2). v9 adds, in
the order that review asked for:

1. **Lexical context.** Every definition and call site carries its module, its full scope
   (``Class.method``, and ``Class.method.<locals>.helper`` for a nested function) and its line.
   A nested function is never flattened into a plain method, and no name is guessed to be
   unreachable.
2. **A small, safe constant evaluator.** ``if False/0``, ``while False/0``, the ``else`` of an
   always-true test, and ``typing.TYPE_CHECKING`` (through a correctly resolved, unshadowed
   import alias) are understood. The tree is never imported and ``eval`` is never called; an
   unknown condition keeps both branches live.
3. **A limited call graph.** Direct calls, calls on a known class (through its in-tree bases),
   calls through a module import and controlled ``self`` calls become edges. Roots are the
   declared entries in ``ENTRY_POINTS`` (each verified to exist) plus the reviewed interface
   bindings in ``INTERFACE_METHODS``. A nested function's body is reachable only when something
   calls it, so recursion or mutual calls with no path from a root are not roots themselves.
4. **Verified declarations.** An entry or interface declaration must name exactly one
   definition and state how it runs; an interface declaration must also have a variable-receiver
   reference from a live root, so free text alone never exempts anything. Dispatch sites
   (``DISPATCH_SITES``, and legacy ``GETATTR_DISPATCHED`` normalized into it) are checked
   against AST evidence *and* against reachability.
5. **One rule for every reference kind.** A reference inside a provably dead branch does not
   count as a caller, whatever syntax reached it.
6. **Unknown is not reachable.** The report separates "syntactically referenced", "evidence in
   known dead code", "entry relation unverified" and "linked through a supported entry chain".
   A check whose only evidence is unreachable fails (exit 1); a tool failure  -- unreadable file,
   missing tree, nothing to judge  -- exits 2 and is not a pass; a clean tree exits 0.

What it still cannot see, so that nobody reads more into a pass than it says: a name assembled
at runtime (``getattr(obj, prefix + name)``), a callback registered by string and invoked by a
framework, a receiver whose type needs real inference, and anything that depends on values
rather than syntax. This is a bounded static inventory  -- "limited reachability", in the review's
own words  -- not a runtime reachability proof.

Run it directly, or let ``tools/verify_all.ps1`` run it as an acceptance check:

    python tools/audit_live_checks.py                  # table + exit status
    python tools/audit_live_checks.py --verbose        # include the live checks
    python tools/audit_live_checks.py --entry pkg::main   # declare an extra root
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TLS = PROJECT_ROOT / "tls"

#: Directories whose references count as "live"  -- the implementation and the drivers that
#: exercise it. `tests/` is separate on purpose: a check reached only from tests is not
#: protecting anything.
LIVE_ROOTS = ("tls", "tools", "bench", "demo")
TEST_ROOT = "tests"
SKIP_PARTS = (".deps", ".deps-falcon", ".tools", "target", "__pycache__", ".venv", ".piptmp")

#: Execution roots for the reachability walk, keyed by ``module::qualname``. Each is verified to
#: exist and states how it runs: this is the "no module is a root just because it sits under
#: ``tls/``" rule. Test modules are deliberately absent  -- they are a separate entry class and
#: cannot make a check live.
ENTRY_POINTS: dict[str, str] = {
    "demo/run_handshake.py::main": "`python demo/run_handshake.py` drives one full handshake",
    "bench/measure_handshake.py::main": "in-process handshake size and latency matrix",
    "bench/measure_primitives.py::main": "primitive timings for the configured backends",
    "bench/measure_tcp.py::main": "loopback TCP handshake driver",
    "bench/measure_shaped.py::main": "shaped-link latency driver",
    "tools/check_x509.py::main": "real X.509 chain check over a handshake",
    "tools/dump_wire.py::main": "one handshake with a per-message wire dump",
}

#: Methods reached through a variable rather than a literal call site, keyed by
#: ``module::Class.method`` so that same-named definitions get no exemption. Each entry names
#: the mechanism that reaches it, is printed in every report, must resolve to exactly one
#: definition, and must have at least one variable-receiver reference from a live root.
INTERFACE_METHODS: dict[str, str] = {
    'tls/config.py::HybridTLSConfig.cipher_suite_id': 'configured suite property in client/server',
    'tls/config.py::HybridTLSConfig.aead_suite': 'handshake state selects record suite through its config receiver',
    'tls/credentials.py::CertificateAuthority.verify': 'called through the authority held by the connection',
    'tls/wire.py::Reader.expect_end': 'wire decoders enforce exact consumption',
    'tls/classical/ecdh.py::EcdheKeyPair.exchange': 'configured ECDHE key pair in client/server',
    # The pair itself is built by the configured ECDHE backend (`EcdheKeyPair.generate(...)`),
    # so the receiver of `self.ephemeral.public_key_bytes` has no statically known type; the
    # property and its helper are reached through that variable receiver by client and server.
    'tls/classical/ecdh.py::EcdheKeyPair.public_key_bytes': 'configured ECDHE key pair in client/server',
    'tls/classical/signature.py::ClassicalSigner.verify': 'called through the configured signer',
    'tls/classical/signature.py::EcdsaP256Sha256.verify': 'called through the configured signer',
    'tls/classical/signature.py::Ed25519.verify': 'called through the configured signer',
    'tls/handshake/client.py::HybridClient.receive_server_hello': 'client driver consumes the server hello',
    'tls/handshake/client.py::HybridClient.receive_server_flight': 'client driver consumes authenticated records',
    'tls/handshake/client.py::HybridClient.send_client_finished': 'connection driver completes the client flight',
    'tls/handshake/server.py::HybridServer.receive_client_hello': 'server driver consumes the client hello',
    'tls/handshake/server.py::HybridServer.send_authenticated_flight': 'server driver emits authenticated records',
    'tls/handshake/server.py::HybridServer.receive_client_finished': 'connection driver verifies client Finished',
    'tls/handshake/state.py::HandshakeState.exporter_secret': 'connection driver exports negotiated key material',
    'tls/pq/backends.py::PqSigner.verify': 'called through the configured signer',
    'tls/pq/slhdsa_sm3.py::SlhDsaSm3.keygen': 'configured SLH signer key generation through a variable receiver',
    'tls/pq/slhdsa_sm3.py::SlhDsaSm3.sign': 'configured SLH signer signing through a variable receiver',
    'tls/pq/slhdsa_sm3.py::SlhDsaSm3.verify': 'configured SLH signer verification through a variable receiver',
    'tls/pq/signature.py::MlDsa.verify': 'called through the configured signer',
    'tls/pq/signature.py::Falcon.verify': 'called through the configured signer',
    'tls/pq/signature.py::Xmss.verify': 'called through the configured signer',
    # Added in v9: key generation goes through the config-selected signer (`config.pq()`), whose
    # concrete type is a runtime choice, so the call `pq.keygen()` cannot be resolved statically.
    # The declaration is verified like every other one: the definition exists and a live root
    # calls that name on a variable receiver.
    'tls/pq/signature.py::Xmss.keygen': 'called through the configured signer',
    'tls/pq/wots_xmss.py::WotsPlus.keygen': 'called by the XMSS backend',
    'tls/pq/wots_xmss.py::WotsPlus.sign': 'called by the XMSS backend',
    'tls/pq/wots_xmss.py::WotsPlus.verify': 'called through the configured signer',
    'tls/pq/wots_xmss.py::XmssSignatureBackend.sign': 'called through the configured signer',
    'tls/pq/wots_xmss.py::XmssSignatureBackend.verify': 'called through the configured signer',
    'tls/record/aead.py::AeadSuite.new': 'transcript instantiates the configured AEAD suite',
    'tls/record/aead.py::RecordLayer.open': 'connection/handshake decrypts incoming records',
    'tls/record/aead.py::RecordLayer.seal': 'configured record layer protects handshake/application fragments',
}

#: Names a framework calls for us. A hook is exempted only in a class carrying the decorator
#: that calls it, so a stray method that happens to be called ``__post_init__`` on a plain
#: class is not silently forgiven.
FRAMEWORK_HOOKS: dict[str, tuple[str | None, str]] = {
    "__init__": (None, "called by the constructor of the class that defines it"),
    "__new__": (None, "called by the constructor machinery"),
    "__post_init__": ("dataclass", "called by @dataclass after __init__"),
    "__enter__": (None, "called by `with`"),
    "__exit__": (None, "called by `with`"),
}

#: Compatibility input for the historical auditor scripts (cases Q2/Q3/S). Free text is never
#: evidence: a legacy entry is accepted only when exactly one definition has that bare name and
#: an imported-module immediate ``getattr(...)()`` invocation can be normalized to it.
GETATTR_DISPATCHED: dict[str, str] = {}

#: Primary declaration table: defining ``module::qualname`` -> (caller module, line, mechanism).
#: Supported mechanism: ``getattr-call``  -- the AST must call the retrieved attribute immediately,
#: through an import that resolves to the defining module, at a site that a declared entry can
#: reach. Other dispatch forms fail closed.
DISPATCH_SITES: dict[str, tuple[str, int, str]] = {}

CHECK_PREFIXES = ("check", "verify", "require", "enforce", "reject", "validate")

#: ``typing.TYPE_CHECKING`` is False at run time, which is the entire point of the constant.
TYPE_CHECKING_ATTR = "TYPE_CHECKING"


# ------------------------------------------------------------------------------------ records


@dataclass
class Reference:
    """One call site (or property read, or ``getattr`` literal) that names a check.

    ``via`` records how the name was reached, because that decides whether the call can be
    attributed to a definition at all:

    * ``self`` -- ``self.check()`` inside a class; attributable through inheritance;
    * ``class`` -- ``RecordLayer(...).check()``; attributable to that class;
    * ``module`` -- a bare ``check()``; attributable to the module-level function;
    * ``variable`` -- ``signer.verify(...)``; **not** attributable to any one class, which is
      why such a name has to be declared in ``INTERFACE_METHODS`` to count as live;
    * ``getattr`` -- a literal mention, which needs validated dispatch evidence to pass.

    ``function`` is the lexical scope: ``Class.method``, ``Class.method.<locals>.helper`` for a
    nested function, or ``<module>``. ``dead`` marks a reference inside a statically dead
    branch; ``invoked`` marks ``getattr(...)()`` where the attribute is called immediately.
    """

    module: str
    lineno: int
    via: str
    owner: str | None = None
    function: str = "<module>"
    invoked: bool = False
    dead: bool = False

    @property
    def dynamic(self) -> bool:
        return self.via == "getattr"

    @property
    def function_key(self) -> str:
        return f"{self.module}::{self.function}"

    @property
    def at_module_level(self) -> bool:
        return self.function == "<module>"


@dataclass
class Check:
    """One candidate check, its location, and the call sites found for it."""

    module: str
    qualname: str
    lineno: int
    end_lineno: int
    decorated: tuple[str, ...] = ()
    references: list[Reference] = field(default_factory=list)
    raises: bool = False

    @property
    def bare_name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def key(self) -> str:
        return f"{self.module}::{self.qualname}"

    @property
    def is_check_like(self) -> bool:
        return self.bare_name.lstrip("_").startswith(CHECK_PREFIXES) or self.raises

    @property
    def exempt_reason(self) -> str | None:
        declared = INTERFACE_METHODS.get(self.key)
        if declared is not None:
            return declared
        hook = FRAMEWORK_HOOKS.get(self.bare_name)
        if hook is not None:
            decorator, reason = hook
            if decorator is None or decorator in self.decorated:
                return reason
        return None


@dataclass
class CallSite:
    """A call inside a function, kept for the limited call graph."""

    name: str
    via: str
    owner: str | None
    lineno: int
    dead: bool = False
    target_module: str | None = None


@dataclass
class FunctionInfo:
    """One function, its lexical key, and the calls it makes."""

    module: str
    qualname: str
    lineno: int
    end_lineno: int
    class_name: str | None = None
    enclosing: str | None = None
    decorated: tuple[str, ...] = ()
    calls: list[CallSite] = field(default_factory=list)
    #: Every plain name this function loads. A nested function whose name is loaded inside a
    #: reachable function is treated as reachable: passing a callback is binding evidence, while
    #: merely defining a nested function is not (the review's T2 probe only defines one).
    loads: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return f"{self.module}::{self.qualname}"

    @property
    def nested(self) -> bool:
        return "<locals>" in self.qualname


@dataclass
class Scope:
    """Lexical state carried down the AST walk.

    ``typing_aliases`` and ``type_checking_names`` are order-sensitive: an import binds them and
    a later assignment to the same name shadows it again, so the evaluator never mistakes a
    shadowed name for the ``typing`` module. ``local_types`` and ``self_types`` hold the bounded
    type inference described in the docstring  -- a name is typed only when *every* assignment to
    it in that scope is a constructor call (or an annotated parameter) naming the same class.
    """

    module: str
    class_stack: tuple[str, ...] = ()
    function_stack: tuple[str, ...] = ()
    typing_aliases: frozenset[str] = frozenset()
    type_checking_names: frozenset[str] = frozenset()
    module_aliases: dict[str, str] = field(default_factory=dict)
    local_types: dict[str, str] = field(default_factory=dict)
    self_types: dict[str, str] = field(default_factory=dict)
    dead: bool = False

    @property
    def class_name(self) -> str | None:
        return self.class_stack[-1] if self.class_stack else None

    @property
    def function_qualname(self) -> str:
        return self.function_stack[-1] if self.function_stack else "<module>"

    def derive(self, **changes) -> "Scope":
        data = dict(
            module=self.module,
            class_stack=self.class_stack,
            function_stack=self.function_stack,
            typing_aliases=self.typing_aliases,
            type_checking_names=self.type_checking_names,
            module_aliases=dict(self.module_aliases),
            local_types=dict(self.local_types),
            self_types=dict(self.self_types),
            dead=self.dead,
        )
        data.update(changes)
        return Scope(**data)

    def shadowed(self, *names: str) -> "Scope":
        typing_aliases = set(self.typing_aliases)
        type_checking = set(self.type_checking_names)
        aliases = dict(self.module_aliases)
        local_types = dict(self.local_types)
        for name in names:
            typing_aliases.discard(name)
            type_checking.discard(name)
            aliases.pop(name, None)
            local_types.pop(name, None)
        return self.derive(
            typing_aliases=frozenset(typing_aliases),
            type_checking_names=frozenset(type_checking),
            module_aliases=aliases,
            local_types=local_types,
        )


@dataclass
class TreeIndex:
    """Everything the analysis needs, collected in one AST pass per file."""

    references: dict[str, list[Reference]] = field(default_factory=dict)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)
    classes: dict[str, set[str]] = field(default_factory=dict)          # class -> in-tree bases
    definers: dict[str, set[str]] = field(default_factory=dict)         # method -> classes
    methods: dict[str, list[tuple[str, str]]] = field(default_factory=dict)   # name -> (module, class)
    module_functions: dict[str, list[str]] = field(default_factory=dict)      # name -> modules
    module_imports: dict[str, set[str]] = field(default_factory=dict)         # module -> modules
    class_names: set[str] = field(default_factory=set)                        # every class in the tree

    def method_key(self, class_name: str, method: str, prefer_module: str) -> str | None:
        """Resolve ``Class.method`` to a definition, preferring the calling module."""
        candidates = [
            (module, owner) for module, owner in self.methods.get(method, ())
            if owner == class_name
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda pair: pair[0] != prefer_module)
        module, owner = candidates[0]
        return f"{module}::{owner}.{method}"

    def function_key(self, name: str, prefer_module: str) -> str | None:
        """Resolve a bare call to a module-level function, preferring the calling module."""
        candidates = list(self.module_functions.get(name, ()))
        if not candidates:
            return None
        candidates.sort(key=lambda module: module != prefer_module)
        return f"{candidates[0]}::{name}"

    def imported_by(self, entry_modules: set[str]) -> set[str]:
        """Modules whose top level runs because an entry module imports them, transitively.

        Module-level code executes when the module is imported, so a decorator applied at module
        level in ``tls/`` is on the live path  -- but only if some declared entry, directly or
        through another import, pulls that module in. Nothing here is guessed from names.
        """
        seen = set(entry_modules)
        queue = sorted(entry_modules)
        while queue:
            current = queue.pop()
            for target in self.module_imports.get(current, ()):
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        return seen


# --------------------------------------------------------------------------- lexical helpers


def _decorator_names(node: ast.AST) -> tuple[str, ...]:
    names = []
    for decorator in getattr(node, "decorator_list", ()):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
    return tuple(names)


def _source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts
        if any(part in SKIP_PARTS for part in parts):
            continue
        if parts[0] not in (*LIVE_ROOTS, TEST_ROOT):
            continue
        files.append(path)
    # One explicit external driver belongs to this TLS implementation but is
    # shipped at the repository root. Give it a stable virtual module name;
    # never sweep arbitrary parent directories or silently exempt its callees.
    external = root.parent / "tools" / "alt_chain_fixtures.py"
    if external.is_file():
        files.append(external)
    return files


def _module_name(path: Path, root: Path) -> str:
    if path.is_relative_to(root):
        return path.relative_to(root).as_posix()
    if path == root.parent / "tools" / "alt_chain_fixtures.py":
        return "project_tools/alt_chain_fixtures.py"
    raise ValueError("unexpected source outside the audited tree")


def _parse(path: Path, root: Path) -> ast.Module:
    """Parse a file, tolerating a UTF-8 BOM (Python does) and reporting failures loudly.

    A file that does not parse is a hard error rather than a silent skip: a sweep that quietly
    ignores the files it cannot read is worse than no sweep.
    """
    try:
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        raise SystemExit(f"tool error: cannot read {_module_name(path, root)}: {error}")
    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError as error:
        raise SystemExit(
            f"tool error: {_module_name(path, root)} does not parse ({error.msg} "
            f"at line {error.lineno}); the sweep cannot judge a tree it cannot read"
        )


def _raises(node: ast.AST) -> bool:
    return any(isinstance(inner, ast.Raise) for inner in ast.walk(node))


def _bound_names(target: ast.AST) -> list[str]:
    """Every plain name a binding target introduces, including tuple/starred targets."""
    return [
        part.id for part in ast.walk(target)
        if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del))
    ]


def _assign_targets(statement: ast.stmt) -> list[ast.AST]:
    if isinstance(statement, ast.Assign):
        return list(statement.targets)
    if isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        return [statement.target]
    return []


def _const_truth(node: ast.AST, scope: Scope) -> tuple[bool, object]:
    """``(known, value)`` for the small constant language the review asked us to understand.

    Literals, boolean composition of literals, comparisons of literals and
    ``typing.TYPE_CHECKING`` (through a resolved, unshadowed import alias) only. No tree is
    imported and ``eval`` is never called; an unknown expression is unknown, and an unknown
    condition keeps both branches live.
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (bool, int, str, bytes)) or node.value is None:
            return True, node.value
        return False, None
    if isinstance(node, ast.Name):
        if node.id in scope.type_checking_names:
            return True, False
        return False, None
    if isinstance(node, ast.Attribute):
        if node.attr == TYPE_CHECKING_ATTR and isinstance(node.value, ast.Name):
            if node.value.id in scope.typing_aliases:
                return True, False
        return False, None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        known, value = _const_truth(node.operand, scope)
        return (True, not value) if known else (False, None)
    if isinstance(node, ast.BoolOp):
        values = []
        for value in node.values:
            known, resolved = _const_truth(value, scope)
            if not known:
                return False, None
            values.append(resolved)
        if isinstance(node.op, ast.And):
            return True, all(values)
        if isinstance(node.op, ast.Or):
            return True, any(values)
        return False, None
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        known_left, left = _const_truth(node.left, scope)
        known_right, right = _const_truth(node.comparators[0], scope)
        if not (known_left and known_right):
            return False, None
        op = node.ops[0]
        try:
            if isinstance(op, ast.Eq):
                return True, left == right
            if isinstance(op, ast.NotEq):
                return True, left != right
            if isinstance(op, ast.Lt):
                return True, left < right
            if isinstance(op, ast.LtE):
                return True, left <= right
            if isinstance(op, ast.Gt):
                return True, left > right
            if isinstance(op, ast.GtE):
                return True, left >= right
        except TypeError:
            return False, None
    return False, None


def _alias_base(node: ast.AST, scope: Scope) -> tuple[str | None, list[str]]:
    """Return ``(module path of the alias, attribute chain)`` for an attribute expression."""
    parts: list[str] = []
    cursor = node
    while isinstance(cursor, ast.Attribute):
        parts.append(cursor.attr)
        cursor = cursor.value
    if not isinstance(cursor, ast.Name):
        return None, []
    return scope.module_aliases.get(cursor.id), list(reversed(parts))


#: Assignment values that are "unknown" for the bounded type inference below.
_UNKNOWN = "?"


def _constructor_class(node: ast.AST | None, class_names: set[str]) -> str | None:
    """``ClassName(...)`` / ``alias.ClassName(...)`` -> ``"ClassName"``, else ``None``."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in class_names:
            return func.id
        if isinstance(func, ast.Attribute) and func.attr in class_names:
            return func.attr
    return None


def _annotation_class(node: ast.AST | None, class_names: set[str]) -> str | None:
    """A parameter or attribute annotation naming a class in this tree."""
    if isinstance(node, ast.Name) and node.id in class_names:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in class_names:
        return node.attr
    if isinstance(node, ast.BinOp):  # `X | None`
        return _annotation_class(node.left, class_names) or _annotation_class(node.right, class_names)
    return None


def _infer_local_types(body: list[ast.stmt], parameters: dict[str, ast.AST | None],
                       class_names: set[str]) -> dict[str, str]:
    """Bound the type of a local name to a class when every assignment agrees.

    Deliberately narrow: a name counts as typed only when each assignment to it in that
    function is a constructor call (or an annotated parameter) naming the *same* class in this
    tree. One unknown assignment drops the name. This exists so that ``reader = Reader(body)``
    followed by ``reader.read_u16()`` yields a call-graph edge; it is not general inference, and
    the report says so.
    """
    votes: dict[str, set[str]] = {}

    def note(name: str, value: str | None) -> None:
        votes.setdefault(name, set()).add(value or _UNKNOWN)

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # a nested scope has its own inference
        if isinstance(node, ast.Assign):
            inferred = _constructor_class(node.value, class_names)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    note(target.id, inferred)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            inferred = _constructor_class(node.value, class_names) or _annotation_class(
                node.annotation, class_names
            )
            note(node.target.id, inferred)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor)):
            for target in (
                [node.target] if isinstance(node, ast.AugAssign) else [node.target]
            ):
                for part in ast.walk(target):
                    if isinstance(part, ast.Name):
                        note(part.id, None)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for statement in body:
        visit(statement)
    for name, annotation in parameters.items():
        note(name, _annotation_class(annotation, class_names))
    return {
        name: next(iter(values))
        for name, values in votes.items()
        if len(values) == 1 and next(iter(values)) != _UNKNOWN
    }


def _infer_self_types(body: list[ast.stmt], class_names: set[str]) -> dict[str, str]:
    """Bound the type of ``self.<attr>`` when every assignment in the class agrees."""
    votes: dict[str, set[str]] = {}

    def note(attr: str, value: str | None) -> None:
        votes.setdefault(attr, set()).add(value or _UNKNOWN)

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                ):
                    note(target.attr, _constructor_class(node.value, class_names))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Attribute):
            attribute = node.target
            if isinstance(attribute.value, ast.Name) and attribute.value.id == "self":
                note(
                    attribute.attr,
                    _constructor_class(node.value, class_names)
                    or _annotation_class(node.annotation, class_names),
                )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child)  # methods assign self.<attr>; their own locals are separate
                continue
            visit(child)

    for statement in body:
        visit(statement)
    return {
        attr: next(iter(values))
        for attr, values in votes.items()
        if len(values) == 1 and next(iter(values)) != _UNKNOWN
    }


# ---------------------------------------------------------------------------------- indexing


def index_tree(root: Path) -> TreeIndex:
    """Walk every source file once, recording references, functions, classes and checks."""
    index = TreeIndex()
    files = _source_files(root)
    parsed: list[tuple[Path, str, ast.Module]] = []
    for path in files:
        module = _module_name(path, root)
        tree = _parse(path, root)
        parsed.append((path, module, tree))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                index.class_names.add(node.name)

    for _path, module, tree in parsed:
        class_names = index.class_names
        call_targets = {
            id(call.func) for call in ast.walk(tree) if isinstance(call, ast.Call)
        }

        def record(name: str, scope: Scope, lineno: int, via: str,
                   owner: str | None, invoked: bool = False) -> None:
            index.references.setdefault(name, []).append(
                Reference(
                    module=scope.module,
                    lineno=lineno,
                    via=via,
                    owner=owner,
                    function=scope.function_qualname,
                    invoked=invoked,
                    dead=scope.dead,
                )
            )

        def classify(receiver: ast.AST, scope: Scope) -> tuple[str, str | None]:
            if isinstance(receiver, ast.Name) and receiver.id == "self":
                return "self", scope.class_name
            if isinstance(receiver, ast.Name) and receiver.id in class_names:
                return "class", receiver.id
            return "variable", None

        def concrete_class_of(receiver: ast.AST, scope: Scope,
                              known: set[str]) -> str | None:
            """The class a receiver provably has, for call-graph edges only.

            Three narrow sources, all documented in the module docstring: a local name whose
            every assignment is a constructor call to the same class, ``self.<attr>`` whose every
            assignment in the class is such a call (or a matching annotation), and a
            ``Class(...)`` call used directly as the receiver.
            """
            if isinstance(receiver, ast.Name):
                return scope.local_types.get(receiver.id)
            if (
                isinstance(receiver, ast.Attribute)
                and isinstance(receiver.value, ast.Name)
                and receiver.value.id == "self"
            ):
                return scope.self_types.get(receiver.attr)
            return _constructor_class(receiver, known)

        def walk_statements(body: list[ast.stmt], scope: Scope) -> Scope:
            """Walk a statement list in order, threading what imports and bindings change."""
            current = scope
            for statement in body:
                current = walk_statement(statement, current)
            return current

        def walk_statement(statement: ast.stmt, scope: Scope) -> Scope:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                return walk_import(statement, scope)
            if isinstance(statement, ast.If):
                known, value = _const_truth(statement.test, scope)
                if known:
                    taken = statement.body if value else statement.orelse
                    other = statement.orelse if value else statement.body
                    walk_statements(taken, scope)
                    walk_statements(other, scope.derive(dead=True))
                else:
                    walk_statements(statement.body, scope)
                    walk_statements(statement.orelse, scope)
                walk_expression(statement.test, scope)
                # A binding inside a branch may not run, so nothing is threaded back out.
                return scope
            if isinstance(statement, ast.While):
                known, value = _const_truth(statement.test, scope)
                if known and not value:
                    walk_statements(statement.body, scope.derive(dead=True))
                    walk_statements(statement.orelse, scope)
                else:
                    walk_statements(statement.body, scope)
                    walk_statements(statement.orelse, scope)
                walk_expression(statement.test, scope)
                return scope
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for target in _assign_targets(statement):
                    # `alias = something` removes the import alias for the rest of the scope.
                    scope = scope.shadowed(*_bound_names(target))
                walk_expression(statement, scope)
                return scope
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                scope = scope.shadowed(*_bound_names(statement.target))
                walk_expression(statement, scope)
                return scope
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if item.optional_vars is not None:
                        scope = scope.shadowed(*_bound_names(item.optional_vars))
                walk_expression(statement, scope)
                return scope
            if isinstance(statement, ast.ExceptHandler):
                if statement.name:
                    scope = scope.shadowed(statement.name)
                walk_expression(statement, scope)
                return scope
            if isinstance(statement, (ast.Global, ast.Nonlocal)):
                scope = scope.shadowed(*statement.names)
                walk_expression(statement, scope)
                return scope
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk_function(statement, scope)
                # The definition binds its own name in the enclosing scope.
                return scope.shadowed(statement.name)
            if isinstance(statement, ast.ClassDef):
                walk_class(statement, scope)
                return scope.shadowed(statement.name)
            walk_expression(statement, scope)
            return scope

        def walk_import(statement: ast.stmt, scope: Scope) -> Scope:
            """Bind the names an import introduces and return the updated scope.

            The caller threads the result through the rest of the statement list, which is what
            makes a *local* import — `import tls.x as x` inside a method — visible to the lines
            that follow it. Without that, an alias declared inside a function body resolves to
            nothing and every dispatch declaration that depends on it fails.
            """
            typing_aliases = set(scope.typing_aliases)
            type_checking = set(scope.type_checking_names)
            aliases = dict(scope.module_aliases)
            imported: set[str] = set()
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    if alias.name == "typing" and alias.asname is None:
                        typing_aliases.add(bound)
                    elif alias.name == "typing" and alias.asname:
                        typing_aliases.add(alias.asname)
                    imported.add(alias.name.replace(".", "/") + ".py")
                    imported.add(alias.name.replace(".", "/") + "/__init__.py")
                    if alias.asname:
                        aliases[alias.asname] = alias.name.replace(".", "/") + ".py"
                    else:
                        root_name = alias.name.split(".")[0]
                        aliases.setdefault(root_name, root_name + ".py")
            else:
                source = (statement.module or "").replace(".", "/")
                if source:
                    imported.add(source + ".py")
                    imported.add(source + "/__init__.py")
                for alias in statement.names:
                    bound = alias.asname or alias.name
                    shadow = {bound}
                    if statement.module == "typing" and alias.name == TYPE_CHECKING_ATTR:
                        type_checking.add(bound)
                    elif alias.name == "*":
                        shadow = set()
                    else:
                        aliases[bound] = f"{source}/{alias.name}.py" if source else f"{alias.name}.py"
                        imported.add(f"{source}/{alias.name}.py")
                    if shadow:
                        scope = scope.shadowed(*shadow)
            if imported:
                index.module_imports.setdefault(module, set()).update(imported)
            return scope.derive(
                typing_aliases=frozenset(typing_aliases),
                type_checking_names=frozenset(type_checking),
                module_aliases=aliases,
            )

        def walk_function(node: ast.AST, scope: Scope, class_decorators: tuple[str, ...] = ()) -> None:
            name = node.name
            if scope.function_stack:
                qualname = f"{scope.function_qualname}.<locals>.{name}"
                enclosing = f"{scope.module}::{scope.function_qualname}"
            elif scope.class_name:
                qualname = f"{scope.class_name}.{name}"
                enclosing = None
            else:
                qualname = name
                enclosing = None
            info = FunctionInfo(
                module=scope.module,
                qualname=qualname,
                lineno=node.lineno,
                end_lineno=node.end_lineno or node.lineno,
                class_name=scope.class_name,
                enclosing=enclosing,
                # A method carries its class's decorators: `@dataclass` sits on the class, and
                # the framework-hook exemption has to see it.
                decorated=class_decorators + _decorator_names(node),
            )
            index.functions[info.key] = info
            if not scope.function_stack and module.startswith("tls/"):
                index.checks.append(
                    Check(
                        module=scope.module,
                        qualname=qualname,
                        lineno=node.lineno,
                        end_lineno=node.end_lineno or node.lineno,
                        decorated=info.decorated,
                        raises=_raises(node),
                    )
                )
                if scope.class_name:
                    index.definers.setdefault(name, set()).add(scope.class_name)
                    index.methods.setdefault(name, []).append((scope.module, scope.class_name))
                else:
                    index.module_functions.setdefault(name, []).append(scope.module)

            inner = scope.shadowed(name)
            arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            for argument in arguments:
                inner = inner.shadowed(argument.arg)
            for extra in (node.args.vararg, node.args.kwarg):
                if extra is not None:
                    inner = inner.shadowed(extra.arg)
            parameters = {argument.arg: argument.annotation for argument in arguments}
            local_types = _infer_local_types(node.body, parameters, class_names)
            inner = inner.derive(
                function_stack=(*scope.function_stack, qualname),
                local_types=local_types,
            )
            walk_statements(node.body, inner)
            for decorator in node.decorator_list:
                walk_expression(decorator, scope)

        def walk_class(node: ast.ClassDef, scope: Scope) -> None:
            bases = [
                base.id if isinstance(base, ast.Name) else base.attr
                for base in node.bases
                if isinstance(base, (ast.Name, ast.Attribute))
            ]
            index.classes.setdefault(node.name, set()).update(bases)
            decorators = _decorator_names(node)
            self_types = _infer_self_types(node.body, class_names)
            inner = scope.shadowed(node.name).derive(
                class_stack=(*scope.class_stack, node.name),
                self_types=self_types,
            )
            for statement in node.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    walk_function(statement, inner, decorators)
                else:
                    walk_statement(statement, inner)

        def walk_expression(node: ast.AST, scope: Scope) -> None:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                current = index.functions.get(f"{scope.module}::{scope.function_qualname}")
                if current is not None:
                    current.loads.add(node.id)
            if isinstance(node, ast.Call):
                target = node.func
                called: str | None = None
                via, owner = "module", None
                target_module: str | None = None
                if isinstance(target, ast.Name):
                    called = target.id
                    if called in class_names:
                        # `ClientHello(...)`: the constructor runs. This is what makes a
                        # framework hook reachable only when its class is actually built.
                        via, owner = "constructor", called
                elif isinstance(target, ast.Attribute):
                    called = target.attr
                    via, owner = classify(target.value, scope)
                    if via == "variable":
                        base, chain = _alias_base(target.value, scope)
                        if base and chain:
                            # `alias.Class.method(...)` / `alias.func(...)`: resolved through
                            # the module the alias points at, so the edge is not lost.
                            target_module = base
                            via = "class-module" if len(chain) > 1 else "module-alias"
                            owner = (
                                "::".join([base[: -len(".py")], *chain[:-1]])
                                if len(chain) > 1
                                else None
                            )
                # The call-graph edge may use the bounded type inference, while the reference
                # keeps the syntactic `via` the report has always shown. Attribution and
                # reachability are deliberately separate answers.
                edge_via, edge_owner = via, owner
                if via == "variable" and isinstance(target, ast.Attribute):
                    inferred = concrete_class_of(target.value, scope, class_names)
                    if inferred:
                        edge_via, edge_owner = "class", inferred
                if called:
                    record(called, scope, node.lineno, via, owner)
                    current = index.functions.get(f"{scope.module}::{scope.function_qualname}")
                    if current is not None:
                        current.calls.append(
                            CallSite(
                                name=called, via=edge_via, owner=edge_owner,
                                lineno=node.lineno, dead=scope.dead,
                                target_module=target_module,
                            )
                        )
                if (
                    isinstance(target, ast.Name)
                    and target.id == "getattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    receiver = node.args[0]
                    base, _chain = _alias_base(receiver, scope)
                    if base is None and isinstance(receiver, ast.Name):
                        base = scope.module_aliases.get(receiver.id)
                    record(
                        node.args[1].value, scope, node.lineno, "getattr",
                        base, invoked=id(node) in call_targets,
                    )
            elif isinstance(node, ast.Attribute):
                # A property is *read*, never called with parentheses: `config.cipher_suite_id`
                # is an attribute access, and a collector that only looks at call targets
                # reports every property as dead. The first version of this tool did exactly
                # that, and acceptance 4b failed on `HybridTLSConfig.cipher_suite_id`.
                via, owner = classify(node.value, scope)
                record(node.attr, scope, node.lineno, via, owner)
                # Reading a property runs its getter, so a read on a receiver whose type is
                # known is a reachability edge, exactly like a call.
                inferred = concrete_class_of(node.value, scope, class_names)
                if inferred:
                    current = index.functions.get(f"{scope.module}::{scope.function_qualname}")
                    if current is not None:
                        current.calls.append(
                            CallSite(
                                name=node.attr, via="class", owner=inferred,
                                lineno=node.lineno, dead=scope.dead,
                            )
                        )
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    walk_function(child, scope)
                elif isinstance(child, ast.ClassDef):
                    walk_class(child, scope)
                else:
                    walk_expression(child, scope)

        walk_statements(tree.body, Scope(module=module))
    return index


# ------------------------------------------------------------------------------ reachability


def class_hierarchy(index: TreeIndex) -> dict[str, set[str]]:
    """Ancestor closure for every class defined in the tree (name-keyed, as before)."""
    ancestors: dict[str, set[str]] = {}

    def close(name: str, seen: frozenset[str]) -> set[str]:
        if name in ancestors:
            return ancestors[name]
        if name in seen:
            return {name}
        result = {name}
        for base in index.classes.get(name, ()):
            if base in index.classes:
                result |= close(base, seen | {name})
        ancestors[name] = result
        return result

    for name in index.classes:
        close(name, frozenset())
    return ancestors


def resolve_call(call: CallSite, index: TreeIndex, ancestors: dict[str, set[str]],
                 module: str) -> str | None:
    """Resolve one call to a function key, or ``None`` when the analysis cannot say.

    Only the forms the review accepts are resolved: a controlled ``self`` call, a call on a
    known class (through its in-tree bases), a call through a module import, and a bare call to
    a module-level function. A variable receiver resolves to nothing: the analysis reports that
    as unverified rather than guessing, which is what keeps V7-04 closed.
    """
    if call.via in ("self", "class", "constructor") and call.owner:
        method = "__init__" if call.via == "constructor" else call.name
        candidates = [call.owner] + sorted(ancestors.get(call.owner, set()) - {call.owner})
        for class_name in candidates:
            key = index.method_key(class_name, method, module)
            if key is not None:
                return key
        return None
    if call.via == "class-module" and call.owner:
        qualname = call.owner.split("::", 1)[1] if "::" in call.owner else call.owner
        base_module = call.target_module[: -len(".py")] if call.target_module else None
        if base_module:
            key = f"{base_module}::{qualname}.{call.name}"
            if key in index.functions:
                return key
        for class_name in [qualname] + sorted(ancestors.get(qualname, set()) - {qualname}):
            key = index.method_key(class_name, call.name, module)
            if key is not None:
                return key
        return None
    if call.via == "module-alias" and call.target_module:
        base_module = call.target_module[: -len(".py")]
        key = f"{base_module}::{call.name}"
        if key in index.functions:
            return key
        return index.function_key(call.name, base_module)
    if call.via == "module":
        key = index.function_key(call.name, module)
        if key is not None:
            return key
        return f"{module}::{call.name}" if f"{module}::{call.name}" in index.functions else None
    return None


def reachable_functions(roots: set[str], index: TreeIndex,
                        ancestors: dict[str, set[str]]) -> set[str]:
    """Breadth-first closure over resolved call edges, skipping statically dead call sites.

    A nested function also becomes reachable when a reachable function *loads its name*: that is
    how a callback, a filter or a handler is bound. Merely defining a nested function is not
    enough  -- which is exactly the difference between the review's T2 probe (defined, never
    touched) and the real ``frame_filter`` callbacks in the drivers.
    """
    reachable = {root for root in roots if root in index.functions}
    nested_by_parent: dict[str, list[FunctionInfo]] = {}
    for info in index.functions.values():
        if info.enclosing:
            nested_by_parent.setdefault(info.enclosing, []).append(info)

    queue = sorted(reachable)
    while queue:
        current = queue.pop()
        info = index.functions.get(current)
        if info is None:
            continue
        for call in info.calls:
            if call.dead:
                continue
            target = resolve_call(call, index, ancestors, info.module)
            if target and target not in reachable:
                reachable.add(target)
                queue.append(target)
        for nested in nested_by_parent.get(current, ()):
            name = nested.qualname.rsplit(".", 1)[-1]
            if name in info.loads and nested.key not in reachable:
                reachable.add(nested.key)
                queue.append(nested.key)
    return reachable


# ----------------------------------------------------------------------------- declarations


def verify_entries(entries: dict[str, str], index: TreeIndex) -> list[str]:
    """Every declared entry must resolve to exactly one definition and state how it runs."""
    errors: list[str] = []
    for key, mechanism in entries.items():
        if "::" not in key:
            errors.append(f"{key}: an entry must be written as module::qualname")
            continue
        module, qualname = key.split("::", 1)
        if not mechanism.strip():
            errors.append(f"{key}: state how the entry runs")
        matches = [
            info for info in index.functions.values()
            if info.module == module and info.qualname == qualname
        ]
        if len(matches) != 1:
            errors.append(f"{key}: entry must identify exactly one definition (found {len(matches)})")
    return errors


def verify_interfaces(entries: dict[str, str], index: TreeIndex,
                      references: dict[str, list[Reference]]) -> list[str]:
    """A reviewed interface binding must exist and be used somewhere the live side can see.

    The second half is what stops "declare anything and it passes": a declaration whose bare
    name has no variable-receiver reference from a live root, outside the definition itself and
    not inside a dead branch, is rejected.
    """
    errors: list[str] = []
    for key in entries:
        if "::" not in key:
            errors.append(f"{key}: an interface entry must be written as module::qualname")
            continue
        module, qualname = key.split("::", 1)
        matches = [
            info for info in index.functions.values()
            if info.module == module and info.qualname == qualname
        ]
        if len(matches) != 1:
            errors.append(f"{key}: interface declaration must identify exactly one definition")
            continue
        definition = matches[0]
        bare = qualname.rsplit(".", 1)[-1]
        used = [
            reference for reference in references.get(bare, ())
            if reference.via == "variable"
            and not reference.dead
            and reference.module.split("/", 1)[0] in LIVE_ROOTS
            and not (
                reference.module == module
                and definition.lineno <= reference.lineno <= definition.end_lineno
            )
        ]
        if not used:
            errors.append(
                f"{key}: declared interface method has no variable-receiver reference "
                f"from a live root"
            )
    return errors


def dispatch_declarations(
    checks: list[Check], references: dict[str, list[Reference]], reachable: set[str],
) -> tuple[dict[str, str], list[str]]:
    """Validate module-qualified dispatch evidence, including that the site can run.

    Legacy free-text entries are accepted only when a unique definition has an immediate
    ``getattr`` invocation through an imported module alias; they are normalized to the same
    source/line evidence. Free text alone never grants an exemption, and a site inside a
    statically dead branch or an unreachable function is reported as such rather than counted.
    """
    valid: dict[str, str] = {}
    errors: list[str] = []
    declarations: dict[str, str | tuple[str, int, str]] = dict(GETATTR_DISPATCHED)
    for key, evidence in DISPATCH_SITES.items():
        if key in declarations:
            errors.append(f"{key}: duplicate declaration across legacy and structured tables")
        declarations[key] = evidence
    for key, evidence in declarations.items():
        matches = [check for check in checks if key == check.key]
        legacy = "::" not in key and isinstance(evidence, str)
        if legacy:
            matches = [check for check in checks if check.qualname == key]
        if len(matches) != 1:
            errors.append(f"{key}: declaration must identify one module::qualname")
            continue
        check = matches[0]
        candidates = [
            reference for reference in references.get(check.bare_name, ())
            if check.qualname == check.bare_name
            and reference.dynamic and reference.invoked and reference.owner == check.module
            and reference.module.split("/", 1)[0] in LIVE_ROOTS
            and not (
                reference.module == check.module
                and check.lineno <= reference.lineno <= check.end_lineno
            )
        ]
        if not legacy:
            if not (isinstance(evidence, (tuple, list)) and len(evidence) == 3
                    and isinstance(evidence[0], str) and type(evidence[1]) is int
                    and evidence[2] == "getattr-call"):
                candidates = []
            else:
                candidates = [
                    reference for reference in candidates
                    if (reference.module, reference.lineno) == tuple(evidence[:2])
                ]
        if not candidates:
            errors.append(f"{key}: no matching imported-module getattr invocation at declared site")
            continue
        reference = candidates[0]
        if reference.dead:
            errors.append(
                f"{key}: declared site {reference.module}:{reference.lineno} is inside a statically "
                f"dead branch in {reference.function}; a branch that cannot run cannot call the check"
            )
            continue
        if not reference.at_module_level and reference.function_key not in reachable:
            errors.append(
                f"{key}: declared site {reference.module}:{reference.lineno} sits in "
                f"{reference.function}, which no path from a declared entry reaches"
            )
            continue
        valid[check.key] = (
            f"{reference.module}:{reference.lineno} in {reference.function} via getattr-call"
            + (" (legacy declaration normalized)" if legacy else "")
        )
    return valid, errors


def verdict_reference(check: Check) -> Reference:
    """Return the reference that carries the verdict on ``check``.

    A check can be live because a driver calls it while its first reference sits in ``tests/``.
    Printing that one would suggest the wrong mechanism  -- "reached from a test"  -- so a live
    reference wins when there is one.
    """
    for reference in check.references:
        if reference.dynamic:
            continue
        if reference.module.split("/", 1)[0] != TEST_ROOT:
            return reference
    return check.references[0]


# -------------------------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sweep A: limited reachability of every security check under tls/"
    )
    parser.add_argument("--verbose", action="store_true", help="also list the live checks")
    parser.add_argument(
        "--explain",
        metavar="NAME",
        default=None,
        help="print every reference of the checks whose name contains NAME, with its reachability",
    )
    parser.add_argument(
        "--entry",
        action="append",
        default=[],
        metavar="MODULE::QUALNAME",
        help="declare an execution root for this tree (repeatable); ENTRY_POINTS applies as well",
    )
    parser.add_argument(
        "--root",
        default=str(PROJECT_ROOT),
        help="tree to sweep; its tls/, tools/, bench/, demo/ and tests/ are read (default: this project)",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    tls = root / "tls"

    if not tls.is_dir():
        print(f"tool error: {tls} does not exist; refusing to report a pass")
        return 2

    index = index_tree(root)
    checks = [check for check in index.checks if check.is_check_like]
    if not checks:
        print(f"tool error: no check-like definition found under {tls}; refusing to report a pass")
        return 2

    entries = dict(ENTRY_POINTS)
    if "project_tools/alt_chain_fixtures.py::main" in index.functions:
        entries["project_tools/alt_chain_fixtures.py::main"] = (
            "actual repository CLI launched by python tools/alt_chain_fixtures.py; direct argparse branches call its actions")
    # The tables above describe this project. A tree that is not this project — a synthetic
    # probe tree with three files in it — cannot be expected to contain those definitions, so a
    # built-in declaration with no counterpart there is reported and skipped. A *copy* of this
    # project (which is what the audit's probes build) does carry them, and there every
    # declaration must resolve. An entry declared with --entry is always verified.
    looks_like_this_project = (root / "tls" / "handshake" / "client.py").is_file()
    absent = []
    if not looks_like_this_project:
        for table in (entries, INTERFACE_METHODS):
            for key in list(table):
                if key not in index.functions:
                    absent.append(key)
                    table.pop(key, None)
    for extra in args.entry:
        entries[extra] = "declared on the command line"
    for key in absent:
        print(f"declaration absent in this tree, skipped: {key}")
    if absent and not args.verbose:
        print()

    entry_errors = verify_entries(entries, index)
    interface_errors = verify_interfaces(INTERFACE_METHODS, index, index.references)

    ancestors = class_hierarchy(index)
    roots = {key for key in entries if key in index.functions}
    roots |= {key for key in INTERFACE_METHODS if key in index.functions}
    reachable = reachable_functions(roots, index, ancestors)
    declared_dispatch, declaration_errors = dispatch_declarations(checks, index.references, reachable)
    verified_interfaces = {
        key for key in INTERFACE_METHODS if key in index.functions
    }
    entry_modules = {key.split("::", 1)[0] for key in entries if "::" in key}
    live_modules = index.imported_by(entry_modules)

    def site_is_reachable(reference: Reference) -> bool:
        if reference.dead:
            return False
        if reference.at_module_level:
            # Module-level code runs when the module is imported by a driver  -- not because it
            # sits under tls/, and not when no entry pulls the module in.
            return reference.module in live_modules
        return reference.function_key in reachable

    ambiguous_variable: dict[str, list[Reference]] = {}
    definers = index.definers
    for check in checks:
        enclosing_class = check.qualname.rsplit(".", 1)[0] if "." in check.qualname else None
        kept: list[Reference] = []
        for reference in index.references.get(check.bare_name, ()):
            # A call site inside the check's own body is a self-reference, not a caller.
            if (
                reference.module == check.module
                and check.lineno <= reference.lineno <= check.end_lineno
            ):
                continue
            if reference.via == "variable":
                ambiguous_variable.setdefault(check.qualname, []).append(reference)
                kept.append(reference)
                continue
            if reference.dynamic or reference.via in ("module", "module-alias", "class-module"):
                kept.append(reference)
                continue
            chain = ancestors.get(reference.owner or "")
            if chain is None:
                kept.append(reference)
            elif enclosing_class is not None and enclosing_class in chain:
                kept.append(reference)  # `self.call()` resolves here, possibly via a base
            elif not (definers.get(check.bare_name, set()) & (chain - {reference.owner})):
                kept.append(reference)  # the receiver's own chain defines no such method
        check.references = kept

    live: list[Check] = []
    interface: list[Check] = []
    unverified: list[Check] = []
    undeclared_dynamic: list[Check] = []
    unattributed: list[Check] = []
    test_only: list[Check] = []
    dead: list[Check] = []
    unreachable: list[Check] = []
    exempt: list[Check] = []
    for check in checks:
        resolved = [
            reference for reference in check.references
            if not reference.dynamic and reference.via != "variable"
        ]
        dynamic = [reference for reference in check.references if reference.dynamic]
        reachable_resolved = [
            reference for reference in resolved
            if site_is_reachable(reference)
        ]
        if reachable_resolved:
            from_tests_only = all(
                reference.module.split("/", 1)[0] == TEST_ROOT
                for reference in reachable_resolved
            )
            (test_only if from_tests_only else live).append(check)
        elif check.key in verified_interfaces:
            # A reviewed interface binding: verified to exist, printed in every report, and
            # required to be used from a live root (see verify_interfaces). It stands on its own
            # because the receiver's type is exactly what a static scan cannot infer.
            interface.append(check)
        elif resolved:
            from_tests_only = all(
                reference.module.split("/", 1)[0] == TEST_ROOT for reference in resolved
            )
            (test_only if from_tests_only else unreachable).append(check)
        elif check.exempt_reason:
            exempt.append(check)
        elif any(reference.via == "variable" for reference in check.references):
            unattributed.append(check)
        elif dynamic and check.key not in declared_dispatch:
            undeclared_dynamic.append(check)
        elif dynamic:
            unverified.append(check)
        else:
            dead.append(check)

    sole_variable = [
        check for check in unattributed
        if len(definers.get(check.bare_name, ())) <= 1
    ]

    print(f"check-like definitions under tls/: {len(checks)}")
    print(f"  live from implementation or drivers : {len(live)}")
    print(f"  reached only through an interface   : {len(interface)}")
    print(f"  called by a framework               : {len(exempt)}")
    print(f"  referenced only from tests/         : {len(test_only)}")
    print(f"  live only via getattr               : {len(unverified)}")
    print(f"  live only via an undeclared getattr : {len(undeclared_dynamic)}")
    print(f"  referenced only through a variable  : {len(unattributed)}")
    print(f"  referenced only from unreachable code: {len(unreachable)}")
    print(f"  referenced nowhere                  : {len(dead)}")
    print(f"  declared entries / reachable functions: {len(entries)} / {len(reachable)}")
    print(f"  of those: sole-implementation variable calls : {len(sole_variable)}")
    print()

    for check in test_only:
        print(f"TESTS-ONLY    {check.module}:{check.lineno} {check.qualname}")
        for reference in check.references[:3]:
            print(f"              test-only call site: {reference.module}:{reference.lineno}")
    for check in unattributed:
        reference = next(
            (ref for ref in check.references if ref.via == "variable"), check.references[0]
        )
        print(f"UNATTRIBUTED  {check.module}:{check.lineno} {check.qualname}")
        print(f"              only ever called on a variable: {reference.module}:{reference.lineno}")
    for check in dead:
        print(f"DEAD          {check.module}:{check.lineno} {check.qualname}")
        print("              no call site and no getattr literal names it")
    for check in unreachable:
        reference = verdict_reference(check)
        where = (
            f"inside `{reference.function}`" if not reference.at_module_level
            else "at module level"
        )
        if reference.dead:
            reason = "that statement is in a statically dead branch"
        elif reference.at_module_level:
            reason = "that module is not a declared entry"
        else:
            reason = "no declared entry reaches that function"
        print(f"UNREACHABLE   {check.module}:{check.lineno} {check.qualname}")
        print(f"              only reference is {reference.module}:{reference.lineno}, {where}  -- {reason}")
    for check in unverified:
        reference = check.references[0]
        print(f"getattr-only  {check.module}:{check.lineno} {check.qualname}"
              f"  <- {reference.module}:{reference.lineno}"
              f"  -- declared: {declared_dispatch[check.key]}")
    for check in undeclared_dynamic:
        reference = check.references[0]
        print(f"getattr-undeclared {check.module}:{check.lineno} {check.qualname}"
              f"  <- {reference.module}:{reference.lineno}")
    for check in sole_variable:
        reference = verdict_reference(check)
        print(f"variable-sole {check.module}:{check.lineno} {check.qualname}"
              f"  <- {reference.module}:{reference.lineno}"
              f" in {reference.function} -- UNVERIFIED: receiver type is unknown; "
              f"name uniqueness is insufficient")
    for check in interface:
        print(f"interface     {check.module}:{check.lineno} {check.qualname}  -- {check.exempt_reason}")
    for check in exempt:
        print(f"exempt        {check.module}:{check.lineno} {check.qualname}  -- {check.exempt_reason}")

    if args.verbose:
        print()
        print(f"declared entries ({len(entries)}):")
        for key, mechanism in sorted(entries.items()):
            state = "in tree" if key in index.functions else "NOT FOUND"
            print(f"  {key:48} [{state}] {mechanism}")
        print()
        print("live checks (verdict call site shown):")
        for check in sorted(live, key=lambda item: item.qualname):
            first = verdict_reference(check)
            print(
                f"  {check.qualname:44} {first.via:12} {first.module}:{first.lineno}"
                f" in {first.function}"
            )

    if args.explain:
        print()
        print(f"explain: checks whose name contains {args.explain!r}")
        for check in sorted(checks, key=lambda item: item.key):
            if args.explain not in check.qualname:
                continue
            print(f"  {check.key}  (line {check.lineno})")
            for reference in index.references.get(check.bare_name, ()):
                flags = []
                if reference.dead:
                    flags.append("DEAD-BRANCH")
                if reference.dynamic:
                    flags.append("getattr" + ("-invoked" if reference.invoked else ""))
                if reference.at_module_level:
                    flags.append("module-level " + ("(imported by an entry)" if site_is_reachable(reference) else "(not imported by any entry)"))
                elif site_is_reachable(reference):
                    flags.append("reachable site")
                else:
                    flags.append("unreachable site")
                print(
                    f"    {reference.module}:{reference.lineno} via={reference.via} "
                    f"in {reference.function} [{' '.join(flags)}]"
                )

    for label, errors in (
        ("INVALID-ENTRY", entry_errors),
        ("INVALID-INTERFACE", interface_errors),
        ("INVALID-DECLARATION", declaration_errors),
    ):
        for error in errors:
            print(f"{label} {error}")
    if entry_errors or interface_errors or declaration_errors:
        print()
        print("FAIL: a declaration could not be verified. Entries and interface bindings must name "
              "exactly one definition, state how it runs, and  -- for dispatch  -- point at a site a "
              "declared entry can reach. Free text is not evidence.")
        return 1
    if dead:
        print()
        print("FAIL: a check that nothing calls cannot be protecting anything.")
        return 1
    if unreachable:
        print()
        print("FAIL: a check whose only references sit in statically dead code or in code no "
              "declared entry reaches is not on the live path. Wire it in, or delete it: a "
              "declaration does not make a site runnable.")
        return 1
    if unattributed:
        print()
        print("FAIL: a check reached only through a variable cannot be attributed to it. Either "
              "declare it in INTERFACE_METHODS with the mechanism that reaches it, or call it "
              "from the live path. A dead method that shares its name with a live one hides here.")
        return 1
    if test_only:
        print()
        print("FAIL: a check reached only from tests/ is not on the handshake path. Either wire it "
              "in or delete it: three reviews have found this shape of defect here.")
        return 1
    if undeclared_dynamic:
        print()
        print("FAIL: a `getattr` string literal names a check without calling it, so it cannot "
              "show that anything runs the check. A dispatcher that really does call it belongs "
              "in DISPATCH_SITES with validated source/line evidence; a check nobody calls must be "
              "wired in or deleted.")
        return 1
    print()
    print("PASS: every check under tls/ is reachable from a declared entry, a reviewed interface "
          "binding, or a validated dispatch site (limited static analysis; see the docstring).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
