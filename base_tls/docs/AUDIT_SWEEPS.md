# v8 当前规则（2026-09-22）

本节取代下方 v7 历史记录中的放行规则与“固定点可达性”表述。

- 未归属变量调用（包括唯一名字）失败，并显示所在函数；真实接口按 module::Class.method 声明。
- DISPATCH_SITES 按 module::qualname 标识定义，值为调用模块、精确行号与 getattr-call 机制；AST 必须在该处立即调用由导入模块解析出的目标。
- 旧 GETATTR_DISPATCHED 文本入口仅兼容可被语法证据规范化的唯一模块级函数目标，文本本身不能放行。
- 87 个定义；本轮完整结果见 ../../validation/live-checks.log。
- 工具只做语法引用清单，没有控制流固定点求解，也不证明运行时必然可达。动态名字、复杂接收者类型与调用别名仍不在分析能力内。

详细修复与测试见 AUDIT_V7_RESPONSE.md。

---

# 下方为 v7 历史记录，数字与旧规则不代表 v8

# Audit sweeps — turning three reading habits into checkable inventories

Three reviews of this repository — a symbolic-verification review, a static security review
and a source audit — each found the **same shape of defect**, in three different places:

| Shape | Instance |
|---|---|
| a check that exists, is correct, and is not on the path a handshake takes | `verify_hybrid_certificate_verify` checked CertificateVerify's scheme identifiers; **nothing called it** (round 3) |
| a derivation that is right in isolation and wrong in context | the exporter's `context` was the raw bytes instead of their hash (round 2); then its master secret came from the wrong transcript stage (round 3) |
| a constraint enforced for one object and not its structural neighbour | the issuer's `keyCertSign` was checked, the leaf's `digital_signature` was not; the leaf's EKU was checked, the CA's was not (rounds 2–3) |

All three are invisible to a test suite that compares this implementation against itself,
which is what the 320 tests here do. Each was found by a reader who did not write the code,
using one of three habits:

1. **For every check, find its caller** — through the live path, not just anywhere.
2. **For every derived value, name the sentence in the standard that fixes its inputs**, and
   compare the code against that, not against the peer.
3. **For every constraint, ask which object it binds and who its structural neighbours are.**

This document is where those three habits become **inventories a reviewer can check**
instead of a reading method they have to reinvent. Check a table, not the whole tree.

## Sweep A — every check is on the live path — **done, and enforced**

`tools/audit_live_checks.py` collects every function or method under `tls/` that looks like a
check (name matching `check`/`verify`/`require`/`enforce`/`reject`/`validate`, or a body that
raises), then counts references to it from live code (`tls/`, `tools/`, `bench/`, `demo/`)
versus from `tests/`. It iterates to a fixed point, because the interesting case is one level
deeper than "does anything mention this": `IssuedCertificate.verify` looked live only
because the unreachable `require_valid` called it — two functions telling each other they
were on duty.

It is now check **4b** in `tools/verify_all.ps1`, so it is re-run on every acceptance pass
and fails the pass if the class reappears.

Current result, on this revision:

```
check-like definitions under tls/: 86
  live from implementation or drivers : 65
  reached only through an interface   : 13
  called by a framework               : 8
  referenced only from tests/         : 0
  live only via getattr               : 0
  live only via an undeclared getattr : 0
  referenced only through a variable  : 0
  referenced nowhere                  : 0
  of those: sole-implementation variable calls : 12
PASS
```

The 13 interface entries are the signer and KEM methods reached through a variable
(`signer.verify(...)`), each declared with the mechanism that reaches it; the 8 framework
hooks are `__init__`/`__post_init__`, called by the constructor or by `@dataclass`. Both
lists are printed in every report and both are *declarations a reader can attack* — which is
the point of printing them rather than folding them into a pass count. The last line is the
sweep's own residual assumption, and §"V6-10a" below is about it.

**What the sweep found when it was first run**, and what happened to each:

| Finding | Disposition |
|---|---|
| `IssuedCertificate.require_valid` — a validating method nothing called, anywhere | **deleted**; the client verifies the CA signature and the scheme itself, so it was a second, unexercised copy of a live check |
| `IssuedCertificate.verify` — referenced only from a test | **deleted**; the test now calls `certificate.authority.verify(...)` directly, which asserts exactly the same thing |
| `HybridTLSConfig.__post_init__`, `XmssSecretKey.__post_init__` | false positives, exempted with the reason |

### Then an audit attacked this tool, and all three probes landed

Round 6 delivered an independent attack package. `case_I_sweep_a.py` planted three probes in
a copy of the tree and measured the verdicts (`audit/sweep_probe_evidence/`). The first
version of this tool misjudged **all three**:

| # | Misjudgement | Cause in the tool |
|---|---|---|
| V-20 | a check named only inside a **comment** was reported `live` | references were found by a regex over the whole file, and a comment is text |
| V-21 | a check really called through `getattr(obj, "name")` was reported **`DEAD`** | the scan looked for `name(`, which a `getattr` call does not contain |
| V-22 | a dead method called `verify` was **exempted** as an interface method | `INTERFACE_METHODS` was keyed on the **bare** method name, so any class's `verify` inherited the exemption |

V-22 is the serious one: an exemption that matches by name is exactly the hiding place the
sweep exists to remove, and it was reintroduced by the exemption table itself.

Two further holes surfaced while reproducing those three: the tool reported **PASS on an
empty tree** (nothing found, nothing to complain about), and it **crashed on a file with a
UTF-8 BOM** instead of parsing it. A third came from running the auditor's own harness: the
tool printed a non-ASCII dash, which the harness could not decode when it read the output as
UTF-8 — a command-line tool whose output is parsed by other programs should emit ASCII only.

All six are fixed, and the auditor's three are now tests in `tests/test_live_checks.py`,
written in their own terms:

* references come from **AST call sites**, so a comment cannot be a caller, by construction;
* a string literal in `getattr(obj, "name")` counts as a reference, is labelled `getattr-only`
  in the report, and is listed separately so a reader verifies it by hand;
* exemptions are keyed on `Class.method`; `__init__` and `__post_init__` are exempted only as
  framework hooks, and `__post_init__` only inside a class that carries `@dataclass`;
* a `self.check(...)` call is attributed to the class that defines the check, **through
  inheritance**, so a subclass calling a base-class check counts for the base;
* a call on a **variable** (`signer.verify(...)`) is attributed only when exactly one class in
  the tree defines that name. When several do, the name is ambiguous: the check must be
  declared in `INTERFACE_METHODS` (with the mechanism) or it is reported **`UNATTRIBUTED`**
  and fails the sweep. This is what closes V-22 completely — the auditor's probe tree still
  reproduced it after the first fix, because the real project calls `.verify(...)` on
  variables, which credited every method called `verify`, including the dead one;
* an empty or missing tree is a tool error (exit 2), not a pass; unparsable files are
  reported rather than skipped; the report is ASCII-only so that a harness reading it as
  UTF-8 cannot break on it.

**Result on the auditor's own probe tree** — their three probes, planted here as the fixtures in
`tests/test_live_checks.py`, judged by the current tool:

```
check-like definitions under tls/: 3
  live only via an undeclared getattr : 1
  referenced nowhere                  : 2
DEAD               tls/_probe_checks.py:2  verify_comment_only_check
DEAD               tls/_probe_checks.py:17 PlantedHolder.verify
getattr-undeclared tls/_probe_checks.py:8  verify_dynamic_dispatch  <- tls/client.py:3
-> exit=1
```

Note on their readings: `case_I_sweep_a.py` decides its three booleans by looking for the
probe **names** in the output, so all three fire whichever way the tool judges them. The
verdict labels above are the ones that carry the answer; the booleans cannot distinguish
"reported DEAD" from "mentioned in the report".

**What it still cannot see.** A name assembled at runtime (`getattr(obj, prefix + name)`) is
invisible, as is a check reached through an interface that `INTERFACE_METHODS` does not list —
both leave the check reported `DEAD`, which fails the sweep, so the tool errs towards crying
wolf rather than towards silence. And the sweep says nothing about whether a check that *is*
called checks the right thing — that is Sweep B and Sweep C.

### Then a second audit attacked it again

Round 7 delivered another attack package. It confirmed the three misjudgements above were
genuinely fixed — planting the same three probes again produced `DEAD`,
`getattr-undeclared` and `UNATTRIBUTED` — and then found two new ways to satisfy the sweep
without wiring anything up (their V6-10). Both are addressed.

#### V6-10a — the `sole_implementation` rule: a documented trade-off, now reported

A call on a variable (`holder.require_ready(...)`) cannot be attributed to a class by type
inference here, so the tool falls back on a name rule: if exactly one class in the tree
defines that name, the call is credited to it and the check counts as `live`. The auditor's
point is that this credits *any* call line with a matching name, including one that can never
execute — so a dead check plus a line like `_unrelated_receiver.validate_var_probe(True)`
passes. Their run of the previous tool printed exactly that:

```
getattr-only  tls/_probe_checks.py:8 verify_dynamic_dispatch  <- tls/client.py:3
validate_var_probe                           variable tls/handshake/client.py:192
```

**What changed:** none of the rule, and all of the reporting. The rule cannot be removed
without breaking the real tree — this repository *does* call `signer.verify(...)`,
`self.ephemeral.exchange(...)`, `record.open(...)` and friends on variables, and a tool that
reports those `DEAD` fails every run, which is the failure mode that gets a check deleted or
ignored. What was wrong was that the assumption was invisible in the output. The report now
prints, in every run and not only under `--verbose`:

* the count of checks that are live **only** through such a call (`of those:
  sole-implementation variable calls : 12`), and
* one `variable-sole` line per entry, naming the call site that carries the verdict, with the
  assumption in the line itself.

The call site shown is chosen by `verdict_reference`: the first *live* reference, because the
first reference in the list is often a `tests/` call site and printing that one suggested the
wrong mechanism. That was a real reporting defect found while writing this section, not by an
auditor.

`test_a_sole_implementation_called_on_a_variable_is_live` pins the new lines, and
`tests/test_audit_v6_fixes.py` header records the residual risk in the same terms: **a call
line that never executes can still lift a dead check to live.** The alternatives — a static
type check, or reporting the bucket as `UNVERIFIED` and failing — would trade a false `PASS`
for false `FAIL`s on the live interfaces, which is why this is recorded as an accepted limit
rather than fixed.

#### V6-10b — a `getattr` literal is not a call, and no longer forgives anything

`getattr(obj, "name")` really can reach a check, so it has to be visible to the sweep — but
the literal itself proves nothing: `getattr(object(), "name", None)` names the check without
ever calling it. The first version of this fix counted such a reference as `live` and listed
it under `getattr-only` for hand verification, and because a *report line* is not a verdict,
`--root` on a tree consisting of a dead check plus that unreachable `getattr` still exited 0.
The auditor's second probe did exactly that.

**What changed:** an **undeclared** `getattr`-only reference now fails the sweep.

```
getattr-undeclared tls/_probe_checks.py:4 verify_dynamic_dispatch  <- tls/client.py:190
```

A dispatcher that genuinely calls a check through a string literal has to be declared in
`GETATTR_DISPATCHED`, keyed by `Class.method` (or the module-level name) with the mechanism
that reaches it — the same shape as `INTERFACE_METHODS`, and the same idea: a human states the
mechanism, and the report prints it. The table is **empty** on this revision: nothing under
`tls/` is reached only through `getattr`, so the rule costs nothing today and prevents the
auditor's shape from returning.

The test that covered V-21 asserted the label *without* the exit code, which is exactly why
the hole survived; `test_a_getattr_dispatched_check_is_live_and_flagged` now asserts exit 1 and
the `getattr-undeclared` label, and `test_a_declared_getattr_check_passes` runs the tool
in-process with the declaration filled to show the declaring path exits 0.

### Then a red-team pass attacked it a third time: V8-01, T1 and T2

The eighth review found the shape the previous fix left behind: `DISPATCH_SITES` was validated
against the **AST** — module alias, exact line, immediate invocation — but not against
reachability. Planting the declared call inside `if typing.TYPE_CHECKING:` (T1) or inside a
function nobody calls (T2) satisfied every check and the sweep still exited 0. That cannot be
patched syntactically; the fix is a bounded *reachability* analysis, with the limits of that
analysis written down rather than implied.

What v9 computes, in the order the plan asked for:

1. **Lexical scope.** Every definition and call site carries its module and full scope; a nested
   function is keyed `Class.method.<locals>.helper`, never flattened into a method, and nothing is
   guessed from its name.
2. **A small constant evaluator.** `if False`/`if 0`, `while False`/`0`, the `else` of an
   always-true test, boolean composition of literals, and `typing.TYPE_CHECKING` through a
   resolved, **unshadowed** import alias (a local or parameter of that name is not the constant).
   The tree is never imported and `eval` is never called.
3. **A limited call graph.** Edges come from direct calls, calls on a known class (through its
   in-tree bases), calls through a module import, `Class(...)` constructors and `self` calls.
   Receiver types are inferred only from three narrow sources — a local assigned a constructor in
   every assignment, `self.<attr>` likewise within its class, or a constructor used directly as
   the receiver — and only to build edges; a reference keeps its syntactic `via`, so attribution
   and reachability stay separate answers. Roots are the seven drivers in `ENTRY_POINTS` (each
   must resolve to exactly one definition and state how it runs) plus the reviewed interface
   bindings. Module-level code counts only in a module a driver imports, is never a root just
   because it lives under `tls/`, and test modules are a separate class that can never make a
   check live.
4. **Verified declarations.** An interface declaration must resolve to one definition *and* have
   a variable-receiver reference from a live root; a dispatch declaration must match AST evidence
   **and** sit in reachable, non-dead code. Free text is not evidence.
5. **One rule per reference syntax.** A reference inside a provably dead branch contributes
   nothing, whether it was reached by `self`, by a class, by a module or by `getattr`.
6. **Unknown is not reachable.** The report separates *syntactically referenced*, *evidence in
   known dead code*, *entry relation unverified* and *linked through a supported entry chain*;
   exit 1 means unverified evidence, exit 2 means the tool could not judge the tree at all.

T1 and T2 were re-run against the result: both now exit 1, and the log names the target and the
reason (`is inside a statically dead branch in HybridClient.receive_server_hello` and
`sits in ...<locals>._never_called_helper, which no path from a declared entry reaches`).
Q1/Q2/S still exit 1, Q3 still exits 0, and the project itself passes:

```
check-like definitions under tls/: 87
  live from implementation or drivers : 54
  reached only through an interface   : 25
  called by a framework               : 8
  referenced only from unreachable code: 0
  referenced nowhere                  : 0
  declared entries / reachable functions: 7 / 223
PASS  (limited static analysis)
```

Two interface entries were added in this round, each with the mechanism named, because the
receiver is a runtime configuration choice: `tls/pq/signature.py::Xmss.keygen` (key generation
goes through `config.pq()`) and `tls/classical/ecdh.py::EcdheKeyPair.public_key_bytes` (the pair
is built by `EcdheKeyPair.generate(...)`). Both must still have a variable-receiver reference from
a live root, which the verifier checks on every run.

**What it still cannot see**, stated as the tool's own boundary: a name assembled at runtime
(`getattr(obj, prefix + name)`), a callback registered by string and invoked by a framework, a
receiver that would need real type inference, and anything decided by values rather than syntax.
A `PASS` therefore means "no syntactic evidence of an unreachable check under this bounded
analysis", not "this runs in production". `tests/test_live_checks.py` (26 tests) pins the rules;
two tests that encoded the older lenient contract were updated in this round (documented in their
docstrings), and the original auditor cases stay untouched in
`02-审查记录/06-v8审计/audit_v9/original/` as counterexample evidence.

## Sweep B — every derived value's inputs are named — **not written yet**

The inventory this needs, one row per derived value:

| Column | Example for `c ap traffic` |
|---|---|
| value | `KeySchedule.client_application_traffic` |
| fixed by | RFC 8446 §7.1, key schedule diagram |
| inputs the standard names | Master Secret; label `"c ap traffic"`; `Hash(ClientHello…server Finished)` |
| inputs the code passes | `master_secret`; the same label; the transcript hash at the call site |
| evidence that the inputs are the standard's and not the peer's | `tests/test_audit_v3_fixes.py::test_application_and_exporter_secrets_use_the_server_finished_transcript` — builds its own transcript from the exchanged frames |

Values to cover: `early_secret`, `derived_early`, `handshake_secret`, `c hs traffic`,
`s hs traffic`, `derived_hs`, `master_secret`, `c ap traffic`, `s ap traffic`, `exp master`,
`res master`, `finished_key`, the record-layer `key`/`iv` pairs, `M_CV`, `Z_hybrid`, and the
CertificateVerify context strings.

The test column is the point: where the only evidence is "both halves agree", the row is
**not** established, and that is what Sweep B exists to show. The auditor's own remark after
round 3 is the criterion — "独立测试 exporter 公式，并不能验证真实握手提供给它的 master
secret 正确".

## Sweep C — every constraint's scope — **not written yet**

One row per certificate field or extension the validator touches:

| Column | Example for `keyUsage` |
|---|---|
| constraint | RFC 5280 §4.2.1.3 key usage |
| which object it binds | the certificate that carries it |
| who the structural neighbours are | the leaf, each intermediate, the root/anchor |
| enforced for | leaf (`digital_signature`), issuers (`keyCertSign`) — since round 3 |
| not enforced for | — |
| test | `test_leaf_whose_key_usage_forbids_digital_signatures_is_rejected`, `test_intermediate_whose_key_usage_forbids_signing_certificates_is_rejected` |

Rows to cover: `basicConstraints` (CA flag, `pathLenConstraint`), `keyUsage` (leaf and
issuer), `extendedKeyUsage` (leaf and issuer), `subjectAltName`, the validity window, the
trust anchor comparison, `nameConstraints` (**refused, not enforced** — fail-closed, and
recorded as a gap), unknown critical extensions, the private-use PQ-key extension, and
revocation (**absent entirely**).

## Why this is a stopping rule rather than a proof

None of these tables can show that the implementation is right. What they can show is that
the *class* of defect three reviews kept finding has been enumerated rather than
rediscovered: a reviewer reads the tables, checks that each row's evidence column points at
something outside this implementation, and looks for the row that is missing. Sweep A is
mechanical and enforced; B and C are owed. Until they exist, the honest statement is the one
in `docs/SECURITY.md`: this code has been read by three external reviewers, each found
something of the same shape, and the shape has not yet been closed by construction.
