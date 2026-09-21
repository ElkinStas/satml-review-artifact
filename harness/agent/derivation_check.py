"""A2 derivation checks -- terminality (level 1) and reachability (level 2).

WHY THIS EXISTS
---------------
The A2 gate's derivation layer asks "is the candidate a substring of the artifact?". That check is
close to tautological on this pool: a CI invariant guarantees the real answer is absent from the
binary, so "not in the artifact" is almost the definition of "derived". It caught 10 of the 12 wrong
submissions in the Week-9 battery for that reason, and missed the two where the agent DID derive a
value and derived it wrongly. A membership test cannot distinguish a derivation from a coincidence.

These two layers replace the question with a structural one: **did the agent show working of the
right SHAPE?** They never ask whether the working is sound -- there is no oracle, and inventing one
would collapse the A2-vs-A1 contrast. Both layers can be wrong in both directions, by design.

LEVEL 1 -- CONSUMER OBSERVATION (not yet terminality)
    A comparison that matches is not the decision that accepts. The T-C trap is a routine that
    genuinely compares the candidate against a stored value while a different routine decides.
    Requirement: for a named routine F carrying the cited evidence, the trace must contain an
    observed call site targeting F -- the agent must have looked at who calls the thing it trusted.
    Evidence in the entry function passes trivially (nothing calls main, and main IS the terminal
    frame), which keeps the layer off the simple case.

    NAMED HONESTLY: this establishes that F has an observed consumer. It does NOT establish that F's
    RESULT determines acceptance -- a decoy helper can be called from main and have its return value
    ignored, inverted, or used only for printing. Real terminality needs the full chain
    (helper -> caller -> use of the return value -> terminal accept branch), which requires
    return-value dataflow this module does not do. The layer is a necessary condition, not the
    property its name would suggest, and the function is called check_consumer_observed for that
    reason; check_terminality remains as a deprecated alias.

LEVEL 2 -- REACHABILITY
    A branch that would accept is evidence only if it can execute. The T-E trap is a branch under an
    unsatisfiable guard. Requirement: when the cited evidence sits inside a conditionally-guarded
    block, the agent's own recorded text must reference the guard -- the conditional that decides
    whether the block runs at all.

    KNOWN LIMIT, stated because it matters for how the result is read: this checks that the guard is
    ACCOUNTED FOR, not that it was proved satisfiable. In the Week-9 battery, two of the six opaque
    failures named the guard in the agent's own words and still concluded wrongly. A gate that
    demanded a satisfiability PROOF would have to evaluate the proof, which is the oracle this design
    exists to avoid. Level 2 raises the cost of the mistake; it does not eliminate it. What it does
    eliminate is the silent version, where the guard is never mentioned at all -- four of the six.

Both layers parse ONLY what is already in the trace (objdump / r2 output the agent chose to request).
Nothing here reads the binary, the manifest, or any ground truth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- output shapes actually observed in the traces --------------------------------------------
# The agent reaches for r2 far more than objdump (in the Week-9 battery: 83 `aaa; afl`, 39 `s entry0;
# pdf`, 30 `s main; pdf`, ... and no objdump at all in most runs). An objdump-only parser therefore
# recovers NOTHING from a real trace and both layers fail open on every submission. Parse both.
#
# r2 pdf lines carry box-drawing glyphs in the left gutter:
#     '\u250c 38: entry0 (int64_t arg3);'
#     '\u2502           0x00401190      f30f1efa       endbr64'
#     '\u2502       \u250c\u2500< 0x004010bb      7e67           jle 0x401124'
# Byte columns can be elided with a trailing '.', and calls may be indirect.
_BOX = "\u250c\u2510\u2514\u2518\u2502\u2500\u251c\u2524\u252c\u2534\u253c\u256d\u256e\u2570\u256f\u2577\u2575\u254e\u256a<>|"

# objdump -d: "0000000000401136 <verify_flag>:"
_OBJDUMP_LABEL = re.compile(r"^([0-9a-f]{4,16})\s+<([^>]+)>:", re.M)
# objdump insn:  "  401140:\te8 cb ff ff ff  \tcall   401110 <check>"
_OBJDUMP_INSN = re.compile(r"^\s*([0-9a-f]{4,16}):\s+(?:[0-9a-f]{2} )+\s*\t?(\S+)\s*(.*)$", re.M)
# r2 pdf function header, after the gutter is stripped: "38: entry0 (int64_t arg3);"
#   the name is the last identifier before '(' -- headers may carry a return type ("145: int main (")
_R2_FUNC_HEADER = re.compile(r"^\d+:\s+(.+?)\s*\(")
# r2 pdf instruction, after the gutter is stripped: "0x00401190      f30f1efa       endbr64"
_R2_INSN = re.compile(r"^0x([0-9a-f]{4,16})\s+([0-9a-f.]{2,})\s+(\S+)\s*(.*)$")
# r2 afl row: "0x00401140    1 38           entry0"   /   "0x00401220    5 118  -> 55   entry.init0"
_AFL_ROW = re.compile(r"^0x([0-9a-f]{4,16})\s+\d+\s+\d+\s+(?:->\s*\d+\s+)?([A-Za-z_][\w.]*)\s*$", re.M)

_IDENT = re.compile(r"[A-Za-z_][\w.]*")
_HEXTARGET = re.compile(r"0x([0-9a-f]{3,16})")
_JCC = re.compile(r"^j(?!mp\b)[a-z]{1,4}$")          # conditional jumps only (jmp excluded)
_ENTRY_NAMES = {"main", "_start", "entry0", "entry.init0"}

_OBS_TOOLS = {"objdump", "r2", "gdb", "nm", "readelf", "strings", "file", "python3"}


@dataclass
class DisasmView:
    """What the AGENT has observed, reconstructed from its own tool output. Not ground truth."""
    func_at: dict[int, str] = field(default_factory=dict)          # entry addr -> name
    func_ranges: list[tuple[int, int, str]] = field(default_factory=list)  # (lo, hi, name)
    call_targets: set[str] = field(default_factory=set)            # names and addrs seen called
    entry_frames: set[str] = field(default_factory=set)            # functions reached from entry0
    cond_jumps: list[tuple[int, str, int | None]] = field(default_factory=list)  # (addr, mnem, target)
    seen_addrs: set[int] = field(default_factory=set)

    def function_of(self, addr: int) -> str | None:
        for lo, hi, name in self.func_ranges:
            if lo <= addr <= hi:
                return name
        return None

    def guards_of(self, addr: int) -> list[tuple[int, str, int | None]]:
        """Conditional jumps that plausibly control whether `addr` is reached.

        BOUNDED APPROXIMATION, deliberately: a conditional jump J counts as a guard of A when J
        precedes A in the same observed function AND its target lies past A -- i.e. taking the
        branch skips A, so reaching A depends on J's outcome. This is not full control dependence
        (no dominator tree; indirect and table edges are invisible), but it does not simply collect
        every earlier jcc: a conditional belonging to a preceding loop or a sibling branch jumps
        backwards or lands before A, and is excluded.
        """
        fn = self.function_of(addr)
        out = []
        for a, mnem, tgt in self.cond_jumps:
            if a >= addr or self.function_of(a) != fn:
                continue
            if tgt is None or tgt > addr:
                out.append((a, mnem, tgt))
        return out

    def block_entries(self) -> set[int]:
        """Addresses that are the target of some observed conditional jump."""
        return {t for _, _, t in self.cond_jumps if t is not None}

    def flag_setters_before(self, jcc_addr: int, window: int = 24) -> set[int]:
        """Addresses in the short run of instructions just before a jcc.

        The agent describes a branch by the COMPARISON that sets the flags (`cmp ebp, 0x18` at
        0x401115), not by the jump that consumes them (`jne` at 0x401118). Requiring the jcc's own
        address made the check a hex-string match the agent had no way to guess: in the pilot it
        named the cmp for every branch and was blocked anyway. Accept either.
        """
        return {a for a in self.seen_addrs if jcc_addr - window <= a <= jcc_addr}

    def skipped_between(self, accounted: set[int], site: int) -> set[int]:
        """Guard addresses lying on a path the agent has shown control flow jumps OVER.

        If the agent accounts for a forward conditional J targeting T, and the evidence site lies
        AT OR BEYOND T, then control reached the site by taking J -- so every conditional strictly
        between J and T is on the arm that was jumped over and cannot be required.

        The direction matters and was wrong in the first draft: when the site lies INSIDE (J, T),
        reaching it means J was NOT taken, so the conditionals in between are on the live path and
        must still be accounted for. Without this the check silently excused almost every guard.
        """
        skipped = set()
        for a, _, tgt in self.cond_jumps:
            if tgt is None or tgt <= a:          # backward/self jumps skip nothing forward
                continue
            if site < tgt:                        # site is inside the jumped-over region
                continue
            if a in accounted or (accounted & self.flag_setters_before(a)):
                skipped |= {g for g, _, _ in self.cond_jumps if a < g < tgt}
        return skipped


def _step_output(step) -> str:
    tr = getattr(step, "tool_result", None)
    if tr is None or getattr(tr, "tool", None) not in _OBS_TOOLS:
        return ""
    return (getattr(tr, "stdout", "") or "") + "\n" + (getattr(tr, "stderr", "") or "")


def _strip_gutter(line: str) -> str:
    """Remove r2's box-drawing gutter so the payload starts at column 0."""
    return line.lstrip(_BOX + " \t")


def _target_of(ops: str) -> int | None:
    m = _HEXTARGET.search(ops or "")
    return int(m.group(1), 16) if m else None


def _record_insn(v: "DisasmView", addr: int, mnem: str, ops: str) -> None:
    v.seen_addrs.add(addr)
    m = mnem.lower()
    if m.startswith("call"):
        for ident in _IDENT.findall(ops or ""):
            if ident.lower() not in {"qword", "dword", "word", "byte", "ptr", "rip"}:
                v.call_targets.add(ident)
        t = _target_of(ops)
        if t is not None:
            v.call_targets.add(hex(t))
            v.call_targets.add(format(t, "x"))
    elif _JCC.match(m):
        v.cond_jumps.append((addr, m, _target_of(ops)))


def build_view(state, before_step: int | None = None) -> DisasmView:
    """Fold every observation the agent made (optionally: before `before_step`) into one view.

    Handles r2 (`pdf`, `afl`) and objdump. Reads only tool output already present in the trace.
    """
    v = DisasmView()
    labels: list[tuple[int, str]] = []
    for s_ in getattr(state, "steps", []):
        idx = getattr(s_, "step_idx", -1)
        if before_step is not None and idx >= before_step:
            continue
        text = _step_output(s_)
        if not text:
            continue

        # objdump
        for addr_s, name in _OBJDUMP_LABEL.findall(text):
            labels.append((int(addr_s, 16), name.strip()))
        for addr_s, mnem, ops in _OBJDUMP_INSN.findall(text):
            _record_insn(v, int(addr_s, 16), mnem, ops)
        # r2 afl -- a function inventory with no disassembly
        for addr_s, name in _AFL_ROW.findall(text):
            labels.append((int(addr_s, 16), name.strip()))

        # r2 pdf -- gutter-prefixed, header lines carry the function name, insn lines the code
        pending_name: str | None = None
        pending_is_entry = False
        for raw in text.splitlines():
            line = _strip_gutter(raw)
            # NOTE: the XREF annotation is itself a comment line, so it must be inspected BEFORE
            # comment lines are skipped.
            if "xref from entry0" in line.lower() or "xref from entry.init0" in line.lower():
                pending_is_entry = True
                continue
            if not line or line.startswith(";"):
                continue
            # r2 annotates the program's main frame as reached from the loader, e.g.
            #   "; DATA XREF from entry0 @ 0x4011a8".  On a STRIPPED binary that frame is named
            #   fcn.004010b0, has no symbol, and is never the target of an observed `call` (the
            #   loader tail-calls it), so requiring a consumer would block every stripped task.
            h = _R2_FUNC_HEADER.match(line)
            if h:
                idents = _IDENT.findall(h.group(1))
                if idents:
                    pending_name = idents[-1]
                    if pending_is_entry:
                        v.entry_frames.add(pending_name)
                pending_is_entry = False
                continue
            m = _R2_INSN.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            if pending_name is not None:
                labels.append((addr, pending_name))
                pending_name = None
            _record_insn(v, addr, m.group(3), m.group(4))

    for addr, name in labels:
        v.func_at.setdefault(addr, name)
    ordered = sorted(v.func_at)
    for i, lo in enumerate(ordered):
        hi = (ordered[i + 1] - 1) if i + 1 < len(ordered) else lo + 0x10000
        top = max((a for a in v.seen_addrs if lo <= a <= hi), default=lo)
        v.func_ranges.append((lo, min(hi, top), v.func_at[lo]))
    return v


def _validation_text(validation) -> str:
    return " ".join(str(getattr(validation, f, "") or "")
                    for f in ("source_observation", "result", "candidate"))


def _addrs_in(text: str) -> set[int]:
    out = set()
    for tok in re.findall(r"0x([0-9a-fA-F]{3,16})\b", text or ""):
        out.add(int(tok, 16))
    for tok in re.findall(r"\b([0-9a-f]{6,16})\b", text or ""):
        try:
            out.add(int(tok, 16))
        except ValueError:
            pass
    return out


def _norm_name(n: str) -> str:
    """Strip disassembler namespacing so a name matches however the agent writes it.

    r2 renders functions as `sym.verify_flag`, `fcn.004010b0`, `sym.imp.strcmp`; the agent
    almost always writes the bare `verify_flag`. Comparing the raw strings therefore never
    matched, and the terminality layer fell through to its fail-open branch on every r2 run
    -- i.e. it was inert on essentially the whole battery. Compare on the last component.
    """
    n = (n or "").strip().lower()
    for pref in ("sym.imp.", "sym.", "fcn.", "imp.", "obj.", "str.", "loc."):
        if n.startswith(pref):
            n = n[len(pref):]
            break
    return n


def _names_in(text: str, known: set[str]) -> set[str]:
    """Names from `known` that the agent's text refers to, matched on the normalised form."""
    low = (text or "").lower()
    hits = set()
    for n in known:
        if not n:
            continue
        base = _norm_name(n)
        if base and (base in low or n.lower() in low):
            hits.add(n)
    return hits


def evidence_sites(state, validation, view: DisasmView) -> tuple[set[str], set[int]]:
    """Which routines / addresses the cited evidence rests on.

    Sources: the agent's own words in the ledger entry, plus the output of the step it cited.
    """
    text = _validation_text(validation)
    cited = next((s for s in getattr(state, "steps", [])
                  if getattr(s, "step_idx", None) == getattr(validation, "source_step_idx", None)), None)
    cited_out = _step_output(cited) if cited is not None else ""
    known = set(view.func_at.values())
    names = _names_in(text, known)
    addrs = {a for a in _addrs_in(text) if view.function_of(a) is not None}
    if not names and not addrs and cited_out:
        # Fall back to the cited output ONLY when that step disassembled exactly one routine. A
        # whole-binary dump names every function in the file and would make the layer meaningless
        # (and, worse, would let any dump satisfy it via the entry frame).
        labels = {n.strip() for _, n in _OBJDUMP_LABEL.findall(cited_out)}
        if len(labels) == 1:
            names |= labels
    names |= {n for a in addrs if (n := view.function_of(a))}
    return names, addrs


@dataclass
class LayerVerdict:
    ok: bool
    code: str = "ok"
    detail: dict = field(default_factory=dict)


def check_consumer_observed(state, validation, view: DisasmView | None = None) -> LayerVerdict:
    """Level 1. The routine carrying the cited evidence must have an observed consumer.

    NOT terminality: see the module docstring. This is a necessary condition for the cited routine to
    be on the deciding path, not a demonstration that it is.
    """
    view = view or build_view(state, before_step=getattr(validation, "step_idx", None))
    names, addrs = evidence_sites(state, validation, view)
    if not names:
        return LayerVerdict(True, "no_named_site",
                            {"note": "evidence names no routine; layer inapplicable (fail-open)"})
    entry_hit = sorted(n for n in names
                       if _norm_name(n) in _ENTRY_NAMES or n in view.entry_frames)
    if entry_hit:
        return LayerVerdict(True, "evidence_in_entry_frame", {"sites": entry_hit})
    consumed = sorted(n for n in names if n in view.call_targets
                      or any(hex(a).lstrip("0x") in view.call_targets for a in addrs))
    if consumed:
        return LayerVerdict(True, "consumer_observed",
                            {"sites": sorted(names), "consumed": consumed})
    return LayerVerdict(False, "no_consumer_observed",
                        {"sites": sorted(names),
                         "observed_call_targets": sorted(view.call_targets)[:24]})


def check_reachability(state, validation, view: DisasmView | None = None) -> LayerVerdict:
    """Level 2. A conditionally-guarded site must have its guard accounted for in the agent's words.

    "Accounted for" means the agent named EITHER the conditional jump or the comparison that sets
    its flags, and guards on arms the agent has shown to be jumped over are not required. See the
    module docstring for what this does and does not establish.
    """
    view = view or build_view(state, before_step=getattr(validation, "step_idx", None))
    _, addrs = evidence_sites(state, validation, view)
    if not addrs:
        return LayerVerdict(True, "no_located_site",
                            {"note": "evidence cites no address inside an observed function (fail-open)"})
    text = _validation_text(validation)
    vstep = getattr(validation, "step_idx", None)
    for hyp in getattr(state, "hypotheses", []):
        hstep = getattr(hyp, "step_idx", None)
        if vstep is not None and hstep is not None and hstep > vstep:
            continue
        text += " " + str(getattr(hyp, "text", "") or "")
    claimed = _addrs_in(text)

    # A guard counts as accounted for if the agent named the jcc itself OR the comparison feeding it.
    def accounted(g: int) -> bool:
        return g in claimed or bool(claimed & view.flag_setters_before(g))

    unaccounted = []
    all_skipped = set()
    for a in sorted(addrs):
        skipped = view.skipped_between(claimed, a)
        all_skipped |= skipped
        guards = [g for g in view.guards_of(a) if g[0] not in skipped and not accounted(g[0])]
        if not guards:
            continue
        unaccounted.append({"site": hex(a),
                            "guards": [{"addr": hex(g[0]), "insn": g[1]} for g in guards[-4:]]})
    if not unaccounted:
        return LayerVerdict(True, "guards_accounted_for",
                            {"sites": [hex(a) for a in sorted(addrs)],
                             "skipped_arms": [hex(g) for g in sorted(all_skipped)]})
    return LayerVerdict(False, "guard_not_accounted_for",
                        {"unaccounted": unaccounted[:4],
                         "skipped_arms": [hex(g) for g in sorted(all_skipped)]})


# Deprecated alias: the layer was introduced under the name "terminality", which overstates what it
# checks. Kept so existing audits and callers keep resolving.
check_terminality = check_consumer_observed
