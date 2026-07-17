# This script checks call sites and finds those that
# check return values against constant values,
# and then attempts to find other sites for the same
# function where those values are not
# checked in order to find improper error handling.
#
# @author NikOffSec
# @category Analysis.BugHunting
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra

import typing

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

calls_by_callee = {}

DECOMP_TIMEOUT = 30
MIN_SITES = 4
MIN_CHECK_PCT = 0.75
MAX_DEPTH = 12
COMMENT_TAG = "[UNCHECKED-RET]"
BOOKMARK_CAT = "UncheckedReturn"

SHOW_DISTRIBUTION = False
ADD_BOOKMARKS = True
ADD_COMMENTS = True


monitor.setMessage("Collecting call sites")
monitor.initialize(fm.getFunctionCount())

for func in fm.getFunctions(True):
    monitor.initialize(fm.getFunctionCount())
    monitor.checkCancelled()
    monitor.incrementProgress(1)

    entry = func.getEntryPoint()
    sites = [
        ref.getFromAddress()
        for ref in ref_mgr.getReferencesTo(entry)
        if ref.getReferenceType().isCall()
    ]

    if sites:
        key = func.getThunkedFunction(True) if func.isThunk() else func
        calls_by_callee.setdefault(key, []).extend(sites)

COMPARE_OPS = {
    PcodeOp.INT_EQUAL,
    PcodeOp.INT_NOTEQUAL,
    PcodeOp.INT_LESS,
    PcodeOp.INT_SLESS,
    PcodeOp.INT_LESSEQUAL,
    PcodeOp.INT_SLESSEQUAL,
    PcodeOp.FLOAT_EQUAL,
    PcodeOp.FLOAT_NOTEQUAL,
    PcodeOp.FLOAT_LESS,
    PcodeOp.FLOAT_LESSEQUAL,
}

TRANSPARENT = {
    PcodeOp.COPY,
    PcodeOp.CAST,
    PcodeOp.MULTIEQUAL,
    PcodeOp.INT_ZEXT,
    PcodeOp.INT_SEXT,
    PcodeOp.SUBPIECE,
    PcodeOp.BOOL_NEGATE,
    PcodeOp.BOOL_AND,
    PcodeOp.BOOL_OR,
    PcodeOp.BOOL_XOR,
    PcodeOp.INDIRECT,
    PcodeOp.PIECE,
    PcodeOp.PTRSUB,
    PcodeOp.PTRADD,
}

DERIVING = {
    PcodeOp.INT_AND,
    PcodeOp.INT_OR,
    PcodeOp.INT_XOR,
    PcodeOp.INT_ADD,
    PcodeOp.INT_SUB,
    PcodeOp.INT_NEGATE,
    PcodeOp.INT_2COMP,
}

DEREF_OPS = {PcodeOp.LOAD, PcodeOp.STORE}
PASS_ON_OPS = {PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER, PcodeOp.RETURN}

SIGNED_OPS = {PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL}
UNSIGNED_OPS = {PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL}


decomp = DecompInterface()
if not decomp.openProgram(currentProgram):
    raise Exception("decompiler failed to open program")


def constant_operand(op):
    a, b = op.getInput(0), op.getInput(1)
    if a.isConstant() and not b.isConstant():
        return a, b
    if b.isConstant() and not a.isConstant():
        return b, a
    return None


def constant_value(vn, signed=True):
    raw = vn.getOffset() & 0xFFFFFFFFFFFFFFFF  # normalize Java signed long
    bits = vn.getSize() * 8
    if bits >= 64:  # Shorten data to varnode length
        raw &= (1 << 64) - 1
    else:
        raw &= (1 << bits) - 1
    if (
        signed and bits and (raw >> (bits - 1)) & 1
    ):  # Check sign bit and flip to negative (if true)
        return raw - (1 << bits)
    return raw


def find_check(vn, seen=None, depth=0, derived=False):
    if seen is None:
        seen = set()

    out_info = {"checks": [], "deref": False, "passed": False, "any_use": False}

    if depth > MAX_DEPTH:
        return out_info

    for use in vn.getDescendants():
        op = use.getOpcode()
        out_info["any_use"] = True

        if op in COMPARE_OPS:
            pair = constant_operand(use)
            if pair is None:
                out_info["checks"].append(
                    {"kind": "compared_to_variable", "op": use, "derived": derived}
                )
                continue
            const_vn, _ = pair
            signed = op in SIGNED_OPS
            out_info["checks"].append(
                {
                    "kind": "compared_to_const",
                    "op": use,
                    "opcode": PcodeOp.getMnemonic(op),
                    "value": constant_value(const_vn, signed=signed),
                    "raw": constant_value(const_vn, signed=False),
                    "size": const_vn.getSize(),
                    "derived": derived,
                }
            )
            continue

        if op == PcodeOp.CBRANCH:
            out_info["checks"].append(
                {
                    "kind": "implicit_zero_test",
                    "op": use,
                    "value": 0,
                    "derived": derived,
                }
            )
            continue

        if op in DEREF_OPS:
            out_info["deref"] = True
            continue

        if op in PASS_ON_OPS:
            out_info["passed"] = True
            continue

        if op in TRANSPARENT or op in DERIVING:
            out = use.getOutput()
            if out is not None and out.getUniqueId() not in seen:
                seen.add(out.getUniqueId())
                sub = find_check(out, seen, depth + 1, derived or op in DERIVING)
                out_info["checks"].extend(sub["checks"])
                out_info["deref"] = out_info["deref"] or sub["deref"]
                out_info["passed"] = out_info["passed"] or sub["passed"]

    return out_info


_hf_cache = {}  # store decompiles for optimization


def classify_call(caller, call_addr):
    key = caller.getEntryPoint()
    if key not in _hf_cache:
        res = decomp.decompileFunction(caller, DECOMP_TIMEOUT, monitor)
        _hf_cache[key] = res.getHighFunction() if res is not None else None
    hf = _hf_cache[key]
    if hf is None:
        return {"kind": "undecompilable", "checks": []}

    call_op = next(
        (
            op
            for op in hf.getPcodeOps(call_addr)
            if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND)
        ),
        None,
    )
    if call_op is None:
        return {"kind": "no_call_op", "checks": []}

    ret = call_op.getOutput()
    if ret is None:
        return {"kind": "void", "checks": []}

    info = find_check(ret)
    if info["checks"]:
        kind = "checked"
    elif not info["any_use"]:
        kind = "unused"
    elif info["deref"]:
        kind = "deref_untested"
    else:
        kind = "used_untested"

    info["kind"] = kind
    return info


# pass 1 (classify every callsite)


results = {}

total_sites = sum(len(addrs) for addrs in calls_by_callee.values())
monitor.setMessage("Classifying call sites")
monitor.initialize(total_sites)

try:
    for callee, addrs in calls_by_callee.items():
        for addr in addrs:
            monitor.checkCancelled()
            monitor.incrementProgress(1)

            caller = fm.getFunctionContaining(addr)
            if caller is None or caller.isThunk():
                continue

            v = classify_call(caller, addr)
            v["addr"] = addr
            v["caller"] = caller
            results.setdefault(callee, []).append(v)
finally:
    decomp.dispose()

if SHOW_DISTRIBUTION:
    println("")
    println("%-24s %5s  %s" % ("callee", "total", "kinds"))
    println("-" * 72)
    for callee, verdicts in sorted(results.items(), key=lambda kv: -len(kv[1])):
        if len(verdicts) < 2:
            continue
        counts = {}
        for v in verdicts:
            counts[v["kind"]] = counts.get(v["kind"], 0) + 1
        kinds = ", ".join("%s=%d" % (k, n) for k, n in sorted(counts.items()))
        println("%-24s %5d  %s" % (callee.getName(), len(verdicts), kinds))
    println("-" * 72)
    println("")

# pass 2 (analyze verdicts)

findings = []

for callee, verdicts in results.items():
    judgeable = [
        v
        for v in verdicts
        if v["kind"] in ("checked", "unused", "deref_untested", "used_untested")
    ]
    total = len(judgeable)
    if total < MIN_SITES:
        continue

    checked = [v for v in judgeable if v["kind"] == "checked"]
    suspect = [
        v
        for v in judgeable
        if v["kind"] in ("unused", "deref_untested", "used_untested")
    ]

    if not checked or not suspect:
        continue
    if len(checked) / total < MIN_CHECK_PCT:
        continue

    consts = set()
    for v in checked:
        for c in v["checks"]:
            if "value" in c:
                consts.add(c["value"])

    for v in suspect:
        findings.append(
            {
                "callee": callee,
                "addr": v["addr"],
                "caller": v["caller"],
                "kind": v["kind"],
                "consts": sorted(consts),
                "n_checked": len(checked),
                "n_total": total,
            }
        )

rank = {"deref_untested": 0, "unused": 1, "used_untested": 2}
findings.sort(key=lambda f: (rank.get(f["kind"], 9), str(f["addr"])))

# report findings


def note_for(f):
    kind = f["kind"].replace("_", " ")
    return (
        f"{COMMENT_TAG} {f['callee'].getName()} return {kind} "
        f"({f['n_checked']}/{f['n_total']} sites check, vs {f['consts']})"
    )


# remove current script generated bookmarks to avoid duplicates
if ADD_BOOKMARKS:
    currentProgram.getBookmarkManager().removeBookmarks("Note", BOOKMARK_CAT, monitor)

println("=" * 72)
println(f"Unchecked return values: {len(findings)} finding(s)")
println("=" * 72)

for f in findings:
    println(
        f"{f['addr']}  {f['callee'].getName():<18} in "
        f"{f['caller'].getName():<28}  {f['kind']}  "
        f"[{f['n_checked']}/{f['n_total']} check vs {f['consts']}]"
    )

    if ADD_BOOKMARKS:
        createBookmark(f["addr"], BOOKMARK_CAT, note_for(f))

    if ADD_COMMENTS:
        old = getPreComment(f["addr"])
        if old is None:
            setPreComment(f["addr"], note_for(f))
        elif COMMENT_TAG not in old:
            setPreComment(f["addr"], old + "\n" + note_for(f))
println("=" * 72)
