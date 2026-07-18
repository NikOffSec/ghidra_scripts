# RetCmpCheck

This script was made to detect improper error handling vulnerabilities. It searches through Ghidra's detected functions
and finds if the caller commonly checks the return value against a constant. This signals that there is some sort of error handling
with the return value, so the script checks to see if that check is not present for any of the call sites to search for bugs. Implementation
and customization info can be found below.


# Customization


Here is a description of the global variables 


```python
DECOMP_TIMEOUT: How long to wait on decompilation before considering it a failure and moving on

MIN_SITES: Minimum call sites with constant checks to consider it a viable target

MIN_CHECK_PCT: Minimum percentage of calls sites that ARE constant checks (to determine that it is the standard pattern)

MAX_DEPTH: Maximum length of high Pcode descendants followed in search of constant comparison

COMMENT_TAG: What to preface the comment inserts at call sites with

BOOKMARK_CAT: What category to show the bookmarks as

SHOW_DISTRIBUTION: Show debug information about call site classifications (useful for tuning settings on stripped binaries)
```

# Testing


The test file is available to test any changes that you make, and a compiled ELF is already available. It tests 4 libc functions, and 3 contain bugs that the script should find.

Output from the script when ran on the test file should look like this:

<img width="807" height="159" alt="image" src="https://github.com/user-attachments/assets/1f0efc04-99b0-47ff-ab9b-cac386e4352a" />



# Implementation


```python
Check    = {"kind": str, "op": PcodeOpAST, "opcode": str,
            "value": int, "raw": int, "size": int, "derived": bool}

Slice    = {"checks": list[Check], "deref": bool,
            "passed": bool, "any_use": bool}

Verdict  = Slice + {"kind": str, "addr": Address, "caller": Function}

Finding  = {"callee": Function, "addr": Address, "caller": Function,
            "kind": str, "consts": list[int],
            "n_checked": int, "n_total": int}
```


**Functions:**
```python
constant_operand(op: PcodeOpAST) -> VarnodeAST, VarnodeAST or None
    # Finds whether one of the two inputs to the Pcode operator is constant and
    # returns them in order: constant, other

constant_value(vn: VarnodeAST, signed: bool) -> int
    # Masks the varnode's raw offset to its own bit width and sign-extends it
    # when signed is set

find_check(vn: VarnodeAST, seen: set or None, depth: int, derived: bool) -> dict
    # Walks the SSA def-use graph forward from a varnode, recording every
    # comparison it reaches and whether it is dereferenced or passed onward.
    # Recurses through relaying ops such as COPY, CAST and PTRSUB; seen guards
    # the cycles that MULTIEQUAL phi nodes create in loops.
    # Returns keys: checks, deref, passed, any_use

classify_call(caller: Function, call_addr: Address) -> dict
    # Decompiles the caller to a HighFunction, finds the CALL op at the address,
    # and slices forward from its output varnode, which is the return value, to
    # judge whether it is checked.
    # Returns a verdict dict whose kind is one of: checked, unused,
    # deref_untested, used_untested, void, no_call_op, undecompilable

note_for(f: dict) -> str
    # Formats one finding into the tagged annotation line shared by the bookmark
    # and both comment branches

print_distribution(results: dict) -> None
    # Prints each callee's raw verdict-kind counts to the Ghidra console before
    # any threshold filtering, so MIN_SITES and MIN_CHECK_PCT can be tuned
    # against a real target
```
