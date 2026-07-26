import re

# FUN_180017d40 
FUN_RE = re.compile(r"\bFUN_([0-9a-fA-F]{5,})\b")
# Data addresses
DATA_REF_RE = re.compile(r"\b(?:PTR_)?(?:DAT|LAB)_([0-9a-fA-F]{5,})\b")
# string-symbol 
STR_SYM_RE = re.compile(r"\bs_[A-Za-z0-9_]*?_([0-9a-fA-F]{6,})\b")
# any identifier immediately followed by '(' -> a call site.
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# constants 
MAGIC_RE = re.compile(r"\b0x([0-9a-fA-F]{8})\b")

_NON_CALLS = {
    "if", "while", "for", "switch", "return", "sizeof", "do", "else", "case",
    "goto", "default", "void", "int", "char", "long", "short", "float",
    "double", "unsigned", "signed", "struct", "union", "enum", "const",
    "byte", "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "uint", "ulong", "ushort", "code", "bool",
}


def _addr(hexstr):
    return "0x" + hexstr.lower()


def extract(decomp, self_name=None):

    callee_addrs = {_addr(h) for h in FUN_RE.findall(decomp)}
  
    if self_name and self_name.startswith("FUN_"):
        callee_addrs.discard("0x" + self_name[4:].lower())
    callee_addrs = sorted(callee_addrs)

    data_addrs = {_addr(h) for h in DATA_REF_RE.findall(decomp)}
    data_addrs |= {_addr(h) for h in STR_SYM_RE.findall(decomp)}

    names = {n for n in CALL_RE.findall(decomp) if n not in _NON_CALLS}
    names.discard(self_name)
    named_calls = sorted(n for n in names if not n.startswith("FUN_"))

    constants = sorted({"0x" + h.lower() for h in MAGIC_RE.findall(decomp)})

    return {
        "callee_addrs": callee_addrs,
        "data_addrs": sorted(data_addrs),
        "named_calls": named_calls,
        "constants": constants,
        "sets_vtable": "vftable" in decomp,
    }


def build_bundle(address, orig_name, decomp, *, get_summary, callers, imports_set=None, max_callees=40):
    raw = extract(decomp, self_name=orig_name)
    imports_set = imports_set or set()

    # split call targets into imported APIs vs already-named internal functions
    apis = sorted({n for n in raw["named_calls"] if n in imports_set})
    known_named = [n for n in raw["named_calls"] if n not in imports_set]

    known_callees, unknown_callees = [], []
    for ca in raw["callee_addrs"][:max_callees]:
        rec = get_summary(ca)
        if rec and rec.get("summary"):
            known_callees.append((rec.get("name") or ca, rec["summary"]))
        else:
            unknown_callees.append(ca)

    return {
        "address": address,
        "orig_name": orig_name,
        "decomp": decomp,
        "apis": apis,
        "known_named_calls": known_named,
        "known_callees": known_callees,
        "unknown_callees": unknown_callees,
        "callers": callers,
        "constants": raw["constants"],
        "sets_vtable": raw["sets_vtable"],
    }


def render_prompt(bundle, max_decomp_chars=9000):
    lines = [f"Function: {bundle['orig_name']} @ {bundle['address']}", ""]


    if bundle["callers"]:
        lines.append("Called by (how it's used):")
        for c in bundle["callers"][:8]:
            s = f" - {c['summary']}" if c.get("summary") else ""
            lines.append(f"  - {c.get('name')}{s}")
        lines.append("")

    if bundle.get("apis"):
        lines.append("Windows/CRT API calls: " + ", ".join(bundle["apis"]))
        lines.append("")

    if bundle["known_callees"]:
        lines.append("Calls (already understood):")
        for name, summ in bundle["known_callees"]:
            lines.append(f"  - {name}: {summ}")
        lines.append("")

    if bundle.get("known_named_calls"):
        lines.append("Other named calls: "
                     + ", ".join(bundle["known_named_calls"][:15]))
        lines.append("")

    if bundle["constants"]:
        lines.append("Notable 32-bit constants: " + ", ".join(bundle["constants"]))
        lines.append("")

    if bundle["sets_vtable"]:
        lines.append("Note: this function writes a vtable pointer "
                     "(likely a C++ constructor).")
        lines.append("")

    decomp = bundle["decomp"]
    if len(decomp) > max_decomp_chars:
        decomp = decomp[:max_decomp_chars] + "\n/* ...truncated... */"
    lines.append("Decompiled code:")
    lines.append("```c")
    lines.append(decomp)
    lines.append("```")
    return "\n".join(lines)
