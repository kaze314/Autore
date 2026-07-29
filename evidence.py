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
# Strings
STR_LIT_RE = re.compile(r'"((?:[^"\\\n]|\\.){3,})"')

_NON_CALLS = {
    "if", "while", "for", "switch", "return", "sizeof", "do", "else", "case",
    "goto", "default", "void", "int", "char", "long", "short", "float",
    "double", "unsigned", "signed", "struct", "union", "enum", "const",
    "byte", "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "uint", "ulong", "ushort", "code", "bool",
}


def _addr(hexstr):
    return "0x" + hexstr.lower()


def global_key(symbol):
    m = re.search(r"([0-9a-fA-F]{5,})$", symbol or "")
    return _addr(m.group(1)) if m else "name:" + (symbol or "").lower()


def extract(decomp, self_name=None):

    callee_addrs = {_addr(h) for h in FUN_RE.findall(decomp)}
  
    if self_name and self_name.startswith("FUN_"):
        callee_addrs.discard("0x" + self_name[4:].lower())
    callee_addrs = sorted(callee_addrs)

    data_addrs = {_addr(h) for h in DATA_REF_RE.findall(decomp)}
    data_addrs |= {_addr(h) for h in STR_SYM_RE.findall(decomp)}

    # addr -> symbol text as written, so the prompt can show "DAT_x -> g_pFoo"
    data_refs = {}
    for m in DATA_REF_RE.finditer(decomp):
        data_refs.setdefault(_addr(m.group(1)), m.group(0))

    names = {n for n in CALL_RE.findall(decomp) if n not in _NON_CALLS}
    names.discard(self_name)
    named_calls = sorted(n for n in names if not n.startswith("FUN_"))
    named_calls = sorted(n for n in named_calls if not n.startswith("thunk"))

    constants = sorted({"0x" + h.lower() for h in MAGIC_RE.findall(decomp)})

    literals, seen = [], set()
    for m in STR_LIT_RE.finditer(decomp):
        s = m.group(1)
        if s not in seen:
            seen.add(s)
            literals.append(s)

    return {
        "callee_addrs": callee_addrs,
        "data_addrs": sorted(data_addrs),
        "data_refs": data_refs,
        "named_calls": named_calls,
        "constants": constants,
        "literals": literals,
        "sets_vtable": "vftable" in decomp,
    }


def build_bundle(address, orig_name, decomp, *, get_summary, callers,
                 imports_set=None, strings_map=None, callees=None,
                 get_globals=None, max_callees=40, max_strings=20,
                 max_globals=6):
    raw = extract(decomp, self_name=orig_name)
    imports_set = imports_set or set()
    callees = callees or []


    strings = list(raw["literals"])
    if strings_map:
        strings += [strings_map[a] for a in raw["data_addrs"] if a in strings_map]
    strings = strings[:max_strings]

    # split call targets into imported APIs vs already-named internal functions
    apis = sorted({n for n in raw["named_calls"] if n in imports_set})
    known_named = [n for n in raw["named_calls"] if n not in imports_set]

    known_callees, unknown_callees = [], []
    for ca in callees[:max_callees]:
        rec = get_summary(ca)
        if rec and rec.get("summary"):
            known_callees.append((rec.get("name") or ca, rec["summary"]))
        else:
            unknown_callees.append(ca)

    # What earlier analyses concluded about the globals this function touches.
    # Only globals that already have history are worth prompt space.
    globals_seen = []
    if get_globals:
        for gaddr, symbol in raw["data_refs"].items():
            if strings_map and gaddr in strings_map:
                continue                      # that's a string literal, not a global
            opinions = get_globals(global_key(symbol))
            if opinions:
                globals_seen.append({"symbol": symbol, "opinions": opinions})
        globals_seen.sort(
            key=lambda g: -(g["opinions"][0].get("confidence") or 0.0))
        globals_seen = globals_seen[:max_globals]

    return {
        "address": address,
        "orig_name": orig_name,
        "decomp": decomp,
        "strings": strings,
        "globals": globals_seen,
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

    if bundle.get("strings"):
        lines.append("Referenced strings:")
        lines += [f'  - "{s}"' for s in bundle["strings"]]
        lines.append("")

    if bundle.get("apis"):
        lines.append("Windows/CRT API calls: " + ", ".join(bundle["apis"]))
        lines.append("")

    if bundle.get("globals"):
        lines.append("Globals used here (what earlier analyses concluded):")
        for g in bundle["globals"]:
            top = g["opinions"][0]
            conf = top.get("confidence")
            who = top.get("func_name") or "?"
            lines.append(f"  {g['symbol']} -> {top.get('new_name') or '?'}  "
                         f"[{who}, conf {conf if conf is not None else '?'}]")
            if top.get("summary"):
                lines.append(f"      {top['summary']}")

            seen = {top.get("new_name")}
            for alt in g["opinions"][1:]:
                if alt.get("new_name") and alt["new_name"] not in seen:
                    seen.add(alt["new_name"])
                    lines.append(
                        f"      also called {alt['new_name']} "
                        f"[{alt.get('func_name') or '?'}, "
                        f"conf {alt.get('confidence')}]")
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
