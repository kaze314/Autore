# Dump ground-truth function names from a Ghidra project that HAS symbols
# applied (import the exe, let Ghidra load the matching .pdb).
#
# Run inside Ghidra (Script Manager) on the symbol-applied project, then score
# your pipeline's output against it with eval_score.py.
#
# @category AutoRE
# @runtime Jython

import json

OUT_PATH = "D:/Main/Programs/auto_re/logs/data/ground_truth.jsonl"


def main():
    fm = currentProgram.getFunctionManager()
    out = open(OUT_PATH, "w")
    n = 0
    try:
        for f in fm.getFunctions(True):
            if f.isExternal():
                continue
            ns = f.getParentNamespace()
            out.write(json.dumps({
                "address": "0x%x" % f.getEntryPoint().getOffset(),
                "name": f.getName(),                 # demangled when PDB applied
                "namespace": ns.getName() if ns else "",
                "thunk": f.isThunk(),
                "size": f.getBody().getNumAddresses(),
            }) + "\n")
            n += 1
    finally:
        out.close()
    println("wrote %d ground-truth names -> %s" % (n, OUT_PATH))


main()
