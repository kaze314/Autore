import json

from ghidra.app.decompiler import DecompInterface


OUT_PATH = "D:/Main/Programs/auto_re/ghidra_dump.jsonl"
DECOMP_TIMEOUT = 60          
SKIP_THUNKS = False


def callee_addrs(func):
    out = set()
    listing = currentProgram.getListing()
    for instr in listing.getInstructions(func.getBody(), True):
        if monitor.isCancelled():
            break
        for ref in instr.getReferencesFrom():
            if ref.getReferenceType().isCall():
                out.add("0x%x" % ref.getToAddress().getOffset())
    return sorted(out)


def main():
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()
    total = fm.getFunctionCount()
    println("Dumping %d functions -> %s" % (total, OUT_PATH))

    out = open(OUT_PATH, "w")
    seen = 0
    decompiled = 0
    try:
        for func in fm.getFunctions(True):    
            if monitor.isCancelled():
                break
            seen += 1
            if func.isExternal() or (SKIP_THUNKS and func.isThunk()):
                continue

            addr = "0x%x" % func.getEntryPoint().getOffset()
            decomp = ""
            res = ifc.decompileFunction(func, DECOMP_TIMEOUT, monitor)
            if res is not None and res.decompileCompleted():
                df = res.getDecompiledFunction()
                if df is not None:
                    decomp = df.getC()
                    decompiled += 1

            rec = {
                "address": addr,
                "name": func.getName(),
                "decomp": decomp,
                "callees": callee_addrs(func),
            }
            out.write(json.dumps(rec))
            out.write("\n")

            if seen % 500 == 0:
                out.flush()
                println("  %d/%d  (%d decompiled)" % (seen, total, decompiled))
    finally:
        out.close()
        ifc.dispose()

    println("Done: %d functions, %d decompiled -> %s"
            % (seen, decompiled, OUT_PATH))


main()
