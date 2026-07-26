import hashlib
import json
import sys

from memory_retrieval import LongTermMemory

DB_PATH = "re_memory.sqlite"
DUMP_PATH = "ghidra_dump.jsonl"


def load(dump_path=DUMP_PATH, db_path=DB_PATH):
    mem = LongTermMemory(db_path)
    n = indexed = skipped = edges = 0
    with open(dump_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            addr = rec["address"].lower()

            for callee in rec.get("callees", []):
                callee = callee.lower()
                if callee != addr:
                    mem.add_edge(addr, callee)
                    edges += 1

            decomp = rec.get("decomp") or ""
            if decomp:
                h = hashlib.sha1(decomp.encode("utf-8", "replace")).hexdigest()
                mem.upsert(addr, orig_name=rec.get("name"), decomp=decomp,
                           decomp_hash=h, status="indexed")
                indexed += 1
            else:
                mem.upsert(addr, orig_name=rec.get("name"), status="skipped")
                skipped += 1

            n += 1
            if n % 1000 == 0:
                mem.commit()
                print("  loaded %d ..." % n)

    mem.commit()
    mem.close()
    print("done: %d functions (%d indexed, %d no-decomp), %d edges -> %s"
          % (n, indexed, skipped, edges, db_path))


if __name__ == "__main__":
    load(*sys.argv[1:])
