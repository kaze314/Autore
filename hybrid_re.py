import argparse
import asyncio
import hashlib
import json
import time
import re
from collections import deque

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI, AsyncOpenAI

from ghidra_conn import GhidraConn
import tests
import evidence as ev
from memory_retrieval import LongTermMemory

DB_PATH = "re_memory.sqlite"
MODEL         = "Qwen/Qwen2.5-Coder-14B-Instruct-AWQ"    
TEMPERATURE   = 0.0

AI_URL  = "http://localhost:8000/v1"
AI_KEY  = ""     

HY_SYSTEM_PROMPT = (
    "You are an expert reverse engineer. You are given ONE function together "
    "with one-line summaries of the functions it calls, strings, "
    "and the functions that call it, and notable constants. Use ALL of this "
    "evidence, not just the code, to decide what the function does. "
    "You do not need to rename all variables, only function parameters and global variables."
    "If you are not atleast 0.8 confident, do not rename any variables.\n"
    "Reply with ONLY a JSON object in exactly this shape:\n"
    '{"new_name": "snake_case_name", '
    '"category": "one of: init, crypto, network, file_io, registry, '
    'string_util, memory, math, ui, parsing, game_logic, wrapper, '
    'error_handling, unknown", '
    '"summary": "one sentence: what it does AND how its data is used", '
    '"confidence": 0.0, '
    '"variables": [{"existing_var_name": "meaningful_name"}]}\n'
    "confidence is 0.0-1.0. If the evidence is thin, lower the confidence and "
    "prefix the name with 'maybe_'. Never invent behavior you cannot justify "
    "from the code or evidence."
)

def extract_json_object(text):
    """Pull the first {...} JSON object out of a model reply, tolerating stray prose."""
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    blob = text[start:end + 1]
    try:
        return json.loads(blob)
    except (json.JSONDecodeError, ValueError):
        # last resort: strip trailing commas
        blob2 = re.sub(r",(\s*[}\]])", r"\1", blob)
        try:
            return json.loads(blob2)
        except (json.JSONDecodeError, ValueError):
            return None
        
async def build_caches(ghidra_conn, memory):
    if memory.strings_count() == 0:
        print("[i] caching string table ...")
        strings = await ghidra_conn.get_strings()
        memory.put_strings(strings)
        print(f"    cached {len(strings)} strings")

    if memory.meta_get("imports") is None:
        print("[i] caching imports ...")
        imports = await ghidra_conn.get_imports()
        memory.meta_set("imports", sorted(imports))
        print(f"    cached {len(imports)} imports")


async def pass_index(ghidra_conn, memory, targets, jobs=1):
    # figure out what still needs indexing (resume-safe)
    todo = []
    for fn in targets:
        addr = fn["address"]
        if not addr:
            continue
        rec = memory.get(addr)
        if rec and rec.get("decomp"):
            continue  # already indexed
        print((addr, fn["name"]), rec)
        todo.append((addr, fn["name"]))
    print(f"[i] Pass A (index): {len(todo)} to index, {jobs} job(s)")

    sem = asyncio.Semaphore(max(jobs, 1))

    async def decompile(addr):
        async with sem:
            try:
                raw = await ghidra_conn.decompile_func(addr)
                return addr, raw
            except:
                return 0, ""

    chunk_size = max(jobs, 1) * 8   
    t0 = time.time()
    t_decomp = 0.0
    done = 0
    for start in range(0, len(todo), chunk_size):
        chunk = todo[start:start + chunk_size]
        
        td = time.time()
        results = dict(await asyncio.gather(*(decompile(a) for a, _ in chunk)))
        t_decomp += time.time() - td

        
        for addr, name in chunk:
            decomp = results.get(addr, "")
            if not decomp or "No function" in decomp:
                memory.upsert(addr, orig_name=name, status="skipped")
                continue

            h = hashlib.sha1(decomp.encode("utf-8", "replace")).hexdigest()
            for callee in ev.extract(decomp, self_name=name)["callee_addrs"]:
                memory.add_edge(addr, callee)
            memory.upsert(addr, orig_name=name, decomp=decomp,
                      decomp_hash=h, status="indexed")
            done += 1

        memory.commit()  
        el = max(time.time() - t0, 1e-6)
        print(f"    {start + len(chunk)}/{len(todo)}  "
              f"{done / el:.1f} fn/s  (decompile ~{100 * t_decomp / el:.0f}% of time)")
        
    memory.commit()
    print(f"[i] indexed {done}: decompile {t_decomp:.0f}s of "
          f"{time.time() - t0:.0f}s total. cached in {DB_PATH}")


def order_bottom_up(memory, addrs):
    addrset = set(addrs)
    indeg = {a: 0 for a in addrs}        
    dependents = {a: [] for a in addrs}  
    for caller, callee in memory.all_edges():
        if caller == callee or caller not in addrset or callee not in addrset:
            continue
        indeg[caller] += 1
        dependents[callee].append(caller)

    ready = deque(a for a in addrs if indeg[a] == 0)
    order = []
    while ready:
        a = ready.popleft()
        order.append(a)
        for parent in dependents[a]:
            indeg[parent] -= 1
            if indeg[parent] == 0:
                ready.append(parent)

    if len(order) < len(addrs): 
        order.extend(a for a in addrs if indeg[a] > 0)
    return order


async def apply_to_ghidra(ghidra_connection, addr, new_name, summary, variables):

    r = await ghidra_connection.batch_rename(addr, new_name)
    #TODO rename variables 

    if summary:
        #TODO set comment
        pass

    return r['success']


async def analyze_one(client, sem, user_prompt):
    """One async LLM call, throttled by a shared semaphore."""
    async with sem:
        resp = await client.chat.completions.create(
            model=MODEL,
            temperature=TEMPERATURE,
            messages=[
                {"role": "system", "content": HY_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
    return extract_json_object(resp.choices[0].message.content or "")


async def pass_analyze(ghidra_connection, memory, client, functions, apply=False, concurrency=8):

    # cached anchors -- resolved into every evidence bundle below
    strings_map = memory.strings_map()
    imports_set = set(memory.meta_get("imports", []))

    indexed = {r[0] for r in memory.db.execute(
        "SELECT address FROM functions WHERE status='indexed'")}
    addrs = [f["address"] for f in functions if f["address"] in indexed]

    order = order_bottom_up(memory, addrs)
    print(f"[i] Pass B (analyze): {len(order)} functions, bottom-up, "
          f"concurrency={concurrency}. apply={apply}")

    import re as _re
    sem = asyncio.Semaphore(concurrency)
    analyzed = deduped = errors = 0
    start = time.time()

    # Process in concurrent waves so vLLM actually batches them together
    # (watch the server log: "Running: N reqs" should now be > 1).
    
    for base_i in range(0, len(order), concurrency):
        chunk = order[base_i:base_i + concurrency]
        
        # Build prompts synchronously (fast); resolve dedups inline (no LLM).
        pending = []   # (addr, bundle, prompt)
        for addr in chunk:
            
            rec = memory.get(addr)
            if not rec or rec.get("status") == "analyzed":
                continue
            twin = memory.by_hash(rec["decomp_hash"])
            if twin and twin["address"] != addr:
                memory.upsert(addr, name=twin["name"], category=twin["category"],
                          summary=twin["summary"], confidence=twin["confidence"],
                          evidence_json=twin["evidence_json"], status="analyzed")
                deduped += 1
                continue
            callers = []
            for c in memory.callers_of(addr)[:8]:
                s = memory.summary_of(c)
                if s:
                    callers.append(s)
            bundle = ev.build_bundle(addr, rec["orig_name"], rec["decomp"],
                                     get_summary=memory.summary_of, callers=callers,
                                     strings_map=strings_map,
                                     imports_set=imports_set)
            pending.append((addr, bundle, ev.render_prompt(bundle)))

        if pending:
            
            # fire the whole wave at once -> vLLM batches concurrent requests
            results = await asyncio.gather(
                *(analyze_one(client, sem, p) for _, _, p in pending),
                return_exceptions=True)

            for (addr, bundle, _), result in zip(pending, results):
                if isinstance(result, Exception):
                    print(f"    ! LLM error @ {addr}: {result}")
                    errors += 1
                    continue
                if not result or not result.get("new_name"):
                    memory.upsert(addr, status="indexed")   # retry on a later pass
                    continue
                new_name = _re.sub(r"[^A-Za-z0-9_]", "_",
                                   str(result["new_name"]))[:60]
                memory.upsert(addr, name=new_name,
                          category=str(result.get("category", "unknown")),
                          summary=str(result.get("summary", "")).strip(),
                          confidence=float(result.get("confidence") or 0.0),
                          evidence_json=json.dumps(
                              {"constants": bundle["constants"]}),
                          status="analyzed")
                analyzed += 1
                if apply:
                    await apply_to_ghidra(ghidra_connection, addr, new_name,
                                          str(result.get("summary", "")).strip(),
                                          result.get("variables"))

    
        memory.commit()
        done = analyzed + deduped
        el = max(time.time() - start, 1e-6)
        print(f"    {base_i + len(chunk)}/{len(order)}  {done / el:.1f} fn/s  "
              f"(analyzed {analyzed}, deduped {deduped}, errors {errors})")

    memory.commit()
    print(f"\n=== analyzed {analyzed}, deduped {deduped}, errors {errors} ===")


async def run(args):
    memory = LongTermMemory(DB_PATH)
    client = AsyncOpenAI(base_url=AI_URL, api_key=AI_KEY)
    conn = GhidraConn()

    functions = await conn.get_functions()
    if args.limit:
        functions = functions[:args.limit]

    print(f"[i] {len(functions)} target functions")

    await build_caches(conn, memory)
    await pass_index(conn, memory, functions, jobs=args.jobs)

    if args.analyze:
        await pass_analyze(conn, memory, client, functions,
                            apply=args.apply, concurrency=args.concurrency)

    memory.close()


def main():
    ap = argparse.ArgumentParser(description="Hybrid evidence-driven RE.")
    ap.add_argument("--analyze", action="store_true",
                    help="analyze bottom-up with evidence bundles (indexes first)")
    ap.add_argument("--apply", action="store_true",
                    help="write names/comments back into Ghidra (default: memory only)")
    ap.add_argument("--limit", type=int, default=0, help="cap target functions (0=all)")
    ap.add_argument("--jobs", type=int, default=1,
                    help="concurrent decompile requests in Pass A (try 4-8; "
                         "may not help if the Ghidra bridge serializes)")

    ap.add_argument("--concurrency", type=int, default=8,
                    help="concurrent LLM requests in Pass B")
    
    args = ap.parse_args()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
