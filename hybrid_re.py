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
import evidence as ev
from memory_retrieval import LongTermMemory

DB_PATH = "logs/data/re_memory.sqlite"
LLM_LOG = "logs/data/llm_log.jsonl"  

MODEL         = "Qwen/Qwen2.5-Coder-14B-Instruct-AWQ"    
TEMPERATURE   = 0.0

AI_URL  = "http://localhost:8000/v1"
AI_KEY  = "KEY"     

HY_SYSTEM_PROMPT = (
    "You are an expert reverse engineer. You are given ONE function together "
    "with one-line summaries of the functions it calls "
    "and the functions that call it, what earlier analyses concluded about the "
    "globals it touches, and notable constants. Use ALL of this "
    "evidence, not just the code, to decide what the function does. "

    "Confidence measures how much your name TELLS SOMEONE, not whether it is "
    "technically true. 'initialize_structure' is usually true and tells the "
    "reader nothing -- that is low confidence.\n"
    "  0.9-1.0  names the specific subject and action "
    "(e.g. validate_ground_item_packet)\n"
    "  0.6-0.8  right subject, action somewhat general "
    "(e.g. parse_item_message)\n"
    "  0.3-0.5  right domain only (e.g. handle_network_message)\n"
    "  0.0-0.2  generic filler: process_data, initialize_structure, "
    "setup_values, handle_input, copy_value\n\n"

    "IMPORTANT: if the evidence does not support a specific name, give a "
    "generic name with confidence below 0.3. Do NOT invent specifics you "
    "cannot point to in the evidence. An honest 'unknown' is more useful than "
    "a confident guess.\n\n"

    "You do not need to rename all variables, only function parameters and global variables."
    "If you think a global variable has an incorrect or vague name, you should rename it."
    "If the global is already named, and you think it is appropriate, you can keep the name the same"
    "add g_ + a Hungarian type prefix (ex. g_pActiveQuestState) for the global names, its the only naming convention that will be accepted."
    "The summary for the global names is not optional.\n"
    "If a global already has conclusions from earlier analyses, they are shown "
    "to you. Treat them as evidence, not fact: they came from other functions "
    "and may be wrong. If this function's use of the global contradicts them, "
    "say so and give your own name.\n"
    "Reply with ONLY a JSON object in exactly this shape:\n"
    '{"new_name": "snake_case_name", '
    '"summary": "Explain what it does AND how its data is used, '
    'include structure details such as memory access. Explain what data gets passed to each function called.",'
    '"confidence": 0.0, '
    '"global_variables": [{"old_name": "the name in ghidra", '
    '"new_name": "The name you give g_ + a Hungarian type prefix", '
    '"summary": "explain how the global variable is used in this function"}]}\n'
    "confidence is 0.0-1.0. If the evidence is thin, lower the confidence and "
    "prefix the name with 'maybe_'. If the function name is vague, drop the confidence significantly. Never invent behavior you cannot justify "
    "from the code or evidence."
)

def log_llm(addr, prompt, response, elapsed, usage=None):
    with open(LLM_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "time": time.strftime("%H:%M:%S"),
            "address": addr,
            "elapsed": round(elapsed, 2),
            "prompt_tokens": getattr(usage, "prompt_tokens", None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "prompt": prompt,
            "response": response,
        }) + "\n")

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
        # last resort, strip trailing commas
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


async def apply_to_ghidra(ghidra_connection, addr, new_name, summary, global_vars):

    r = await ghidra_connection.batch_rename(addr, new_name, global_renames=global_vars)
    #TODO rename variables 

    if summary:
        #TODO set comment
        pass

    return r['success']


async def analyze_one(client, sem, user_prompt, addr=""):
    async with sem:
        t0 = time.time()
        resp = await client.chat.completions.create(
            model=MODEL,
            temperature=TEMPERATURE,
            messages=[
                {"role": "system", "content": HY_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
    raw = resp.choices[0].message.content or ""
    log_llm(addr, user_prompt, raw, time.time() - t0,
            getattr(resp, "usage", None))
    return extract_json_object(raw)


async def pass_analyze(ghidra_connection, memory, client, functions, apply=False, concurrency=8):

    strings_map = memory.strings_map()
    imports_set = set(memory.meta_get("imports", []))

    indexed = {r[0] for r in memory.db.execute(
        "SELECT address FROM functions WHERE status='indexed'")}

    addrs = [f["address"] for f in functions if f["address"] in indexed]


    # Start with leaves and analyze up
    order = order_bottom_up(memory, addrs)
    print(f"[i] Pass B (analyze): {len(order)} functions, bottom-up, "
          f"concurrency={concurrency}. apply={apply}")

    import re as _re
    sem = asyncio.Semaphore(concurrency)
    analyzed = deduped = errors = 0
    start = time.time()
    
    for base_i in range(0, len(order), concurrency):
        chunk = order[base_i:base_i + concurrency]
        
        # Build prompts synchronously 
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
                                     get_summary=memory.summary_of, callers=callers, callees=memory.callees_of(addr),
                                     imports_set=imports_set,
                                     get_globals=memory.globals_history)
            pending.append((addr, bundle, ev.render_prompt(bundle)))

        if pending:
            
            results = await asyncio.gather(
                *(analyze_one(client, sem, p, a) for a, _, p in pending),
                return_exceptions=True)

            for (addr, bundle, _), result in zip(pending, results):
                if isinstance(result, Exception):
                    print(f"    ! LLM error @ {addr}: {result}")
                    errors += 1
                    continue
                if not result or not result.get("new_name"):
                    memory.upsert(addr, status="indexed")  
                    continue
                new_name = _re.sub(r"[^A-Za-z0-9_]", "_",
                                   str(result["new_name"]))[:60]
                memory.upsert(addr, name=new_name,
                          summary=str(result.get("summary", "")).strip(),
                          confidence=float(result.get("confidence") or 0.0),
                          evidence_json=json.dumps(
                              {"constants": bundle["constants"]}),
                          status="analyzed")
                gvars = result.get("global_variables") or []
                for global_rename in gvars:
                    if not isinstance(global_rename, dict):
                        continue
                    old = str(global_rename.get("old_name", "")).strip()
                    if not old:
                        continue
                    memory.record_global(
                        ev.global_key(old),
                        orig_name=old,
                        new_name=str(global_rename.get("new_name", "")).strip(),
                        # the model has spelled this key both ways; accept either
                        summary=str(global_rename.get("summary")
                                    or global_rename.get("summery") or "").strip(),
                        function=addr,
                        func_name=new_name,
                        confidence=float(result.get("confidence") or 0.0),
                    )
                analyzed += 1

                if apply and gvars and (result.get("confidence") or 0) > 0.6:
                    await apply_to_ghidra(ghidra_connection, addr, new_name,
                                          str(result.get("summary", "")).strip(),
                                          result['global_variables'])

    
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

    # Get strings and imports
    await build_caches(conn, memory)
    await pass_analyze(conn, memory, client, functions,
                        apply=args.apply, concurrency=args.concurrency)

    memory.close()


def main():
    ap = argparse.ArgumentParser(description="Hybrid evidence-driven RE.")
    ap.add_argument("--apply", action="store_true",
                    help="write names/comments back into Ghidra (default: memory only)")
    ap.add_argument("--limit", type=int, default=0, help="cap target functions (0=all)")
    ap.add_argument("--concurrency", type=int, default=8,
                    help="concurrent LLM requests in Pass B")
    
    args = ap.parse_args()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
