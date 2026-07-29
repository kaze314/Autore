import argparse
import json
import random
import re
import sqlite3
import hybrid_re
import statistics


from openai import OpenAI


EVAL_SYSTEM_PROMPT = (
    "You are grading a reverse engineer's guess at a function's name. "
    "You are given the TRUE name (from the original source) and a PREDICTED "
    "name inferred from decompiled code. Judge how well the prediction "
    "captures the function's actual purpose.\n\n"
    "Rubric:\n"
    "  1.0  same meaning; an expert would accept the prediction as correct\n"
    "  0.75 core purpose right, missing a qualifier or detail\n"
    "  0.5  partially right: right action or right subject, not both\n"
    "  0.25 only loosely related (right subsystem, wrong operation)\n"
    "  0.0  unrelated, or so generic it conveys nothing\n\n"
    "Ignore naming style entirely: snake_case vs CamelCase, abbreviations "
    "(init/initialize, buf/buffer), and class prefixes do not matter. "
    "Judge meaning only.\n"
    "Generic names such as 'process_data' or 'initialize_structure' score at "
    "most 0.25, unless the true name is equally generic.\n\n"
    'Reply with ONLY this JSON: {"score": 0.0, "reason": "<8 words max>"}'
)

def load_truth(path):
    truth = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            n = r["name"]

            if r.get("thunk") or re.match(r"^(FUN_|SUB_|LAB_|Ordinal_)", n):
                continue
            truth[r["address"].lower()] = r
    return truth


def load_preds(db_path):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT address, name, summary, confidence, category FROM functions "
        "WHERE status='analyzed' AND name IS NOT NULL AND name != ''")
    preds = {r["address"].lower(): dict(r) for r in rows}
    db.close()
    return preds


    
def score(llm_client, pred, truth):
    user_prompt = (
        f"Correct function name: {truth}\n "
        f"Predicted function name: {pred}"
    )
    resp = llm_client.chat.completions.create(
        model=hybrid_re.MODEL,
        temperature=hybrid_re.TEMPERATURE,
        messages=[
            {"role": "system", "content": EVAL_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    raw = resp.choices[0].message.content or ""

    return hybrid_re.extract_json_object(raw)
    
def report(truth, preds, show, sample=1000, seed=0):
    client = OpenAI(base_url=hybrid_re.AI_URL, api_key=hybrid_re.AI_KEY)

    keys = sorted(set(truth) & set(preds))
    if not keys:
        print("No overlapping addresses. Are ground truth and predictions from "
              "the SAME binary? (a debug build won't match a release build)")
        return

    # Shuffle before slicing
    # Fixed seed so separate runs score the SAME functions and stay comparable.
    random.seed(seed)
    random.shuffle(keys)
    if sample:
        keys = keys[:sample]
    print(f"[i] scoring {len(keys)} randomly sampled functions (seed={seed})")

    scored = []
    for i, key in enumerate(keys):
        scored.append((score(client, preds[key]["name"], truth[key]["name"])))
        print(f"\n\n\n\nFunction: {i}")
        print(f"pred: {preds[key]["name"]}")
        print(f"truth: {truth[key]["name"]}")

        print(f"score: {scored[i]['score']}")
        scores = [float(n["score"]) for n in scored]
        n = len(scores)
        mean = statistics.mean(scores)
        median = statistics.median(scores) 
        if i > 3:
            variance = statistics.variance(scores)
        else:
            variance = 0
        print(f"\n{'='*62}\nEVALUATION  ({n} functions with ground truth)\n{'='*62}")
        print(f"  ground truth names : {len(truth)}")
        print(f"  predictions        : {len(preds)}")
        print(f"  scored (overlap)   : {n}")
        print(f"\n  mean             : {mean:.3f}")
        print(f"  median             : {median:.3f}")
        print(f"  variance             : {variance:.3f}")

    # calibration: does the model's confidence predict correctness?
    print(f"\n  confidence calibration")
    print(f"    {'bucket':<10}{'n':>7}{'mean F1':>10}")
    for lo, hi in [(0, .5), (.5, .7), (.7, .9), (.9, 1.01)]:
        sel = [s for s, a in scores
               if (preds[a]["confidence"] or 0) >= lo and (preds[a]["confidence"] or 0) < hi]
        if sel:
            print(f"    {lo:.1f}-{hi:<6.1f}{len(sel):>7}{sum(sel)/len(sel):>10.3f}")


def main():
    ap = argparse.ArgumentParser(description="Score predicted names vs ground truth.")
    ap.add_argument("--db", default="re_memory.sqlite", help="predictions DB")
    ap.add_argument("--truth", default="ground_truth.jsonl")
    ap.add_argument("--show", type=int, default=10, help="examples to print (0=none)")
    ap.add_argument("--json", help="also write metrics to this JSON file")
    ap.add_argument("--sample", type=int, default=1000,
                    help="how many functions to score (0 = all)")
    ap.add_argument("--seed", type=int, default=0,
                    help="shuffle seed; keep fixed so runs are comparable")
    args = ap.parse_args()

    m = report(load_truth(args.truth), load_preds(args.db), args.show,
               sample=args.sample, seed=args.seed)
    if args.json and m:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2)


if __name__ == "__main__":
    main()
