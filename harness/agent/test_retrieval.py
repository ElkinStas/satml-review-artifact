#!/usr/bin/env python3
"""Tests for BM25 failure-pattern retrieval (no LLM).

Run from repo root:  python agent/test_retrieval.py
"""
import sys
import inspect
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from agent.state import Card
from agent.retrieval import retrieve, BM25, _doc_tokens, load_cards
from agent.policy import ClaudePolicy as _CP

checks = []
def expect(label, cond):
    checks.append((label, bool(cond)))


def card(cid, family, title="", sig="", mech="", kws=None):
    return Card(card_id=cid, family=family, title=title, applicability_signal=sig,
                mechanism=mech, recommended_validation_actions=[], requires_differential=False,
                validation_note="", retrieval_keywords=kws or [], grounding="well_grounded")


def main() -> int:
    # 1. BM25 ranks the matching family first; unrelated cards score ~0.
    cards = [
        card("c_tr", "transform_then_compare", "Transform then compare",
             "a visible constant is the post-transform value", kws=["transform", "xor", "compare"]),
        card("c_dec", "decoy_static_string", "Flag-shaped string",
             "a printable flag-like string in strings/.rodata", kws=["strings", "rodata", "visible"]),
        card("c_sym", "misleading_symbol_name", "Misleading symbol",
             "a function named like the gate", kws=["symbol", "function", "name"]),
    ]
    r = retrieve(cards, "xor transform compare constant", k=3, backend="bm25")
    expect("bm25: transform query -> transform card first", r[0].card_id == "c_tr")
    expect("bm25: returns k cards", len(r) == 3)

    r2 = retrieve(cards, "printable string visible in rodata", k=3, backend="bm25")
    expect("bm25: decoy query -> decoy card first", r2[0].card_id == "c_dec")

    # 2. keyword backend still works and agrees on a clear query
    rk = retrieve(cards, "xor transform compare", k=3, backend="keyword")
    expect("keyword backend: transform query -> transform card first", rk[0].card_id == "c_tr")

    # 3. IDF: a rare distinctive term outranks a common one.
    idf_cards = [
        card("a", "fam_a", "A", "common token here", kws=["common"]),
        card("b", "fam_b", "B", "common token plus rare marker", kws=["common", "zzrare"]),
        card("c", "fam_c", "C", "common token here too", kws=["common"]),
    ]
    ri = retrieve(idf_cards, "common zzrare", k=3, backend="bm25")
    expect("bm25 IDF: card with the rare term ranks first", ri[0].card_id == "b")

    # 4. determinism + no-query behaviour
    expect("bm25: deterministic (same query -> same order)",
           [c.card_id for c in retrieve(cards, "xor transform compare", k=3)] ==
           [c.card_id for c in retrieve(cards, "xor transform compare", k=3)])
    expect("no query -> [] (hypothesis-keyed; no first-k transform bias)",
           retrieve(cards, None, k=2) == [])

    # 5. all-miss (zero lexical evidence) query -> [] (no first-k transform-order bias)
    rt = retrieve(cards, "qqqqq nomatch wwwww", k=3, backend="bm25")
    expect("bm25: all-miss query -> [] (zero lexical evidence)", rt == [])
    rtk = retrieve(cards, "qqqqq nomatch wwwww", k=3, backend="keyword")
    expect("keyword: all-miss query -> [] (zero lexical evidence)", rtk == [])

    # 6. integration on the real seed library: family-name query returns that family
    seed = REPO / "cards/cards_pilot_seed.json"
    if seed.exists():
        lib = load_cards(seed)
        expect("seed library loads (>=5 cards)", len(lib) >= 5)
        top = retrieve(lib, "decoy static string visible", k=1, backend="bm25")
        expect("seed: 'decoy' query -> a decoy_* family card",
               top and "decoy" in top[0].family)
        top2 = retrieve(lib, "transform then compare constant", k=3, backend="bm25")
        expect("seed: 'transform' query -> transform_then_compare in top-3",
               any(c.family == "transform_then_compare" for c in top2))
    else:
        expect("seed library present", False)

    # 7. retrieval freeze: live config must match retrieval_lock.json (fails on drift)
    import json
    import hashlib
    import agent.retrieval as RET
    lock_path = REPO / "retrieval_lock.json"
    if lock_path.exists():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        expect("lock: BM25_K1 matches retrieval.py", RET.BM25_K1 == lock["bm25_k1"])
        expect("lock: BM25_B matches retrieval.py", RET.BM25_B == lock["bm25_b"])
        expect("lock: KEYWORD_WEIGHT matches retrieval.py", RET.KEYWORD_WEIGHT == lock["keyword_weight"])
        expect("lock: default backend == bm25",
               inspect.signature(retrieve).parameters["backend"].default == lock["retrieval_backend"])
        expect("lock: default top_k matches",
               inspect.signature(retrieve).parameters["k"].default == lock["top_k"])
        expect("lock: dense_rerank is null", lock["dense_rerank"] is None)
        cl = REPO / lock["card_library_path"]
        h = hashlib.sha256(cl.read_bytes()).hexdigest() if cl.exists() else ""
        expect("lock: card library SHA-256 matches (library not drifted)",
               h == lock["card_library_sha256"])
        # algorithm lock: ranker code hash + frozen regression vectors catch drift the param-lock misses
        # (e.g. a change to _toks / _doc_tokens / IDF / tie-breaking leaves k1/b/weight/top_k unchanged)
        rp = REPO / "agent/retrieval.py"
        expect("lock: retrieval.py SHA-256 matches (ranker code not drifted)",
               hashlib.sha256(rp.read_bytes()).hexdigest() == lock.get("retrieval_py_sha256"))
        expect("lock: retrieval policy method SHA-256 matches (query/reinjection not drifted)",
               hashlib.sha256(inspect.getsource(_CP._retrieve_for_step).encode()).hexdigest()
               == lock.get("retrieval_policy_method_sha256"))
        rv = lock.get("regression_vectors", {})
        expect("lock: regression vectors present (>=3)", len(rv) >= 3)
        vlib_l = load_cards(REPO / lock["card_library_path"])
        expect("lock: all regression vectors reproduce (query -> ordered card_ids)",
               all([c.card_id for c in retrieve(vlib_l, q, k=3, backend="bm25")] == ids
                   for q, ids in rv.items()))
    else:
        expect("retrieval_lock.json present", False)

    # 8. frozen-library retrieval smoke on cards_v1.0.json: family-specific query lands its family
    #    in top-3. This is a retrieval SANITY smoke on the registered library, NOT proof of MC1
    #    (MC1 relevance is measured at run time on real tasks).
    v10 = REPO / "cards/cards_v1.0.json"
    if v10.exists():
        vlib = load_cards(v10)
        expect("v1.0 library loads 25 cards", len(vlib) == 25)
        smoke = [
            ("xor transform compare", "transform_then_compare"),
            ("flag string rodata no xref", "decoy_static_string"),
            ("silent output no baseline", "silent_validation_failure"),
            ("opaque predicate branch reachable", "decompiler_artifact"),
        ]
        for q, want in smoke:
            fams = [c.family for c in retrieve(vlib, q, k=3, backend="bm25")]
            expect(f"v1.0 smoke: {want} in top-3 for {q!r}", want in fams)
    else:
        expect("cards_v1.0.json present", False)

    # 9. keyword tokenization (retrieval_keywords are tokenized, not inserted raw) + k<=0 disables retrieval
    kwc = card("kw", "silent_validation_failure", "Silent validation",
               "well-formed wrong input accepted with no signal",
               kws=["wrong-input", "no-output", "exit-code"])
    dt = _doc_tokens(kwc)
    expect("keywords tokenized ('wrong'/'input' present, raw 'wrong-input' absent)",
           "wrong" in dt and "input" in dt and "wrong-input" not in dt)
    expect("k == 0 disables retrieval (returns [])",
           retrieve(cards, "xor transform compare", k=0) == [])
    expect("k < 0 disables retrieval (returns [])",
           retrieve(cards, "anything", k=-1) == [])

    # multi-token keyword queries land the right family on the frozen v1.0 library (the fix in action:
    # before, query 'wrong input' could not match the doc token 'wrong-input', so the x3 boost was dead)
    if v10.exists():
        for q, want in [
            # W10: the family no longer carries runtime vocabulary (wrong-input/baseline/
            # differential); this probes its static keywords, which are still multi-token.
            ("same output both outcomes converge", "silent_validation_failure"),
            ("check flag symbol name", "misleading_symbol_name"),
            ("linear sweep anti disasm junk bytes", "decompiler_artifact"),
        ]:
            fams = [c.family for c in retrieve(vlib, q, k=3, backend="bm25")]
            expect(f"kw-tokenization: {want} in top-3 for {q!r}", want in fams)

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"BM25 RETRIEVAL TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"BM25 RETRIEVAL TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
