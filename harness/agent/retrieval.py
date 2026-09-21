"""Failure-pattern retrieval (A1, A2).

Registered design (prereg §5): **BM25 over card text**, per-step, observation-keyed. Each step
the agent's current hypothesis/observation is the query; cards are ranked by BM25 over their
text (title + applicability_signal + mechanism + family + retrieval_keywords) and the top-k are
returned. Cards are tied to the current observation, not injected once up front, so per-step
attribution is possible (see ClaudePolicy.last_retrieved and the per-step retrieved_cards in the
trace). This module ranks; retrieval *triggers* and query construction live in the policy, and
the A1/A2 wiring is unchanged by the ranker.

`retrieve(..., backend=...)`:
  - "bm25"    (default, REGISTERED): BM25-Okapi over the card corpus, computed from the supplied
              card list (k1=1.5, b=0.75; retrieval_keywords up-weighted x3 as curated signal).
  - "keyword" (ABLATION/pilot): the Week-3 keyword-overlap ranker, retained for comparison.

Optional dense reranking (prereg §5, "optional") is intentionally NOT implemented (it needs an
embedding model); `rerank=None` is the only mode. If added later it reorders BM25's top-k only.

The BM25 ranker is self-contained (no external dependency, no network at runtime). To FREEZE
retrieval for main runs, lock the card library (cards/*.json) and the BM25 params below; the
ranking is then a pure function of (locked library, query).
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from agent.state import Card

# BM25-Okapi parameters (FROZEN for main runs together with the card library).
BM25_K1 = 1.5
BM25_B = 0.75
KEYWORD_WEIGHT = 3  # retrieval_keywords are curated signal; up-weight in the document


def load_cards(path: str | Path) -> list[Card]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw["cards"] if isinstance(raw, dict) else raw
    return [
        Card(
            card_id=c["card_id"], family=c["family"], title=c.get("title", ""),
            applicability_signal=c.get("applicability_signal", ""),
            mechanism=c.get("mechanism", ""),
            recommended_validation_actions=list(c.get("recommended_validation_actions", [])),
            requires_differential=bool(c.get("requires_differential", False)),
            validation_note=c.get("validation_note", ""),
            retrieval_keywords=list(c.get("retrieval_keywords", [])),
            grounding=c.get("grounding", "well_grounded"),
            misleading_interpretation=c.get("misleading_interpretation", ""),
            better_interpretation=c.get("better_interpretation", ""),
            not_applicable_when=list(c.get("not_applicable_when", [])),
            misfire_risks=list(c.get("misfire_risks", [])),
            minimum_evidence_before_use=list(c.get("minimum_evidence_before_use", [])),
            provenance=dict(c.get("provenance", {})),
        )
        for c in items
    ]


def _toks(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", (s or "").lower())


def _doc_tokens(c: Card) -> list[str]:
    """Card document: free text + curated keywords up-weighted by KEYWORD_WEIGHT.

    Keywords are TOKENIZED with the same tokenizer as the query (not inserted raw), so a
    multi-token keyword like 'wrong-input' / 'linear-sweep' / 'check_flag' contributes the
    tokens 'wrong','input' / 'linear','sweep' / 'check','flag' -- which is what a query like
    'wrong input baseline' actually produces. Inserting the raw hyphenated form (the old bug)
    silently killed the x3 boost for every multi-token keyword in the library.
    """
    text = " ".join([c.title, c.applicability_signal, c.mechanism, c.family])
    toks = _toks(text)
    for kw in c.retrieval_keywords:
        for t in _toks(kw):
            toks.extend([t] * KEYWORD_WEIGHT)
    return toks


class BM25:
    """Minimal BM25-Okapi over a list of token-lists (one per card)."""

    def __init__(self, docs: list[list[str]], k1: float = BM25_K1, b: float = BM25_B):
        self.k1, self.b = k1, b
        self.N = len(docs)
        self.tf = [Counter(d) for d in docs]
        self.dl = [len(d) for d in docs]
        self.avgdl = (sum(self.dl) / self.N) if self.N else 0.0
        df: Counter = Counter()
        for d in docs:
            for t in set(d):
                df[t] += 1
        # idf with the standard BM25 +0.5 smoothing (always > 0 here)
        self.idf = {t: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for t, n in df.items()}

    def score(self, q_tokens: list[str], i: int) -> float:
        tf, dl = self.tf[i], (self.dl[i] or 1)
        denom_norm = self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1))
        s = 0.0
        for t in q_tokens:
            f = tf.get(t, 0)
            if not f:
                continue
            s += self.idf.get(t, 0.0) * (f * (self.k1 + 1)) / (f + denom_norm)
        return s


def retrieve_scored(cards: list[Card], query: str | None, k: int = 3,
                    backend: str = "bm25", rerank=None) -> list[tuple[Card, float, int]]:
    """Ranked (card, score, rank) triples for the query (current hypothesis/observation).

    No query (before the first hypothesis) / k <= 0 / no cards / zero lexical evidence -> []. Retrieval
    is registered as hypothesis-keyed; the old first-k fallback surfaced the library's first five cards
    (all transform_then_compare) as a systematic transform bias, so it is gone.
    """
    if k <= 0 or not query or not cards:
        return []
    if rerank is not None:
        raise NotImplementedError("dense reranking is optional and not implemented; rerank must be None")

    if backend == "keyword":
        qset = set(_toks(query))

        def kscore(c: Card) -> float:
            kw = {t for kw_ in c.retrieval_keywords for t in _toks(kw_)}
            text = " ".join([c.title, c.applicability_signal, c.mechanism, c.family])
            return float(len(qset & kw) * 2 + len(qset & set(_toks(text))))

        scores = [kscore(c) for c in cards]
    elif backend == "bm25":
        bm = BM25([_doc_tokens(c) for c in cards])
        q = _toks(query)
        scores = [float(bm.score(q, i)) for i in range(len(cards))]
    else:
        raise ValueError(f"unknown retrieval backend: {backend!r}")

    if not scores or max(scores) <= 0:
        return []  # zero lexical evidence -> no retrieval (no first-k transform-order bias)
    order = sorted(range(len(cards)), key=lambda i: scores[i], reverse=True)  # stable ties = library order
    return [(cards[i], scores[i], rank + 1) for rank, i in enumerate(order[:k])]


def retrieve(cards: list[Card], query: str | None, k: int = 3,
             backend: str = "bm25", rerank=None) -> list[Card]:
    """Top-k cards for the query. Thin wrapper over retrieve_scored (see it for the rules)."""
    return [c for c, _, _ in retrieve_scored(cards, query, k=k, backend=backend, rerank=rerank)]


def format_cards_block(cards: list[Card]) -> str:
    if not cards:
        return ""
    out = ["Pattern cards (advisory; retrieved for your current observation):"]
    for c in cards:
        tag = " [ADVISORY/under-exercised]" if c.grounding != "well_grounded" else ""
        out.append(f"Card: [{c.card_id}] {c.title}{tag}")
        if c.applicability_signal:
            out.append(f"  cue: {c.applicability_signal}")
        if c.misleading_interpretation:
            out.append(f"  misleading: {c.misleading_interpretation}")
        if c.better_interpretation:
            out.append(f"  better: {c.better_interpretation}")
        acts = ", ".join(c.recommended_validation_actions) or "(none)"
        diff = " (requires a wrong-input differential)" if c.requires_differential else ""
        note = f" -- {c.validation_note}" if c.validation_note else ""
        out.append(f"  validate: {acts}{diff}{note}")
        if c.not_applicable_when:
            out.append(f"  do_not_apply_when: {'; '.join(c.not_applicable_when)}")
        if c.minimum_evidence_before_use:
            out.append(f"  min_evidence: {'; '.join(c.minimum_evidence_before_use)}")
        if c.misfire_risks:
            out.append(f"  misfire_risk: {'; '.join(c.misfire_risks)}")
    return "\n".join(out)
