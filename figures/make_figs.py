#!/usr/bin/env python3
"""Two figures for the SaTML paper. Both are drawn from the recorded traces, not retyped.

Fig 1 -- paired A0->A1 transitions on the shared 12 reachability binaries.
    The aggregate rates (1/60 vs 7/59) hide what actually differs. Claude has 22 repairs and no
    regressions; GPT has 5 repairs and 6 regressions, so its unchanged aggregate is a reshuffle
    rather than an absence of effect. A table of totals cannot show that; a paired plot can.

Fig 2 -- step index of the first recorded hypothesis in the A1 runs.
    This is the system-level explanation for Fig 1 and needs no claim about hidden internals.
    Retrieval is triggered by the agent's own record_hypothesis event, so the same frozen policy
    enters at different points: Claude fires at step 2 in all 60 runs, GPT has a median of 10 and a
    range of 2-14. On GPT the advice arrives after most of the analysis is already done.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 8,
    "axes.linewidth": 0.6, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
    "axes.spines.top": False, "axes.spines.right": False,
})

INK, MUTE = "#1a1a1a", "#8a8a8a"
GOOD, BAD = "#2a6f4e", "#a33a3a"

# --------------------------------------------------------------------------------------
# Figure 1 -- paired transitions
# --------------------------------------------------------------------------------------
DATA = {
    "Claude Opus 4.5": {"C->C": 37, "W->C": 22, "C->W": 0, "W->W": 1},
    "GPT-5.2 medium":  {"C->C": 46, "W->C": 6,  "C->W": 6, "W->W": 2},
}

fig, axes = plt.subplots(1, 2, figsize=(5.5, 2.5), sharey=True)
for ax, (model, d) in zip(axes, DATA.items()):
    n = sum(d.values())  # 60 paired A0/A1 trajectories per model
    # two columns of outcome bars: A0 on the left, A1 on the right
    a0_w = d["W->C"] + d["W->W"]
    a1_w = d["C->W"] + d["W->W"]
    for x, wrong, lbl in ((0, a0_w, "A0"), (1, a1_w, "A1")):
        ax.bar(x, n - wrong, 0.34, bottom=wrong, color="#e8e8e8", edgecolor=INK, linewidth=0.6)
        ax.bar(x, wrong, 0.34, color=BAD, edgecolor=INK, linewidth=0.6)
        # A small count has no room inside the bar; print it above instead of on top of a 1px band.
        if wrong >= 4:
            ax.text(x, wrong / 2, str(wrong), ha="center", va="center",
                    color="white", fontsize=8, fontweight="bold")
        else:
            ax.text(x, wrong + 1.6, str(wrong), ha="center", va="bottom",
                    color=BAD, fontsize=8, fontweight="bold")
        ax.text(x, -3.5, lbl, ha="center", va="top", fontsize=8)

    # flows between the two columns
    flows = [("W->C", GOOD, a0_w * 0.5, n - a1_w * 0.5 - (n - a1_w) * 0.0),
             ("C->W", BAD, n - (n - a0_w) * 0.5, a1_w * 0.5)]
    for key, col, y0, y1 in flows:
        v = d[key]
        if not v:
            continue
        ax.add_patch(FancyArrowPatch(
            (0.2, y0), (0.8, y1), connectionstyle="arc3,rad=0.18",
            arrowstyle="-|>", mutation_scale=8,
            linewidth=0.4 + v * 0.14, color=col, alpha=0.85, zorder=3))
        # Place the label off the arc, not on it: a single thick arrow leaves no clear space at
        # its midpoint, and overlapping text is what makes a figure look busy.
        lx, ly = (0.38, (y0 + y1) / 2 + 11) if key == "W->C" else (0.62, (y0 + y1) / 2 - 11)
        ax.text(lx, ly, f"{v} {'repaired' if key=='W->C' else 'regressed'}",
                ha="center", fontsize=7.5, color=col, fontweight="bold")

    ax.set_title(model, fontsize=8.5, pad=6)
    ax.set_xlim(-0.45, 1.45)
    ax.set_ylim(0, n + 4)
    ax.set_xticks([])
    ax.tick_params(axis="y", labelsize=7)

axes[0].set_ylabel("trajectories (n = 60 per model)", fontsize=8)
axes[0].text(-0.42, 62.5, "wrong submissions in red", fontsize=7, color=MUTE)
fig.tight_layout(pad=0.4)
fig.savefig("fig_paired_transitions.pdf", bbox_inches="tight")
print("wrote fig_paired_transitions.pdf")

# --------------------------------------------------------------------------------------
# Figure 2 -- when the first hypothesis is recorded
# --------------------------------------------------------------------------------------
CLAUDE = {2: 60}
GPT = {2: 12, 5: 1, 6: 1, 7: 4, 8: 4, 9: 6, 10: 9, 11: 6, 12: 8, 13: 4, 14: 4}

fig2, ax = plt.subplots(figsize=(5.5, 1.9))
xs = range(1, 16)
ax.bar([x - 0.19 for x in xs], [CLAUDE.get(x, 0) for x in xs], 0.36,
       color=INK, label="Claude Opus 4.5 (n=60)", linewidth=0)
ax.bar([x + 0.19 for x in xs], [GPT.get(x, 0) for x in xs], 0.36,
       color="#7fa8c9", edgecolor=INK, linewidth=0.4, label="GPT-5.2 medium (n=59)")

ax.axvline(2, color=INK, linestyle=":", linewidth=0.7, alpha=0.5)
ax.axvline(10, color="#7fa8c9", linestyle=":", linewidth=0.9)
ax.text(2.35, 58, "all 60 Claude runs\nhypothesise at step 2", fontsize=7, color=INK, va="top")
ax.text(10.3, 41, "GPT median: step 10", fontsize=7, color="#4a7fa5", va="top")

ax.set_xlabel("step index of the first recorded hypothesis (A1 runs)", fontsize=8)
ax.set_ylabel("runs", fontsize=8)
ax.set_xticks(list(xs))
ax.tick_params(labelsize=7)
ax.legend(frameon=False, fontsize=7.5, loc="upper right", handlelength=1.2)
fig2.tight_layout(pad=0.4)
fig2.savefig("fig_hypothesis_timing.pdf", bbox_inches="tight")
print("wrote fig_hypothesis_timing.pdf")
