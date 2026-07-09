"""Top-level orchestrator for the AgOSS matched-comparison analysis.

Pipeline:
  0. GATE: require a human-reviewed control pool
     (control-search/control_pool_reviewed.json, exported from review.html)
     before doing anything else. This is what main.py calls automatically
     after the main pipeline, so this gate is what prevents an unreviewed
     control pool from ever silently reaching the dashboard on a first run.
     Pass --allow-unreviewed (standalone use only) to bypass it for local
     testing; main.py never passes that flag.
  1. Resolve control_pool.json from the reviewed export (build_control_pool)
  2. Compute matching covariates for all 54 dataset repos + control pool
     (GitHub REST metadata + dependency count via the pipeline's dependency
     runner, which also yields dependency-based outcome data as a side effect)
  3. Compute eligibility (Mahalanobis caliper within a language/ecosystem
     exact-match gate) + covariate balance diagnostics
  4. Collect outcome data (Scorecard) for the eligible union only; reuse
     dependency/KEV data from step 2
  5. Primary: deterministic top-k nearest-neighbor matched-pair effect
     (bootstrap CI + single Wilcoxon test), summarized with FDR correction.
     Secondary/robustness: repeated *random* matched-pair sampling across
     many seeds, summarized the same way -- reported separately to show
     whether the primary conclusion survives looser, non-optimal matching.
  6. Write outputs/processed/matched_comparison.json

This does not establish causality — it tests whether the AgOSS maturity gap
persists once compared against operationally-similar, non-ag-critical
software matched on observable size/age/activity/ecosystem. See data_notes
in the output file for the full interpretation framing and limitations.

Usage:
    python control-search/run_matched_comparison.py
    python control-search/run_matched_comparison.py --force
    python control-search/run_matched_comparison.py --n-seeds 500
    python control-search/run_matched_comparison.py --allow-unreviewed  # local testing only
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_PROJECT_ROOT), str(_THIS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pipeline import config
from pipeline.models import RepoEntry
from pipeline.input_parser import parse_input

import covariates as cov_mod
import matching as matching_mod
import collect_outcomes as outcomes_mod
import build_control_pool

logger = logging.getLogger("control_search.run_matched_comparison")

OUTPUT_FILE = config.PROCESSED_DIR / "matched_comparison.json"
CONTROL_POOL_FILE = _THIS_DIR / "control_pool.json"
REVIEWED_FILE = _THIS_DIR / "control_pool_reviewed.json"

OUTCOME_METRICS_BASE = ["scorecard_overall", "vuln_count", "vuln_density", "kev_exploitable_count"]

# Curated "headline" metrics — the same set the dashboard's forest plot shows
# — get their full per-seed value list preserved in the output (for the seed
# stability distribution chart). Kept small deliberately: attaching this for
# every one of the ~30 metrics would bloat the JSON considerably.
HEADLINE_METRICS = {
    "scorecard_overall", "check_Dependency-Update-Tool", "check_Signed-Releases",
    "check_Maintained", "check_Vulnerabilities", "vuln_count", "vuln_density",
    "kev_exploitable_count",
}

# Maps each control_search.py keyword to a coarse domain label, for the
# "domain breakdown" diversity chart. Every repo in control_pool.json carries
# the keyword that first found it, so this is a simple lookup — deliberately
# using the actual keyword taxonomy from control_search.py rather than an
# invented category scheme, since the whole point is to show what's really
# in the pool.
KEYWORD_TO_DOMAIN = {
    "topic:iot": "IoT",
    "iot platform": "IoT",
    "topic:embedded-systems": "Embedded",
    "embedded systems": "Embedded",
    "topic:robotics": "Robotics",
    "robotics middleware": "Robotics",
    "topic:sensor": "Sensors",
    "sensor framework": "Sensors",
    "topic:environmental-monitoring": "Environmental",
    "environmental monitoring": "Environmental",
    "topic:scada": "Industrial / SCADA",
    "topic:plc": "Industrial / SCADA",
    "topic:firmware": "Firmware",
    "topic:cyber-physical-systems": "Cyber-Physical",
    "topic:home-automation": "Home Automation",
    "small cloud dashboard": "Dashboards",
}

DATA_NOTES = (
    "This analysis compares all 54 dataset repos (both ag_specific=True and "
    "ag_specific=False -- the latter are ag-critical infrastructure used in "
    "agriculture but not purpose-built for it, so both groups are treated "
    "here as the object of comparison) against k=3 matched controls each, "
    "drawn from a pool of non-ag-critical but operationally similar repos "
    "(IoT platforms, embedded systems, robotics middleware, sensor "
    "frameworks, environmental monitoring tools, small cloud dashboards, "
    "cyber-physical software). Matching uses a hard exact-primary-language "
    "gate (no ecosystem-bucket fallback -- a dataset repo with zero "
    "same-language candidates in the control pool is dropped into the "
    "unmatched cohort rather than matched against a different-language "
    "proxy) plus a Mahalanobis-distance caliper on log stars, log "
    "forks, repository age, log contributor count, and log recent commit "
    "activity (all four right-skewed count covariates are log1p-transformed "
    "for the same reason -- Mahalanobis distance assumes roughly elliptical "
    "covariate distributions, which raw GitHub activity counts are not). "
    "release_count and dependency_count are deliberately excluded from the "
    "caliper -- both are plausible mediators of ag-specific status (part of "
    "the security/maturity story being tested, not a nuisance confound of "
    "it) rather than confounds, and dependency_count was already "
    "well-balanced pre-matching while getting worse post-matching, so "
    "including them risked partialling out part of the effect without "
    "correcting a real imbalance in return; vuln_density still normalizes "
    "for dependency count at the outcome layer. Organization-vs-individual "
    "GitHub ownership was also excluded -- it's a noisy proxy for "
    "institutional backing (not a verified measure of it) and wasn't the "
    "main driver of caliper failures (stars/forks accounted for more of "
    "those). Matching covariates are "
    "computed uniformly via GitHub REST for every repo in the analysis "
    "to avoid a measurement-source confound between groups. "
    "PRIMARY ESTIMATE: each dataset repo is paired with its k nearest "
    "eligible controls by Mahalanobis distance (deterministic top-k "
    "nearest-neighbor matching -- the standard, defensible estimator in the "
    "matching literature), with no random re-assignment. The reported point "
    "estimate is the median matched-pair difference across dataset repos; "
    "its [2.5th, 97.5th] percentile interval comes from a nonparametric "
    "bootstrap over the matched pairs themselves (resampling which dataset "
    "repos ended up in the sample), and effect size is the matched-pairs "
    "rank-biserial correlation from a single Wilcoxon signed-rank test on "
    "the fixed set of paired differences. "
    "SECONDARY ROBUSTNESS CHECK: for each of many random seeds, k controls "
    "are instead drawn at random from the full eligible pool per dataset "
    "repo (without replacement within a seed where possible, with "
    "replacement only if the eligible pool is too small); the median "
    "matched-pair difference and [2.5th, 97.5th] percentile interval across "
    "seeds is reported separately, under Robustness, to show whether the "
    "primary conclusion survives even looser, non-optimal (randomly rather "
    "than optimally assigned) matching -- it is not the headline number. "
    "Benjamini-Hochberg FDR correction is applied across metrics within each "
    "grouping (all / ag_specific / non_ag_specific) for both the primary "
    "estimate and the robustness check, consistent with the existing "
    "ag_vs_nonag comparison in statistical_analysis.json. "
    "This analysis does not establish causality (\"agriculture causes weaker "
    "security posture\"); it tests whether the observed maturity/security gap "
    "persists after matching on observable size, age, activity, and "
    "ecosystem. Matching is on observed covariates only -- unobserved "
    "confounders (funding model, institutional backing, etc.) are not "
    "addressed. The non_ag_specific dataset subgroup is small and has "
    "limited statistical power; its interval should be read as suggestive, "
    "not conclusive, on its own. Repos left unmatched (zero eligible "
    "controls -- there is no ecosystem-bucket fallback) are disclosed by "
    "name below, not silently excluded from the denominator."
)


def build_pool_construction_summary() -> dict[str, Any] | None:
    """Read the control-search/ provenance files (raw candidates -> triage ->
    final pool) and summarize the funnel from discovery through automatic
    filtering to the resolved pool. Returns None if control_candidates.json
    doesn't exist (e.g. the analysis ran against a manually-assembled pool
    that never went through control_search.py)."""
    candidates_file = _THIS_DIR / "control_candidates.json"
    triaged_file = _THIS_DIR / "control_candidates_triaged.json"
    if not candidates_file.exists():
        return None

    candidates = json.loads(candidates_file.read_text(encoding="utf-8"))
    meta = candidates.get("meta", {})
    stats = candidates.get("stats", {})

    discovery_by_method: dict[str, int] = {}
    filters = {"archived": 0, "forks": 0, "already_in_dataset": 0, "ag_adjacent": 0, "curated_lists": 0, "cross_keyword_duplicates": 0}
    for keyword, s in stats.items():
        method = "GitHub Topics" if str(keyword).startswith("topic:") else "Free-Text Keywords"
        raw = (
            int(s.get("fetched", 0)) + int(s.get("archived_filtered", 0))
            + int(s.get("fork_filtered", 0)) + int(s.get("already_in_dataset_filtered", 0))
            + int(s.get("ag_adjacent_filtered", 0)) + int(s.get("curated_list_filtered", 0))
        )
        discovery_by_method[method] = discovery_by_method.get(method, 0) + raw
        filters["archived"] += int(s.get("archived_filtered", 0))
        filters["forks"] += int(s.get("fork_filtered", 0))
        filters["already_in_dataset"] += int(s.get("already_in_dataset_filtered", 0))
        filters["ag_adjacent"] += int(s.get("ag_adjacent_filtered", 0))
        filters["curated_lists"] += int(s.get("curated_list_filtered", 0))
        filters["cross_keyword_duplicates"] += int(s.get("duplicates", 0))

    summary: dict[str, Any] = {
        "discovery": {
            "by_method": discovery_by_method,
            "total_raw_examined": sum(discovery_by_method.values()),
        },
        "automatic_filters": filters,
        "after_filters_unique": int(meta.get("total_unique", 0)),
        "manual_review": None,
    }

    if triaged_file.exists():
        triaged = json.loads(triaged_file.read_text(encoding="utf-8"))
        final_pool_size = None
        review_status = None
        if CONTROL_POOL_FILE.exists():
            pool = json.loads(CONTROL_POOL_FILE.read_text(encoding="utf-8"))
            final_pool_size = pool.get("count")
            review_status = pool.get("review_status")
        total = triaged.get("total")
        summary["manual_review"] = {
            "total_candidates": total,
            "suggested_accept": triaged.get("suggested_accept"),
            "suggested_review": triaged.get("suggested_review"),
            "review_status": review_status,
            "final_pool_size": final_pool_size,
            "not_included_in_final_pool": (
                (total - final_pool_size) if total is not None and final_pool_size is not None else None
            ),
        }

    return summary


def build_domain_breakdown(control_entries: list[RepoEntry]) -> dict[str, int]:
    """Count control-pool repos per coarse domain (IoT / Embedded / Robotics /
    etc.), inferred from the keyword that first found each repo — demonstrates
    the operational diversity of the control pool, not just its size."""
    if not CONTROL_POOL_FILE.exists():
        return {}
    pool = json.loads(CONTROL_POOL_FILE.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    for r in pool.get("repos", []):
        keyword = str(r.get("keyword") or "")
        domain = KEYWORD_TO_DOMAIN.get(keyword, "Other")
        counts[domain] = counts.get(domain, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def compute_robustness(
    eligibility: "matching_mod.EligibilityResult",
    dataset_covariates: dict[str, dict],
    control_covariates: dict[str, dict],
    outcomes: dict[str, dict],
    random_matching_effects_by_k: dict[str, Any],
    *,
    k: int,
    n_seeds: int,
) -> dict[str, Any]:
    """Secondary robustness checks, all built on the repeated-*random*-matching
    machinery (run_seeds/summarize) rather than the deterministic
    nearest-neighbor primary estimate: does the conclusion survive varying k
    (controls per repo), the caliper width, or -- since these controls are
    drawn at random rather than picked as the single closest match -- looser,
    non-optimal matching assignment generally? This is what tells a reader
    the headline result isn't an artifact of one arbitrary specification
    choice, nor dependent on always picking the single best-available control.

    random_matching_effects_by_k is the full (all groups/metrics/k) random-
    seed result, already computed once by the caller for the Seed Stability
    section -- the "by_k" slice below just narrows it to headline
    metrics/"all" group rather than re-running run_seeds.

    Reuses already-collected outcome data. For the "loose" caliper, some
    newly-eligible controls may not have been Scorecard-collected (they
    weren't part of the primary caliper's eligible union) -- run_seeds
    already skips repos with missing outcome data gracefully, and coverage
    (how many of the loose caliper's eligible controls actually have outcome
    data) is reported explicitly rather than silently glossed over.
    """
    headline_list = sorted(HEADLINE_METRICS)

    by_k: dict[str, Any] = {}
    for kval_str, group_effects in random_matching_effects_by_k.items():
        all_group_effects = group_effects.get("all", {})
        by_k[kval_str] = {m: all_group_effects[m] for m in headline_list if m in all_group_effects}

    by_caliper: dict[str, Any] = {}
    caliper_coverage: dict[str, Any] = {}
    for label, q in {"tight": 0.25, "primary": 0.5, "loose": 0.75}.items():
        elig = eligibility if label == "primary" else matching_mod.compute_eligibility(
            dataset_covariates, control_covariates, caliper_quantile=q,
        )
        sr = matching_mod.run_seeds(elig, outcomes, {"all": list(elig.eligible.keys())}, headline_list, k=k, n_seeds=n_seeds)
        by_caliper[label] = matching_mod.summarize(sr, headline_list)["all"]
        union = {c for lst in elig.eligible.values() for c in lst}
        covered = sum(1 for c in union if c in outcomes)
        caliper_coverage[label] = {"eligible_union_size": len(union), "eligible_union_with_outcome_data": covered}

    return {
        "metrics": headline_list,
        "random_matching_by_k": random_matching_effects_by_k,
        "by_k": by_k,
        "by_caliper": by_caliper,
        "caliper_coverage": caliper_coverage,
    }


def _load_control_pool_entries(*, allow_unreviewed: bool) -> tuple[list[RepoEntry], str]:
    logger.info("[run_matched_comparison] Building control_pool.json from the reviewed export …")
    build_control_pool.main(allow_unreviewed=allow_unreviewed)

    payload = json.loads(CONTROL_POOL_FILE.read_text(encoding="utf-8"))
    repos = payload.get("repos", [])
    review_status = payload.get("review_status", "auto_suggested_fallback")

    entries: list[RepoEntry] = []
    for i, r in enumerate(repos, start=1):
        full_name = r.get("name") or ""
        if "/" not in full_name:
            continue
        owner, repo_name = full_name.split("/", 1)
        entries.append(RepoEntry(
            display_name=full_name,
            repo_url=r.get("url") or f"https://github.com/{full_name}",
            owner=owner,
            repo_name=repo_name,
            category="Control Pool",
            ag_specific=False,
            line_number=i,
        ))
    return entries, review_status


def run(
    *,
    force: bool = False,
    n_seeds: int = 1000,
    k: int = 3,
    k_options: tuple[int, ...] | None = None,
    allow_unreviewed: bool = False,
) -> Path | None:
    logger.info("[run_matched_comparison] Starting matched-comparison analysis …")

    if not REVIEWED_FILE.exists() and not allow_unreviewed:
        logger.warning(
            "[run_matched_comparison] SKIPPED — no human-reviewed control pool found at "
            "%s. The matched-comparison analysis will not run (and the dashboard tab will "
            "show no data) until you: 1) run `python control-search/control_search.py`, "
            "2) run `python control-search/triage.py`, 3) open "
            "`control-search/review.html`, review the candidates, and export the reviewed "
            "pool to that path. (--allow-unreviewed bypasses this gate for local testing "
            "only; main.py never passes it.)",
            REVIEWED_FILE,
        )
        return None

    # k_options is the set of k values the dashboard's live k selector can
    # switch between (effects + matching quality are precomputed for every
    # value); k is which of those is selected by default. k is always folded
    # into k_options even if a caller passes a custom set without it.
    k_options = tuple(sorted(set((k_options or (1, 3, 5)) + (k,))))

    config.FORCE_REFRESH = force

    merged_path = config.PROCESSED_DIR / "merged_repos.json"
    if not merged_path.exists():
        raise FileNotFoundError(
            f"{merged_path} not found — run the main pipeline (python main.py) before "
            "the matched comparison."
        )
    dataset_merged_repos = json.loads(merged_path.read_text(encoding="utf-8"))

    dataset_entries = parse_input(config.INPUT_FILE)
    control_entries, review_status = _load_control_pool_entries(allow_unreviewed=allow_unreviewed)

    logger.info(
        "[run_matched_comparison] %d dataset repos, %d control-pool repos",
        len(dataset_entries), len(control_entries),
    )
    if not control_entries:
        logger.warning(
            "[run_matched_comparison] Control pool is empty — run control_search.py, "
            "triage.py, and (optionally) review.html first."
        )

    # ── Step 2: matching covariates (GitHub REST) + dependency count ───────
    all_pairs = (
        [(e.owner, e.repo_name) for e in dataset_entries]
        + [(e.owner, e.repo_name) for e in control_entries]
    )
    all_covariates = cov_mod.fetch_covariates_batch(all_pairs, force=force)
    dep_report = cov_mod.attach_dependency_counts(all_covariates, dataset_entries + control_entries)

    dataset_keys = [f"{e.owner}/{e.repo_name}" for e in dataset_entries]
    control_keys = [f"{e.owner}/{e.repo_name}" for e in control_entries]
    dataset_covariates = {k: all_covariates[k] for k in dataset_keys if k in all_covariates}
    control_covariates = {k: all_covariates[k] for k in control_keys if k in all_covariates}

    # ── Step 3: eligibility + balance ───────────────────────────────────────
    eligibility = matching_mod.compute_eligibility(dataset_covariates, control_covariates)
    unmatched = sorted(k for k, v in eligibility.eligible.items() if not v)
    dataset_ag_specific = {f"{e.owner}/{e.repo_name}": e.ag_specific for e in dataset_entries}
    dataset_category = {f"{e.owner}/{e.repo_name}": e.category for e in dataset_entries}

    # Groups = the fixed all/ag_specific/non_ag_specific split, plus one group
    # per distinct category (Domain-specific agricultural platform, Field-
    # Deployed Sensor, etc.) -- lets the dashboard ask "is the gap
    # concentrated in one layer of the stack" the same way it already asks
    # "is the gap concentrated in ag-specific vs not."
    groups = matching_mod.build_standard_groups(eligibility, dataset_ag_specific, dataset_category)
    category_names = sorted({c for c in dataset_category.values() if c})

    # Matching-quality is computed per group only (it already reports
    # avg_controls_per_repo_by_k internally). Balance and covariate
    # distributions are computed per k *and* per group -- "after" must
    # reflect each repo's actual top-k nearest-eligible controls (the same
    # sample primary_effects_by_k uses), not the full caliper-eligible union.
    # The union is a superset of what's ever matched (up to max_eligible=20
    # per repo vs. k<=5 actually used), so averaging over it as a stand-in
    # for "after" silently mixes in controls no effect estimate ever touches
    # -- inflating the apparent imbalance on some covariates (e.g. stars/
    # forks) while masking it on others (e.g. contributor_count), independent
    # of which k a reader has selected. Computing it per k instead makes the
    # balance table/Love Plot/covariate-distribution charts agree with
    # whichever k the dashboard's selector is currently showing.
    matching_quality: dict[str, Any] = {}
    for group, group_keys in groups.items():
        matching_quality[group] = matching_mod.compute_matching_quality(
            eligibility, len(group_keys), k_options=k_options, dataset_keys_filter=group_keys,
        )

    balance_by_k: dict[str, Any] = {}
    covariate_distributions_by_k: dict[str, Any] = {}
    for kval in k_options:
        balance_by_k[str(kval)] = {}
        covariate_distributions_by_k[str(kval)] = {}
        for group, group_keys in groups.items():
            balance_by_k[str(kval)][group] = matching_mod.compute_balance(
                dataset_covariates, control_covariates, eligibility, dataset_keys_filter=group_keys, k=kval,
            )
            covariate_distributions_by_k[str(kval)][group] = matching_mod.compute_covariate_distributions(
                dataset_covariates, control_covariates, eligibility, dataset_keys_filter=group_keys, k=kval,
            )

    # ── Step 4: outcomes (Scorecard for eligible union; deps/KEV already have) ──
    union_keys = sorted({c for lst in eligibility.eligible.values() for c in lst})
    union_entries = [e for e in control_entries if f"{e.owner}/{e.repo_name}" in union_keys]
    logger.info(
        "[run_matched_comparison] Eligible-union control repos needing Scorecard: %d",
        len(union_entries),
    )
    control_scorecard = outcomes_mod.collect_scorecard_for_union(union_entries)
    kev_counts = outcomes_mod.build_kev_exploitable_counts(dep_report)
    outcomes, check_name_list = outcomes_mod.build_outcome_table(
        dep_report, kev_counts, control_scorecard, dataset_merged_repos,
    )

    metrics = OUTCOME_METRICS_BASE + [f"check_{c}" for c in check_name_list]

    # ── Step 5a: deterministic top-k nearest-neighbor effects (primary/headline) ──
    # Computed for every group and every metric at each k in k_options (not
    # just the default k) so the dashboard's k selector can switch instantly
    # between precomputed results rather than needing a rerun.
    primary_effects_by_k: dict[str, Any] = {}
    for kval in k_options:
        logger.info("[run_matched_comparison] Computing deterministic k=%d nearest-neighbor effects (primary) …", kval)
        det_results = matching_mod.run_deterministic(eligibility, outcomes, groups, metrics, k=kval)
        primary_effects_by_k[str(kval)] = matching_mod.summarize_deterministic(det_results, metrics)

    # ── Step 5b: repeated random-matching seeds (secondary robustness check) ──
    random_matching_effects_by_k: dict[str, Any] = {}
    for kval in k_options:
        logger.info("[run_matched_comparison] Running %d random-matching seeds for k=%d (robustness) …", n_seeds, kval)
        seed_results = matching_mod.run_seeds(eligibility, outcomes, groups, metrics, k=kval, n_seeds=n_seeds)
        random_matching_effects_by_k[str(kval)] = matching_mod.summarize(seed_results, metrics, headline_metrics=HEADLINE_METRICS)

    logger.info("[run_matched_comparison] Running robustness checks (k + caliper width) …")
    robustness = compute_robustness(
        eligibility, dataset_covariates, control_covariates, outcomes, random_matching_effects_by_k, k=k, n_seeds=n_seeds,
    )
    unmatched_characterization = matching_mod.characterize_unmatched(dataset_covariates, eligibility)

    # Guidance for picking k: how big is the eligible-control pool most
    # matched repos actually have to draw from, and how much would higher k
    # values force reusing (with replacement) the same control repo.
    matched_eligible_counts = [len(v) for v in eligibility.eligible.values() if v]
    avg_eligible = round(sum(matched_eligible_counts) / len(matched_eligible_counts), 2) if matched_eligible_counts else None
    min_eligible = min(matched_eligible_counts) if matched_eligible_counts else None
    k_guidance = {
        "avg_eligible_controls_per_matched_repo": avg_eligible,
        "min_eligible_controls_per_matched_repo": min_eligible,
        "note": (
            f"Across the {len(matched_eligible_counts)} successfully matched repos, the average "
            f"eligible-control pool size is {avg_eligible} (minimum {min_eligible}). k=1 "
            "(nearest-neighbor) is the most conservative choice in the matching literature -- for "
            "the primary deterministic estimate it means every dataset repo is paired with just its "
            "single closest control (at the cost of noisier per-repo estimates); for the secondary "
            "random-matching robustness check it also avoids reusing the same control across seeds "
            "as much as possible. Higher k averages more controls per matched pair, reducing noise "
            "but increasing how often a control gets reused -- especially for repos near the minimum "
            "eligible-pool size above. If that minimum is close to or below the largest k option, "
            "treat results at that k with extra caution for the affected repos."
            if matched_eligible_counts else
            "No repos were successfully matched, so no k guidance is available."
        ),
    }

    # ── Per-dataset-repo eligibility summary + matched-control detail ───────
    display_by_key = {f"{e.owner}/{e.repo_name}": e for e in dataset_entries}
    control_display_by_key = {f"{e.owner}/{e.repo_name}": e for e in control_entries}

    def _covariate_snapshot(cov_key: str, covariates: dict[str, dict]) -> dict[str, Any]:
        cov = covariates.get(cov_key, {})
        age = matching_mod.age_years(cov.get("created_at"))
        return {
            "language": cov.get("language"),
            "age_years": round(age, 1) if age is not None else None,
            "stars": cov.get("stars"),
            "forks": cov.get("forks"),
            "codebase_bytes": cov.get("codebase_bytes"),
            "contributor_count": cov.get("contributor_count"),
            "commit_activity_52w": cov.get("commit_activity_52w"),
        }

    per_dataset_repo = []
    for key in dataset_keys:
        entry = display_by_key[key]
        eligible_for_key = eligibility.eligible.get(key, [])
        # Nearest max(k_options) eligible controls (already distance-sorted by
        # compute_eligibility) — covers every k the dashboard's k selector can
        # switch to, which then just slices this list client-side. Distinct
        # from the randomized per-seed draws used for the statistical effect
        # estimation above, which sample from the full eligible pool across
        # many seeds.
        nearest = eligible_for_key[:max(k_options)]
        matched_controls = []
        for ck in nearest:
            control_entry = control_display_by_key.get(ck)
            snapshot = _covariate_snapshot(ck, control_covariates)
            matched_controls.append({
                "name": ck,
                "url": control_entry.repo_url if control_entry else f"https://github.com/{ck}",
                "distance": round(eligibility.distances.get(key, {}).get(ck, 0.0), 4),
                **snapshot,
            })

        # "Why didn't this repo match" + "closest rejected candidate" — only
        # populated for repos with zero eligible controls.
        why_not_matched = None
        diag = eligibility.unmatched_diagnostics.get(key)
        if diag is not None:
            closest_key = diag.get("closest_candidate")
            closest_entry = control_display_by_key.get(closest_key) if closest_key else None
            why_not_matched = {
                "reason": diag.get("reason"),
                "reason_label": diag.get("reason_label"),
                "exceeded_covariates": diag.get("exceeded_covariates", []),
                "closest_rejected_candidate": {
                    "name": closest_key,
                    "url": closest_entry.repo_url if closest_entry else (f"https://github.com/{closest_key}" if closest_key else None),
                    "distance": round(diag["closest_distance"], 4) if diag.get("closest_distance") is not None else None,
                    **(_covariate_snapshot(closest_key, control_covariates) if closest_key else {}),
                } if closest_key else None,
            }

        per_dataset_repo.append({
            "display_name": entry.display_name,
            "repo_url": entry.repo_url,
            "ag_specific": entry.ag_specific,
            "category": entry.category,
            "n_eligible_controls": len(eligible_for_key),
            "dataset_covariates": _covariate_snapshot(key, dataset_covariates),
            "matched_controls": matched_controls,
            "why_not_matched": why_not_matched,
        })

    n_ag = sum(1 for e in dataset_entries if e.ag_specific is True)
    n_non_ag = sum(1 for e in dataset_entries if e.ag_specific is False)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_dataset_repos": len(dataset_entries),
        "n_ag_specific": n_ag,
        "n_non_ag_specific": n_non_ag,
        "n_control_pool": len(control_entries),
        "n_seeds": n_seeds,
        "k_default": k,
        "k_options": list(k_options),
        "k_guidance": k_guidance,
        "caliper": {
            "primary_chi2_quantile": 0.5,
            "sensitivity_table": eligibility.sensitivity_table,
            "thresholds": eligibility.caliper_chi2,
        },
        "review_status": review_status,
        "data_notes": DATA_NOTES,
        "unmatched_dataset_repos": unmatched,
        "unmatched_characterization": unmatched_characterization,
        "matching_quality": matching_quality,
        "balance": balance_by_k,
        "covariate_distributions": covariate_distributions_by_k,
        "covariate_labels": matching_mod.RAW_COVARIATE_LABELS,
        "pool_construction": build_pool_construction_summary(),
        "domain_breakdown": build_domain_breakdown(control_entries),
        "headline_metrics": sorted(HEADLINE_METRICS),
        "category_names": category_names,
        "robustness": robustness,
        "per_dataset_repo": per_dataset_repo,
        "primary_effects_by_k": primary_effects_by_k,
    }

    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    logger.info("[run_matched_comparison] Wrote %s", OUTPUT_FILE)
    return OUTPUT_FILE


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run the AgOSS matched-comparison analysis.")
    p.add_argument("--force", action="store_true", help="Re-fetch covariates/outcomes even if cached.")
    p.add_argument("--n-seeds", type=int, default=1000, help="Number of random matching seeds (default: 1000).")
    p.add_argument("--k", type=int, default=3, help="Default matched controls per dataset repo, shown pre-selected in the dashboard's k selector (default: 3).")
    p.add_argument(
        "--k-options", type=str, default="1,3,5",
        help="Comma-separated k values to precompute for the dashboard's live k selector (default: 1,3,5). "
             "--k is always included even if omitted here.",
    )
    p.add_argument(
        "--allow-unreviewed", action="store_true",
        help="Bypass the human-review gate and use auto-suggested-accept candidates. "
             "Local testing only — main.py never passes this flag.",
    )
    return p.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    args = parse_args()
    k_options = tuple(int(v.strip()) for v in args.k_options.split(",") if v.strip())
    run(
        force=args.force, n_seeds=args.n_seeds, k=args.k, k_options=k_options,
        allow_unreviewed=args.allow_unreviewed,
    )


if __name__ == "__main__":
    main()
