"""
rules_engine.py
================

Backend risk-scoring engine for a crypto forensics tool.

Consumes a NetworkX directed graph of Ethereum transactions and produces a
Risk Score (1.0 - 10.0) for every wallet (node) in the graph, based on a
pluggable set of heuristics. This module contains no GUI or visualization
code -- it is pure analysis logic intended to be called from a CLI, API,
or notebook.

Expected graph shape
---------------------
A `networkx.DiGraph` (or `MultiDiGraph`) where:

- Nodes are wallet addresses (str).
- Edges represent transactions, directed from sender -> receiver, and carry
  attributes on the edge data dict:
    - "value"     : float, amount transferred (ETH or any consistent unit)
    - "timestamp" : int (unix epoch seconds) or datetime.datetime
    - "tx_hash"   : str, optional, transaction hash for evidence trails

Only "value" and "timestamp" are required for the built-in heuristics.

Heuristics implemented
-----------------------
1. Peel Chain Detection
   Flags wallets that behave like a link in a "peel chain": a laundering
   pattern where a wallet receives a lump sum and forwards the bulk of it
   (>80%) onward to a single "change" address, peeling off a small amount
   (<20%) to one or more other addresses (often exchanges, mixers, or
   destination wallets). The heuristic also rewards nodes that sit inside a
   *chain* of such behavior (multiple hops), since isolated peels are far
   less suspicious than long repeating chains.

2. High Velocity Detection
   Flags wallets that hold funds for an unusually short amount of time
   before forwarding them -- a classic "pass-through" / layering signal.
   Velocity is estimated from the gap between when value arrives at a node
   and when it next leaves the node.

3. Structuring / Smurfing Detection
   Flags wallets that send many outgoing transactions of near-identical,
   sub-threshold value in a short window -- the on-chain analogue of
   structuring cash deposits to stay under a currency transaction report
   (CTR) threshold. Detection combines transaction count, value
   uniformity (coefficient of variation), and proximity to a configurable
   reporting threshold, within a rolling time window.

The engine combines heuristic sub-scores (each normalized to 0.0-1.0) into
a single weighted Risk Score on a 1.0-10.0 scale, and returns structured
evidence explaining *why* a wallet was scored the way it was.

Example
-------
    import networkx as nx
    from rules_engine import RiskScoringEngine

    g = nx.DiGraph()
    g.add_edge("A", "B", value=10.0, timestamp=1_700_000_000, tx_hash="0x1")
    g.add_edge("B", "C", value=8.5, timestamp=1_700_000_060, tx_hash="0x2")
    g.add_edge("B", "D", value=1.5, timestamp=1_700_000_060, tx_hash="0x3")

    engine = RiskScoringEngine(g)
    results = engine.analyze()

    for address, assessment in results.items():
        print(address, assessment.risk_score, assessment.risk_level)
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

try:
    import networkx as nx
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "rules_engine.py requires networkx. Install it with `pip install networkx`."
    ) from exc


logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

class HeuristicName(str, Enum):
    PEEL_CHAIN = "peel_chain"
    HIGH_VELOCITY = "high_velocity"
    STRUCTURING = "structuring"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EngineConfig:
    """Tunable thresholds and weights for the scoring engine."""

    # --- Peel chain heuristic ---
    peel_dominant_share_threshold: float = 0.80   # ">80% to one output" trigger
    peel_min_outputs: int = 2                      # needs a change AND a peel
    peel_chain_max_depth: int = 8                  # cap chain traversal
    peel_chain_bonus_per_hop: float = 0.08          # extra score per chained hop

    # --- High velocity heuristic ---
    high_velocity_seconds: float = 600.0            # < 10 minutes = high velocity
    extreme_velocity_seconds: float = 60.0           # < 1 minute = extreme

    # --- Structuring / smurfing heuristic ---
    structuring_min_transactions: int = 5            # min micro-txs to consider a burst
    structuring_window_seconds: float = 86_400.0     # rolling window (default 24h)
    structuring_reporting_threshold: float = 10.0     # on-chain equivalent of a CTR limit
    structuring_proximity_band: float = 0.25          # values within 25% below threshold count
    structuring_max_cv: float = 0.15                  # coefficient of variation "near-identical" cutoff
    structuring_min_unique_recipients: int = 1        # 1 = allow fan-out to a single address too

    # --- Weighting of sub-scores into the final risk score ---
    weight_peel_chain: float = 0.45
    weight_high_velocity: float = 0.30
    weight_structuring: float = 0.25

    # A single strongly-triggered heuristic contributes at least this
    # fraction of its own score to the final normalized risk, preventing
    # a lone strong red flag from being averaged away by quiet heuristics.
    single_heuristic_floor_factor: float = 0.65

    # --- Final score scaling ---
    min_score: float = 1.0
    max_score: float = 10.0

    # --- Risk level cut points, on the 1.0-10.0 scale ---
    level_medium_at: float = 4.0
    level_high_at: float = 6.5
    level_critical_at: float = 8.5


# --------------------------------------------------------------------------- #
# Result data model
# --------------------------------------------------------------------------- #

@dataclass
class HeuristicResult:
    """Normalized (0.0-1.0) output of a single heuristic for one node."""

    name: str
    score: float                     # 0.0 (no signal) - 1.0 (strong signal)
    triggered: bool
    evidence: Dict = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Full risk assessment for a single wallet node."""

    address: str
    risk_score: float                # 1.0 - 10.0
    risk_level: RiskLevel
    heuristics: List[HeuristicResult] = field(default_factory=list)

    def flags(self) -> List[str]:
        return [h.name for h in self.heuristics if h.triggered]

    def to_dict(self) -> Dict:
        return {
            "address": self.address,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level.value,
            "flags": self.flags(),
            "heuristics": [
                {
                    "name": h.name,
                    "score": round(h.score, 3),
                    "triggered": h.triggered,
                    "evidence": h.evidence,
                }
                for h in self.heuristics
            ],
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _to_epoch(ts) -> Optional[float]:
    """Coerce a timestamp field (int/float/datetime) into unix epoch seconds."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    try:
        return float(ts)
    except (TypeError, ValueError):
        logger.warning("Unrecognized timestamp format: %r", ts)
        return None


def _out_edges_with_data(graph: "nx.DiGraph", node) -> List[Tuple[str, str, dict]]:
    """Return outgoing edges for a node, handling MultiDiGraph transparently."""
    if graph.is_multigraph():
        return list(graph.out_edges(node, data=True, keys=False))
    return list(graph.out_edges(node, data=True))


def _in_edges_with_data(graph: "nx.DiGraph", node) -> List[Tuple[str, str, dict]]:
    if graph.is_multigraph():
        return list(graph.in_edges(node, data=True, keys=False))
    return list(graph.in_edges(node, data=True))


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class RiskScoringEngine:
    """
    Computes per-wallet Risk Scores (1.0-10.0) over a transaction graph
    using a set of composable heuristics.
    """

    def __init__(self, graph: "nx.DiGraph", config: Optional[EngineConfig] = None):
        if not isinstance(graph, nx.Graph):
            raise TypeError("graph must be a networkx Graph/DiGraph instance")
        if not graph.is_directed():
            raise ValueError(
                "rules_engine requires a directed graph (DiGraph/MultiDiGraph) "
                "so fund flow direction can be determined."
            )
        self.graph = graph
        self.config = config or EngineConfig()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze(self, nodes: Optional[Sequence[str]] = None) -> Dict[str, RiskAssessment]:
        """
        Run all heuristics over the graph and return a risk assessment for
        every requested node (or every node in the graph, by default).
        """
        target_nodes = list(nodes) if nodes is not None else list(self.graph.nodes)
        results: Dict[str, RiskAssessment] = {}

        for node in target_nodes:
            if node not in self.graph:
                logger.warning("Node %r not found in graph, skipping.", node)
                continue
            results[node] = self._assess_node(node)

        return results

    def score_node(self, node: str) -> RiskAssessment:
        """Convenience method to score a single wallet."""
        if node not in self.graph:
            raise KeyError(f"Node {node!r} not found in graph")
        return self._assess_node(node)

    # ------------------------------------------------------------------ #
    # Core scoring
    # ------------------------------------------------------------------ #

    def _assess_node(self, node: str) -> RiskAssessment:
        cfg = self.config
        heuristics = [
            self._detect_peel_chain(node),
            self._detect_high_velocity(node),
            self._detect_structuring(node),
        ]
        weights = [cfg.weight_peel_chain, cfg.weight_high_velocity, cfg.weight_structuring]

        weighted_sum = sum(h.score * w for h, w in zip(heuristics, weights))
        total_weight = sum(weights)
        weighted_avg = weighted_sum / total_weight if total_weight else 0.0

        # A weighted average alone can dilute a single strongly-triggered
        # heuristic (e.g. clear-cut smurfing with no peel-chain or velocity
        # signal present) down into a falsely reassuring LOW score. Apply a
        # floor so one high-confidence red flag can't be averaged away.
        max_individual = max((h.score for h in heuristics), default=0.0)
        floor = cfg.single_heuristic_floor_factor * max_individual
        normalized = max(weighted_avg, floor)
        normalized = max(0.0, min(1.0, normalized))

        risk_score = self.config.min_score + normalized * (
            self.config.max_score - self.config.min_score
        )

        return RiskAssessment(
            address=node,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            heuristics=heuristics,
        )

    def _risk_level(self, score: float) -> RiskLevel:
        cfg = self.config
        if score >= cfg.level_critical_at:
            return RiskLevel.CRITICAL
        if score >= cfg.level_high_at:
            return RiskLevel.HIGH
        if score >= cfg.level_medium_at:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    # ------------------------------------------------------------------ #
    # Heuristic: Peel Chain
    # ------------------------------------------------------------------ #

    def _detect_peel_chain(self, node: str) -> HeuristicResult:
        """
        A node is "peel-like" if its outgoing value is dominated by one edge
        (the "change", typically >80% of total outflow) while the remainder
        is "peeled off" to one or more other addresses (typically <20%).

        The score is boosted when this pattern repeats along the forward
        chain of change addresses (i.e. B -> C -> D -> ... each peeling),
        which is the real fingerprint of a peel chain as opposed to a
        single unremarkable split payment.
        """
        cfg = self.config
        local_hit, local_evidence = self._peel_pattern_at_node(node)

        chain_depth = 0
        chain_path: List[str] = [node]
        if local_hit:
            chain_depth, chain_path = self._trace_peel_chain(node)

        # Base score: 0 if no local pattern, else scaled by how dominant
        # the "change" output is (more dominant = more classic peel chain).
        if not local_hit:
            score = 0.0
        else:
            dominance = local_evidence.get("dominant_share", 0.0)
            # Map dominance in [threshold, 1.0] to base score in [0.5, 0.8]
            span = max(1e-9, 1.0 - cfg.peel_dominant_share_threshold)
            base = 0.5 + 0.3 * (
                (dominance - cfg.peel_dominant_share_threshold) / span
            )
            base = max(0.5, min(0.8, base))

            # Chain bonus: longer repeating chains are strong evidence of
            # deliberate layering rather than a coincidental split.
            chain_bonus = min(
                0.2, cfg.peel_chain_bonus_per_hop * max(0, chain_depth - 1)
            )
            score = min(1.0, base + chain_bonus)

        evidence = dict(local_evidence)
        evidence.update(
            {
                "chain_depth": chain_depth,
                "chain_path": chain_path if chain_depth > 1 else [],
            }
        )

        return HeuristicResult(
            name=HeuristicName.PEEL_CHAIN.value,
            score=score,
            triggered=local_hit,
            evidence=evidence,
        )

    def _peel_pattern_at_node(self, node: str) -> Tuple[bool, Dict]:
        """
        Check whether the outgoing edges of `node` match the peel pattern:
        one dominant "change" output >= threshold of total value, plus at
        least one smaller "peel" output.
        """
        cfg = self.config
        out_edges = _out_edges_with_data(self.graph, node)

        if len(out_edges) < cfg.peel_min_outputs:
            return False, {"reason": "insufficient_outputs", "num_outputs": len(out_edges)}

        values = [(dst, float(data.get("value", 0.0))) for _, dst, data in out_edges]
        total_out = sum(v for _, v in values)
        if total_out <= 0:
            return False, {"reason": "zero_total_outflow"}

        values.sort(key=lambda x: x[1], reverse=True)
        change_dst, change_val = values[0]
        dominant_share = change_val / total_out

        hit = dominant_share >= cfg.peel_dominant_share_threshold

        evidence = {
            "total_outflow": total_out,
            "num_outputs": len(values),
            "dominant_output": change_dst,
            "dominant_value": change_val,
            "dominant_share": dominant_share,
            "peel_outputs": [
                {"address": dst, "value": val, "share": val / total_out}
                for dst, val in values[1:]
            ],
        }
        return hit, evidence

    def _trace_peel_chain(self, start_node: str) -> Tuple[int, List[str]]:
        """
        Follow the "change" (dominant-value) output edge forward from
        `start_node` as long as the receiving node also exhibits the peel
        pattern, up to `peel_chain_max_depth` hops. Returns the depth of the
        chain (including the starting node) and the path traversed.
        """
        cfg = self.config
        path = [start_node]
        visited = {start_node}
        current = start_node

        for _ in range(cfg.peel_chain_max_depth):
            hit, evidence = self._peel_pattern_at_node(current)
            if not hit:
                break
            next_node = evidence.get("dominant_output")
            if next_node is None or next_node in visited:
                break
            path.append(next_node)
            visited.add(next_node)
            current = next_node

        return len(path), path

    # ------------------------------------------------------------------ #
    # Heuristic: High Velocity
    # ------------------------------------------------------------------ #

    def _detect_high_velocity(self, node: str) -> HeuristicResult:
        """
        Estimates how long funds typically sit in `node` before moving on.
        Short average/median holding times score higher (more suspicious).

        Holding time per "cycle" is approximated as:
            next_outgoing_timestamp - incoming_timestamp
        for each incoming transaction, matched to the earliest subsequent
        outgoing transaction (a conservative, order-based approximation
        rather than exact UTXO-style coin tracing, which Ethereum's
        account model doesn't have anyway).
        """
        cfg = self.config
        in_edges = _in_edges_with_data(self.graph, node)
        out_edges = _out_edges_with_data(self.graph, node)

        in_times = sorted(
            t for t in (_to_epoch(d.get("timestamp")) for _, _, d in in_edges) if t is not None
        )
        out_times = sorted(
            t for t in (_to_epoch(d.get("timestamp")) for _, _, d in out_edges) if t is not None
        )

        if not in_times or not out_times:
            return HeuristicResult(
                name=HeuristicName.HIGH_VELOCITY.value,
                score=0.0,
                triggered=False,
                evidence={"reason": "insufficient_timestamp_data"},
            )

        holding_times: List[float] = []
        oi = 0
        for in_t in in_times:
            # advance to the first outgoing timestamp at/after this inflow
            while oi < len(out_times) and out_times[oi] < in_t:
                oi += 1
            if oi >= len(out_times):
                break
            holding_times.append(out_times[oi] - in_t)

        if not holding_times:
            return HeuristicResult(
                name=HeuristicName.HIGH_VELOCITY.value,
                score=0.0,
                triggered=False,
                evidence={"reason": "no_matchable_in_out_pairs"},
            )

        median_hold = statistics.median(holding_times)
        min_hold = min(holding_times)

        triggered = median_hold < cfg.high_velocity_seconds

        # Score: 1.0 at/under extreme threshold, fading to 0.0 at the
        # high-velocity threshold and beyond.
        if median_hold <= cfg.extreme_velocity_seconds:
            score = 1.0
        elif median_hold >= cfg.high_velocity_seconds:
            score = 0.0
        else:
            span = cfg.high_velocity_seconds - cfg.extreme_velocity_seconds
            score = 1.0 - ((median_hold - cfg.extreme_velocity_seconds) / span)
        score = max(0.0, min(1.0, score))

        evidence = {
            "median_holding_seconds": median_hold,
            "min_holding_seconds": min_hold,
            "num_in_out_pairs": len(holding_times),
            "num_inflows": len(in_times),
            "num_outflows": len(out_times),
        }

        return HeuristicResult(
            name=HeuristicName.HIGH_VELOCITY.value,
            score=score,
            triggered=triggered,
            evidence=evidence,
        )

    # ------------------------------------------------------------------ #
    # Heuristic: Structuring / Smurfing
    # ------------------------------------------------------------------ #

    def _detect_structuring(self, node: str) -> HeuristicResult:
        """
        Flags "smurfing": a wallet fires off a burst of outgoing
        transactions with near-identical values, sized just under a
        monitoring/reporting threshold, within a short rolling window.

        This mirrors the classic cash-structuring pattern (e.g. multiple
        $9,800 deposits to stay under a $10,000 CTR threshold), adapted for
        on-chain transfers. The heuristic looks at every outgoing edge from
        `node`, groups them into rolling time windows, and within each
        window scores based on:
          - transaction count (more micro-txs = more suspicious)
          - value uniformity (low coefficient of variation = "near-identical")
          - proximity to (but under) the configured reporting threshold
          - number of unique recipients touched (fan-out is a stronger
            smurfing signal than repeatedly paying the same address, but is
            not required -- a single "structured drip" to one address is
            still flagged)

        The best-scoring window found for the node is reported as evidence.
        """
        cfg = self.config
        out_edges = _out_edges_with_data(self.graph, node)

        txs = []
        for _, dst, data in out_edges:
            ts = _to_epoch(data.get("timestamp"))
            val = data.get("value")
            if ts is None or val is None:
                continue
            txs.append((ts, dst, float(val)))

        if len(txs) < cfg.structuring_min_transactions:
            return HeuristicResult(
                name=HeuristicName.STRUCTURING.value,
                score=0.0,
                triggered=False,
                evidence={
                    "reason": "insufficient_outgoing_transactions",
                    "num_outgoing": len(txs),
                },
            )

        txs.sort(key=lambda t: t[0])

        best_score = 0.0
        best_evidence: Dict = {}
        best_triggered = False

        # Slide a window over the sorted transactions; for each starting
        # transaction, gather all subsequent ones within the configured
        # time window and evaluate the burst as a candidate structuring set.
        n = len(txs)
        left = 0
        for right in range(n):
            while txs[right][0] - txs[left][0] > cfg.structuring_window_seconds:
                left += 1
            window = txs[left : right + 1]
            if len(window) < cfg.structuring_min_transactions:
                continue

            score, triggered, evidence = self._score_structuring_window(window)
            if score > best_score:
                best_score = score
                best_triggered = triggered
                best_evidence = evidence

        if not best_evidence:
            return HeuristicResult(
                name=HeuristicName.STRUCTURING.value,
                score=0.0,
                triggered=False,
                evidence={"reason": "no_qualifying_burst_window"},
            )

        return HeuristicResult(
            name=HeuristicName.STRUCTURING.value,
            score=best_score,
            triggered=best_triggered,
            evidence=best_evidence,
        )

    def _score_structuring_window(
        self, window: List[Tuple[float, str, float]]
    ) -> Tuple[float, bool, Dict]:
        """
        Score a single candidate burst window of (timestamp, dst, value)
        outgoing transactions for structuring-like behavior. Returns
        (score in [0,1], triggered bool, evidence dict).
        """
        cfg = self.config
        values = [v for _, _, v in window]
        recipients = {dst for _, dst, _ in window}
        count = len(window)

        mean_val = statistics.fmean(values)
        stdev_val = statistics.pstdev(values) if count > 1 else 0.0
        cv = (stdev_val / mean_val) if mean_val > 0 else float("inf")

        threshold = cfg.structuring_reporting_threshold
        band_floor = threshold * (1.0 - cfg.structuring_proximity_band)
        # Fraction of transactions sitting just under the threshold, in the
        # "structuring band" (band_floor <= value < threshold).
        in_band = [v for v in values if band_floor <= v < threshold]
        proximity_fraction = len(in_band) / count if count else 0.0

        uniform = cv <= cfg.structuring_max_cv
        near_threshold = proximity_fraction >= 0.6  # most of the burst hugs the limit
        enough_recipients = len(recipients) >= cfg.structuring_min_unique_recipients

        triggered = uniform and near_threshold and enough_recipients

        # --- Sub-scores, each in [0, 1] ---
        # Uniformity: perfect (score 1.0) at cv=0, decays to 0 at 2x the cutoff.
        cv_cap = max(1e-9, cfg.structuring_max_cv * 2.0)
        uniformity_score = max(0.0, 1.0 - min(cv, cv_cap) / cv_cap)

        # Threshold proximity: reward values sitting just under the limit.
        proximity_score = proximity_fraction

        # Volume: more transactions in the burst is more suspicious, saturating
        # at 4x the minimum burst size.
        volume_score = min(
            1.0,
            (count - cfg.structuring_min_transactions)
            / max(1, cfg.structuring_min_transactions * 3),
        )
        volume_score = max(0.0, volume_score) * 0.5 + 0.5 if count >= cfg.structuring_min_transactions else 0.0

        # Fan-out bonus: spreading across multiple recipients (classic
        # "smurfing" via mule wallets) is a stronger signal than repeatedly
        # paying one address.
        fan_out_score = min(1.0, (len(recipients) - 1) / max(1, count - 1)) if count > 1 else 0.0

        score = (
            0.40 * uniformity_score
            + 0.30 * proximity_score
            + 0.15 * volume_score
            + 0.15 * fan_out_score
        )
        score = max(0.0, min(1.0, score)) if triggered or score > 0 else 0.0
        if not triggered:
            # Non-qualifying bursts are capped so they surface as low-signal
            # rather than as false positives dominating the final score.
            score = min(score, 0.35)

        evidence = {
            "window_start": window[0][0],
            "window_end": window[-1][0],
            "num_transactions": count,
            "num_unique_recipients": len(recipients),
            "mean_value": mean_val,
            "coefficient_of_variation": cv,
            "reporting_threshold": threshold,
            "fraction_near_threshold": proximity_fraction,
            "sample_values": values[:10],
            "sample_recipients": list(recipients)[:10],
        }

        return score, triggered, evidence


# --------------------------------------------------------------------------- #
# Convenience module-level function
# --------------------------------------------------------------------------- #

def analyze_graph(
    graph: "nx.DiGraph", config: Optional[EngineConfig] = None
) -> Dict[str, RiskAssessment]:
    """Functional shortcut: score every wallet in `graph` in one call."""
    return RiskScoringEngine(graph, config=config).analyze()


if __name__ == "__main__":
    # Minimal smoke test / usage demo when run directly (no GUI, console only).
    logging.basicConfig(level=logging.INFO)

    demo = nx.DiGraph()
    # A classic peel chain: A -> B -> C -> D, each hop peeling off a bit,
    # all happening within seconds of each other (high velocity too).
    demo.add_edge("A", "B", value=100.0, timestamp=1_700_000_000, tx_hash="0x1")
    demo.add_edge("B", "C", value=85.0, timestamp=1_700_000_030, tx_hash="0x2")
    demo.add_edge("B", "PeelWallet1", value=15.0, timestamp=1_700_000_030, tx_hash="0x3")
    demo.add_edge("C", "D", value=72.0, timestamp=1_700_000_060, tx_hash="0x4")
    demo.add_edge("C", "PeelWallet2", value=13.0, timestamp=1_700_000_060, tx_hash="0x5")
    # A normal, slow-moving wallet for contrast.
    demo.add_edge("X", "Y", value=5.0, timestamp=1_650_000_000, tx_hash="0x6")
    demo.add_edge("Y", "Z", value=5.0, timestamp=1_680_000_000, tx_hash="0x7")

    # A smurfing wallet: six near-identical, just-under-threshold payouts
    # to distinct mule wallets within a few hours.
    base_ts = 1_710_000_000
    for i, mule in enumerate(["M1", "M2", "M3", "M4", "M5", "M6"]):
        demo.add_edge(
            "Smurf",
            mule,
            value=9.7 + (i * 0.05),
            timestamp=base_ts + i * 900,
            tx_hash=f"0xs{i}",
        )

    engine = RiskScoringEngine(demo)
    assessments = engine.analyze()

    for address, assessment in sorted(
        assessments.items(), key=lambda kv: kv[1].risk_score, reverse=True
    ):
        print(
            f"{address:12s} risk={assessment.risk_score:5.2f} "
            f"level={assessment.risk_level.value:8s} flags={assessment.flags()}"
        )