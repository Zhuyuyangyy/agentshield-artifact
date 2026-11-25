"""
AgentBehaviorGraph - V3 Layer 1
===============================
redacted Agent redacted。

redacted Agent redacted：
- redacted（BehaviorNode）：Agent redacted + redacted + redacted + redacted
- redacted（BehaviorEdge）：Agent redacted（invoke/subagent/delegate）redacted
- redacted：redacted

redacted ToolCallRequest redacted，redacted/redacted。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

# redacted，redacted「redacted」。
_AMPLIFICATION_THRESHOLD = 0.1
# redacted「redacted」redacted（redacted get_critical_nodes redacted）。
_CRITICAL_RISK_THRESHOLD = 0.7


class NodeRiskStatus(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class BehaviorNode:
    """
    redacted：redacted
    """
    node_id: str = field(default_factory=lambda: f"node_{uuid.uuid4().hex[:8]}")
    agent_id: str = "unknown"
    session_id: str = "unknown"
    tool_name: str = ""
    params_summary: str = ""          # redacted（redacted，redacted）
    fuse_action: str = "allow"        # allow / block / human_review
    shadow_risk_score: float = 0.0    # V2 redacted
    risk_status: NodeRiskStatus = NodeRiskStatus.SAFE
    timestamp: datetime = field(default_factory=datetime.now)
    # redacted（redacted）
    downstream_risk_amplified: bool = False
    # redacted
    intervention_count: int = 0
    # redacted：redacted
    inherited_risk: float = 0.0
    # redacted（redacted）
    labels: list[str] = field(default_factory=list)
    # redacted
    metadata: dict = field(default_factory=dict)

    def is_risk_amplifier(self) -> bool:
        """redacted"""
        return self.downstream_risk_amplified

    def to_summary(self) -> dict:
        return {
            "node_id": self.node_id,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "fuse_action": self.fuse_action,
            "risk_score": self.shadow_risk_score,
            "risk_status": self.risk_status.value,
            "inherited_risk": round(self.inherited_risk, 3),
            "intervention_count": self.intervention_count,
        }


@dataclass
class BehaviorEdge:
    """
    redacted：redacted Agent redacted
    """
    edge_id: str = field(default_factory=lambda: f"edge_{uuid.uuid4().hex[:8]}")
    from_node_id: str = ""
    to_node_id: str = ""
    edge_type: str = "calls"          # calls / invokes / data_flow / returns
    # Pure transfer coefficient in [0, 1]. Risk lives on nodes, not edges: an
    # edge says how much of the upstream node's *total* risk reaches the
    # downstream node. It used to be set to the upstream node's own risk, while
    # propagation also multiplied by it -- so three chained calls attenuated
    # 0.8 as 0.8 * 0.8 * 0.8. One concept, one place.
    transfer_weight: float = 1.0
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def risk_flow(self) -> float:
        """Deprecated alias for :attr:`transfer_weight`."""
        return self.transfer_weight

    def to_summary(self) -> dict:
        return {
            "edge_id": self.edge_id,
            "from": self.from_node_id,
            "to": self.to_node_id,
            "type": self.edge_type,
            "transfer_weight": round(self.transfer_weight, 3),
        }


#: Default transfer coefficient per edge type. ``calls`` loses something
#: across an agent boundary; ``data_flow`` carries the value through intact.
TRANSFER_WEIGHTS = {
    "calls": 0.7,
    "invokes": 0.7,
    "data_flow": 1.0,
    "consumes": 1.0,
    "returns": 0.5,
}


def transfer_weight_for(edge_type: str) -> float:
    """Transfer coefficient for ``edge_type`` (unknown types default to 1.0)."""
    return TRANSFER_WEIGHTS.get(edge_type, 1.0)


class AgentBehaviorGraph:
    """
    Agent redacted

    redacted session redacted Agent redacted，
    redacted：
    - redacted
    - redacted
    - redacted（redacted）
    - redacted（redacted）
    - redacted
    """

    def __init__(self, session_id: str = "unknown"):
        self.session_id = session_id
        self.nodes: dict[str, BehaviorNode] = {}
        self.edges: dict[str, BehaviorEdge] = {}
        self._node_list: list[BehaviorNode] = []   # redacted
        self._adjacency: dict[str, list[str]] = {}  # node_id → [child_node_ids]
        # redacted
        self._total_risk_cache: dict[str, float] = {}
        self._dirty_nodes: set[str] = set()
        self._topo_cache: Optional[list[str]] = None
        # redacted（summary() redacted，O(1) redacted O(V)）
        self._status_counts: dict[NodeRiskStatus, int] = {
            status: 0 for status in NodeRiskStatus
        }
        self._action_counts: dict[str, int] = {}
        self._critical_node_ids: set[str] = set()

    # ─── redacted ──────────────────────────────────────────────

    def add_node(self, node: BehaviorNode) -> BehaviorNode:
        """redacted"""
        if node.node_id in self.nodes:
            # redacted（redacted）
            existing = self.nodes[node.node_id]
            before = (existing.risk_status, existing.fuse_action)
            for k, v in node.__dict__.items():
                if v != getattr(existing, k):
                    setattr(existing, k, v)
            self._bump_status_counters(before, existing)
            # redacted，redacted。
            self._mark_dirty(node.node_id)
            return existing

        self.nodes[node.node_id] = node
        self._node_list.append(node)
        self._adjacency[node.node_id] = []
        self._bump_status_counters(None, node)
        self._mark_dirty(node.node_id)
        return node

    def add_edge(self, edge: BehaviorEdge) -> BehaviorEdge:
        """redacted（Agent redacted）"""
        if edge.edge_id in self.edges:
            return self.edges[edge.edge_id]
        if edge.from_node_id not in self.nodes:
            raise ValueError(f"from_node {edge.from_node_id} not in graph")
        if edge.to_node_id not in self.nodes:
            raise ValueError(f"to_node {edge.to_node_id} not in graph")

        self.edges[edge.edge_id] = edge
        self._adjacency[edge.from_node_id].append(edge.to_node_id)
        # redacted，redacted。
        self._mark_dirty(edge.to_node_id)
        self._topo_cache = None
        return edge

    def add_tool_call_as_node(
        self,
        agent_id: str,
        tool_name: str,
        params_summary: str,
        fuse_action: str,
        shadow_risk_score: float,
        parent_node_id: Optional[str] = None,
        edge_type: str = "calls",
        inherited_risk: float = 0.0,
        labels: Optional[list[str]] = None,
    ) -> BehaviorNode:
        """
        redacted。
        redacted parent_node_id，redacted。
        """
        node = BehaviorNode(
            agent_id=agent_id,
            session_id=self.session_id,
            tool_name=tool_name,
            params_summary=params_summary,
            fuse_action=fuse_action,
            shadow_risk_score=shadow_risk_score,
            risk_status=self._score_to_status(shadow_risk_score),
            inherited_risk=inherited_risk,
            labels=labels or [],
        )
        self.add_node(node)

        if parent_node_id and parent_node_id in self.nodes:
            edge = BehaviorEdge(
                from_node_id=parent_node_id,
                to_node_id=node.node_id,
                edge_type=edge_type,
                # Transfer coefficient only -- the upstream node's risk is
                # already on that node, so putting it here too squared it.
                transfer_weight=transfer_weight_for(edge_type),
            )
            self.add_edge(edge)

        return node

    def update_node_risk(
        self,
        node_id: str,
        total_risk: float,
        fuse_action: Optional[str] = None,
    ) -> Optional[BehaviorNode]:
        """Write a governed risk back onto a node.

        Used by the engine's two-pass governance: the node is first inserted at
        its local risk so the parent edge exists, propagation then computes the
        effective risk, and this records that outcome so the graph, its counters
        and the audit chain all agree with the decision that was made.

        Marks the node dirty so the next propagation recomputes it and its
        descendants rather than serving a stale cache entry.
        """
        node = self.nodes.get(node_id)
        if node is None:
            return None

        before = (node.risk_status, node.fuse_action)
        node.shadow_risk_score = max(0.0, min(float(total_risk), 1.0))
        node.risk_status = self._score_to_status(node.shadow_risk_score)
        if fuse_action is not None:
            node.fuse_action = fuse_action
        self._bump_status_counters(before, node)
        self._mark_dirty(node_id)
        return node

    # ─── redacted ──────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[BehaviorNode]:
        return self.nodes.get(node_id)

    def get_session_nodes(self) -> list[BehaviorNode]:
        """redacted（redacted）"""
        return self._node_list

    def get_critical_nodes(self, threshold: float = 0.7) -> list[BehaviorNode]:
        """
        redacted（redacted + redacted）
        """
        return [
            n for n in self._node_list
            if n.shadow_risk_score >= threshold and n.downstream_risk_amplified
        ]

    def get_risk_path(self, start_node_id: str, end_node_id: str) -> list[BehaviorNode]:
        """redacted start redacted end redacted**redacted**。

        “redacted”redacted（redacted）redacted。
        redacted：redacted BFS redacted，docstring redacted
        "risk-weighted shortest path / higher risk = shorter effective distance"，
        redacted。

        redacted Dijkstra（redacted）；redacted，
        redacted，redacted。
        """
        if start_node_id not in self.nodes or end_node_id not in self.nodes:
            return []
        if start_node_id == end_node_id:
            return [self.nodes[start_node_id]]

        # redacted（redacted）redacted Dijkstra redacted“redacted”。
        best: dict[str, float] = {start_node_id: self._path_risk(self.nodes[start_node_id])}
        prev: dict[str, Optional[str]] = {start_node_id: None}
        # redacted：Python redacted，redacted。
        import heapq

        heap: list[tuple[float, str]] = [(-best[start_node_id], start_node_id)]
        settled: set[str] = set()

        while heap:
            # ``best`` remains the authoritative score; the heap only orders.
            _neg_score, node_id = heapq.heappop(heap)
            if node_id in settled:
                continue
            settled.add(node_id)
            if node_id == end_node_id:
                break

            for child_id in self._adjacency.get(node_id, []):
                if child_id not in self.nodes or child_id in settled:
                    continue
                candidate = best[node_id] + self._path_risk(self.nodes[child_id])
                if candidate > best.get(child_id, float("-inf")):
                    best[child_id] = candidate
                    prev[child_id] = node_id
                    heapq.heappush(heap, (-candidate, child_id))

        if end_node_id not in prev:
            return []

        # redacted
        path_ids: list[str] = []
        cursor: Optional[str] = end_node_id
        while cursor is not None:
            path_ids.append(cursor)
            cursor = prev.get(cursor)
        path_ids.reverse()
        return [self.nodes[nid] for nid in path_ids if nid in self.nodes]

    @staticmethod
    def _path_risk(node: BehaviorNode) -> float:
        """redacted（redacted）。"""
        return node.shadow_risk_score

    def get_downstream_nodes(self, node_id: str) -> list[BehaviorNode]:
        """redacted"""
        result = []
        visited = set()
        queue = list(self._adjacency.get(node_id, []))

        while queue:
            child_id = queue.pop(0)
            if child_id in visited:
                continue
            visited.add(child_id)
            if child_id in self.nodes:
                result.append(self.nodes[child_id])
                queue.extend(self._adjacency.get(child_id, []))

        return result

    def compute_risk_propagation(self) -> dict[str, float]:
        """redacted，redacted。

        redacted::

            local[node]      = node.shadow_risk_score
            total[node]      = max(local[node],
                                   max over incoming edges e of total[e.from] * e.transfer_weight)
            inherited[node]  = total[node] - local[node]

        redacted**redacted** ``total[node]``（redacted
        redacted），redacted ``risk_local_context`` redacted。
        redacted :attr:`BehaviorNode.inherited_risk` redacted
        ``inherited[node]`` —— redacted，redacted。

        redacted**redacted**（redacted），redacted、redacted：
        redacted。

        redacted**redacted**redacted：redacted（redacted/redacted，redacted
        redacted）redacted，redacted。redacted
        redacted「redacted」redacted，redacted，
        redacted。
        """
        if not self._node_list:
            return {}

        dirty = self._collect_dirty_nodes()
        if not dirty:
            # redacted：redacted（redacted）。
            return dict(self._total_risk_cache)

        order = self._topological_order()
        total_risk = dict(self._total_risk_cache)

        for nid in order:
            if nid not in dirty and nid in total_risk:
                continue  # redacted，redacted
            candidates = [
                total_risk[src] * flow
                for src, flow in self._incoming_edges(nid)
                if src in total_risk
            ]
            base = self.nodes[nid].shadow_risk_score if nid in self.nodes else 0.0
            total_risk[nid] = max([base, *candidates])

        # redacted inherited_risk（redacted），redacted。
        for nid, total in total_risk.items():
            if nid not in self.nodes:
                continue
            node = self.nodes[nid]
            inherited = max(0.0, total - node.shadow_risk_score)
            node.inherited_risk = inherited
            if inherited > _AMPLIFICATION_THRESHOLD:
                node.downstream_risk_amplified = True

        self._total_risk_cache = total_risk
        self._dirty_nodes.clear()
        return dict(total_risk)

    def _incoming_edges(self, node_id: str) -> list[tuple[str, float]]:
        """node_id redacted [(from, transfer_weight), ...]。"""
        edges = []
        for edge in self.edges.values():
            if edge.to_node_id == node_id and edge.from_node_id in self.nodes:
                edges.append((edge.from_node_id, edge.transfer_weight))
        return edges

    def _collect_dirty_nodes(self) -> set[str]:
        """redacted。

        redacted（redacted/redacted、redacted）redacted，redacted
        redacted —— redacted。
        """
        dirty = set(self._dirty_nodes)
        # redacted（redacted）redacted。
        if not self._total_risk_cache:
            dirty.update(self.nodes.keys())
        # redacted，redacted。
        frontier = list(dirty)
        while frontier:
            nid = frontier.pop()
            for child in self._adjacency.get(nid, []):
                if child in self.nodes and child not in dirty:
                    dirty.add(child)
                    frontier.append(child)
        return dirty

    def _mark_dirty(self, *node_ids: str) -> None:
        """redacted（redacted）。"""
        self._dirty_nodes.update(node_ids)

    def invalidate_risk_cache(self) -> None:
        """redacted，redacted compute redacted。"""
        self._total_risk_cache = {}
        self._dirty_nodes.clear()
        self._topo_cache = None

    def _topological_order(self) -> list[str]:
        """redacted。

        redacted Kahn redacted：redacted。redacted
        （agent redacted），redacted id redacted，redacted
        redacted。

        redacted：redacted**redacted**，redacted。
        redacted，redacted
        redacted。
        """
        if self._topo_cache is not None:
            return self._topo_cache

        out_edges: dict[str, list[str]] = {
            nid: list(children) for nid, children in self._adjacency.items()
        }
        in_degree: dict[str, int] = {nid: 0 for nid in self.nodes}
        for nid, children in out_edges.items():
            for child in children:
                if child in in_degree:
                    in_degree[child] += 1

        ready = sorted(nid for nid, deg in in_degree.items() if deg == 0)
        order: list[str] = []
        seen: set[str] = set()

        while ready:
            nid = ready.pop(0)
            if nid in seen:
                continue
            seen.add(nid)
            order.append(nid)
            newly_ready = []
            for child in out_edges.get(nid, []):
                if child not in in_degree:
                    continue
                in_degree[child] -= 1
                if in_degree[child] == 0 and child not in seen:
                    newly_ready.append(child)
            if newly_ready:
                ready.extend(sorted(newly_ready))

        # redacted：redacted，redacted
        for nid in sorted(self.nodes):
            if nid not in seen:
                order.append(nid)

        self._topo_cache = order
        return order

    def to_graph_dict(self) -> dict:
        """redacted dict（redacted）"""
        return {
            "session_id": self.session_id,
            "nodes": [n.to_summary() for n in self._node_list],
            "edges": [e.to_summary() for e in self.edges.values()],
            "critical_nodes": [n.node_id for n in self.get_critical_nodes()],
        }

    # ─── redacted ──────────────────────────────────────────────

    @staticmethod
    def _score_to_status(score: float) -> NodeRiskStatus:
        if score >= 0.90:
            return NodeRiskStatus.CRITICAL
        elif score >= 0.70:
            return NodeRiskStatus.HIGH
        elif score >= 0.50:
            return NodeRiskStatus.MEDIUM
        elif score >= 0.20:
            return NodeRiskStatus.LOW
        return NodeRiskStatus.SAFE

    def summary(self) -> dict:
        """redacted。

        redacted :meth:`_bump_status_counters` redacted，
        redacted O(1) redacted O(V)。redacted ``process_tool_call``
        redacted summary，redacted。
        """
        return {
            "session_id": self.session_id,
            "total_nodes": len(self._node_list),
            "total_edges": len(self.edges),
            "risk_distribution": {
                status.value: self._status_counts[status]
                for status in NodeRiskStatus
            },
            "critical_node_count": len(self._critical_node_ids),
            "blocked_count": self._action_counts.get("block", 0),
            "review_count": self._action_counts.get("human_review", 0),
        }

    # ─── redacted ───────────────────────────────────────────

    def _bump_status_counters(self, before, node: BehaviorNode) -> None:
        """redacted。

        ``before`` redacted ``None`` redacted；redacted
        ``(risk_status, fuse_action)`` redacted。
        """
        if before is not None:
            old_status, old_action = before
            if old_status != node.risk_status:
                self._status_counts[old_status] -= 1
                self._status_counts[node.risk_status] += 1
            if old_action != node.fuse_action:
                self._action_counts[old_action] = (
                    self._action_counts.get(old_action, 0) - 1
                )
                self._action_counts[node.fuse_action] = (
                    self._action_counts.get(node.fuse_action, 0) + 1
                )
        else:
            self._status_counts[node.risk_status] += 1
            self._action_counts[node.fuse_action] = (
                self._action_counts.get(node.fuse_action, 0) + 1
            )
        self._refresh_critical(node)

    def _refresh_critical(self, node: BehaviorNode) -> None:
        """redacted shadow_risk_score / amplified redacted。"""
        is_critical = (
            node.shadow_risk_score >= _CRITICAL_RISK_THRESHOLD
            and node.downstream_risk_amplified
        )
        if is_critical:
            self._critical_node_ids.add(node.node_id)
        else:
            self._critical_node_ids.discard(node.node_id)
