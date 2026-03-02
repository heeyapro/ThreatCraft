#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from graphviz import Digraph

# -----------------------------
# TM7 helpers
# -----------------------------
def local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag

def get_child_text(el: ET.Element, child_name: str) -> Optional[str]:
    for c in el:
        if local(c.tag) == child_name:
            return c.text
    return None

def get_itype(el: ET.Element) -> Optional[str]:
    for k, v in el.attrib.items():
        if k.endswith("type"):
            return v
    return None

def extract_properties(el: ET.Element) -> Dict[str, Optional[str]]:
    props: Dict[str, Optional[str]] = {}
    props_el = None
    for c in el:
        if local(c.tag) == "Properties":
            props_el = c
            break
    if props_el is None:
        return props
    for anytype in list(props_el):
        name = None
        disp = None
        value = None
        for c in list(anytype):
            t = local(c.tag)
            if t == "Name":
                name = c.text
            elif t == "DisplayName":
                disp = c.text
            elif t == "Value":
                value = c.text
        key = name or disp
        if key is not None:
            props[key] = value
    return props

def safe_float(x: Optional[str]) -> Optional[float]:
    if x is None:
        return None
    try:
        return float(x)
    except ValueError:
        return None


# -----------------------------
# Data models
# -----------------------------
@dataclass(frozen=True)
class DFDNode:
    guid: str
    name: str
    stencil_type: str
    left: float
    top: float
    width: float
    height: float

@dataclass(frozen=True)
class DFDFlow:
    guid: str
    source_guid: str
    target_guid: str
    label: Optional[str]

@dataclass(frozen=True)
class ThreatInfo:
    threat_id: str
    threat_name: str
    tactic: str
    phase: str  # In/Through/Out

PHASE_ORDER = {"In": 0, "Through": 1, "Out": 2}


# -----------------------------
# Path validity (Remote/Adjacent)  - unchanged
# -----------------------------
def path_phase_counts_remote(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> Dict[str, int]:
    cnt = {"Entry": 0, "In": 0, "Through": 0, "Out": 0}
    for nid in path_node_ids:
        ph = graph_nodes.get(nid, {}).get("phase")
        if ph in cnt:
            cnt[ph] += 1
    return cnt

def is_valid_attack_path_remote(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> bool:
    cnt = path_phase_counts_remote(path_node_ids, graph_nodes)
    return (
        cnt["Entry"] == 1
        and cnt["In"] == 1
        and cnt["Through"] >= 1
        and cnt["Out"] == 1
    )


# -----------------------------
# Path validity (Local/Physical) - CHANGED to In->Through+->Out
# -----------------------------
def path_phase_counts_local(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> Dict[str, int]:
    cnt = {"In": 0, "Through": 0, "Out": 0}
    for nid in path_node_ids:
        ph = graph_nodes.get(nid, {}).get("phase")
        if ph in cnt:
            cnt[ph] += 1
    return cnt

def is_valid_attack_path_local(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> bool:
    """
    Local/Physical 유효 경로(수정 후):
      - In == 1
      - Through >= 1
      - Out == 1
      - (Entry는 사용하지 않음)
    """
    cnt = path_phase_counts_local(path_node_ids, graph_nodes)
    return (cnt["In"] == 1 and cnt["Through"] >= 1 and cnt["Out"] == 1)

def dedupe_paths(paths: List[List[str]]) -> List[List[str]]:
    """Remove fully identical paths while preserving the first-seen order."""
    seen: Set[Tuple[str, ...]] = set()
    out: List[List[str]] = []
    for p in paths:
        key = tuple(p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


# -----------------------------
# Merged DFD subgraph helpers
# -----------------------------
def build_merged_dfd_subgraph(
    *,
    used_node_ids: Set[str],
    used_edges: Set[Tuple[str, str, str]],
    graph_nodes: Dict[str, dict],
    nodes_by_guid: Dict[str, DFDNode],
    flows: List[DFDFlow],
    paths: List[List[str]],
) -> dict:
    """Build a DFD-level subgraph that is the union of all identified attack paths."""
    used_asset_guids: Set[str] = set()
    for nid in used_node_ids:
        g = graph_nodes.get(nid, {}).get('asset_guid')
        if g:
            used_asset_guids.add(g)

    dfd_nodes_out: List[dict] = []
    for g in sorted(used_asset_guids):
        n = nodes_by_guid.get(g)
        if not n:
            continue
        dfd_nodes_out.append({
            'guid': n.guid,
            'name': n.name,
            'stencil_type': n.stencil_type,
            'left': n.left,
            'top': n.top,
            'width': n.width,
            'height': n.height,
        })

    flow_map: Dict[str, DFDFlow] = {f.guid: f for f in flows}
    used_flow_guids: Set[str] = {fg for (_, _, fg) in used_edges if fg}

    dfd_edges_out: List[dict] = []
    for fg in sorted(used_flow_guids):
        f = flow_map.get(fg)
        if not f:
            continue
        dfd_edges_out.append({
            'guid': f.guid,
            'source_guid': f.source_guid,
            'target_guid': f.target_guid,
            'label': f.label,
        })

    start_asset_guids: Set[str] = set()
    end_asset_guids: Set[str] = set()
    for p in paths:
        if not p:
            continue
        s = graph_nodes.get(p[0], {}).get('asset_guid')
        e = graph_nodes.get(p[-1], {}).get('asset_guid')
        if s:
            start_asset_guids.add(s)
        if e:
            end_asset_guids.add(e)

    return {
        'dfd_nodes': dfd_nodes_out,
        'dfd_edges': dfd_edges_out,
        'start_asset_guids': sorted(start_asset_guids),
        'end_asset_guids': sorted(end_asset_guids),
        'node_count': len(dfd_nodes_out),
        'edge_count': len(dfd_edges_out),
    }


# -----------------------------
# Load mappings
# -----------------------------
def norm_tactic(t: str) -> str:
    return " ".join((t or "").strip().split()).lower()

def build_tactic_to_phase(threat_to_tactic_json: dict) -> Dict[str, str]:
    ukc = threat_to_tactic_json.get("UnifiedKillChain", {})
    tactic_to_phase: Dict[str, str] = {}
    for phase in ("In", "Through", "Out"):
        for tactic in ukc.get(phase, []):
            tactic_to_phase[norm_tactic(tactic)] = phase
    return tactic_to_phase

def load_asset_threats(asset_to_threats_path: Path) -> Dict[str, List[dict]]:
    data = json.loads(asset_to_threats_path.read_text(encoding="utf-8"))
    out: Dict[str, List[dict]] = {}
    for a in data.get("assets", []):
        name = a.get("asset_name")
        if not name:
            continue
        out.setdefault(name, [])
        out[name].extend(a.get("threats", []))
    return out

# ✅ NEW: attack_vector_feasability.json 로드
def load_attack_vectors(attack_vector_path: Path) -> Dict[str, Set[str]]:
    """
    threat_id -> {"remote","local","adjacent","physical"} (소문자 집합)
    파일 포맷은 아래 둘 중 하나를 허용:
      - {"threats":[{"id":..., "attack_vector":[...]} ...]}
      - [{"id":..., "attack_vector":[...]} ...]
    """
    raw = json.loads(attack_vector_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        items = raw.get("threats", [])
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    out: Dict[str, Set[str]] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        tid = it.get("id") or it.get("threat_id")
        if not tid:
            continue
        vecs = it.get("attack_vector") or it.get("attack_vectors") or []
        if isinstance(vecs, str):
            vecset = {vecs.strip().lower()}
        else:
            vecset = {str(v).strip().lower() for v in vecs if v is not None}
        if vecset:
            out[str(tid)] = vecset
    return out


# -----------------------------
# TM7 parse
# -----------------------------
def parse_tm7(tm7_path: Path) -> Tuple[Dict[str, DFDNode], List[DFDFlow], List[dict]]:
    tree = ET.parse(str(tm7_path))
    root = tree.getroot()

    node_types = {"StencilRectangle", "StencilEllipse", "StencilParallelLines"}
    nodes_by_guid: Dict[str, DFDNode] = {}

    for el in root.iter():
        itype = get_itype(el)
        if itype in node_types:
            guid = get_child_text(el, "Guid")
            if not guid:
                continue
            props = extract_properties(el)
            name = props.get("Name") or props.get("Label") or props.get("DisplayName") or guid
            name = name.strip() if isinstance(name, str) else str(name)
            left = safe_float(get_child_text(el, "Left")) or 0.0
            top = safe_float(get_child_text(el, "Top")) or 0.0
            width = safe_float(get_child_text(el, "Width")) or 0.0
            height = safe_float(get_child_text(el, "Height")) or 0.0
            nodes_by_guid[guid] = DFDNode(
                guid=guid,
                name=name,
                stencil_type=itype,
                left=left,
                top=top,
                width=width,
                height=height,
            )

    flows: List[DFDFlow] = []
    for el in root.iter():
        if get_itype(el) != "Connector":
            continue
        guid = get_child_text(el, "Guid")
        src = get_child_text(el, "SourceGuid")
        dst = get_child_text(el, "TargetGuid")
        if not guid or not src or not dst:
            continue
        props = extract_properties(el)
        label = props.get("Name") or props.get("Label") or None
        flows.append(DFDFlow(guid=guid, source_guid=src, target_guid=dst, label=label))

    boundaries: List[dict] = []
    for el in root.iter():
        if get_itype(el) != "BorderBoundary":
            continue
        guid = get_child_text(el, "Guid")
        props = extract_properties(el)
        name = (props.get("Name") or "").strip()
        left = safe_float(get_child_text(el, "Left")) or 0.0
        top = safe_float(get_child_text(el, "Top")) or 0.0
        width = safe_float(get_child_text(el, "Width")) or 0.0
        height = safe_float(get_child_text(el, "Height")) or 0.0
        boundaries.append(
            {
                "guid": guid,
                "name": name,
                "left": left,
                "top": top,
                "width": width,
                "height": height,
            }
        )

    return nodes_by_guid, flows, boundaries


# -----------------------------
# Threat selection / phase logic
# -----------------------------
def threat_candidates_for_asset(
    asset_name: str,
    asset_to_threats: Dict[str, List[dict]],
    tactic_to_phase: Dict[str, str],
    max_phase_allowed: int,
    require_phase: Optional[str] = None,
    # ✅ NEW: In-phase only filtering by attack vector + mode
    in_attack_vector_required: Optional[str] = None,
    attack_vectors_by_threat: Optional[Dict[str, Set[str]]] = None,
) -> List[ThreatInfo]:
    threats = asset_to_threats.get(asset_name, [])
    cands: List[ThreatInfo] = []

    need_vec = (in_attack_vector_required or "").strip().lower()
    vec_map = attack_vectors_by_threat or {}

    for th in threats:
        tid = th.get("id")
        if not tid:
            continue
        tid = str(tid)
        tname = th.get("name") or tid
        tactics = th.get("tactics") or []
        for tactic in tactics:
            phase = tactic_to_phase.get(norm_tactic(tactic))
            if not phase:
                continue
            if require_phase and phase != require_phase:
                continue
            if PHASE_ORDER[phase] > max_phase_allowed:
                continue

            # ✅ 핵심: In일 때만 mode 기반 attack_vector 제약 적용
            if phase == "In" and need_vec:
                allowed_vecs = vec_map.get(tid, set())
                if need_vec not in allowed_vecs:
                    continue

            cands.append(ThreatInfo(threat_id=tid, threat_name=tname, tactic=str(tactic), phase=phase))

    cands.sort(key=lambda x: PHASE_ORDER[x.phase], reverse=True)
    return cands


# -----------------------------
# Attack graph shared state
# -----------------------------
@dataclass
class GraphBuildState:
    nodes_by_guid: Dict[str, DFDNode]
    flows: List[DFDFlow]
    incoming: Dict[str, List[DFDFlow]]
    asset_to_threats: Dict[str, List[dict]]
    tactic_to_phase: Dict[str, str]
    max_depth: int

    # Remote/Adjacent에서만 사용
    boundary_rect: Optional[dict] = None
    side_of_guid: Optional[Dict[str, str]] = None
    threat_side: Optional[str] = None
    entry_side: Optional[str] = None

    # ✅ NEW: mode + attack_vector map (In 제약에만 사용)
    mode: Optional[str] = None  # remote/adjacent/local/physical
    attack_vectors_by_threat: Optional[Dict[str, Set[str]]] = None

def build_incoming_index(flows: List[DFDFlow]) -> Dict[str, List[DFDFlow]]:
    incoming: Dict[str, List[DFDFlow]] = {}
    for f in flows:
        incoming.setdefault(f.target_guid, []).append(f)
    return incoming

def make_graph_node_id(asset_guid: str, threat_id: str, phase: str, tactic: str) -> str:
    return f"{asset_guid}::{threat_id}::{phase}::{tactic}"

def make_entry_node_id(asset_guid: str) -> str:
    return f"{asset_guid}::ENTRY"

def is_inside_rect(node: DFDNode, rect: dict) -> bool:
    return (
        node.left >= rect["left"]
        and node.top >= rect["top"]
        and (node.left + node.width) <= (rect["left"] + rect["width"])
        and (node.top + node.height) <= (rect["top"] + rect["height"])
    )


# -----------------------------
# Remote/Adjacent: Entry 생성 (unchanged)
# -----------------------------
def add_single_entry_before_in(
    st: GraphBuildState,
    in_guid: str,
    in_node_id: str,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    incoming_flows = st.incoming.get(in_guid, [])
    for flow in incoming_flows:
        src_guid = flow.source_guid
        if src_guid in visited_assets:
            continue
        if not st.side_of_guid or not st.entry_side:
            continue
        if st.side_of_guid.get(src_guid) != st.entry_side:
            continue
        src_node = st.nodes_by_guid.get(src_guid)
        if not src_node:
            continue
        entry_id = make_entry_node_id(src_guid)
        if entry_id not in graph_nodes:
            graph_nodes[entry_id] = {
                "node_id": entry_id,
                "asset_guid": src_guid,
                "asset_name": src_node.name,
                "stencil_type": src_node.stencil_type,
                "phase": "Entry",
                "threat_id": None,
                "threat_name": None,
                "tactic": None,
            }
        path_node_ids.append(entry_id)
        graph_edges.add((entry_id, in_node_id, flow.guid))
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        path_node_ids.pop()


# -----------------------------
# Remote/Adjacent DFS (only change: In 후보에 mode attack_vector 제약 적용)
# -----------------------------
def dfs_backward_remote(
    st: GraphBuildState,
    target_guid: str,
    cur_guid: str,
    allowed_max_phase: int,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    if len(path_node_ids) >= st.max_depth:
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    # Target Out 중복 방지
    if cur_guid == target_guid and path_node_ids:
        last_id = path_node_ids[-1]
        last_node = graph_nodes.get(last_id, {})
        if last_node.get("asset_guid") == target_guid and last_node.get("phase") == "Out":
            incoming_flows = st.incoming.get(cur_guid, [])
            for flow in incoming_flows:
                src_guid = flow.source_guid
                if src_guid in visited_assets:
                    continue
                visited_assets.add(src_guid)
                before_nodes = set(graph_nodes.keys())
                dfs_backward_remote(
                    st=st,
                    target_guid=target_guid,
                    cur_guid=src_guid,
                    allowed_max_phase=allowed_max_phase,
                    visited_assets=visited_assets,
                    path_node_ids=path_node_ids,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                    all_paths=all_paths,
                )
                after_nodes = set(graph_nodes.keys())
                new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
                for up_id in new_upstream_nodes:
                    graph_edges.add((up_id, last_id, flow.guid))
                visited_assets.remove(src_guid)
            return

    cands = threat_candidates_for_asset(
        asset_name=dfd_node.name,
        asset_to_threats=st.asset_to_threats,
        tactic_to_phase=st.tactic_to_phase,
        max_phase_allowed=allowed_max_phase,
        require_phase=None,
        in_attack_vector_required=st.mode,  # ✅ remote/adjacent
        attack_vectors_by_threat=st.attack_vectors_by_threat,
    )
    if not cands:
        if is_valid_attack_path_remote(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    for th in cands:
        if th.phase == "Out" and cur_guid != target_guid:
            continue

        node_id = make_graph_node_id(dfd_node.guid, th.threat_id, th.phase, th.tactic)
        if node_id not in graph_nodes:
            graph_nodes[node_id] = {
                "node_id": node_id,
                "asset_guid": dfd_node.guid,
                "asset_name": dfd_node.name,
                "stencil_type": dfd_node.stencil_type,
                "threat_id": th.threat_id,
                "threat_name": th.threat_name,
                "phase": th.phase,
                "tactic": th.tactic,
            }

        path_node_ids.append(node_id)

        if th.phase == "In":
            add_single_entry_before_in(
                st=st,
                in_guid=cur_guid,
                in_node_id=node_id,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )
            path_node_ids.pop()
            continue

        next_allowed = PHASE_ORDER[th.phase]
        incoming_flows = st.incoming.get(cur_guid, [])
        for flow in incoming_flows:
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue
            visited_assets.add(src_guid)
            before_nodes = set(graph_nodes.keys())
            dfs_backward_remote(
                st=st,
                target_guid=target_guid,
                cur_guid=src_guid,
                allowed_max_phase=next_allowed,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )
            after_nodes = set(graph_nodes.keys())
            new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
            for up_id in new_upstream_nodes:
                graph_edges.add((up_id, node_id, flow.guid))
            visited_assets.remove(src_guid)

        path_node_ids.pop()


# -----------------------------
# Local/Physical DFS (CHANGED to include In, and stop at In)
# -----------------------------
def dfs_backward_local_physical(
    st: GraphBuildState,
    target_guid: str,
    cur_guid: str,
    allowed_max_phase: int,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    """
    Local/Physical (수정 후):
      - Out은 target에서만
      - 경로 유효 조건: In==1 & Through>=1 & Out==1
      - Entry는 사용하지 않음
      - In은 "시작점" 역할: In을 선택하면 더 이상 upstream으로 진행하지 않고 경로 완성 여부만 판단
    """
    if len(path_node_ids) >= st.max_depth:
        if is_valid_attack_path_local(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        if is_valid_attack_path_local(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    # Target Out 중복 방지: Remote와 동일 패턴
    if cur_guid == target_guid and path_node_ids:
        last_id = path_node_ids[-1]
        last_node = graph_nodes.get(last_id, {})
        if last_node.get("asset_guid") == target_guid and last_node.get("phase") == "Out":
            incoming_flows = st.incoming.get(cur_guid, [])
            for flow in incoming_flows:
                src_guid = flow.source_guid
                if src_guid in visited_assets:
                    continue
                visited_assets.add(src_guid)
                before_nodes = set(graph_nodes.keys())
                dfs_backward_local_physical(
                    st=st,
                    target_guid=target_guid,
                    cur_guid=src_guid,
                    allowed_max_phase=allowed_max_phase,
                    visited_assets=visited_assets,
                    path_node_ids=path_node_ids,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                    all_paths=all_paths,
                )
                after_nodes = set(graph_nodes.keys())
                new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
                for up_id in new_upstream_nodes:
                    graph_edges.add((up_id, last_id, flow.guid))
                visited_assets.remove(src_guid)
            return

    cands = threat_candidates_for_asset(
        asset_name=dfd_node.name,
        asset_to_threats=st.asset_to_threats,
        tactic_to_phase=st.tactic_to_phase,
        max_phase_allowed=allowed_max_phase,
        require_phase=None,
        in_attack_vector_required=st.mode,  # ✅ local or physical
        attack_vectors_by_threat=st.attack_vectors_by_threat,
    )
    if not cands:
        if is_valid_attack_path_local(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    for th in cands:
        # Out은 target에서만
        if th.phase == "Out" and cur_guid != target_guid:
            continue

        node_id = make_graph_node_id(dfd_node.guid, th.threat_id, th.phase, th.tactic)
        if node_id not in graph_nodes:
            graph_nodes[node_id] = {
                "node_id": node_id,
                "asset_guid": dfd_node.guid,
                "asset_name": dfd_node.name,
                "stencil_type": dfd_node.stencil_type,
                "threat_id": th.threat_id,
                "threat_name": th.threat_name,
                "phase": th.phase,
                "tactic": th.tactic,
            }

        path_node_ids.append(node_id)

        # ✅ In을 선택하면: 여기서 경로 완성 여부만 체크하고 종료(더 upstream으로 안 감)
        if th.phase == "In":
            if is_valid_attack_path_local(path_node_ids, graph_nodes):
                all_paths.append(list(path_node_ids))
            path_node_ids.pop()
            continue

        # Through/Out은 계속 upstream 탐색
        next_allowed = PHASE_ORDER[th.phase]
        incoming_flows = st.incoming.get(cur_guid, [])
        for flow in incoming_flows:
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue
            visited_assets.add(src_guid)
            before_nodes = set(graph_nodes.keys())
            dfs_backward_local_physical(
                st=st,
                target_guid=target_guid,
                cur_guid=src_guid,
                allowed_max_phase=next_allowed,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )
            after_nodes = set(graph_nodes.keys())
            new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
            for up_id in new_upstream_nodes:
                graph_edges.add((up_id, node_id, flow.guid))
            visited_assets.remove(src_guid)

        path_node_ids.pop()


# -----------------------------
# Build: Remote or Adjacent  (기존 로직 유지 + mode별 In 필터만 추가)
# -----------------------------
def build_attack_graph_remote_adjacent(
    tm7_path: Path,
    target_asset_name: str,
    boundary_name: str,
    asset_to_threats_path: Path,
    threat_to_tactic_path: Path,
    attack_vector_path: Path,
    mode: str,  # "remote" or "adjacent"
    max_depth: int = 30,
) -> dict:
    nodes_by_guid, flows, boundaries = parse_tm7(tm7_path)
    incoming = build_incoming_index(flows)
    asset_to_threats = load_asset_threats(asset_to_threats_path)
    threat_to_tactic = json.loads(threat_to_tactic_path.read_text(encoding="utf-8"))
    tactic_to_phase = build_tactic_to_phase(threat_to_tactic)

    attack_vectors_by_threat = load_attack_vectors(attack_vector_path)

    boundary = None
    for b in boundaries:
        if b.get("name") == boundary_name:
            boundary = b
            break
    if boundary is None:
        return {
            "ok": False,
            "reason": f"TM7에서 BorderBoundary 이름 '{boundary_name}' 을 찾지 못했습니다.",
            "tm7_path": str(tm7_path),
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    rect = {"left": boundary["left"], "top": boundary["top"], "width": boundary["width"], "height": boundary["height"]}
    side_of_guid: Dict[str, str] = {}
    for g, n in nodes_by_guid.items():
        side_of_guid[g] = "inside" if is_inside_rect(n, rect) else "outside"

    threat_applicable_guids: List[str] = []
    for g, n in nodes_by_guid.items():
        if n.name in asset_to_threats and asset_to_threats.get(n.name):
            threat_applicable_guids.append(g)
    if not threat_applicable_guids:
        return {
            "ok": False,
            "reason": "asset_to_threats 매핑 기준으로 위협이 적용되는 DFD 노드를 하나도 찾지 못했습니다.",
            "tm7_path": str(tm7_path),
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    inside_cnt = sum(1 for g in threat_applicable_guids if side_of_guid.get(g) == "inside")
    outside_cnt = len(threat_applicable_guids) - inside_cnt
    threat_side = "inside" if inside_cnt >= outside_cnt else "outside"
    entry_side = "outside" if threat_side == "inside" else "inside"

    target_guids = [g for g, n in nodes_by_guid.items() if n.name == target_asset_name]
    if not target_guids:
        return {
            "ok": False,
            "reason": f"DFD에서 자산명 '{target_asset_name}' 과 동일한 요소를 찾지 못했습니다.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    graph_nodes: Dict[str, dict] = {}
    graph_edges: Set[Tuple[str, str, str]] = set()
    all_paths: List[List[str]] = []

    st = GraphBuildState(
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        incoming=incoming,
        asset_to_threats=asset_to_threats,
        tactic_to_phase=tactic_to_phase,
        max_depth=max_depth,
        boundary_rect=rect,
        side_of_guid=side_of_guid,
        threat_side=threat_side,
        entry_side=entry_side,
        mode=mode,
        attack_vectors_by_threat=attack_vectors_by_threat,
    )

    any_start = False
    for tgt_guid in target_guids:
        tgt_node = nodes_by_guid[tgt_guid]
        out_cands = threat_candidates_for_asset(
            asset_name=tgt_node.name,
            asset_to_threats=asset_to_threats,
            tactic_to_phase=tactic_to_phase,
            max_phase_allowed=PHASE_ORDER["Out"],
            require_phase="Out",
            in_attack_vector_required=mode,
            attack_vectors_by_threat=attack_vectors_by_threat,
        )
        if not out_cands:
            continue

        any_start = True
        for out_th in out_cands:
            start_node_id = make_graph_node_id(tgt_guid, out_th.threat_id, out_th.phase, out_th.tactic)
            if start_node_id not in graph_nodes:
                graph_nodes[start_node_id] = {
                    "node_id": start_node_id,
                    "asset_guid": tgt_guid,
                    "asset_name": tgt_node.name,
                    "stencil_type": tgt_node.stencil_type,
                    "threat_id": out_th.threat_id,
                    "threat_name": out_th.threat_name,
                    "phase": out_th.phase,
                    "tactic": out_th.tactic,
                }
            visited_assets = {tgt_guid}
            dfs_backward_remote(
                st=st,
                target_guid=tgt_guid,
                cur_guid=tgt_guid,
                allowed_max_phase=PHASE_ORDER["Out"],
                visited_assets=visited_assets,
                path_node_ids=[start_node_id],
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

    if not any_start:
        return {
            "ok": False,
            "reason": f"목표 자산 '{target_asset_name}' 에 Out phase 위협이 없어 공격 그래프를 만들 수 없습니다.",
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths_raw = [p for p in all_paths if is_valid_attack_path_remote(p, graph_nodes)]
    valid_paths_raw = dedupe_paths(valid_paths_raw)
    if not valid_paths_raw:
        return {
            "ok": False,
            "reason": (
                f"목표 자산 '{target_asset_name}' 기준으로 탐색된 경로 중 "
                f"'Entry==1 & In==1 & Through>=1 & Out==1' 조건을 만족하는 경로가 없습니다."
            ),
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths = [list(reversed(p)) for p in valid_paths_raw]

    used_node_ids: Set[str] = set()
    for p in valid_paths_raw:
        used_node_ids.update(p)

    used_edges = set()
    for (src_node_id, dst_node_id, flow_guid) in graph_edges:
        if src_node_id in used_node_ids and dst_node_id in used_node_ids:
            used_edges.add((src_node_id, dst_node_id, flow_guid))

    flow_label_map = {f.guid: f.label for f in flows}
    edges_out = []
    for (src_node_id, dst_node_id, flow_guid) in sorted(used_edges):
        edges_out.append(
            {
                "from": src_node_id,
                "to": dst_node_id,
                "dfd_flow_guid": flow_guid,
                "dfd_flow_label": flow_label_map.get(flow_guid),
            }
        )

    nodes_out = [graph_nodes[nid] for nid in used_node_ids if nid in graph_nodes]
    merged_dfd_subgraph = build_merged_dfd_subgraph(
        used_node_ids=used_node_ids,
        used_edges=used_edges,
        graph_nodes=graph_nodes,
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        paths=valid_paths,
    )

    return {
        "ok": True,
        "mode": mode,
        "target_asset_name": target_asset_name,
        "boundary_name": boundary_name,
        "tm7_path": str(tm7_path),
        "nodes": nodes_out,
        "edges": edges_out,
        "paths": valid_paths,
        "merged_dfd_subgraph": merged_dfd_subgraph,
        "phase_order": ["Entry", "In", "Through", "Out"],
        "path_constraint": "Entry==1 & In==1 & Through>=1 & Out==1",
        "in_phase_policy": {
            "attack_vector_mode": mode,
            "attack_vector_map": str(attack_vector_path),
            "note": "Only threats with matching attack_vector are allowed as In."
        },
        "out_phase_policy": "Out phase is allowed only on the target asset in this search.",
        "boundary_policy": {
            "boundary_rect": rect,
            "threat_side": threat_side,
            "entry_side": entry_side,
            "note": "Entry node is chosen from the opposite side of the boundary relative to threat-applicable nodes (exactly one Entry per path).",
        },
    }


# -----------------------------
# Build: Local or Physical (CHANGED: now finds In->Through+->Out)
# -----------------------------
def build_attack_graph_local_physical(
    tm7_path: Path,
    target_asset_name: str,
    asset_to_threats_path: Path,
    threat_to_tactic_path: Path,
    attack_vector_path: Path,
    mode: str,  # "local" or "physical"
    max_depth: int = 30,
) -> dict:
    nodes_by_guid, flows, _boundaries = parse_tm7(tm7_path)
    incoming = build_incoming_index(flows)
    asset_to_threats = load_asset_threats(asset_to_threats_path)
    threat_to_tactic = json.loads(threat_to_tactic_path.read_text(encoding="utf-8"))
    tactic_to_phase = build_tactic_to_phase(threat_to_tactic)

    attack_vectors_by_threat = load_attack_vectors(attack_vector_path)

    target_guids = [g for g, n in nodes_by_guid.items() if n.name == target_asset_name]
    if not target_guids:
        return {
            "ok": False,
            "reason": f"DFD에서 자산명 '{target_asset_name}' 과 동일한 요소를 찾지 못했습니다.",
            "target_asset_name": target_asset_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    graph_nodes: Dict[str, dict] = {}
    graph_edges: Set[Tuple[str, str, str]] = set()
    all_paths: List[List[str]] = []

    st = GraphBuildState(
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        incoming=incoming,
        asset_to_threats=asset_to_threats,
        tactic_to_phase=tactic_to_phase,
        max_depth=max_depth,
        mode=mode,
        attack_vectors_by_threat=attack_vectors_by_threat,
    )

    any_start = False
    for tgt_guid in target_guids:
        tgt_node = nodes_by_guid[tgt_guid]
        out_cands = threat_candidates_for_asset(
            asset_name=tgt_node.name,
            asset_to_threats=asset_to_threats,
            tactic_to_phase=tactic_to_phase,
            max_phase_allowed=PHASE_ORDER["Out"],
            require_phase="Out",
            in_attack_vector_required=mode,
            attack_vectors_by_threat=attack_vectors_by_threat,
        )
        if not out_cands:
            continue

        any_start = True
        for out_th in out_cands:
            start_node_id = make_graph_node_id(tgt_guid, out_th.threat_id, out_th.phase, out_th.tactic)
            if start_node_id not in graph_nodes:
                graph_nodes[start_node_id] = {
                    "node_id": start_node_id,
                    "asset_guid": tgt_guid,
                    "asset_name": tgt_node.name,
                    "stencil_type": tgt_node.stencil_type,
                    "threat_id": out_th.threat_id,
                    "threat_name": out_th.threat_name,
                    "phase": out_th.phase,
                    "tactic": out_th.tactic,
                }
            visited_assets = {tgt_guid}
            dfs_backward_local_physical(
                st=st,
                target_guid=tgt_guid,
                cur_guid=tgt_guid,
                allowed_max_phase=PHASE_ORDER["Out"],
                visited_assets=visited_assets,
                path_node_ids=[start_node_id],
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

    if not any_start:
        return {
            "ok": False,
            "reason": f"목표 자산 '{target_asset_name}' 에 Out phase 위협이 없어 공격 그래프를 만들 수 없습니다.",
            "target_asset_name": target_asset_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths_raw = [p for p in all_paths if is_valid_attack_path_local(p, graph_nodes)]
    valid_paths_raw = dedupe_paths(valid_paths_raw)
    if not valid_paths_raw:
        return {
            "ok": False,
            "reason": (
                f"목표 자산 '{target_asset_name}' 기준으로 탐색된 경로 중 "
                f"'In==1 & Through>=1 & Out==1' 조건을 만족하는 경로가 없습니다."
            ),
            "target_asset_name": target_asset_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    valid_paths = [list(reversed(p)) for p in valid_paths_raw]

    used_node_ids: Set[str] = set()
    for p in valid_paths_raw:
        used_node_ids.update(p)

    used_edges = set()
    for (src_node_id, dst_node_id, flow_guid) in graph_edges:
        if src_node_id in used_node_ids and dst_node_id in used_node_ids:
            used_edges.add((src_node_id, dst_node_id, flow_guid))

    flow_label_map = {f.guid: f.label for f in flows}
    edges_out = []
    for (src_node_id, dst_node_id, flow_guid) in sorted(used_edges):
        edges_out.append(
            {
                "from": src_node_id,
                "to": dst_node_id,
                "dfd_flow_guid": flow_guid,
                "dfd_flow_label": flow_label_map.get(flow_guid),
            }
        )

    nodes_out = [graph_nodes[nid] for nid in used_node_ids if nid in graph_nodes]
    merged_dfd_subgraph = build_merged_dfd_subgraph(
        used_node_ids=used_node_ids,
        used_edges=used_edges,
        graph_nodes=graph_nodes,
        nodes_by_guid=nodes_by_guid,
        flows=flows,
        paths=valid_paths,
    )

    return {
        "ok": True,
        "mode": mode,
        "target_asset_name": target_asset_name,
        "tm7_path": str(tm7_path),
        "nodes": nodes_out,
        "edges": edges_out,
        "paths": valid_paths,
        "merged_dfd_subgraph": merged_dfd_subgraph,
        "phase_order": ["In", "Through", "Out"],
        "path_constraint": "In==1 & Through>=1 & Out==1",
        "in_phase_policy": {
            "attack_vector_mode": mode,
            "attack_vector_map": str(attack_vector_path),
            "note": "Only threats with matching attack_vector are allowed as In."
        },
        "out_phase_policy": "Out phase is allowed only on the target asset in this search.",
        "note": "Local/Physical now includes In and searches In->Through->Out paths (no Entry).",
    }


# -----------------------------
# Graphviz rendering (merged DFD subgraph) - unchanged
# -----------------------------
def _shape_from_stencil(stencil_type: str) -> str:
    if stencil_type == "StencilParallelLines":
        return "cylinder"
    if stencil_type == "StencilEllipse":
        return "circle"
    return "box"

def _phase_style(phases: Set[str]) -> Tuple[str, str]:
    p = set(phases)
    p.discard(None)
    if p == {"Out"}:
        return "red", "Out"
    if p == {"In"}:
        return "lightgreen", "In"
    if p == {"Through"}:
        return "orange", "Through"
    if p.issuperset({"In", "Through"}) and "Out" not in p:
        return "orange", "In/Through"
    if p == {"Entry"}:
        return "lightgrey", "Entry"
    if "Out" in p:
        return "red", "/".join(sorted(p))
    if "Through" in p:
        note = "In/Through" if "In" in p else "Through"
        return "orange", note
    if "In" in p:
        return "lightgreen", "In"
    return "white", ""

def wrap_label(text: str, max_len: int = 14) -> str:
    words = text.split(" ")
    lines = []
    cur = ""
    for w in words:
        if len(cur) + len(w) <= max_len:
            cur = (cur + " " + w).strip()
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return "<BR/>".join(lines)

def render_merged_attack_graph_graphviz(
    result: dict,
    out_prefix: Path | str,
    fmt: str = "png",
    font: str = "Malgun Gothic",
) -> Optional[Path]:
    if not result.get("ok"):
        return None
    out_prefix = Path(out_prefix)
    merged = result.get("merged_dfd_subgraph") or {}
    dfd_nodes = merged.get("dfd_nodes") or []
    dfd_edges = merged.get("dfd_edges") or []
    if not dfd_nodes:
        return None

    phases_by_guid: Dict[str, Set[str]] = {}
    for n in (result.get("nodes") or []):
        g = n.get("asset_guid")
        ph = n.get("phase")
        if not g or not ph:
            continue
        phases_by_guid.setdefault(g, set()).add(ph)

    dot = Digraph("MergedAttackGraph", format=fmt)
    dot.attr("graph", fontname=font)
    dot.attr(
        "node",
        fontname=font,
        fontsize="12",
        style="filled",
        fixedsize="true",
        width="1.8",
        height="1.8",
    )
    dot.attr("edge", fontname=font, fontsize="10", color="black")

    for n in dfd_nodes:
        guid = n.get("guid")
        name = n.get("name") or guid
        stencil = n.get("stencil_type") or ""
        phases = phases_by_guid.get(guid, set())
        fillcolor, note = _phase_style(phases)
        shape = _shape_from_stencil(stencil)
        if note:
            wrapped_name = wrap_label(name)
            label = (
                f"<<B><FONT POINT-SIZE='12'>{wrapped_name}</FONT></B>"
                f"<BR/><FONT POINT-SIZE='9'>{note}</FONT>>"
            )
        else:
            label = f"<<B>{name}</B>>"
        dot.node(guid, label=label, shape=shape, fillcolor=fillcolor)

    for e in dfd_edges:
        src = e.get("source_guid")
        dst = e.get("target_guid")
        if not src or not dst:
            continue
        lbl = e.get("label")
        if lbl:
            dot.edge(src, dst, label=str(lbl))
        else:
            dot.edge(src, dst)

    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    rendered = dot.render(str(out_prefix), cleanup=True)
    return Path(rendered)


# -----------------------------
# CLI  (CHANGED: 4 modes + attack_vector map)
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="TM7 기반 공격 그래프(JSON) 생성 (Tool-2)")
    ap.add_argument("--tm7", required=True, help="분석할 .tm7 파일 경로")
    ap.add_argument("--type", required=True, choices=["remote", "adjacent", "local", "physical"], help="탐색 모드")
    ap.add_argument("--target", required=True, help="공격자의 최종 목표 자산명(DFD 노드명과 동일해야 함)")
    ap.add_argument("--boundary", default="", help="(remote/adjacent 전용) Trust Boundary/Border 이름(BorderBoundary Name)")
    ap.add_argument("--asset-map", default="asset_to_threats.json", help="asset_to_threats.json 경로")
    ap.add_argument("--threat-map", default="threat_to_tactic.json", help="threat_to_tactic.json 경로")
    ap.add_argument("--attack-vector-map", default="attack_vector_feasability.json", help="attack_vector_feasability.json 경로")
    ap.add_argument("--max-depth", type=int, default=30, help="DFS 최대 깊이(기본 30)")
    ap.add_argument("--out", default="attack_graph.json", help="출력 JSON 파일 경로")
    ap.add_argument(
        "--render-graph",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="병합된 공격 그래프(DFD 서브그래프)를 Graphviz로 렌더링할지 여부 (기본: 렌더링)",
    )
    ap.add_argument(
        "--graph-out",
        default="../out/merged_attack_graph",
        help="Graphviz 출력 파일 prefix (확장자 제외). 예: out/merged_attack_graph",
    )
    ap.add_argument(
        "--graph-format",
        default="png",
        choices=["png", "svg", "pdf"],
        help="Graphviz 출력 포맷 (기본: png)",
    )

    args = ap.parse_args()

    tm7_path = Path(args.tm7)
    if not tm7_path.exists():
        print(f"[ERROR] tm7 not found: {tm7_path}", file=sys.stderr)
        sys.exit(2)

    asset_map = Path(args.asset_map)
    threat_map = Path(args.threat_map)
    attack_vector_map = Path(args.attack_vector_map)

    if not asset_map.exists():
        print(f"[ERROR] asset-map not found: {asset_map}", file=sys.stderr)
        sys.exit(2)
    if not threat_map.exists():
        print(f"[ERROR] threat-map not found: {threat_map}", file=sys.stderr)
        sys.exit(2)
    if not attack_vector_map.exists():
        print(f"[ERROR] attack-vector-map not found: {attack_vector_map}", file=sys.stderr)
        sys.exit(2)

    if args.type in ("remote", "adjacent"):
        if not args.boundary:
            print("[ERROR] --boundary is required for remote/adjacent", file=sys.stderr)
            sys.exit(2)
        result = build_attack_graph_remote_adjacent(
            tm7_path=tm7_path,
            target_asset_name=args.target,
            boundary_name=args.boundary,
            asset_to_threats_path=asset_map,
            threat_to_tactic_path=threat_map,
            attack_vector_path=attack_vector_map,
            mode=args.type,
            max_depth=args.max_depth,
        )
    else:
        result = build_attack_graph_local_physical(
            tm7_path=tm7_path,
            target_asset_name=args.target,
            asset_to_threats_path=asset_map,
            threat_to_tactic_path=threat_map,
            attack_vector_path=attack_vector_map,
            mode=args.type,
            max_depth=args.max_depth,
        )

    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] wrote: {out_path}")
    path_count = len(result.get("paths") or [])
    print(f"[INFO] identified attack paths: {path_count}")

    if not result.get("ok", False):
        print(f"[INFO] reason: {result.get('reason')}")
        return

    if args.render_graph:
        try:
            rendered = render_merged_attack_graph_graphviz(
                result,
                out_prefix=args.graph_out,
                fmt=args.graph_format,
            )
            print(f"[OK] rendered merged attack graph: {rendered}")
        except Exception as e:
            print(f"[WARN] graphviz rendering failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
"""
Exec examples:

# remote
python parse_attack_graph_v14.py --tm7 "../in/Automotive DFD_B.tm7" --type remote --target "Door" --boundary "External Vehicle Boundary" --asset-map "threat_library/asset_to_threats_ver0.1.json" --threat-map "threat_library/threat_to_tactic.json" --attack-vector-map "threat_library/attack_vector_feasibility.json" --out "../out/attack_graph_remote.json" --graph-out "../out/merged_attack_graph_remote"

# adjacent
python parse_attack_graph_v14.py --tm7 "../in/Automotive DFD_B.tm7" --type adjacent --target "Door" --boundary "External Vehicle Boundary" --asset-map "threat_library/asset_to_threats_ver0.1.json" --threat-map "threat_library/threat_to_tactic.json" --attack-vector-map "threat_library/attack_vector_feasibility.json" --out "../out/attack_graph_adjacent.json" --graph-out "../out/merged_attack_graph_adjacent"

# local
python parse_attack_graph_v14.py --tm7 "../in/Automotive DFD_B.tm7" --type local --target "Door" --boundary "External Vehicle Boundary" --asset-map "threat_library/asset_to_threats_ver0.1.json" --threat-map "threat_library/threat_to_tactic.json" --attack-vector-map "threat_library/attack_vector_feasibility.json" --out "../out/attack_graph_local.json" --graph-out "../out/merged_attack_graph_local"

# physical
python parse_attack_graph_v14.py --tm7 "../in/Automotive DFD_B.tm7" --type physical --target "Door" --boundary "External Vehicle Boundary" --asset-map "threat_library/asset_to_threats_ver0.1.json" --threat-map "threat_library/threat_to_tactic.json" --attack-vector-map "threat_library/attack_vector_feasibility.json" --out "../out/attack_graph_physical.json" --graph-out "../out/merged_attack_graph_physical"
"""