## 아래 코드에 대한 보완사항.
## - 기존에는 In 1개인 노드 -> Through 1개 이상 노드 -> Out 1개 노드 였어
## - 이제는 공격의 entry point에 해당하는 노드 1개 이상 -> In 1개인 노드 -> Through 1개 이상 노드 -> Out 1개 노드
## - entry point에 해당하는 노드
##   -> 입력으로 받은 이름을 가진 Trust Boundary 또는 Trust Border를 기준으로 In, Through, Out의 위협이 적용될 수 있는 노드와 다른쪽에 있는 노드 


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tool-2: TM7(.tm7) DFD 파서 + 공격 그래프(JSON) 생성기

입력:
  1) tm7_path: 분석할 .tm7 파일 경로 (문자열)
  2) graph_type: "Remote/Adjacent" | "Local/Physical"
  3) target_asset_name: 공격자의 최종 목표 자산명(문자열)
  4) boundary_name: Entry point를 나누는 Trust Boundary/Border 이름(문자열)

추가 입력(코드 내 기본값 / CLI 옵션):
  - asset_to_threats.json: 자산명 -> (위협 id/name/tactics)
  - threat_to_tactic.json: threat_index + UnifiedKillChain (tactic -> phase)

출력:
  - JSON 공격 그래프 파일

강제 조건(중요):
  - 공격 경로(paths)는 반드시
      Entry >= 1  AND  In == 1  AND  Through >= 1  AND  Out == 1
    를 만족하는 경로만 포함

반영된 정책:
  1) Out phase 위협은 "Target 자산에서만" 선택 가능
  2) 경로 내에서 Target의 Out 노드가 중복으로 들어가는 버그 제거
  3) In을 만나면 entry-point 구간을 추가로 만들어 붙임 (boundary 기반)
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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
    """
    Extract <Properties> <anyType> ... <Name>/<DisplayName>/<Value> ...
    Returns dict keyed by Name (preferred) or DisplayName.
    """
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
# Path validity (강제 조건)
# -----------------------------
def path_phase_counts(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> Dict[str, int]:
    cnt = {"Entry": 0, "In": 0, "Through": 0, "Out": 0}
    for nid in path_node_ids:
        ph = graph_nodes.get(nid, {}).get("phase")
        if ph in cnt:
            cnt[ph] += 1
    return cnt


def is_valid_attack_path(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> bool:
    """
    유효 경로 조건(변경됨):
      - Entry >= 1
      - In == 1
      - Through >= 1
      - Out == 1
    """
    cnt = path_phase_counts(path_node_ids, graph_nodes)
    return (
        cnt["Entry"] >= 1
        and cnt["In"] == 1
        and cnt["Through"] >= 1
        and cnt["Out"] == 1
    )


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
    """
    Returns: asset_name -> list of threat objects {id,name,tactics[]}
    """
    data = json.loads(asset_to_threats_path.read_text(encoding="utf-8"))
    out: Dict[str, List[dict]] = {}
    for a in data.get("assets", []):
        name = a.get("asset_name")
        if not name:
            continue
        out.setdefault(name, [])
        out[name].extend(a.get("threats", []))
    return out


# -----------------------------
# TM7 parse
# -----------------------------
def parse_tm7(tm7_path: Path) -> Tuple[Dict[str, DFDNode], List[DFDFlow], List[dict]]:
    """
    Parse TM7 XML and return:
      - nodes_by_guid
      - flows (connectors)
      - boundaries: list of {guid,name,left,top,width,height}
    """
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

    # Trust Boundary / Border (TM7에서 BorderBoundary로 나오는 경우 확인됨)
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
) -> List[ThreatInfo]:
    threats = asset_to_threats.get(asset_name, [])
    cands: List[ThreatInfo] = []

    for th in threats:
        tid = th.get("id")
        tname = th.get("name") or tid
        tactics = th.get("tactics") or []
        for tactic in tactics:
            phase = tactic_to_phase.get(norm_tactic(tactic))
            if not phase:
                continue
            if require_phase and phase != require_phase:
                continue
            if PHASE_ORDER[phase] <= max_phase_allowed:
                cands.append(ThreatInfo(threat_id=tid, threat_name=tname, tactic=str(tactic), phase=phase))

    cands.sort(key=lambda x: PHASE_ORDER[x.phase], reverse=True)
    return cands


# -----------------------------
# Attack graph build (Remote/Adjacent)
# -----------------------------
@dataclass
class GraphBuildState:
    nodes_by_guid: Dict[str, DFDNode]
    flows: List[DFDFlow]
    incoming: Dict[str, List[DFDFlow]]
    asset_to_threats: Dict[str, List[dict]]
    tactic_to_phase: Dict[str, str]
    max_depth: int

    boundary_rect: dict
    side_of_guid: Dict[str, str]          # guid -> "inside" | "outside"
    threat_side: str                      # "inside" | "outside"
    entry_side: str                       # opposite of threat_side


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


def add_entry_chain_backward(
    st: GraphBuildState,
    from_guid: str,              # In 노드 GUID
    in_node_id: str,             # In threat node_id (graph node id)
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    """
    In 노드에서 더 역방향으로 확장하되,
    boundary 반대편(entry_side)에 있는 노드만 'Entry'로 path에 추가한다.
    Entry는 1개 이상이어야 하므로, entry를 하나라도 추가한 경로만 저장.
    """
    incoming_flows = st.incoming.get(from_guid, [])
    for flow in incoming_flows:
        src_guid = flow.source_guid
        if src_guid in visited_assets:
            continue

        # entry_side가 아닌 곳은 Entry로 추가하지 않고 더 올라가지 않는다(정의대로).
        # (필요하면 여기 로직을 "경유는 허용"으로 확장 가능)
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

        # path에 Entry 추가
        path_node_ids.append(entry_id)

        # edge: Entry -> In (DFD flow와 동일)
        graph_edges.add((entry_id, in_node_id, flow.guid))

        # Entry는 여러 개 가능: Entry 쪽에서 더 upstream으로 계속 확장
        visited_assets.add(src_guid)
        add_entry_chain_backward(
            st=st,
            from_guid=src_guid,
            in_node_id=entry_id,  # 이제 Entry 체인의 "현재 노드"로 연결을 이어가야 함
            visited_assets=visited_assets,
            path_node_ids=path_node_ids,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            all_paths=all_paths,
        )
        visited_assets.remove(src_guid)

        # leaf 처리: 지금까지 만든 경로가 유효하면 저장
        if is_valid_attack_path(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))

        path_node_ids.pop()


def dfs_backward(
    st: GraphBuildState,
    target_guid: str,  # Out은 이 target_guid에서만 허용
    cur_guid: str,
    allowed_max_phase: int,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    """
    Target Out에서 시작하여 incoming flow를 따라 역방향 확장.
    Through는 1개 이상, In은 정확히 1개가 되도록:
      - In을 선택하는 순간 더 이상 Threat 선택을 하지 않고 Entry chain을 만든 뒤 종료.
    """

    # depth limit
    if len(path_node_ids) >= st.max_depth:
        if is_valid_attack_path(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        if is_valid_attack_path(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    # ✅ Target Out 노드 중복 방지:
    # 이미 path 마지막이 target Out이면, target에서 threat를 다시 붙이지 말고 incoming만 탄다.
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

                dfs_backward(
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

    # Threat candidates
    cands = threat_candidates_for_asset(
        asset_name=dfd_node.name,
        asset_to_threats=st.asset_to_threats,
        tactic_to_phase=st.tactic_to_phase,
        max_phase_allowed=allowed_max_phase,
        require_phase=None,
    )

    if not cands:
        if is_valid_attack_path(path_node_ids, graph_nodes):
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

        # ✅ In은 "정확히 1개"여야 하므로:
        # In을 선택하는 순간, 더 이상 Threat를 쌓지 않고 Entry chain을 만든 뒤 종료/저장한다.
        if th.phase == "In":
            add_entry_chain_backward(
                st=st,
                from_guid=cur_guid,
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

        # incoming flow 따라 upstream 확장
        incoming_flows = st.incoming.get(cur_guid, [])
        for flow in incoming_flows:
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue

            visited_assets.add(src_guid)
            before_nodes = set(graph_nodes.keys())

            dfs_backward(
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


def build_attack_graph_remote_adjacent(
    tm7_path: Path,
    target_asset_name: str,
    boundary_name: str,
    asset_to_threats_path: Path,
    threat_to_tactic_path: Path,
    max_depth: int = 30,
) -> dict:
    nodes_by_guid, flows, boundaries = parse_tm7(tm7_path)
    incoming = build_incoming_index(flows)

    asset_to_threats = load_asset_threats(asset_to_threats_path)
    threat_to_tactic = json.loads(threat_to_tactic_path.read_text(encoding="utf-8"))
    tactic_to_phase = build_tactic_to_phase(threat_to_tactic)

    # boundary 선택
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

    # 각 노드가 boundary 안/밖인지(side) 계산
    rect = {"left": boundary["left"], "top": boundary["top"], "width": boundary["width"], "height": boundary["height"]}
    side_of_guid: Dict[str, str] = {}
    for g, n in nodes_by_guid.items():
        side_of_guid[g] = "inside" if is_inside_rect(n, rect) else "outside"

    # "위협이 적용될 수 있는 노드"의 side를 기준으로 threat_side 결정
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

    # target 찾기
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
    )

    any_start = False

    # 시작: Target에서 Out 위협이 있어야 함(Out은 target에서만)
    for tgt_guid in target_guids:
        tgt_node = nodes_by_guid[tgt_guid]

        out_cands = threat_candidates_for_asset(
            asset_name=tgt_node.name,
            asset_to_threats=asset_to_threats,
            tactic_to_phase=tactic_to_phase,
            max_phase_allowed=PHASE_ORDER["Out"],
            require_phase="Out",
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
            dfs_backward(
                st=st,
                target_guid=tgt_guid,
                cur_guid=tgt_guid,
                allowed_max_phase=PHASE_ORDER["Out"],
                visited_assets=visited_assets,
                path_node_ids=[start_node_id],  # Out은 1개로 시작
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

    # 최종 필터: 유효 경로만
    valid_paths_raw = [p for p in all_paths if is_valid_attack_path(p, graph_nodes)]
    if not valid_paths_raw:
        return {
            "ok": False,
            "reason": (
                f"목표 자산 '{target_asset_name}' 기준으로 탐색된 경로 중 "
                f"'Entry>=1 & In==1 & Through>=1 & Out==1' 조건을 만족하는 경로가 없습니다."
            ),
            "target_asset_name": target_asset_name,
            "boundary_name": boundary_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    # path는 현재 [Out ... Entry] (역방향 append 구조)이므로, 사용자 보기 좋게 Entry -> ... -> Out으로 뒤집어서 저장
    valid_paths = [list(reversed(p)) for p in valid_paths_raw]

    # prune: 경로에 등장한 node/edge만
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

    return {
        "ok": True,
        "target_asset_name": target_asset_name,
        "boundary_name": boundary_name,
        "tm7_path": str(tm7_path),
        "nodes": nodes_out,
        "edges": edges_out,
        "paths": valid_paths,  # ✅ Entry -> ... -> Out 순서로 저장
        "phase_order": ["Entry", "In", "Through", "Out"],
        "path_constraint": "Entry>=1 & In==1 & Through>=1 & Out==1",
        "out_phase_policy": "Out phase is allowed only on the target asset in this search.",
        "boundary_policy": {
            "boundary_rect": rect,
            "threat_side": threat_side,
            "entry_side": entry_side,
            "note": "Entry nodes are chosen from the opposite side of the boundary relative to threat-applicable nodes.",
        },
        "path_fix": "Target Out node duplication prevented; In triggers entry expansion.",
    }


# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="TM7 기반 공격 그래프(JSON) 생성 (Tool-2)")
    ap.add_argument("--tm7", required=True, help="분석할 .tm7 파일 경로")
    ap.add_argument("--type", required=True, choices=["Remote/Adjacent", "Local/Physical"], help="공격 그래프 유형")
    ap.add_argument("--target", required=True, help="공격자의 최종 목표 자산명(DFD 노드명과 동일해야 함)")
    ap.add_argument("--boundary", required=True, help="Entry point를 나누는 Trust Boundary/Border 이름(BorderBoundary Name)")
    ap.add_argument("--asset-map", default="asset_to_threats.json", help="asset_to_threats.json 경로")
    ap.add_argument("--threat-map", default="threat_to_tactic.json", help="threat_to_tactic.json 경로")
    ap.add_argument("--max-depth", type=int, default=30, help="DFS 최대 깊이(기본 30)")
    ap.add_argument("--out", default="attack_graph.json", help="출력 JSON 파일 경로")
    args = ap.parse_args()

    tm7_path = Path(args.tm7)
    if not tm7_path.exists():
        print(f"[ERROR] tm7 not found: {tm7_path}", file=sys.stderr)
        sys.exit(2)

    asset_map = Path(args.asset_map)
    threat_map = Path(args.threat_map)
    if not asset_map.exists():
        print(f"[ERROR] asset-map not found: {asset_map}", file=sys.stderr)
        sys.exit(2)
    if not threat_map.exists():
        print(f"[ERROR] threat-map not found: {threat_map}", file=sys.stderr)
        sys.exit(2)

    if args.type == "Remote/Adjacent":
        result = build_attack_graph_remote_adjacent(
            tm7_path=tm7_path,
            target_asset_name=args.target,
            boundary_name=args.boundary,
            asset_to_threats_path=asset_map,
            threat_to_tactic_path=threat_map,
            max_depth=args.max_depth,
        )
    else:
        raise NotImplementedError("Local/Physical 그래프 유형은 아직 구현되지 않았습니다.")

    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] wrote: {out_path}")
    if not result.get("ok", False):
        print(f"[INFO] reason: {result.get('reason')}")


if __name__ == "__main__":
    main()


'''
Exec command :

python parse_attack_graph_v06.py --tm7 "Automotive DFD_B.tm7" --type "Remote/Adjacent" --target "Door" --boundary "External Vehicle Boundary" --asset-map "asset_to_threats.json" --threat-map "threat_to_tactic.json" --out "attack_graph.json"



'''