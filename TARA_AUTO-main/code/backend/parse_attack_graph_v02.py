#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tool-2: TM7(.tm7) DFD 파서 + 공격 그래프(JSON) 생성기

입력:
  1) tm7_path: 분석할 .tm7 파일 경로 (문자열)
  2) graph_type: "Remote/Adjacent" | "Local/Physical"
  3) target_asset_name: 공격자의 최종 목표 자산명(문자열)

추가 입력(코드 내 기본값 / CLI 옵션):
  - asset_to_threats.json: 자산명 -> (위협 id/name/tactics)
  - threat_to_tactic.json: threat_index + UnifiedKillChain (tactic -> phase)

출력:
  - JSON 공격 그래프 파일

강제 조건(중요):
  - 공격 경로(paths)는 반드시
      In 적용 노드 >= 1  AND  Through 적용 노드 >= 1  AND  Out 적용 노드 >= 1
    를 만족하는 경로만 포함 (Out-only, In->Out 형태는 절대 저장되지 않음)
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
    """Strip XML namespace."""
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


# -----------------------------
# Data models
# -----------------------------
@dataclass(frozen=True)
class DFDNode:
    guid: str
    name: str
    stencil_type: str  # StencilRectangle/Ellipse/ParallelLines etc.


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
    cnt = {"In": 0, "Through": 0, "Out": 0}
    for nid in path_node_ids:
        ph = graph_nodes.get(nid, {}).get("phase")
        if ph in cnt:
            cnt[ph] += 1
    return cnt


def is_valid_attack_path(path_node_ids: List[str], graph_nodes: Dict[str, dict]) -> bool:
    """
    유효 경로 조건:
      - In >= 1, Through >= 1, Out >= 1
    """
    cnt = path_phase_counts(path_node_ids, graph_nodes)
    return cnt["In"] >= 1 and cnt["Through"] >= 1 and cnt["Out"] >= 1


# -----------------------------
# Load mappings
# -----------------------------
def norm_tactic(t: str) -> str:
    return " ".join((t or "").strip().split()).lower()


def build_tactic_to_phase(threat_to_tactic_json: dict) -> Dict[str, str]:
    """
    Build mapping: tactic(normalised) -> phase ("In"/"Through"/"Out")
    Uses threat_to_tactic.json["UnifiedKillChain"].
    """
    ukc = threat_to_tactic_json.get("UnifiedKillChain", {})
    tactic_to_phase: Dict[str, str] = {}

    for phase in ("In", "Through", "Out"):
        for tactic in ukc.get(phase, []):
            tactic_to_phase[norm_tactic(tactic)] = phase

    return tactic_to_phase


def load_asset_threats(asset_to_threats_path: Path) -> Dict[str, List[dict]]:
    """
    Returns: asset_name -> list of threat objects {id,name,tactics[]}
    Note: 동일 asset_name이 여러 번 나오는 경우 전부 합칩니다.
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
def parse_tm7(tm7_path: Path) -> Tuple[Dict[str, DFDNode], List[DFDFlow]]:
    """
    Parse TM7 XML and return:
      - nodes_by_guid
      - flows (connectors)
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
            nodes_by_guid[guid] = DFDNode(guid=guid, name=name, stencil_type=itype)

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

    return nodes_by_guid, flows


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
    """
    해당 asset_name에 대해 "현재 허용 phase(max_phase_allowed) 이하"인 위협 후보들을 리턴.
    - require_phase가 있으면 그 phase만 필터링.
    - 위협이 여러 tactics를 가지면, tactics 각각을 독립 후보로 취급
    """
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

    # 가능한 한 현재 max_phase_allowed에 가까운 후보 우선
    cands.sort(key=lambda x: PHASE_ORDER[x.phase], reverse=True)
    return cands


# -----------------------------
# Attack graph build (Remote/Adjacent)
# -----------------------------
@dataclass
class GraphBuildState:
    nodes_by_guid: Dict[str, DFDNode]
    flows: List[DFDFlow]
    incoming: Dict[str, List[DFDFlow]]  # target_guid -> list of flows
    asset_to_threats: Dict[str, List[dict]]
    tactic_to_phase: Dict[str, str]
    max_depth: int


def build_incoming_index(flows: List[DFDFlow]) -> Dict[str, List[DFDFlow]]:
    incoming: Dict[str, List[DFDFlow]] = {}
    for f in flows:
        incoming.setdefault(f.target_guid, []).append(f)
    return incoming


def make_graph_node_id(asset_guid: str, threat_id: str, phase: str, tactic: str) -> str:
    return f"{asset_guid}::{threat_id}::{phase}::{tactic}"


def dfs_backward(
    st: GraphBuildState,
    cur_guid: str,
    allowed_max_phase: int,
    visited_assets: Set[str],
    path_node_ids: List[str],
    graph_nodes: Dict[str, dict],
    graph_edges: Set[Tuple[str, str, str]],
    all_paths: List[List[str]],
):
    """
    목표 자산(cur_guid)에서 시작하여 들어오는 Data Flow를 따라 역방향 확장.

    all_paths에는 '유효 경로(In>=1 & Through>=1 & Out>=1)'만 저장한다.
    """

    # (A) max depth
    if len(path_node_ids) >= st.max_depth:
        if is_valid_attack_path(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        if is_valid_attack_path(path_node_ids, graph_nodes):
            all_paths.append(list(path_node_ids))
        return

    # 현재 자산 위협 후보(허용 phase 이하)
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

    extended_any = False  # 이번 단계에서 실제로 상류로 확장했는지 (확장 못하면 leaf 처리)

    for th in cands:
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

        # (B) In을 만나도 Through 포함 유효 조건 만족할 때만 저장
        if th.phase == "In":
            if is_valid_attack_path(path_node_ids, graph_nodes):
                all_paths.append(list(path_node_ids))
            path_node_ids.pop()
            continue

        next_allowed = PHASE_ORDER[th.phase]

        # 들어오는 데이터 플로우 따라 상류로 확장
        incoming_flows = st.incoming.get(cur_guid, [])
        for flow in incoming_flows:
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue

            visited_assets.add(src_guid)

            before_nodes = set(graph_nodes.keys())
            before_paths_len = len(all_paths)

            dfs_backward(
                st=st,
                cur_guid=src_guid,
                allowed_max_phase=next_allowed,
                visited_assets=visited_assets,
                path_node_ids=path_node_ids,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                all_paths=all_paths,
            )

            after_nodes = set(graph_nodes.keys())
            # 이번 확장으로 새로 생긴 상류 노드들(같은 src_guid prefix)을 현재 노드로 연결
            new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
            for up_id in new_upstream_nodes:
                graph_edges.add((up_id, node_id, flow.guid))

            # 확장 자체가 한 번이라도 일어나면 leaf가 아니다
            if len(all_paths) > before_paths_len or new_upstream_nodes:
                extended_any = True

            visited_assets.remove(src_guid)

        path_node_ids.pop()

    # (C) 더 이상 확장할 수 없는 leaf에서도 "유효 경로"만 저장
    # (단, 위 루프에서 In 처리로 저장이 되거나, 상류 확장을 통해 저장이 되었다면 중복 방지 필요)
    # 여기서는 path_node_ids가 호출 스택 기준으로 이미 복원(pop)되어서 leaf 저장이 애매해져서,
    # leaf 저장은 위쪽 (cands 없음/노드 없음/깊이 제한)에서만 수행하도록 두는 게 안전함.
    # => extended_any 플래그는 현재 구조에선 추가 저장에 사용하지 않음.


def build_attack_graph_remote_adjacent(
    tm7_path: Path,
    target_asset_name: str,
    asset_to_threats_path: Path,
    threat_to_tactic_path: Path,
    max_depth: int = 30,
) -> dict:
    nodes_by_guid, flows = parse_tm7(tm7_path)
    incoming = build_incoming_index(flows)

    asset_to_threats = load_asset_threats(asset_to_threats_path)
    threat_to_tactic = json.loads(threat_to_tactic_path.read_text(encoding="utf-8"))
    tactic_to_phase = build_tactic_to_phase(threat_to_tactic)

    # (1) 목표 자산명 동일 노드 찾기 (동명이인 허용)
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
    )

    any_start = False

    # 시작은 "목표 자산에서 Out phase 위협"이 있어야 함
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

    # (최종 방어) 유효 경로만 남김
    valid_paths = [p for p in all_paths if is_valid_attack_path(p, graph_nodes)]
    if not valid_paths:
        return {
            "ok": False,
            "reason": (
                f"목표 자산 '{target_asset_name}' 기준으로 탐색된 경로 중 "
                f"'In>=1 & Through>=1 & Out>=1' 조건을 만족하는 경로가 없습니다."
            ),
            "target_asset_name": target_asset_name,
            "nodes": [],
            "edges": [],
            "paths": [],
        }

    # (선택하지만 권장) 유효 경로에 등장한 node/edge만 남기기(prune)
    used_node_ids: Set[str] = set()
    for p in valid_paths:
        used_node_ids.update(p)

    # edges는 (from,to)가 모두 used_node_ids에 포함되는 것만 남김
    used_edges = set()
    for (src_node_id, dst_node_id, flow_guid) in graph_edges:
        if src_node_id in used_node_ids and dst_node_id in used_node_ids:
            used_edges.add((src_node_id, dst_node_id, flow_guid))

    # flow guid -> label 빠르게 찾기
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
        "tm7_path": str(tm7_path),
        "nodes": nodes_out,
        "edges": edges_out,
        "paths": valid_paths,
        "phase_order": ["In", "Through", "Out"],
        "path_constraint": "In>=1 & Through>=1 & Out>=1",
    }


# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="TM7 기반 공격 그래프(JSON) 생성 (Tool-2)")
    ap.add_argument("--tm7", required=True, help="분석할 .tm7 파일 경로")
    ap.add_argument("--type", required=True, choices=["Remote/Adjacent", "Local/Physical"], help="공격 그래프 유형")
    ap.add_argument("--target", required=True, help="공격자의 최종 목표 자산명(DFD 노드명과 동일해야 함)")
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
