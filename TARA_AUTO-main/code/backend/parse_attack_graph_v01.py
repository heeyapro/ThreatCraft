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
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Iterable


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

    # 흔한 대소문자/표기 차이 보정 (예: "credential access" vs "Credential Access")
    # norm_tactic로 흡수되긴 하지만, 혹시 모를 변형 대비.
    if norm_tactic("Credential Access") in tactic_to_phase:
        tactic_to_phase[norm_tactic("credential access")] = tactic_to_phase[norm_tactic("Credential Access")]

    return tactic_to_phase


def load_asset_threats(asset_to_threats_path: Path) -> Dict[str, List[dict]]:
    """
    Returns: asset_name -> list of threat objects {id,name,tactics[]}
    Note: 동일 asset_name이 여러 번 나오는 경우(예: Sensors) 전부 합칩니다.
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

    # 1) Nodes: StencilRectangle / StencilEllipse / StencilParallelLines
    node_types = {"StencilRectangle", "StencilEllipse", "StencilParallelLines"}
    nodes_by_guid: Dict[str, DFDNode] = {}

    for el in root.iter():
        itype = get_itype(el)
        if itype in node_types:
            guid = get_child_text(el, "Guid")
            if not guid:
                continue
            props = extract_properties(el)
            # tm7에서 실질적인 라벨은 Properties["Name"]에 들어있는 경우가 많음
            name = props.get("Name") or props.get("Label") or props.get("DisplayName") or guid
            name = name.strip() if isinstance(name, str) else str(name)
            nodes_by_guid[guid] = DFDNode(guid=guid, name=name, stencil_type=itype)

    # 2) Flows: i:type="Connector"
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
    - 위협이 여러 tactics를 가지면, tactics 각각을 독립 후보로 취급 (노드엔 tactic 1개만 넣기 위함)
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
                # UnifiedKillChain에 없는 tactic이면 phase 판정 불가 → 제외
                continue
            if require_phase and phase != require_phase:
                continue
            if PHASE_ORDER[phase] <= max_phase_allowed:
                cands.append(ThreatInfo(threat_id=tid, threat_name=tname, tactic=str(tactic), phase=phase))

    # “이전 phase와 같거나 선행되는 phase” 조건을 더 자연스럽게 만들려면,
    # 가능한 한 현재 max_phase_allowed에 가까운 후보를 우선 사용.
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
    # JSON 안정성을 위해 구분자 고정
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
    목표 자산(cur_guid)에서 시작하여,
    들어오는 Data Flow를 따라 역방향으로 확장.

    - visited_assets: 사이클 방지(자산 단위)
    - allowed_max_phase: 현재 노드에서 선택 가능한 위협 phase의 상한
    """

    if len(path_node_ids) >= st.max_depth:
        all_paths.append(list(path_node_ids))
        return

    dfd_node = st.nodes_by_guid.get(cur_guid)
    if not dfd_node:
        # TM7에 노드가 없으면 더 못 감
        all_paths.append(list(path_node_ids))
        return

    # 현재 자산에 대해 "허용 phase 이하" 위협 후보 선택
    cands = threat_candidates_for_asset(
        asset_name=dfd_node.name,
        asset_to_threats=st.asset_to_threats,
        tactic_to_phase=st.tactic_to_phase,
        max_phase_allowed=allowed_max_phase,
        require_phase=None,
    )

    if not cands:
        # 위협이 없으면 더 못 감
        all_paths.append(list(path_node_ids))
        return

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

        # 종료 조건: In phase면 “공격 진입점”으로 보고 멈춤
        if th.phase == "In":
            all_paths.append(list(path_node_ids))
            path_node_ids.pop()
            continue

        # 다음은 "현재 phase와 같거나 선행"이므로,
        # 역추적 시 다음(상류) 노드는 <= 현재 phase
        next_allowed = PHASE_ORDER[th.phase]

        # 들어오는 데이터 플로우 따라 상류로 확장
        for flow in st.incoming.get(cur_guid, []):
            src_guid = flow.source_guid
            if src_guid in visited_assets:
                continue

            visited_assets.add(src_guid)

            # edge는 DFD 방향(소스->타겟)을 그대로 유지
            # node는 각 단계에서 threat 선택에 따라 node_id가 달라지므로,
            # 실제 edge는 "상류에서 선택된 노드"가 결정된 뒤 연결해야 함.
            # 여기서는 “후행 노드(th)”가 정해진 상태이므로,
            # 재귀가 끝나고 돌아왔을 때 graph_edges를 넣는 방식이 더 깔끔하지만,
            # 구현 단순화를 위해: 재귀 호출에서 상류 node가 생성된 후,
            # 그 상류 node들과 현재 node를 연결하는 edge를 별도로 생성합니다.

            # 재귀 확장
            before_nodes = set(graph_nodes.keys())
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

            # 이번 확장으로 새로 생긴 "상류 노드들"을 현재 노드로 연결
            new_upstream_nodes = [nid for nid in (after_nodes - before_nodes) if nid.startswith(src_guid + "::")]
            for up_id in new_upstream_nodes:
                graph_edges.add((up_id, node_id, flow.guid))

            visited_assets.remove(src_guid)

        path_node_ids.pop()


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

    # (1) 목표 자산명과 동일한 DFD 요소 찾기 (동명이인 다 허용)
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

    # (3) 목표 자산에 Out phase 위협 존재 확인
    # 시작 노드 후보는 "Out 위협"이 있어야 함.
    # (Out 후보가 여러개면 모두 시작점으로 확장)
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

        # 목표 자산에서 Out 위협별로 각각 DFS 시작
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
                allowed_max_phase=PHASE_ORDER["Out"],  # 시작은 Out에서 시작
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

    # edges 정리
    edges_out = []
    for (src_node_id, dst_node_id, flow_guid) in sorted(graph_edges):
        # flow 라벨 찾아 넣기
        flow_label = None
        for f in flows:
            if f.guid == flow_guid:
                flow_label = f.label
                break
        edges_out.append(
            {
                "from": src_node_id,
                "to": dst_node_id,
                "dfd_flow_guid": flow_guid,
                "dfd_flow_label": flow_label,
            }
        )

    return {
        "ok": True,
        "target_asset_name": target_asset_name,
        "tm7_path": str(tm7_path),
        "nodes": list(graph_nodes.values()),
        "edges": edges_out,
        "paths": all_paths,  # 각 경로는 node_id 리스트
        "phase_order": ["In", "Through", "Out"],
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



'''
실행 예시
- python parse_attack_graph.py --tm7 "Automotive DFD_B.tm7" --type "Remote/Adjacent" --target "Gateway" --asset-map "asset_to_threats.json" --threat-map "threat_to_tactic.json" --out "attack_graph.json"
'''