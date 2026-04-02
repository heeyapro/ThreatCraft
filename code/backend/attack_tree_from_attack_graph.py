# attack_tree_from_attack_graph.py
# - 중복 노드/엣지 병합(set) 유지
# - OR 게이트 제거
# - 라벨은 무조건 한 줄(줄바꿈 없음, \n 문자도 없음)
# - 화살표 방향 반대로(단계 -> Goal)
# - attack_graph.json 을 읽어와 attack tree로 변환함
# - phase 기반 색상 지정 추가

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from collections import defaultdict

def gv_escape(s: str) -> str:
    if s is None:
        return ""
    return str(s).replace('"', '\\"')

def sanitize_id(s: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", str(s))

def one_line_label(node_obj: dict) -> str:
    """
    줄바꿈 없이 한 줄로만 라벨을 만든다.
    예: "Gateway | Threat_105"
    """
    asset = (node_obj.get("asset_name") or "").strip()
    tid = (node_obj.get("threat_id") or "").strip()
    tname = (node_obj.get("threat_name") or "").strip()

    parts = [p for p in [asset, tid] if p]
    if not parts:
        parts = [tname] if tname else ["node"]
    return " | ".join(parts)

def ensure_dot() -> str:
    p = shutil.which("dot")
    if not p:
        raise FileNotFoundError(
            "Graphviz 'dot'을 찾지 못했다. 새 터미널에서 `dot -V`가 되는지 확인해야 한다."
        )
    return p

# -----------------------------
# 색/도형 규칙
# -----------------------------

def _shape_from_stencil(stencil_type: str | None) -> str:
    """
    parse_attack_graph_v12/v13에서 stencil_type이 들어오는 경우를 고려
    - StencilParallelLines -> cylinder
    - StencilEllipse -> circle
    - default -> box
    """
    if stencil_type == "StencilParallelLines":
        return "cylinder"
    if stencil_type == "StencilEllipse":
        return "circle"
    return "box"

def _phase_fillcolor(phases: set[str]) -> str:
    """
    여러 phase가 한 노드에 섞이는 경우(=같은 노드를 병합했을 때 발생 가능)
    우선순위로 단색 결정: Out > Through > In > Entry
    """
    if "Out" in phases:
        return "red"
    if "Through" in phases:
        return "orange"
    if "In" in phases:
        return "lightgreen"
    if "Entry" in phases:
        return "lightgrey"
    return "white"

def collect_phases_by_asset_guid(node_map: dict) -> dict[str, set[str]]:

    phases_by_guid = defaultdict(set)
    for nid, obj in node_map.items():
        g = obj.get("asset_guid")
        ph = obj.get("phase")
        if g and ph:
            phases_by_guid[g].add(ph)
    return phases_by_guid

def node_attrs(node_obj: dict, phases_by_asset_guid: dict[str, set[str]]) -> dict:

    ph = node_obj.get("phase")
    asset_guid = node_obj.get("asset_guid")

    # 병합된 자산이면 자산의 phase 집합을 사용, 아니면 노드 자체 phase만 사용
    phases = set()
    if asset_guid and asset_guid in phases_by_asset_guid:
        phases = phases_by_asset_guid[asset_guid]
    elif ph:
        phases = {ph}

    fillcolor = _phase_fillcolor(phases)
    shape = _shape_from_stencil(node_obj.get("stencil_type"))

    return {
        "shape": "box",
        "style": "filled,rounded",
        "fillcolor": fillcolor,
        "color": "black",
        "fontcolor": "black",
        "penwidth": "1.2",
    }

# -----------------------------
# 경로 병합
# -----------------------------

def build_merged_edges(data: dict, reverse_arrows: bool = True):
    """
    paths: [step1, step2, ..., goal]
    reverse_arrows=True면 step->goal로 엣지를 뒤집어 만든다.
    """
    nodes = data.get("nodes", [])
    paths = data.get("paths", [])
    node_map = {n["node_id"]: n for n in nodes if "node_id" in n}

    if not paths:
        raise ValueError("paths가 비어 있다. 이 스크립트는 paths 기반이다.")

    edges = set()
    goals = set()

    for p in paths:
        if not p:
            continue

        goal = p[-1]
        goals.add(goal)

        steps = p[:-1]
        steps = list(reversed(steps))  # goal 가까운 단계부터

        prev = goal
        for s in steps:
            if reverse_arrows:
                edges.add((s, prev))  # s -> goal
            else:
                edges.add((prev, s))
            prev = s

    return list(goals), edges, node_map

def to_dot(data: dict, reverse_arrows: bool = True) -> str:
    target_asset_name = data.get("target_asset_name", "Target")
    goals, edges, node_map = build_merged_edges(data, reverse_arrows=reverse_arrows)

    # asset_guid 기준 phase 집합(색 결정용)
    phases_by_asset_guid = collect_phases_by_asset_guid(node_map)

    lines = []
    lines.append("digraph AttackTree {")
    lines.append("  rankdir=BT;")
    lines.append('  graph [splines=true, nodesep=0.25, ranksep=0.45, concentrate=true];')
    lines.append('  node  [fontsize=11];')
    lines.append('  edge  [arrowsize=0.7];')
    lines.append("")

    root = "ROOT"
    # ROOT는 회색 박스로 두자(원하면 색 변경 가능)
    lines.append(
        f'  {root} [shape=box, style="filled,bold", fillcolor="lightgrey", '
        f'label="{gv_escape("Goal: " + target_asset_name)}"];'
    )

    # goal 노드 정의 + ROOT 연결
    for g in goals:
        gid = sanitize_id(g)
        gobj = node_map.get(g, {"asset_name": target_asset_name, "threat_id": "GOAL", "phase": "Out"})
        glabel = "Goal | " + one_line_label(gobj)

        attrs = node_attrs(gobj, phases_by_asset_guid)
        # goal은 좀 굵게
        lines.append(
            f'  {gid} [shape={attrs["shape"]}, style="{attrs["style"]},rounded,bold", '
            f'fillcolor="{attrs["fillcolor"]}", color="{attrs["color"]}", fontcolor="{attrs["fontcolor"]}", '
            f'penwidth={attrs["penwidth"]}, label="{gv_escape(glabel)}"];'
        )

        if reverse_arrows:
            lines.append(f"  {gid} -> {root};")
        else:
            lines.append(f"  {root} -> {gid};")

    # edges에 등장하는 노드만 정의
    used = set()
    for u, v in edges:
        used.add(u)
        used.add(v)

    for nid in used:
        if nid in goals:
            continue

        gv_id = sanitize_id(nid)
        obj = node_map.get(nid, {"asset_name": "", "threat_id": nid})
        label = one_line_label(obj)

        attrs = node_attrs(obj, phases_by_asset_guid)

        lines.append(
            f'  {gv_id} [shape={attrs["shape"]}, style="{attrs["style"]}", '
            f'fillcolor="{attrs["fillcolor"]}", color="{attrs["color"]}", fontcolor="{attrs["fontcolor"]}", '
            f'penwidth={attrs["penwidth"]}, label="{gv_escape(label)}"];'
        )

    lines.append("")
    for u, v in sorted(edges):
        lines.append(f"  {sanitize_id(u)} -> {sanitize_id(v)};")

    lines.append("}")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="attack_graph.json 경로")
    ap.add_argument("--dot", dest="dot_path", default=None, help="DOT 저장 경로(선택)")
    ap.add_argument("--png", dest="png_path", required=True, help="PNG 출력 경로")
    ap.add_argument("--no-reverse", dest="no_reverse", action="store_true", help="화살표 반대 적용 안 함")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    if not in_path.exists():
        raise FileNotFoundError(f"입력 JSON을 찾지 못했다: {in_path}")

    with in_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    dot_text = to_dot(data, reverse_arrows=(not args.no_reverse))

    if args.dot_path:
        dot_path = Path(args.dot_path)
    else:
        dot_path = Path(args.png_path).with_suffix(".dot")

    dot_path.parent.mkdir(parents=True, exist_ok=True)
    dot_path.write_text(dot_text, encoding="utf-8")

    dot_exe = ensure_dot()
    png_path = Path(args.png_path)
    png_path.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run([dot_exe, "-Tpng", str(dot_path), "-o", str(png_path)], check=True)
    print(f"[OK] PNG 생성 완료: {png_path}")
    print(f"[OK] DOT 저장 위치: {dot_path}")

if __name__ == "__main__":
    main()

"""
python attack_tree_from_attack_graph.py --in ..\\out\\attack_graph.json --dot ..\\out\\attack_tree.dot --png ..\\out\\attack_tree.png

"""
