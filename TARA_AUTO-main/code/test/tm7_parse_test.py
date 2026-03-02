import xml.etree.ElementTree as ET
from collections import defaultdict
from math import isclose

TM7_PATH = "test_model.tm7"  # current directory

# --- helpers ---
def local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag

def first_child_text(el, child_name: str):
    for c in el:
        if local(c.tag) == child_name:
            return c.text
    return None

def is_connector_value(el) -> bool:
    for k, v in el.attrib.items():
        if k.endswith("type") and v == "Connector":
            return True
    return False

def extract_properties(el) -> dict:
    props = {}
    props_el = None
    for c in el:
        if local(c.tag) == "Properties":
            props_el = c
            break
    if props_el is None:
        return props

    for anyt in list(props_el):
        name = disp = val = None
        for cc in list(anyt):
            t = local(cc.tag)
            if t == "Name":
                name = cc.text
            elif t == "DisplayName":
                disp = cc.text
            elif t == "Value":
                val = cc.text
        key = name or disp
        if key:
            props[key] = val
    return props

def centre(rect):
    return (rect["left"] + rect["width"]/2.0, rect["top"] + rect["height"]/2.0)

def inside(pt, b):
    x, y = pt
    return (b["left"] <= x <= b["left"] + b["width"]) and (b["top"] <= y <= b["top"] + b["height"])

def rect_area(r):
    return r["width"] * r["height"]

# --- geometry for line/arc boundary intersection ---
def bezier_quadratic(p0, p1, p2, t):
    """Quadratic Bezier point."""
    x = (1-t)*(1-t)*p0[0] + 2*(1-t)*t*p1[0] + t*t*p2[0]
    y = (1-t)*(1-t)*p0[1] + 2*(1-t)*t*p1[1] + t*t*p2[1]
    return (x, y)

def bezier_polyline(p0, p1, p2, steps=60):
    """Approximate bezier curve with polyline points."""
    return [bezier_quadratic(p0, p1, p2, i/steps) for i in range(steps+1)]

def orient(a, b, c):
    """2D cross product sign of (b-a) x (c-a)."""
    return (b[0]-a[0])*(c[1]-a[1]) - (b[1]-a[1])*(c[0]-a[0])

def on_segment(a, b, p):
    return (min(a[0], b[0]) <= p[0] <= max(a[0], b[0]) and
            min(a[1], b[1]) <= p[1] <= max(a[1], b[1]) and
            isclose(orient(a, b, p), 0.0, abs_tol=1e-9))

def segments_intersect(a, b, c, d):
    """Check if segments ab and cd intersect (including touching)."""
    o1 = orient(a, b, c)
    o2 = orient(a, b, d)
    o3 = orient(c, d, a)
    o4 = orient(c, d, b)

    # general case
    if (o1 > 0) != (o2 > 0) and (o3 > 0) != (o4 > 0):
        return True

    # collinear / touching
    if isclose(o1, 0.0, abs_tol=1e-9) and on_segment(a, b, c): return True
    if isclose(o2, 0.0, abs_tol=1e-9) and on_segment(a, b, d): return True
    if isclose(o3, 0.0, abs_tol=1e-9) and on_segment(c, d, a): return True
    if isclose(o4, 0.0, abs_tol=1e-9) and on_segment(c, d, b): return True
    return False

def segment_intersects_polyline(seg_a, seg_b, poly_pts):
    for i in range(len(poly_pts)-1):
        if segments_intersect(seg_a, seg_b, poly_pts[i], poly_pts[i+1]):
            return True
    return False


# --- parse tm7 ---
tree = ET.parse(TM7_PATH)
root = tree.getroot()

# guid -> rect + typeid + name (for elements with rect)
rects = {}
names = {}

# store line-boundary geometry: guid -> (p0, p1, p2)
line_boundaries_geom = {}

for el in root.iter():
    if local(el.tag) != "Value":
        continue

    guid = first_child_text(el, "Guid")
    if not guid:
        continue

    props = extract_properties(el)
    if guid not in names:
        names[guid] = props.get("Name")

    typeid = first_child_text(el, "TypeId")

    # Rect-based objects (elements, border boundaries)
    left = first_child_text(el, "Left")
    top = first_child_text(el, "Top")
    width = first_child_text(el, "Width")
    height = first_child_text(el, "Height")
    if left and top and width and height:
        rects[guid] = {
            "left": float(left),
            "top": float(top),
            "width": float(width),
            "height": float(height),
            "typeid": typeid,
        }

    # Line/arc boundary (GE.TB.L): Source/Handle/Target points
    if typeid == "GE.TB.L":
        sx = first_child_text(el, "SourceX")
        sy = first_child_text(el, "SourceY")
        hx = first_child_text(el, "HandleX")
        hy = first_child_text(el, "HandleY")
        tx = first_child_text(el, "TargetX")
        ty = first_child_text(el, "TargetY")
        if sx and sy and hx and hy and tx and ty:
            p0 = (float(sx), float(sy))
            p1 = (float(hx), float(hy))
            p2 = (float(tx), float(ty))
            line_boundaries_geom[guid] = (p0, p1, p2)

# --- collect boundaries ---
# Border (square/rectangle) boundaries: GE.TB.B
border_boundaries = []
for guid, r in rects.items():
    if r.get("typeid") == "GE.TB.B":
        bname = names.get(guid) or "Trust Boundary"
        border_boundaries.append((guid, bname, r))

# Line/arc boundaries: GE.TB.L
line_boundaries = []
for guid, (p0, p1, p2) in line_boundaries_geom.items():
    bname = names.get(guid) or "Trust Line Boundary"
    line_boundaries.append((guid, bname, (p0, p1, p2)))

# disambiguate duplicate names (common: "Generic Trust Border Boundary")
def disambiguate(boundary_list, key_index=1, extra_sort_key=None):
    tmp = list(boundary_list)
    if extra_sort_key:
        tmp.sort(key=extra_sort_key, reverse=True)
    counts = defaultdict(int)
    out = []
    for item in tmp:
        name = item[key_index]
        counts[name] += 1
        label = name if counts[name] == 1 else f"{name} #{counts[name]}"
        out.append((item[0], label, item[2]))
    return out

border_boundaries_labeled = disambiguate(
    border_boundaries,
    key_index=1,
    extra_sort_key=lambda x: rect_area(x[2])
)
line_boundaries_labeled = disambiguate(
    line_boundaries,
    key_index=1,
    extra_sort_key=None
)

# --- data flows ---
flows = []
for el in root.iter():
    if local(el.tag) != "Value":
        continue
    if not is_connector_value(el):
        continue
    if first_child_text(el, "TypeId") != "GE.DF":
        continue

    props = extract_properties(el)
    flows.append({
        "guid": first_child_text(el, "Guid"),
        "name": props.get("Name") or "(unnamed data flow)",
        "source": first_child_text(el, "SourceGuid"),
        "target": first_child_text(el, "TargetGuid"),
    })

# --- detect crossing, grouped by boundary ---
crossing_by_boundary = defaultdict(list)

for f in flows:
    s, t = f["source"], f["target"]
    if s not in rects or t not in rects:
        continue

    seg_a = centre(rects[s])
    seg_b = centre(rects[t])

    # 1) square/rectangle border boundaries: XOR inside
    for b_guid, b_label, b_rect in border_boundaries_labeled:
        s_in = inside(seg_a, b_rect)
        t_in = inside(seg_b, b_rect)
        if s_in != t_in:
            crossing_by_boundary[b_label].append(f["name"])

    # 2) arc/line boundaries: segment intersects bezier curve
    for b_guid, b_label, (p0, p1, p2) in line_boundaries_labeled:
        curve_pts = bezier_polyline(p0, p1, p2, steps=80)
        if segment_intersects_polyline(seg_a, seg_b, curve_pts):
            crossing_by_boundary[b_label].append(f["name"])

# --- output format requested ---
# Print only boundaries that have crossings
print(f"Found {len(border_boundaries_labeled)} border boundary(ies) (GE.TB.B).")
print(f"Found {len(line_boundaries_labeled)} line/arc boundary(ies) (GE.TB.L).")
print(f"Found {len(flows)} data flow(s) (GE.DF).\n")

for b_label in sorted(crossing_by_boundary.keys()):
    uniq = sorted(set(crossing_by_boundary[b_label]))
    if not uniq:
        continue
    print(f"[{b_label}]")
    for n in uniq:
        print(f"- {n}")
    print()





'''
-> 작업 목표 : Microsoft Threat Modeling Tool에서 사용되는 DFD(.tm7 확장자) 파일을 입력받은 다음, 해당 DFD에서 가능한 공격 그래프를 탐지하여 시각화
-> 필요 도구
   -->(도구-1) 공격 그래프 시각화 도구 : Graphviz
   -->(도구-2) .tm7 파일 파서 및 공격 그래프 생성 스크립트 : Python 스크립트
   -->(도구-3) 생성된 공격 그래프를 Graphviz에서 인식가능한 포맷으로 변환한뒤 png 또는 JPG로 렌더링 : Python 스크립트
-> 개발해야 하는 것 : (도구-2), (도구-3) 
-> (도구-2)의 입출력
    --> (도구-2)의 입력
         ---> (도구-2-입력-1). 분석하고자하는 DFD 파일의 경로 (문자열)
         ---> (도구-2-입력-2). 탐색하고자하는 공격 그래프 유형 ("Remote/Adjacent", "Local/Physical" 중 택 1)
    --> (도구-2)의 출력 : JSON 형식의 공격 그래프 파일
         ---> 노드는 DFD 상의 위협이 적용될 수 있는 요소의 이름, 적용될 수 있는 위협명,
-> (도구-3)의 입출력
    --> (도구-3)의 입력 : (도구-2)의 출력
    --> (도구-3)의 출력 : png 또는 JPG
-> (도구-2 알고리즘)
    <(도구-2-입력-2)가 "Remote/Adjacent"인 경우>
    --> (1) DFD 상에서 차량의 Trust Boundary 바깥에 있는 노드 탐색
        ---> 도구-2-(1)-1. External Vehicle Boundary 라는 신뢰 경계 안에 있는 DFD 요소들 식별
        ---> 도구-2-(1)-2. 도구-2-(1)-1 단계에서 식별된 요소를 공격 그래프를 저장하는 배열이나 구조체에 저장
        ---> 도구-2-(1)-3.식별된 요소들 중 하나를 골라, 그 요소에서 나가는 방향의 Data Flow를 타고 이동
        ---> 도구-2-(1)-4. 타고 이동한 후, 현재 노드가 이전에 방문되었는지를 확인
            ----> 만약에 이전에 방문했다면, 다시 직전 노드로 후퇴한뒤 선택되지 않았던 다음 Data Flow를 타고 이동한 뒤 도구-2-(1)-4 이동
            ----> 만약에 이전에 방문하지 않았다면, External Vehicle Boundary 신뢰 경계를 건넜는지여부를 판단하고 도구-2-(1)-5 로 이동
        ---> 도구-2-(1)-5. External Vehicle Boundary 신뢰 경계를 넘었는지 판단하고 그 결과에 따라 아래와 같이 대처
              ----> 만약에 건넜다면 (2) 로 이동함
              ----> 만약에 건너지 않았다면,  현재 요소를 공격 그래프를 저장하는 배열이나 구조체에 저장하고 현재 요소에서 나가는 방향의 Data Flow를 타고 이동한 후 도구-2-(1)-4 로 이동 
        ---> ※ 본 작업의 수행 알고리즘(차량의 Trust Boundary 바깥에 있는 노드의 조건)은 추후 변경될 수 있으므로, 변경이 용이하도록 구현
    --> (2) In phase의 공격이 적용될 수 있는 DFD 요소 식별
        ---> 도구-2-(2)-1. 직전에 방문한 노드에서 적용될 수 있던 위협이 In phase 위협인지, through phase 위협인지, out phase 위협인지 확인
            ----> In-phase 위협이거나 그 어떤 위협도 적용될 수 없었던 노드라면, 도구-2-(2)-2 로 이동 
            ----> Through-phase 위협이라면, 도구-2-(2)-3 로 이동
            ----> Out-phase 위협이라면, 도구-2-(2)-4 로 이동
        ---> 도구-2-(2)-2.  현재 노드에서 적용될 수 있는 In phase의 위협이 있는지 확인
             ----> asset_to_threats.json 과 threat_to_tactic.json을 참고하여 현재 노드의 이름을 자산으로 하여 현재 자산에 적용될 수 있는 In phase의 위협이 있는지 확인 
             ----> 만약 적용 가능한 In phase 위협이 없다면 직전 요소로 후퇴하고, 직전 요소에서 적용 중이었던 단계를 수행
             ----> 만약 적용 가능한 In phase 위협이 있다면 현재 노드와 적용 가능한 위협을 공격 그래프를 저장하는 배열이나 구조체에 저장하고 그 요소에서 나가는 방향의 Data Flow를 타고 이동
        ---> 도구-2-(2)-3.  현재 노드에서 적용될 수 있는 Through phase의 공격이 있는지 확인
             ----> asset_to_threats.json 과 threat_to_tactic.json을 참고하여 현재 노드의 이름을 자산으로 하여 현재 자산에 적용될 수 있는 through phase의 위협이 있는지 확인 
             ----> 만약 적용 가능한 In phase 위협이 없다면 직전 요소로 후퇴하고, 직전 요소에서 적용 중이었던 단계를 수행
             ----> 만약 적용 가능한 In phase 위협이 있다면 현재 노드와 적용 가능한 위협을 공격 그래프를 저장하는 배열이나 구조체에 저장하고 그 요소에서 나가는 방향의 Data Flow를 타고 이동
        ---> 도구-2-(2)-4.  현재 노드에서 적용될 수 있는 Out phase의 공격이 있는지 확인
             ----> asset_to_threats.json 과 threat_to_tactic.json을 참고하여 현재 노드의 이름을 자산으로 하여 현재 자산에 적용될 수 있는 out phase의 위협이 있는지 확인 
             ----> 만약 적용 가능한 In phase 위협이 없다면 직전 요소로 후퇴하고, 직전 요소에서 적용 중이었던 단계를 수행
             ----> 만약 적용 가능한 In phase 위협이 있다면 현재 노드와 적용 가능한 위협을 공격 그래프를 저장하는 배열이나 구조체에 저장하고 그 요소에서 나가는 방향의 Data Flow를 타고 이동

        ---> ※ 본 알고리즘의 종료 조건 : 방문할 노드 또는 타고 이동할 Data Flow 가 없을 때 본 알고리즘은 지금까지 공격 그래프를 JSON 형식으로 반환함
        ---> 

    <(도구-2-입력-2)가 "Local/Physical"인 경우>
    --> (1)
    --> (2)
    --> (3)
    --> (4)
    --> (5)
    --> (6)

-> (도구-3 알고리즘 - (1), (2) .. 와 같이 순번 표시가 없는 것은 순서가 상관없기 때문)
    --> Process에 해당하는 노드는 동그라미로, DataStore에 해당하는 노드는 데이터베이스 모양(cylinder), External Entity에 해당하는 노드는 사각형으로 표현
    --> 노드별로 적용될 수 있는 공격 기법은 노드에 같이 표시
    --> 노드 안의 노드 이름(구성요소 이름)은 진하게, 노드에 적용될 수 있는 공격기법은 상대적으로 연하게 표현

    



-> (1). 엔트리 포인트 식별 : DFD 상에서 차량 Trust Boundary 바깥에 있는 Asset 식별
   --> assets_to_threats.json을 참고하여 Trust Boundary 바깥에 있어야 하는 Asset들이 주어진 DFD 상에 있는지 식별
   --> 엔트리 포인트에 해당하는 Node가 있다면
-> (2). In-> Through -> Out 체인 식별 시작 :
-> remote/adjacent 에 대한 공격 그래프 탐지 : In (한개 이상) -> Through(한개 이상) -> Out (한개 이상)
   --> (1). In에 해당하는 위협들이 적용될 수 있는 Asset이 DFD 상에 존재하는지 찾기
   --> (2)-1. 그 Asset을 찾으면 현재 Asset과 현재 Asset에 적용될 수 있는 In에 해당하는 위협을 Attack Graph의 Node로 추가하고 (3)으로 이동
   --> (2)-2. 그 Asset을 못 찾으면 remote/adjacent 수준의 공격은 적용 불가능함
   --> (3). 찾은 Asset에서 dataflow를 타고 이동할 수 있는 Asset들 각각에 대하여 다음을 수행
   --> (3)-1. 더이상 이동할 수 있는 Asset이 없다면 
   --> (3)-2. 아직 방문되지 않은 Data Flow 하나를 선택해서 타고 이동
   --> (3)-3. 이동한 후 Asset에서 Through의  위협들이 적용될 수 있는 Asset인지 확인
   --> (3)-4. 그런 Asset이 라면, 현재 Asset과 그 Asset에 적용될 수 있는 Through의 위협을 attack graph릐 노드로 추가
   --> (3)-5. 다음 노드로 이도
   --> (4)-2. 위협이 있다면, 해당 위협이 through 단계의 위협인지 확인
   --> 본 자산에 적용될 수 있는 위협이 중에 Out에 해당하는 위협이 있다면, 지금까지의 그래프를 공격 그래프로 출력

-> local/physical 에 대한 공격 그래프 탐지 : Through -> Out
->
->
->
'''


'''
-> 작업 목표 : Microsoft Threat Modeling Tool에서 사용되는 DFD(.tm7 확장자) 파일을 입력받은 다음, 해당 DFD에서 가능한 공격 그래프를 탐지하여 시각화
->
'''

