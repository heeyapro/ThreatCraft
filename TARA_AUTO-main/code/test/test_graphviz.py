from graphviz import Digraph
from pathlib import Path

FONT = "Malgun Gothic"  # Windows 한글 폰트

dot = Digraph("Vehicle", format="png")

# 기본 속성
dot.attr("graph", fontname=FONT)
dot.attr("node", fontname=FONT, fontsize="11", style="filled")
dot.attr("edge", fontname=FONT, fontsize="10", color="black")

# 1) ECU - 원형 / 초록색 / 진한 글씨
dot.node(
    "ECU",
    label="<<B>ECU<br/>- UDS 진단 악용<br/>- CAN 메시지 스푸핑</B>>",
    shape="circle",
    fillcolor="lightgreen"
)

# 2) Gateway - 사각형 / 주황색 / 진한 글씨
dot.node(
    "Gateway",
    label="<<B>Gateway<br/>- DoS (버스 과부하)</B>>",
    shape="box",
    fillcolor="orange"
)

# 3) Data Store - 실린더 / 빨간색 / 진한 글씨
dot.node(
    "LogDB",
    label="<<B>Vehicle Log DB<br/>- 진단 로그 저장</B>>",
    shape="cylinder",
    fillcolor="red"
)

# 에지 (검정색 유지)
dot.edge("ECU", "Gateway", label="CAN")
dot.edge("Gateway", "LogDB", label="Log Write")

# 출력
Path("out").mkdir(exist_ok=True)
outpath = dot.render("out/vehicle_kr_win", cleanup=True)
print("Rendered to:", outpath)
