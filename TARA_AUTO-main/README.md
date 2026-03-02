## sheet
-link: https://koreaoffice-my.sharepoint.com/:x:/g/personal/kangdohee1211_korea_ac_kr/IQA9PJq93GTPSKHvj6ZCunukAdwPxqHDx0RnqALMBV5n8ik?e=dyOpeZ

## Test DFD
<img width="1008" height="732" alt="20260128_130636" src="/20260211_172126.png" />

## Installation
+ https://graphviz.org/download/ 에 가서 graphviz 설치파일 다운받고 실행
+ graphviz 설치한 후에는 pip 사용하여 Python 전용 graphviz 인터페이스 라이브러리 설치 ```pip install graphviz```
+ PILLOW 라이브러리 설치 ```pip install pillow```

## Usage
### By GUI
+ ./code/frontend 로 이동
+ 09 버전의 python 스크립트 실행
  ```python tool_gui_v09.py```
+ 추가로 휠줌/줌아웃이 가능한 10 버전을 만들어놨는데 아직 테스트를 못해봄. 그러니, 09 버전 돌린 다음 제대로 돌아가는거 확인했으면 ```python tool_gui_v10.py``` 쳐서 테스트 한번 해주셈


## 실행화면
<img width="350" height="1083" alt="merged_attack_graph_remote" src="/code/frontend/gui_display/20260211_163542.png" />
<img width="350" height="1083" alt="merged_attack_graph_remote" src="/code/frontend/gui_display/20260211_164013.png" />
<img width="350" height="1083" alt="merged_attack_graph_remote" src="/code/frontend/gui_display/20260211_164633.png" />
<img width="350" height="1083" alt="merged_attack_graph_remote" src="/code/frontend/gui_display/20260211_164650.png" />
<img width="350" height="1083" alt="merged_attack_graph_remote" src="/code/frontend/gui_display/20260211_174725.png" />

## Output by TARA_AUTO (When Target is Door)
### Remote
<img width="419" height="1083" alt="merged_attack_graph_remote" src="/code/out/merged_attack_graph_remote.png" />
<img width="700" height="419" alt="merged_attack_graph_remote" src="/code/out/attack_tree_remote.png" />

### Adjacent
<img width="419" height="1083" alt="merged_attack_graph_adjacent" src="/code/out/merged_attack_graph_adjacent.png" />
<img width="700" height="419" alt="merged_attack_graph_adjacent" src="/code/out/attack_tree_adjacent.png" />

### Local
<img width="419" height="1083" alt="merged_attack_graph_local" src="/code/out/merged_attack_graph_local.png" />
<img width="700" height="419" alt="merged_attack_graph_local" src="/code/out/attack_tree_local.png" />

### Physical
<img width="419" height="1083" alt="merged_attack_graph_physical" src="/code/out/merged_attack_graph_physical.png" />
<img width="700" height="419" alt="merged_attack_graph_physical" src="/code/out/attack_tree_physical.png" />


### Threat Report
+ /code/backend 경로에서 백엔드 코드 실행 후 out 폴더로 이동 ```cd ../out```
+ HTML렌더링을 위한 HTTP 서버 실행 ```python -m http.server 8000```
+ 웹브라우저 켜서 로컬 호스트의 8000 번 포트로 접속 ```http://127.0.0.1:8080/result_report.html```
<img width="700" height="419" alt="merged_attack_graph_remote" src="/code/out/report1.png" />
<img width="700" height="419" alt="merged_attack_graph_remote" src="/code/out/report2.png" />
<img width="700" height="419" alt="merged_attack_graph_remote" src="/code/out/report3.png" />
