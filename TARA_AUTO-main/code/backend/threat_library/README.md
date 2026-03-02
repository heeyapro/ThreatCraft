## dependency.json 작성법

### FLOW_IMPLY_THREATS 유형
+ 시트의 Flow 유형 규칙에 해당
+ "when" 키는 시트의 if열에 해당함
+ "then" 키는 시트의 mapping열(D열)에 해당함
+ "op"키는 AND 또는는 경우(예 8번, 9번, 10번 행), '-' 기재

### PRE_THREAT_ENABLES_POST_THREAT 유형
+ 시트의 Pre-Post 유형 규칙에 해당
+ "when" 키는 시트의 if열에 해당함
+ "then" 키는 시트의 mapping열에 해당함
+ "op"키는 AND 또는 OR 또는 - 중 하나만 가능
  + 단일 위협만 매핑되는 경우(예 25번 행의 mapping열 값, 20,21,22 번 행의 if열 값), '-' 기재

### TARGET_ASSET_FORBIDS_THREATS 유형
+ 시트의 Not Mapping-Goal 유형 규칙에 해당
+ "when" 키는 시트의 if열에 해당함
+ "then" 키는 시트의 mapping열에 해당함
+ "op"키는 AND 또는 OR 또는 - 중 하나만 가능
	+ 해당 유형의 규칙들 모두 모든 단일 target asset -> 단일 Threat 관계이므로, op 에는 "-" 기재 

### THREAT_FORBIDS_THREATS
+ "when" 키는 시트의 if열에 해당함
+ "then" 키는 시트의 mapping열에 해당함
+ "op"키는 AND 또는 OR 또는 - 중 하나만 가능
  + 해당 유형의 모든 규칙들에서 mapping 열의 값이 AND로 묶이므로 이 경우 "op"에는 "AND" 만 옴

