#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from collections import Counter
from pathlib import Path


def analyse_duplicate_paths(json_path: Path):
    data = json.loads(json_path.read_text(encoding="utf-8"))

    paths = data.get("paths", [])
    if not paths:
        print("[INFO] paths 항목이 비어 있습니다.")
        return

    # 경로를 tuple(node_id, ...) 형태로 변환
    path_tuples = [tuple(p) for p in paths]

    counter = Counter(path_tuples)

    total_paths = len(path_tuples)
    unique_paths = len(counter)

    # 중복된 경로들만 필터
    duplicated = {k: v for k, v in counter.items() if v > 1}
    duplicated_count = sum(v - 1 for v in duplicated.values())

    print("==== Attack Path Duplication Analysis ====")
    print(f"Total paths           : {total_paths}")
    print(f"Unique paths          : {unique_paths}")
    print(f"Duplicated paths      : {duplicated_count}")
    print(f"Duplicated path types : {len(duplicated)}")
    print("=========================================")

    if duplicated:
        print("\n[Duplicated Path Details]")
        for i, (path, cnt) in enumerate(duplicated.items(), 1):
            print(f"\n#{i}  (appears {cnt} times)")
            for node_id in path:
                print(f"  - {node_id}")


def main():
    import argparse

    ap = argparse.ArgumentParser(description="attack_graph.json 중복 공격 경로 분석기")
    ap.add_argument("json", help="attack_graph.json 파일 경로")
    args = ap.parse_args()

    json_path = Path(args.json)
    if not json_path.exists():
        print(f"[ERROR] File not found: {json_path}")
        return

    analyse_duplicate_paths(json_path)


if __name__ == "__main__":
    main()

'''
python test_dup_path.py ../out/attack_graph.json
'''