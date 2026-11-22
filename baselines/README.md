# baselines/ — 수동 정답 데이터

| 파일 | 형식 | 쓰는 곳 |
| --- | --- | --- |
| `<CVE-ID>.json` | `Baseline` (`aosp1day/schemas.py`) | M2 기준선 비교(F-204), M5 차분 오라클 확인, M11 평가 |
| `example.tests.json` | `TestCases` 형식 예시 | **후속 범위**(동적 재현, M8) 참고용 — 이번 프로젝트에서는 쓰지 않음 |

- 기준선 CVE (제안): CVE-2023-40105 · CVE-2024-0037 · CVE-2024-0053 · CVE-2023-40111 · CVE-2023-40109 ([docs/scope-v2.3.md](../docs/scope-v2.3.md) 5절)
- 각 정답에는 변경 메서드, 수정 유형(`fix_kind`), 추가된 Guard·검사, 기대하는 차분 오라클 결과(패치 전 탐지·후 미탐지 지점)를 적는다.
- 미공개 후보의 위치·코드·경로는 이 폴더에 커밋하지 않는다 (책임 있는 공개 절차, [docs/limitations.md](../docs/limitations.md)).
