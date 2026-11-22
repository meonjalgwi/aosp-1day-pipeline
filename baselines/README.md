# baselines/ — 수동 정답 데이터 (3주차)

| 파일 | 형식 | 쓰는 곳 |
| --- | --- | --- |
| `<CVE-ID>.json` | `Baseline` (`aosp1day/schemas.py`) | M2 기준선 비교(F-204), M11 평가 |
| `<CVE-ID>.tests.json` | `TestCases` — 사람이 작성한 기준선 테스트 | M8 Harness P0 (F-807) |

- `example.tests.json` 은 형식 예시 (가상의 서비스). 실제 CVE 파일은 같은 형식으로 작성한다.
- ValueSpec P0 type: `null | bool | int | long | float | string | array | bundle | intent | ref`
- outcome 값: `ok | returned_data | security_exception | exception | crash | timeout`
- 미공개 후보의 재현 입력은 이 폴더에 커밋하지 않는다.
