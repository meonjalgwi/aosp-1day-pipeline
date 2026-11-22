# M8. Verifier — 후속 범위 (이번 프로젝트 제외)

> 11/11 피드백과 11/23 리뷰에 따라 **동적 재현·패치 전후 실행 검증은 이번 프로젝트의 산출물·평가·일정에서 제외**합니다.
> 이 폴더와 코드 뼈대는 프로젝트 이후 확장할 때의 출발점으로만 남겨 둡니다. 이번 프로젝트에서 후보의 악용 가능성은 정적 근거 + 라벨 판정 기준표 + 사람 판정으로 다룹니다 ([docs/limitations.md](../../docs/limitations.md) L4).

## 남겨 둔 것

- 코드 뼈대: [`aosp1day/stages/m08_harness.py`](../../aosp1day/stages/m08_harness.py) (`Harness`), [`aosp1day/stages/m08_verifier.py`](../../aosp1day/stages/m08_verifier.py) (`Verifier`) — `PIPELINE` 에서 제외, `STANDALONE` 에만 등록
- 스키마: `TestCase`, `ValueSpec`, `CallerSpec`, `ExpectedResult`, `Verification` ([`aosp1day/schemas.py`](../../aosp1day/schemas.py))
- 예시 입력: [`baselines/example.tests.json`](../../baselines/example.tests.json)

## 후속 범위에서 다룰 내용 (참고)

이전 기능명세 v0.3.1 의 F-801~F-810 (가상 기기 초기화, 공용 instrumentation APK, 패치 전후 차등 판정 등) — [docs/feature-spec.md](../../docs/feature-spec.md) 부록 A
