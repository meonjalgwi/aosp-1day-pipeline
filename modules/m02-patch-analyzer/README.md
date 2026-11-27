# M2. Patch Analyzer — 패치 분석

- 주차: 3주
- 담당: 현아 ([@gusdkcjs4](https://github.com/gusdkcjs4))
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-201~F-204

## 입력 / 출력

- 입력: `cve.json`
- 출력: `patch_analysis.json`

## 진행 상태

- [ ] 기준선 CVE 수동 분석 정답 데이터 작성
- [ ] Tree-sitter로 변경 클래스·메서드 추출
- [ ] 변경 유형 분류 (권한 검사/입력 검증/조건문/예외 처리)
- [ ] 권한 검사 API 인식
- [ ] 정답 데이터와 비교

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m02_patch_analyzer.py`](../../aosp1day/stages/m02_patch_analyzer.py)
- 클래스: `PatchAnalyzer`
- CLI: `aosp1day analyze <CVE-ID>`

## 1주차(11/24~30) B — 수정 유형 분석·패턴 추출 (나연)

| 산출물 | 위치 | 설명 |
| --- | --- | --- |
| 정답 데이터 (**초안, 셋 합의 필요**) | [`baselines/ground_truth.json`](../../baselines/ground_truth.json) | 기준선 2건(CVE-2023-40105, CVE-2024-0037). 공통 형식(`patch`/`vuln_pattern`/`rule`) + 합의용 `manual`(변경 메서드, 패치 전 문제 조건, 복구된 보안 조건, 탐지 위치) |
| Guard 사전 초안 | [`config/guard_dictionary.json`](../../config/guard_dictionary.json) | `PERMISSION` · `CALLER_UID` · `UID_PACKAGE_BINDING` · `APP_OPS` · `CROSS_USER` · `URI_USER_BOUNDARY` · `BINDER_IDENTITY` |
| 추출기 | [`aosp1day/analysis/`](../../aosp1day/analysis/) | Tree-sitter 로 변경 클래스·메서드, 추가·삭제 조건문, 호출 API, 추가된 보안 검사 추출 + `pattern_type` 분류 |
| 패턴 | [`patterns/<CVE>.json`](../../patterns/) | 추출기 출력. 공통 형식 그대로라 C 가 `ground_truth.json` 대신 바로 읽을 수 있다. `rule` 은 비워 두고 C 가 채움. 세부 추출 결과는 `analysis` |

```bash
pip install -e ".[analysis,dev]"
aosp1day extract CVE-2023-40105 --sources sources/CVE-2023-40105 --repo platform/frameworks/base   # -> patterns/CVE-2023-40105.json
pytest tests/test_extractor.py                                                                   # 정답 데이터와 비교
```

- 입력 폴더 구조는 A 산출물과 같다: `sources/<CVE>/{before,after}/<저장소 상대 경로>`, 있으면 `sources/<CVE>/patch.diff` (없으면 before/after 를 직접 비교).
- **`pattern_type` 규칙** (메서드 단위, 위에서부터): `GUARD_ADDITION`(사전 Guard 호출 지점이 늘어남, 같은 커밋의 헬퍼는 2단계까지 따라감) → `PRECONDITION_ADDITION`(사전엔 없지만 return/throw/continue 로 끝나는 if 추가) → `API_REPLACEMENT`(같은 이름 호출의 인자 수만 바뀜) → `OTHER`. **분류가 안 되면 추측하지 않고 `OTHER`.** `BINDER_IDENTITY` 만 늘어난 것은 Guard 추가로 보지 않는다.
- 템플릿 대응(`analysis.suggested_template`): `GUARD_ADDITION`→T1, `PRECONDITION_ADDITION`→T2, `API_REPLACEMENT`→T3.
- `vuln_pattern` 의 `sink` · `precondition` · `target_api` · `unsafe_api` · `safe_api` 는 위치가 여러 곳일 수 있어 **리스트**다. `source` 는 정적으로 확정하지 않고 변경 메서드 파라미터를 후보(`status: candidate`)로만 남긴다 — 확정값은 `ground_truth.json`.
- Guard 비교는 유형 집합이 아니라 **(유형, 호출 이름) 개수**로 한다. CVE-2024-0037 `SaveUi` 처럼 같은 메서드에 같은 Guard 가 이미 있고 다른 경로에만 빠져 있던 경우를 놓치지 않기 위해서다.
- `tests/fixtures/sources/` 는 테스트용 **발췌본**이다: 패치가 건드린 메서드만 남기고 나머지 줄은 비워 원본 줄 번호를 유지했다. A 가 전체 소스를 `sources/` 에 넣으면 같은 명령으로 `patterns/` 를 다시 만든다.
