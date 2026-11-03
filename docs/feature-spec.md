# 기능명세서 (Feature Specification)

> 산출물 툴: **AOSP Framework 1-Day 패치 기반 분석·유사 취약점 탐지 도구**
> 용어가 낯설면 [glossary.md](glossary.md) 참고
> 상태: v0.3 (2026-11-03) — PR #20 리뷰 반영: P0 축소, Tree-sitter 통일, Cuttlefish 1차, LLM 추상화·키 관리, Streamlit 단독, 배포 원칙. PR #30 리뷰 반영: 데이터 계약에 출처(CodeRef) 추가

## 1. 개요

공개된 CVE/보안 패치를 입력하면, 패치를 분석해 취약점의 근본 원인과 패턴을 뽑고, 같은 패턴을 AOSP `frameworks/base`에서 찾아 후보를 순위화하고, 패치 전후 동적 검증 결과까지 담은 보고서를 자동으로 만드는 도구.

```
CVE/패치 입력
→ 패치 분석
→ Binder/AIDL 경로 분석
→ 취약 패턴 추출
→ AOSP 유사 코드 스캔
→ 후보 우선순위화
→ 패치 전후 검증
→ HTML/Markdown 보고서 생성
```

### 산출물 형태

최종 산출물은 **웹 대시보드**(Streamlit)다. 파이프라인(M1~M9)은 CLI로 실행해 `output/<CVE-ID>/*.json` 을 만들고, 대시보드는 **미리 생성된 JSON을 읽어 보여주기만** 한다. 별도 Backend API·작업 큐는 두지 않는다.

```
[CLI] → 파이프라인 (M1~M9) → output/<CVE-ID>/*.json → [Streamlit 대시보드] ⇄ [브라우저]
                                              ↘ 마스킹 → report_public.* (공개용)
```

외부 API나 별도 프론트엔드가 실제로 필요해지면 그때 FastAPI + React/Next.js 구조로 교체한다.

### 범위

| 구분 | 내용 |
| --- | --- |
| 대상 | `frameworks/base`의 Framework / System Service **Java** 코드 |
| 취약점 유형 | 권한 검사 누락, UID–packageName 불일치, Cross-user 접근, 입력 검증 누락 등 |
| 제외 | Native(C/C++), 커널, 벤더 코드, 실제 공격용 exploit 작성 |
| 입력 CVE | 후보 6~8개 + 기준선 CVE 1개 |

## 2. 전체 구조

| 모듈 | 입력 | 출력 (JSON) | 주차 |
| --- | --- | --- | --- |
| M1. Collector | CVE ID 또는 패치 커밋 URL/해시 | `cve.json` | 2주 |
| M2. Patch Analyzer | `cve.json` | `patch_analysis.json` | 3주 |
| M3. Binder Path Analyzer | `patch_analysis.json` + AOSP 소스 | `call_path.json` | 4주 |
| M4. Root Cause Analyzer (AI) | M2·M3 결과 | `root_cause.json` | 4주 |
| M5. Pattern / Rule Generator | M4 결과 | `pattern.json` + 규칙 파일 | 5주 |
| M6. Scanner | 규칙 파일 + `frameworks/base` | `candidates.json` | 6주 |
| M7. Prioritizer | `candidates.json` | `ranked_candidates.json` | 6주 |
| M8. Verifier — Harness | `root_cause.json` 가설 + `call_path.json` | `test_cases.json` + 테스트 APK | 7주 |
| M8. Verifier — 실행·판정 | `test_cases.json` | `verification.json` + logcat | 2주(환경) · 7주 |
| M9. Reporter | 위 JSON 전부 | `report.json`, `report.md`, `report.html` (+ `_public` 마스킹본) | 8주 |
| M10. Web Dashboard | 모든 단계의 JSON | Streamlit 대시보드 (최종 산출물) | 6·8주 |
| M11. Evaluation | `baselines/<CVE-ID>.json` + 결과 | `output/eval.json` | 8주 |

모든 모듈은 **독립 실행 가능**(단계별 CLI 서브커맨드)하고, 앞 단계의 JSON만 있으면 다음 단계를 다시 돌릴 수 있어야 한다.

## 3. 기능 상세

우선순위: **P0** = MVP 필수 / **P1** = 있으면 좋음 / **P2** = 여유 있으면

**P0 범위 (v0.3에서 축소)** — 8주 안에 끝내는 것을 기준으로 아래 10개로 제한한다.

1. CVE 또는 패치 commit 수집 — F-101, F-103
2. diff와 변경 전·후 소스 저장 — F-104
3. 변경 클래스·메서드·보안 API 추출 — F-201, F-203
4. 제한된 AIDL/Binder 경로 분석 (변경 메서드 → 같은 서비스의 Binder 메서드까지) — F-301, F-302
5. 근거 기반 Root Cause 및 보안 불변식 생성 — F-401~F-403, F-405, F-406
6. 취약 패턴 2종 (권한 검사 누락, UID–packageName 불일치) — F-501~F-504
7. `frameworks/base` 스캔과 후보 순위화 — F-601, F-701, F-702
8. 기준선 CVE 1건의 패치 전후 검증 — F-801, F-803, F-804, F-807, F-1105(정답 데이터)
9. JSON·Markdown·HTML 보고서 — F-901, F-902, F-905
10. 미리 생성된 JSON을 보여주는 최소 대시보드 — D-1, D-3, D-4, D-6~D-9, F-1004(CLI), F-1005(설정)

복수 CVE 자동 재현, 패턴 3종 이상, 범용 테스트 생성, WebSocket·비동기 작업 큐, 설정 화면은 P1/P2.

### M1. Collector — CVE/패치 수집

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-101 | CVE 입력 | CVE ID 또는 AOSP 커밋 URL/해시 입력 | P0 |
| F-102 | 보안 공지 파싱 | Android Security Bulletin에서 컴포넌트·심각도·영향 버전·패치 링크 추출 (P0는 커밋 URL 직접 입력으로 대체 가능) | P1 |
| F-103 | 패치 메타데이터 수집 | 커밋 메시지, 작성일, 부모 커밋, 변경 파일 목록 | P0 |
| F-104 | diff·소스 저장 | 패치 diff(`patches/<hash>.diff`)와 변경 파일의 전/후 원본(`src/<hash>/before·after/`) 저장, 경로를 `cve.json`에 기록 | P0 |
| F-105 | 예외 처리 | 잘못된 링크, 비공개 버그, 여러 브랜치에 나뉜 패치 처리 | P1 |
| F-106 | 캐시 | 이미 수집한 CVE는 재다운로드하지 않음 | P1 |

### M2. Patch Analyzer — 패치 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-201 | 변경 위치 추출 | Tree-sitter로 변경된 클래스·메서드 식별, hunk별 전/후 코드(`CodeRef`) 보관 | P0 |
| F-202 | 변경 유형 분류 | 조건문 추가/변경, 권한 검사 추가, 예외 처리, 입력 검증 추가 등으로 분류 | P1 |
| F-203 | 권한 검사 API 인식 | `enforceCallingPermission`, `checkCallingOrSelfPermission`, `Binder.getCallingUid`, `handleIncomingUser` 등 탐지 | P0 |
| F-204 | 기준선 비교 | 수동 분석 정답 데이터와 비교해 일치율 출력 | P1 |

### M3. Binder Path Analyzer — 진입점 경로 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-301 | AIDL 매핑 | Tree-sitter로 `.aidl` 인터페이스 ↔ `Stub` 구현 클래스(Service) 연결 | P0 |
| F-302 | 호출 경로 추출 (제한) | 외부 진입점(Binder 메서드) → 패치된 함수까지 호출 경로. P0는 같은 서비스 클래스 안까지만, 못 찾으면 `unresolved`로 기록 | P0 |
| F-303 | 노출 여부 판정 | 해당 경로가 일반 앱에서 호출 가능한지 (서비스 등록, 권한 요구 여부) | P1 |
| F-304 | 경로 시각화 | 호출 그래프를 보고서용 다이어그램으로 출력 | P2 |

### M4. Root Cause Analyzer — AI 보조 원인 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-401 | 근본 원인 생성 | M2·M3 증거를 LLM에 넣어 근본 원인·발생 조건 생성 | P0 |
| F-402 | 보안 불변식 도출 | "이 동작 전에는 반드시 X 검사가 있어야 한다" 형태로 정리 | P0 |
| F-403 | 근거 연결 | 모든 주장에 근거(`Evidence` = commit·side·줄 범위·snippet + 주장) 첨부, 실제 hunk와 대조해 없는 위치는 버리고 근거 없는 주장은 표시 | P0 |
| F-404 | 스키마 검증 | LLM 출력이 JSON 스키마를 따르는지 검사, 실패 시 재시도 | P1 |
| F-405 | LLM 추상화 | `LlmClient.generate_structured(prompt, schema)` 인터페이스만 사용, 업체 SDK는 구현체에만 | P0 |
| F-406 | 추론 상태 표시 | LLM 결과는 `status=inferred` 분석 초안으로 저장, 사람이 확인해야 `confirmed`. provider·model·prompt hash 기록 | P0 |

### M5. Pattern / Rule Generator — 취약 패턴·탐지 규칙

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-501 | source·guard·sink 추출 | 입력(source), 검사(guard), 민감 동작(sink) 구조로 패턴화 | P0 |
| F-502 | 패턴 2종 | ① 권한 검사 누락 ② UID–packageName 불일치 | P0 |
| F-506 | 패턴 추가 | ③ Cross-user 검사 누락 등 3종 이상 | P1 |
| F-503 | 규칙 변환 | 패턴을 Tree-sitter Query(`.scm`) + Python matcher 규칙으로 변환 | P0 |
| F-504 | 규칙 자가 검증 | 패치 전 소스에서는 탐지, 패치 후 소스에서는 미탐지인지 확인. 통과한 규칙만 M6에서 사용 | P0 |
| F-505 | 과적합 분리 | 특정 CVE에만 맞는 조건과 일반 조건 분리 | P1 |

### M6. Scanner — AOSP 유사 코드 스캔

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-601 | 전체 스캔 | 생성 규칙을 `frameworks/base` 전체에 적용, 후보마다 위치·코드(`CodeRef`)와 매칭된 source/sink 위치 기록 | P0 |
| F-602 | 중복 제거 | 같은 위치/같은 원인 결과 병합 | P1 |
| F-603 | 증분 스캔 | 특정 디렉터리·서비스만 스캔 | P2 |

### M7. Prioritizer — 후보 우선순위화

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-701 | 점수화 | Binder 노출 여부 + 민감 동작 여부 + 검증 누락 여부로 점수 계산 | P0 |
| F-702 | 상위 N 출력 | 상위 10~20건 출력, 점수 산정 근거 함께 표시 | P0 |
| F-703 | 수동 라벨링 | 사람이 TP/FP/보류로 표시하고 결과에 반영 | P1 |

### M8. Verifier — 패치 전후 동적 검증

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-801 | 환경 초기화 | Cuttlefish 재시작 (Emulator 전환 시 스냅샷 복원) | P0 |
| F-807 | 기준선 테스트 | 기준선 CVE 1건용 테스트 APK / instrumentation을 템플릿으로 작성 (`TestCase`) | P0 |
| F-802 | 범용 테스트 생성 (Harness) | 가설(`hypotheses`) → `TestCase`(대상 서비스·메서드, 인자, 호출자 권한, 전/후 기대 결과) → APK 자동 생성 | P1 |
| F-803 | 실행 자동화 | 초기화 → APK 설치 → 테스트 실행 → logcat 수집을 한 명령으로 | P0 |
| F-804 | 차등 판정 | 취약 버전 vs 패치 버전 결과 비교 (SecurityException, 크래시, 반환값 등). 빌드 정보·logcat 경로·판정 근거 줄 기록 | P0 |
| F-808 | 복수 CVE 재현 | 공개 CVE 2~3건 자동 재현 | P1 |
| F-805 | 실패 원인 분류 | 환경/빌드/가설/테스트 실패 구분 | P1 |
| F-806 | 재시도 정책 | 부팅 지연·flaky test 재시도 | P2 |

### M9. Reporter — 보고서 생성

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-901 | Markdown 보고서 | CVE 요약, 패치 분석, 호출 경로, 근본 원인, 패턴, 후보, 검증 결과 | P0 |
| F-902 | HTML 보고서 | 같은 내용 + diff 하이라이트, 로그 접기/펼치기 | P0 |
| F-905 | JSON 보고서 | 모든 단계 결과를 묶은 `report.json` (대시보드·정적 데모 입력) | P0 |
| F-903 | 근거 링크 | 각 주장마다 diff 줄·로그 위치 링크 | P1 |
| F-904 | 공개용 마스킹 | 미공개 후보의 코드·위치·재현 입력을 제거한 `_public` 버전 생성 (발표용 화면은 이것만 사용) | P1 |

### M10. Web Dashboard — 최종 산출물

#### 화면 구성

Streamlit 단독. 미리 생성된 JSON만 읽는다. P0 화면이 끝나면 여유에 따라 확대.

| ID | 화면 | 보여주는 것 / 할 수 있는 것 | 데이터 | 우선순위 |
| --- | --- | --- | --- | --- |
| D-1 | CVE 목록 | 분석된 CVE 목록, 컴포넌트·심각도·재현 결과 요약 | `cve.json`, `verification.json` | P0 |
| D-3 | 패치 | 패치 diff (hunk별 before/after), 변경 클래스·메서드·보안 API | `cve.json`, `patch_analysis.json` | P0 |
| D-4 | Root Cause | 근본 원인·발생 조건·보안 불변식 (`inferred` 표시), 근거 코드 | `root_cause.json` | P0 |
| D-6 | 패턴 | Source–Guard–Sink, 규칙 원문, 자가 검증 결과 | `pattern.json` | P0 |
| D-7 | 후보 | 점수순 후보, 점수 근거, 코드 근거(snippet) | `ranked_candidates.json` | P0 |
| D-8 | 검증 결과 | 취약 vs 패치 결과 비교, 판정, logcat 근거 줄 | `verification.json` | P0 |
| D-9 | 보고서 | HTML/Markdown/JSON 다운로드 (공개 모드는 `_public`만) | `report.*` | P0 |
| D-5 | 호출 경로 | Binder 진입점 → 변경 함수 경로 | `call_path.json` | P1 |
| D-10 | 평가 | 지표 차트, CVE별 비교표 | `output/eval.json` | P1 |
| D-12 | 후보 라벨링 | TP/FP/보류 표시를 JSON에 저장 | `ranked_candidates.json` | P1 |
| D-2 | 새 분석 실행 | 대시보드에서 파이프라인 실행·진행률 | — | P2 |
| D-11 | 설정 | 설정 확인/수정 | `config.yaml` | P2 |

#### 기능

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-1004 | CLI | `run`/`collect`/`analyze`/`binder-path`/`root-cause`/`pattern`/`scan`/`prioritize`/`harness`/`verify`/`report`/`eval`/`dashboard` | P0 |
| F-1005 | 설정 파일 | `config.yaml`(커밋 금지, `config.example.yaml`만 커밋)에 AOSP 경로·LLM provider/model/키 환경변수 **이름**·기기 설정 | P0 |
| F-1006 | 공개 모드 | 대시보드를 `_public` JSON만 읽는 모드로 실행 (발표용) | P1 |
| F-1003 | 단계별 재실행 | `run --start <단계>` | P1 |
| F-1001 | Backend API | (삭제) Streamlit 단독으로 결정 — 별도 프론트엔드가 필요해지면 재도입 | — |
| F-1002 | 비동기 작업 큐 / WebSocket | (P2) 대시보드에서 실행 기능을 넣을 때만 | P2 |

### M11. Evaluation

| ID | 지표 | 측정 방법 | 우선순위 |
| --- | --- | --- | --- |
| F-1105 | 정답 데이터 형식 | 3주차 수동 기준선을 `baselines/<CVE-ID>.json`(`Baseline`)으로 작성 | P0 |
| F-1101 | 분석 정확도 | 기준선 정답 대비 변경 함수·원인 일치율 | P1 |
| F-1102 | 탐지율 | 알려진 CVE를 규칙이 다시 찾아내는 비율 | P1 |
| F-1103 | 오탐률 | 상위 후보 중 FP 비율 (수동 라벨 기준) | P1 |
| F-1104 | 시간 절감 | 수동 분석 소요 시간 vs 도구 소요 시간 | P1 |

## 4. 공통 데이터 (JSON 스키마)

코드 기준: [`aosp1day/schemas.py`](../aosp1day/schemas.py) (PR #30). 이 장과 코드가 다르면 둘 다 고친다.
산출물은 `output/<CVE-ID>/` 아래에 저장한다 (평가만 `output/eval.json`).

### 4.1 공통 구조

모든 산출물은 `meta`를 가진다. 코드 위치는 전부 `CodeRef` 하나로 표현한다.

```jsonc
// meta — 재현성·추적성
{ "schema_version": "0.2", "generated_at": "", "tool_version": "", "stage": "",
  "inputs": { "<입력 산출물>": "<sha256>" } }

// CodeRef — 코드 출처 (M2 hunk, M3 경로 노드, M4 근거, M6 후보, Baseline)
{ "commit": "", "file": "", "side": "before|after|aosp",
  "start_line": 0, "end_line": 0, "snippet": "", "diff_path": "", "class": "", "method": "" }

// Evidence = CodeRef + 어떤 주장을 뒷받침하는지
{ ...CodeRef, "claim": "", "change_id": "" }

// Claim — 주장 + 근거 목록 (근거가 비어 있으면 "근거 없음" 표시)
{ "text": "", "evidence": [Evidence] }
```

### 4.2 단계별 산출물

```jsonc
// cve.json (M1)
{ "meta": {}, "cve_id": "", "bulletin": "", "bulletin_url": "", "severity": "", "type": "",
  "component": "", "affected_versions": [], "notes": [],
  "patch_commits": [{ "repo": "", "hash": "", "parent": "", "url": "", "branch": "",
    "message": "", "authored_at": "", "changed_files": [],
    "diff_path": "patches/<hash>.diff", "before_dir": "src/<hash>/before", "after_dir": "src/<hash>/after" }] }

// patch_analysis.json (M2)
{ "meta": {}, "cve_id": "", "baseline_match": null,
  "changes": [{ "id": "chg-1", "commit": "", "file": "", "class": "", "method": "",
    "change_type": "permission_check|input_validation|condition|exception|other",
    "security_apis": [], "hunks": [{ "before": CodeRef, "after": CodeRef }] }] }

// call_path.json (M3)
{ "meta": {}, "cve_id": "", "unresolved": ["chg-2"],
  "paths": [{ "target_change": "chg-1", "aidl_interface": "", "aidl_file": "", "stub_impl": "",
    "entrypoint": "", "app_reachable": null, "required_permissions": [],
    "nodes": [{ "ref": CodeRef, "call_site": CodeRef }] }] }

// root_cause.json (M4) — 확정 판정이 아닌 분석 초안
{ "meta": {}, "cve_id": "", "status": "inferred|confirmed|rejected", "reviewed_by": "",
  "root_cause": Claim, "trigger_conditions": [Claim], "security_invariant": Claim,
  "hypotheses": [Claim],
  "llm": { "provider": "", "model": "", "temperature": 0, "prompt_hash": "", "prompt_path": "" } }

// pattern.json (M5) — 패턴 목록
{ "meta": {}, "cve_id": "",
  "patterns": [{ "pattern_id": "", "type": "missing_permission|uid_pkg_mismatch|cross_user",
    "source": { "kind": "", "apis": [], "description": "" },
    "guard":  { "kind": "", "apis": [], "description": "" },
    "sink":   { "kind": "", "apis": [], "description": "" },
    "invariant": "", "rule_file": "rules/<id>.scm", "generic": true,
    "check": { "vulnerable_hits": 0, "patched_hits": 0, "passed": false },
    "derived_from": [Evidence] }] }

// candidates.json (M6) / ranked_candidates.json (M7)
{ "meta": {}, "cve_id": "", "aosp_revision": "",        // ranked 는 "weights": {} 추가
  "candidates": [{ "id": "", "pattern_id": "", "location": CodeRef,
    "matched": { "source": CodeRef, "sink": CodeRef },
    "score": 0, "score_reason": { "binder_exposed": false, "sensitive_sink": false, "guard_missing": false, "notes": "" },
    "label": "unreviewed|tp|fp|hold", "public": false }] }

// test_cases.json (M8 Harness)
{ "meta": {}, "cve_id": "",
  "tests": [{ "id": "", "hypothesis": "", "target_service": "", "target_interface": "", "target_method": "",
    "call_args": {}, "caller": "untrusted_app", "expected_vulnerable": "", "expected_patched": "",
    "template": "", "apk_path": "" }] }

// verification.json (M8)
{ "meta": {}, "cve_id": "", "target": "", "verdict": "reproduced|not_reproduced|error",
  "results": [{ "test_id": "", "verdict": "", "failure_reason": "env|build|hypothesis|test",
    "vulnerable": { "build": { "side": "vulnerable", "device": "cuttlefish|emulator", "image": "", "fingerprint": "" },
                    "outcome": "", "logcat_path": "", "log_excerpt": [], "exit_code": null },
    "patched":    { ... } }] }

// baselines/<CVE-ID>.json (3주차 수동 정답)
{ "cve_id": "", "analyst": "", "changed_methods": [CodeRef], "root_cause": "", "security_invariant": "",
  "trigger_conditions": [], "entrypoint": "", "repro_steps": [],
  "expected_vulnerable": "", "expected_patched": "", "analysis_minutes": null }

// output/eval.json (M11)
{ "meta": {}, "per_cve": [{ "cve_id": "", "method_match": null, "root_cause_match": null,
    "reproduced": null, "tool_minutes": null }],
  "analysis_accuracy": null, "detection_rate": null, "false_positive_rate": null, "time_saved": null }
```

## 5. 비기능 요구사항

| 항목 | 요구사항 |
| --- | --- |
| 재현성 | 같은 입력이면 같은 결과. 모든 산출물에 `meta`(스키마 버전·입력 해시), LLM은 temperature 고정 + provider·model·prompt hash 기록 |
| 추적성 | 모든 주장·후보·판정에 근거(`CodeRef`: commit·전/후·줄 범위·snippet, logcat 줄) 연결 |
| LLM 결과 | 확정 판정이 아니라 `inferred` 분석 초안. 최종 판단은 사람이 함 |
| 비밀값 | API 키는 환경변수로만 전달. `config.yaml`에는 provider·model·환경변수 **이름**만. `.env`·`config.yaml`은 `.gitignore`. 키를 결과 JSON·로그·프롬프트 기록·대시보드에 넣지 않음. CI는 GitHub Actions Secret |
| 모듈성 | 단계별 독립 실행, JSON으로만 연결 (대시보드도 JSON만 읽음) |
| 공개·배포 | 대시보드는 로컬/팀 내부에서만 실행. 미공개 후보의 코드·위치·재현 입력은 외부 공개 금지. 발표용 공개 화면은 사전 생성한 마스킹 JSON만 사용. 공개 결과물은 Markdown/HTML 보고서 또는 정적 데모 |
| 실행 환경 | Linux + KVM (Cuttlefish), Python 3.11+, AOSP `frameworks/base` 체크아웃, ADB. Emulator 전환 시 Android SDK Emulator |
| 윤리 | 실제 공격용 exploit 미포함, 미공개 후보는 공개 보고서에서 마스킹 |

## 6. 결정 사항

| 항목 | 결정 | 근거 |
| --- | --- | --- |
| P0 범위 | 3장 앞의 10개로 축소 | PR #20 리뷰 |
| 규칙 엔진 | **Tree-sitter로 통일** — M2 Java AST 추출, M3 AIDL/Stub/Service 분석, M5·M6 Tree-sitter Query + Python matcher | PR #20 리뷰 |
| 검증 기기 | **Cuttlefish 1차**. 2주차 종료(11/8) 전 `launch_cvd` 부팅 · `adb devices` 연결 · 테스트 APK 설치 · logcat 수집이 안 되면 **Emulator로 전환**. 최종 구현은 하나만 지원 | PR #20 리뷰 |
| LLM | `LlmClient.generate_structured(prompt, schema)` 인터페이스, 키는 환경변수, 결과는 `inferred` | PR #20 리뷰 |
| 대시보드 | **Streamlit 단독**, 미리 생성된 JSON만 읽음 | PR #20 리뷰 |
| 배포 | 5장 "공개·배포" | PR #20 리뷰 |
| 데이터 계약 | 모든 코드 위치를 `CodeRef`(commit·side·줄 범위·snippet)로, 근거는 `Evidence` | PR #30 리뷰 |

## 7. 남은 논의

- [ ] 담당자 배정 (구현 시작 전 별도 확정)
- [ ] Linux + KVM 머신 확보 (누가, 어디서)
- [ ] 패치 전·후 이미지 준비 방식: CI 빌드 이미지 다운로드 vs `framework.jar`/`services.jar` 교체 vs 직접 빌드
- [ ] LLM provider·model 선정
