# 기능명세서 (Feature Specification)

> 산출물 툴: **AOSP Framework 1-Day 패치 기반 분석·유사 취약점 탐지 도구**
> 용어가 낯설면 [glossary.md](glossary.md) 참고
> 상태: 초안 (v0.2, 2026-11-02 — 산출물 형태를 웹 대시보드로 확정) — 팀 리뷰 후 확정

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

최종 산출물은 **웹 대시보드**다. 사용자는 브라우저에서 CVE를 입력하고, 단계별 진행 상황·분석 결과·후보·검증 결과·보고서를 한 곳에서 본다. 내부 파이프라인(M1~M9)은 CLI로도 돌릴 수 있게 두고, 대시보드는 그 결과 JSON을 읽어 보여준다.

```
[브라우저] ⇄ [Web Dashboard (Frontend)] ⇄ [Backend API] → 파이프라인 작업 실행 (M1~M9)
                                                  ↘ output/<CVE-ID>/*.json 읽기
```

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
| M8. Verifier (동적 검증) | CVE/후보 + 테스트 템플릿 | `verification.json` + 로그 | 7주 |
| M9. Reporter | 위 JSON 전부 | `report.html`, `report.md` | 8주 |
| M10. Web Dashboard | 사용자 조작 + 모든 단계의 JSON | 웹 대시보드 (최종 산출물) | 6·8주 |
| M11. Evaluation | 정답 데이터 + 결과 | `eval.json`, 평가표 | 8주 |

모든 모듈은 **독립 실행 가능**(단계별 CLI 서브커맨드)하고, 앞 단계의 JSON만 있으면 다음 단계를 다시 돌릴 수 있어야 한다.

## 3. 기능 상세

우선순위: **P0** = MVP 필수 / **P1** = 있으면 좋음 / **P2** = 여유 있으면

### M1. Collector — CVE/패치 수집

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-101 | CVE 입력 | CVE ID 또는 AOSP 커밋 URL/해시 입력 | P0 |
| F-102 | 보안 공지 파싱 | Android Security Bulletin에서 컴포넌트·심각도·영향 버전·패치 링크 추출 | P0 |
| F-103 | 패치 메타데이터 수집 | 커밋 메시지, 작성일, 부모 커밋, 변경 파일 목록 | P0 |
| F-104 | diff 저장 | 패치 diff와 변경 전/후 파일 원본 저장 | P0 |
| F-105 | 예외 처리 | 잘못된 링크, 비공개 버그, 여러 브랜치에 나뉜 패치 처리 | P1 |
| F-106 | 캐시 | 이미 수집한 CVE는 재다운로드하지 않음 | P1 |

### M2. Patch Analyzer — 패치 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-201 | 변경 위치 추출 | Tree-sitter로 변경된 클래스·메서드 식별 | P0 |
| F-202 | 변경 유형 분류 | 조건문 추가/변경, 권한 검사 추가, 예외 처리, 입력 검증 추가 등으로 분류 | P0 |
| F-203 | 권한 검사 API 인식 | `enforceCallingPermission`, `checkCallingOrSelfPermission`, `Binder.getCallingUid`, `handleIncomingUser` 등 탐지 | P0 |
| F-204 | 기준선 비교 | 수동 분석 정답 데이터와 비교해 일치율 출력 | P1 |

### M3. Binder Path Analyzer — 진입점 경로 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-301 | AIDL 매핑 | `.aidl` 인터페이스 ↔ `Stub` 구현 클래스(Service) 연결 | P0 |
| F-302 | 호출 경로 추출 | 외부 진입점(Binder 메서드) → 패치된 함수까지 호출 경로 | P0 |
| F-303 | 노출 여부 판정 | 해당 경로가 일반 앱에서 호출 가능한지 (서비스 등록, 권한 요구 여부) | P1 |
| F-304 | 경로 시각화 | 호출 그래프를 보고서용 다이어그램으로 출력 | P2 |

### M4. Root Cause Analyzer — AI 보조 원인 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-401 | 근본 원인 생성 | M2·M3 증거를 LLM에 넣어 근본 원인·발생 조건 생성 | P0 |
| F-402 | 보안 불변식 도출 | "이 동작 전에는 반드시 X 검사가 있어야 한다" 형태로 정리 | P0 |
| F-403 | 근거 연결 | 모든 주장에 diff 줄·파일 위치 근거 첨부, 근거 없는 주장은 표시 | P0 |
| F-404 | 스키마 검증 | LLM 출력이 JSON 스키마를 따르는지 검사, 실패 시 재시도 | P1 |

### M5. Pattern / Rule Generator — 취약 패턴·탐지 규칙

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-501 | source·guard·sink 추출 | 입력(source), 검사(guard), 민감 동작(sink) 구조로 패턴화 | P0 |
| F-502 | 패턴 3종 이상 | ① 권한 검사 누락 ② UID–packageName 불일치 ③ Cross-user 검사 누락 | P0 |
| F-503 | 규칙 변환 | 패턴을 Semgrep 또는 Tree-sitter 쿼리로 변환 | P0 |
| F-504 | 규칙 자가 검증 | 취약 버전에서는 탐지, 패치 버전에서는 미탐지인지 확인 | P0 |
| F-505 | 과적합 분리 | 특정 CVE에만 맞는 조건과 일반 조건 분리 | P1 |

### M6. Scanner — AOSP 유사 코드 스캔

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-601 | 전체 스캔 | 생성 규칙을 `frameworks/base` 전체에 적용 | P0 |
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
| F-801 | 환경 초기화 | Emulator/Cuttlefish 스냅샷 복원 | P0 |
| F-802 | 테스트 템플릿 | 테스트 APK / instrumentation 템플릿에 Intent·Binder 호출 파라미터 주입 | P0 |
| F-803 | 실행 자동화 | 초기화 → APK 설치 → 테스트 실행 → logcat 수집을 한 명령으로 | P0 |
| F-804 | 차등 판정 | 취약 버전 vs 패치 버전 결과 비교 (SecurityException, 크래시, 반환값 등) | P0 |
| F-805 | 실패 원인 분류 | 환경/빌드/가설/테스트 실패 구분 | P1 |
| F-806 | 재시도 정책 | 부팅 지연·flaky test 재시도 | P2 |

### M9. Reporter — 보고서 생성

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-901 | Markdown 보고서 | CVE 요약, 패치 분석, 호출 경로, 근본 원인, 패턴, 후보, 검증 결과 | P0 |
| F-902 | HTML 보고서 | 같은 내용 + diff 하이라이트, 로그 접기/펼치기 | P0 |
| F-903 | 근거 링크 | 각 주장마다 diff 줄·로그 위치 링크 | P1 |
| F-904 | 공개용 마스킹 | 미공개 후보·위험 입력 제거한 공개용 버전 생성 (책임 있는 공개) | P1 |

### M10. Web Dashboard — 최종 산출물

#### 화면 구성

| ID | 화면 | 보여주는 것 / 할 수 있는 것 | 데이터 | 우선순위 |
| --- | --- | --- | --- | --- |
| D-1 | 홈 (CVE 목록) | 분석한 CVE 목록, 컴포넌트·심각도·진행 상태·재현 결과 요약, 검색/필터 | `cve.json`, `verification.json` | P0 |
| D-2 | 새 분석 실행 | CVE ID / 커밋 URL 입력 → 실행, 단계별 진행률(수집→분석→경로→패턴→스캔→검증→보고서), 실패 단계·에러 로그 | 작업 상태 API | P0 |
| D-3 | CVE 상세 — 패치 | 보안 공지 정보, 패치 diff 뷰어(추가·삭제 하이라이트), 변경 클래스·메서드·변경 유형 | `cve.json`, `patch_analysis.json` | P0 |
| D-4 | CVE 상세 — 원인 분석 | 근본 원인, 발생 조건 가설, 보안 불변식, 근거 클릭 시 diff 해당 줄로 이동 | `root_cause.json` | P0 |
| D-5 | CVE 상세 — 호출 경로 | Binder 진입점 → 변경 함수 호출 그래프, 일반 앱 노출 여부 | `call_path.json` | P1 |
| D-6 | 패턴 / 규칙 | 추출 패턴(source·guard·sink), 생성된 규칙 원문, 취약·패치 버전 자가 검증 결과 | `pattern.json` | P0 |
| D-7 | 유사 후보 | 스캔 후보 표(점수순), 점수 근거, 코드 위치 미리보기, TP/FP/보류 라벨링 | `ranked_candidates.json` | P0 |
| D-8 | 검증 결과 | 취약 vs 패치 버전 결과 나란히 비교, 판정, logcat 펼치기, 실패 원인 | `verification.json` | P0 |
| D-9 | 보고서 | 보고서 미리보기, HTML/Markdown 다운로드, 공개용(마스킹) 버전 다운로드 | `report.*` | P0 |
| D-10 | 평가 | 정확도·탐지율·오탐률·시간 절감 지표 차트, CVE별 비교표 | `eval.json` | P1 |
| D-11 | 설정 | AOSP 경로, LLM 모델, Emulator 설정 확인/수정 | `config.yaml` | P2 |

#### 기능

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-1001 | Backend API | 파이프라인 실행·상태 조회·결과 조회 REST API (아래 표) | P0 |
| F-1002 | 비동기 작업 실행 | 분석은 오래 걸리므로 작업 큐로 실행하고 진행 상태를 폴링/웹소켓으로 갱신 | P0 |
| F-1003 | 단계별 재실행 | 특정 단계부터 다시 실행 (예: 패턴만 다시 생성) | P1 |
| F-1004 | CLI 유지 | 대시보드 없이도 `run`/`collect`/`analyze`/`scan`/`verify`/`report` 실행 가능 (개발·디버깅용) | P0 |
| F-1005 | 설정 파일 | AOSP 경로, LLM 키/모델, Emulator 설정을 `config.yaml`로 관리 (키는 환경변수, 리포에 커밋 금지) | P0 |
| F-1006 | 데모 모드 | 미리 돌려둔 결과 JSON만으로 화면 시연 (발표용, Emulator 없이) | P1 |

#### Backend API 초안

| Method | Endpoint | 설명 |
| --- | --- | --- |
| POST | `/api/analyses` | 새 분석 실행 (`{ "cve_id" }` 또는 `{ "commit_url" }`) |
| GET | `/api/analyses` | 분석 목록 |
| GET | `/api/analyses/{cve_id}` | 진행 상태 + 단계별 결과 요약 |
| GET | `/api/analyses/{cve_id}/{stage}` | 단계 결과 JSON (`patch`, `call_path`, `root_cause`, `pattern`, `candidates`, `verification`) |
| PATCH | `/api/candidates/{id}` | 후보 라벨 수정 (TP/FP/보류) |
| GET | `/api/analyses/{cve_id}/report?format=html\|md&public=true` | 보고서 다운로드 |
| GET | `/api/eval` | 평가 지표 |

### M11. Evaluation

| ID | 지표 | 측정 방법 | 우선순위 |
| --- | --- | --- | --- |
| F-1101 | 분석 정확도 | 기준선 정답 대비 변경 함수·원인 일치율 | P0 |
| F-1102 | 탐지율 | 알려진 CVE를 규칙이 다시 찾아내는 비율 | P0 |
| F-1103 | 오탐률 | 상위 후보 중 FP 비율 (수동 라벨 기준) | P0 |
| F-1104 | 시간 절감 | 수동 분석 소요 시간 vs 도구 소요 시간 | P1 |

## 4. 공통 데이터 (JSON 스키마 초안)

모든 산출물은 `output/<CVE-ID>/` 아래에 저장한다. 1주차에 확정할 핵심 필드만 정리.

```jsonc
// cve.json
{ "cve_id": "", "bulletin": "", "severity": "", "component": "",
  "affected_versions": [], "patch_commits": [{ "repo": "", "hash": "", "parent": "", "url": "" }],
  "changed_files": [] }

// patch_analysis.json
{ "cve_id": "", "changes": [{ "file": "", "class": "", "method": "",
  "change_type": "permission_check|input_validation|condition|exception",
  "added_lines": [], "removed_lines": [] }] }

// root_cause.json
{ "cve_id": "", "root_cause": "", "trigger_conditions": [],
  "security_invariant": "", "evidence": [{ "file": "", "line": 0 }] }

// pattern.json
{ "pattern_id": "", "type": "missing_permission|uid_pkg_mismatch|cross_user",
  "source": "", "guard": "", "sink": "", "rule_file": "" }

// ranked_candidates.json
{ "candidates": [{ "id": "", "file": "", "method": "", "pattern_id": "",
  "score": 0, "score_reason": { "binder_exposed": true, "sensitive_sink": true, "guard_missing": true },
  "label": "unreviewed|tp|fp" }] }

// verification.json
{ "target": "", "vulnerable_build": { "result": "", "log": "" },
  "patched_build": { "result": "", "log": "" }, "verdict": "reproduced|not_reproduced|error",
  "failure_reason": "" }
```

## 5. 비기능 요구사항

| 항목 | 요구사항 |
| --- | --- |
| 재현성 | 같은 입력이면 같은 결과 (LLM은 temperature 고정, 프롬프트·모델 버전 기록) |
| 추적성 | 모든 결과에 근거(diff 줄, 로그 위치) 연결 |
| 모듈성 | 단계별 독립 실행, JSON으로만 연결 (대시보드도 JSON만 읽음) |
| 접근 제어 | 대시보드는 기본 로컬/팀 내부 접근만, 미공개 후보 화면은 외부 공개 금지 |
| 실행 환경 | Linux, Python 3.11+, AOSP 소스 체크아웃, Android SDK/ADB/Emulator |
| 윤리 | 실제 공격용 exploit 미포함, 미공개 후보는 공개 보고서에서 마스킹 |

## 6. 리뷰할 것 (팀 논의)

- [ ] 모듈 → 담당자 배정
- [ ] P0 범위가 8주 안에 가능한지
- [ ] 규칙 엔진: Semgrep vs Tree-sitter 중 하나로 통일할지
- [ ] Emulator vs Cuttlefish
- [ ] 사용할 LLM / API 키 관리 방식
- [ ] 대시보드 기술 스택 (예: FastAPI + React / Next.js, 또는 FastAPI + Streamlit으로 빠르게)
- [ ] 대시보드 배포 방식 (로컬 실행 vs 서버 배포, 공개 시 미공개 후보 노출 금지)
