# 기능명세서 (Feature Specification)

> 산출물 툴: **공개 패치 기반 AOSP 유사 취약점 탐지 도구** - 패치 기반 규칙 생성 파이프라인
> 용어가 낯설면 [glossary.md](glossary.md) 참고 · 클래스·메서드 상세는 [design.md](design.md) · 범위 근거는 [scope-v2.3.md](scope-v2.3.md)
> 상태: **v0.5 (2026-11-28)** - 4주 계획(1~4주차) 재편, 1주차 공통 JSON 형식(`patch`/`vuln_pattern`/`rule`), 수정 유형 `pattern_type`·Guard 유형 새 이름 반영 (대응표: [design.md](design.md) v2.5). 모듈 구성은 그대로.
> 이전: **v0.4 (2026-11-23)** - 설계 v2.4 와 맞춤. ① 동적 재현(M8)을 **후속 범위로 분리**(이번 프로젝트 산출물·평가·일정에서 제외) ② 대상을 "지원 대상에 해당하는 AOSP 공개 보안 패치" 로 정의 ③ 수정 유형 분류(`fix_kind`)·차분 오라클·3개 트랙·T1~T3 규칙 생성 반영 ④ 한계 대응(L1~L8) 반영.
> 이전 버전: v0.3.1 (2026-11-05, PR #20·#30 리뷰 반영) - 동적 검증 관련 결정은 부록 A 로 옮김.

## 1. 개요

공개된 CVE·보안 패치를 입력하면, 패치가 고친 결함 구조를 **탐지 규칙으로 생성하고 패치 전·후 코드로 검증**한 뒤, 같은 결함이 남아 있는 다른 AOSP 코드 후보를 찾아 순위화하고, 근거와 함께 보고서·대시보드로 보여주는 도구.

새 패치가 들어온다는 것은 **모델을 재학습한다는 뜻이 아니라**, 그 패치에서 규칙을 새로 생성·검증하는 파이프라인을 한 번 더 돈다는 뜻이다. 검증된 규칙은 파일(패턴 라이브러리)로 저장해 다음 분석에서 재사용한다.

```
CVE/패치 입력
→ 패치 분석 (수정 유형 분류)
→ 진입점·Source 경로 분석
→ 결함 구조(Source–Guard–Sink) 정리
→ 탐지 규칙 생성 + 차분 오라클 검증 (패치 전 탐지 · 후 미탐지 · 대조군 예산)
→ AOSP 유사 코드 스캔
→ 후보 선별·우선순위화 (+ LLM 검증 계층, 사람 라벨)
→ HTML/Markdown/JSON 보고서 · 대시보드
```

### 산출물 형태

최종 산출물은 **웹 대시보드**(Streamlit)다. 파이프라인(M1~M7, M9)은 CLI 로 실행해 `output/<CVE-ID>/*.json` 을 만들고, 대시보드는 **미리 생성된 JSON 을 읽어 보여주기만** 한다. 별도 Backend API·작업 큐는 두지 않는다.

```
[CLI] → 파이프라인 (M1~M7, M9) → output/<CVE-ID>/*.json → [Streamlit 대시보드] ⇄ [브라우저]
                                                    ↘ 마스킹 → report_public.* (공개용)
```

### 범위

| 구분 | 내용 |
| --- | --- |
| **지원 대상** | Android 보안 공지(2023~2025)에 AOSP 커밋 링크가 있는 패치 중 **Java(P0)·Kotlin(P1) 코드 변경으로 결함을 고친 것**. 저장소는 `frameworks/base` 외 `packages/*`, `packages/modules/*` 포함 ([scope-v2.3.md](scope-v2.3.md) 1절) |
| 처리 방식 | 템플릿에 맞는 형식은 트랙 A(권한형 Guard)·B(검사형)·C(API 교체형) 규칙으로, 맞지 않는 형식은 T2(LLM 규칙 합성)·T3(탐색형)으로 처리 ([novel-patterns.md](novel-patterns.md)) |
| **지원 대상 밖** (범위 밖으로 기록) | 네이티브(C/C++)·커널·벤더/비공개 수정, 리소스·설정만 바꾼 패치, 생성 코드만 바뀐 패치, 수정 지점을 분리할 수 없는 대규모 리팩터링, 실제 공격용 exploit 작성 |
| **후속 범위** (이번 프로젝트 제외) | **동적 재현·패치 전후 실행 검증**(M8 Harness·Verifier, 테스트 APK, 가상 기기). 코드·스키마 뼈대는 저장소에 남기되 산출물·평가·일정에 포함하지 않음 (부록 A) |
| 기준선 CVE | **CVE-2023-40105 · CVE-2024-0037 (확정)**. CVE-2023-21113 은 Development 데이터 겸 대체 기준선. 추가 후보: CVE-2024-0053 · CVE-2023-40111 · CVE-2023-40109 ([scope-v2.3.md](scope-v2.3.md) 5절) |

## 2. 전체 구조

| 모듈 | 입력 | 출력 (JSON) | 주차 |
| --- | --- | --- | --- |
| M1. Collector | CVE ID 또는 패치 커밋 URL/해시 | `cve.json` + `patches/`, `src/` | 1주차 (A: 기준선 전·후 소스 `sources/<CVE>/`) |
| M2. Patch Analyzer | `cve.json` | `patch_analysis.json` (`pattern_type`, 추가된 Guard·검사, 플래그 조건) | 1주차 (B: 추출기·`patterns/<CVE>.json`) |
| M3. Binder Path / Source | `patch_analysis.json` + AOSP 소스 | `call_path.json` | 2주차 (잠정) |
| M4. Root Cause (LLM, 트랙 A) | M2·M3 결과 | `root_cause.json` (S·G·S 초안) | 2주차 (잠정). 1주차는 `ground_truth.json` 의 S·G·S 로 대신 |
| M5. Pattern / Rule | M4·M2 결과 + 전·후 소스 | `pattern.json` + `rules/` | 1주차 (C: T1~T3 템플릿·차분 검증) |
| M6. Scanner | 규칙 + 스캔 스냅샷 인덱스 | `candidates.json` | 2주차 (잠정) |
| M7. Prioritizer | `candidates.json` | `ranked_candidates.json` | 2~3주차 (잠정) |
| M9. Reporter | 위 JSON 전부 | `report.json`·`.md`·`.html` (+ `_public`) | 3주차 (잠정) |
| M10. Web Dashboard | 모든 단계의 JSON | Streamlit 대시보드 (최종 산출물) + `labels.json` | 2~3주차 (잠정) |
| M11. Evaluation | `baselines/` + 결과 | `output/eval.json` | 3~4주차 (잠정) |
| ~~M8. Verifier~~ | - | - | **후속 범위** (부록 A) |

1주차 = 11/24~11/30, 2주차 = 12/1~12/7, 3주차 = 12/8~12/14, 4주차 = 12/15~12/21. 2주차 이후는 1주차 주말 점검 후 확정 ([roadmap.md](roadmap.md)).

모든 모듈은 **독립 실행 가능**(단계별 CLI 서브커맨드)하고, 앞 단계의 JSON 만 있으면 다음 단계를 다시 돌릴 수 있다.

## 3. 기능 상세

우선순위: **P0** = 이번 프로젝트 필수 / **P1** = 시간 되면 / **P2** = 여유 있으면 / **후속** = 이번 프로젝트 제외

**P0 범위 (v0.4)**

1. CVE·패치 커밋 수집, 다중 저장소, 같은 수정의 브랜치별 커밋 묶음 - F-101, F-103, F-104, F-107
2. 지원 대상 데이터셋 구축과 수정 유형 집계 - F-108
3. 변경 위치·보안 검사 추출, **수정 유형 분류**, 기능 플래그 처리 - F-201, F-202, F-203, F-205
4. 제한된 진입점 경로 분석 (Binder 진입점·`APP_OBJECT` Source, 도달성 3값) - F-301, F-302
5. 근거 기반 S·G·S 초안 (트랙 A) - F-401~F-403, F-405, F-406
6. **탐지 규칙 생성 + 차분 오라클 검증** (T1 템플릿, T2 LLM 합성 L0) - F-501, F-503, F-504, F-507, F-508
7. 스캔 스냅샷 기준 AOSP 스캔, 후보 순위화, 오탐 필터, LLM 질문 분해 검토 - F-601, F-604, F-701, F-702, F-704, F-705
8. JSON·Markdown·HTML 보고서 - F-901, F-902, F-905
9. 미리 생성된 JSON 을 보여주는 대시보드 (5개 탭 + 라벨) - D-1, D-3~D-7, D-9, F-1004, F-1005
10. 평가: 규칙 채택률, Precision(라벨), 회고 검증(LLM 끔), Vanir 베이스라인 - F-1105, F-1106, F-1107, F-1108

### M1. Collector - CVE/패치 수집

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-101 | CVE 입력 | CVE ID 또는 AOSP 커밋 URL/해시 입력 | P0 |
| F-102 | 보안 공지 파싱 | Android Security Bulletin 에서 컴포넌트·심각도·영향 버전·패치 링크 추출 | P1 |
| F-103 | 패치 메타데이터 수집 | 커밋 메시지, 작성일, 부모 커밋, 변경 파일 목록. **저장소는 커밋 URL 기준으로 일반화** | P0 |
| F-104 | diff·소스 저장 | 패치 diff 와 변경 파일의 전/후 원본 저장, 경로를 `cve.json` 에 기록 | P0 |
| F-105 | 예외 처리 | 잘못된 링크, 비공개 버그 | P1 |
| F-106 | 캐시 | 모든 커밋의 diff·전/후 소스가 실제로 있을 때만 재다운로드 생략 | P1 |
| F-107 | 같은 수정 묶음 | `Change-Id`·`Merged-In` 으로 브랜치별 같은 수정을 묶고 대표 커밋 1개 분석 (L6) | P0 |
| F-108 | 데이터셋 | 2023~2025 보안 공지의 AOSP 커밋 수집 → `pattern_type` 1차 분류 → 유형별·범위 밖 사유별 개수 (`output/dataset.csv`) | P0 |

### M2. Patch Analyzer - 패치 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-201 | 변경 위치 추출 | Tree-sitter 로 변경된 클래스·메서드 식별, hunk 별 전/후 코드(`CodeRef`) | P0 |
| F-202 | **수정 유형 분류** | `pattern_type` = `GUARD_ADDITION`(트랙 A, 템플릿 T1) · `PRECONDITION_ADDITION`(B, T2) · `API_REPLACEMENT`(C, T3) · `OTHER`. **분류 불가 시 추측하지 않고 `OTHER`** (이전 `NOVEL`·`CONDITION_CHANGE`·`BYPASS` 는 `OTHER` + 사유). 같은 커밋의 헬퍼 메서드 안 검사까지 2단계 추적 | P0 |
| F-203 | 보안 검사 인식 | Guard 사전([`config/guard_dictionary.json`](../config/guard_dictionary.json): PERMISSION · CALLER_UID · UID_PACKAGE_BINDING · APP_OPS · CROSS_USER · URI_USER_BOUNDARY · BINDER_IDENTITY, 보안 목적이 같으면 같은 유형으로 정규화) 기반 탐지, `clearCallingIdentity` 구간 처리 | P0 |
| F-205 | 기능 플래그 처리 | `Flags.xxx()` 조건 감지 → "플래그 켜짐" 기준 실효 after 뷰 (L2) | P0 |
| F-204 | 기준선 비교 | 수동 정답과 변경 메서드 일치율 | P1 |

### M3. Binder Path / Source - 진입점 경로 분석

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-301 | AIDL 매핑 | `.aidl` 인터페이스 ↔ `Stub` 구현 클래스 연결 | P0 |
| F-302 | 경로 추출 (제한) | Binder 진입점 → 변경 메서드. 해석 못 한 호출은 `resolved`/`partial`/`unknown` 3값으로 기록 | P0 |
| F-305 | `APP_OBJECT` Source | 다른 앱이 채우는 객체(`Icon`·`Uri`·`RemoteViews` 등) 출처를 컨테이너 타입 카탈로그로 판별, 불확실하면 `unknown` | P0 |
| F-303 | 노출 여부 판정 | 서비스 등록·권한 요구 여부 | P1 |
| F-304 | 경로 시각화 | mermaid 다이어그램 | P2 |

### M4. Root Cause - LLM 보조 S·G·S 초안 (트랙 A)

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-401 | 원인·불변식 | M2·M3 근거로 근본 원인·보안 불변식 생성, Guard·Sink 는 **후보 번호로만** 선택 | P0 |
| F-403 | 근거 연결 | 모든 주장에 `Evidence`, 실제 hunk 와 대조해 없는 위치는 버림 | P0 |
| F-404 | 스키마 검증 | 실패 시 오류를 붙여 재요청 | P1 |
| F-405 | LLM 추상화 | `LlmClient.generate_structured` 만 사용 | P0 |
| F-406 | 추론 상태 표시 | `status=inferred`, provider·model·prompt hash 기록 | P0 |
| F-407 | 표본 일치도 | 3회 표본의 선택 일치도, 낮으면 `sgs_unstable` | P1 |

트랙 B·C 는 패치 diff 자체가 S·G·S 라 LLM 을 쓰지 않는다.

### M5. Pattern / Rule - 패치 기반 규칙 생성·검증

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-501 | S·G·S 정리 | Source·Guard·Sink 구조로 결함 정리 | P0 |
| F-503 | T1 템플릿 규칙 | 트랙별 템플릿(`perm_guard`·`api_guard`·`api_usage`) + 파라미터 | P0 |
| F-504 | **차분 오라클** | 패치 전 탐지 · 패치 후 미탐지 · 대조군 예산(`control_hits`). 통과한 규칙만 M6 에서 사용. after·대조군은 실효 after 뷰 기준 | P0 |
| F-507 | LLM 규칙 일반화 | 실패 사유(실행 결과)를 피드백으로 최대 3회 재생성, 실패 시 seed 채택. 트랙 C 는 일반화 금지 | P0 (A) · P1 (B) |
| F-508 | T2 열린 규칙 합성 | 템플릿에 없는 형식(`NOVEL`)은 LLM 이 Semgrep 규칙 전체 작성 → 같은 오라클 | P0 (L0) · P1 (사다리) |
| F-509 | 일반화 사다리 | L0~L3 중 예산 안에서 가장 일반적인 규칙 채택, 수준별 결과 보존 | P1 |
| F-510 | 패턴 라이브러리 | 사람 승인된 생성 규칙을 파일로 저장해 다음 CVE 라우팅에 재사용 (재학습 아님) | P1 |
| F-511 | T3 탐색형 | 규칙 생성 실패 시 불변식·앵커 API 로 후보를 좁혀 M7 검증 계층으로 판정 (낮은 신뢰, 지표 분리) | P1 |

### M6. Scanner - AOSP 유사 코드 스캔

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-601 | 스캔 | 채택 규칙을 스캔 스냅샷 전체에 적용, 후보마다 `CodeRef`·경로·누락 Guard 기록 | P0 |
| F-604 | 스캔 스냅샷 | `android-latest-release` + 이후 보안 공지 패치 적용본, 후보에 `scan_snapshot` 기록. 이후 공지에서 고쳐진 후보는 `superseded` (L1) | P0 |
| F-605 | 스캔 예산 | 패턴별 Match 수가 `max_scan_hits` 초과 시 seed 규칙으로 재스캔 | P0 |
| F-602 | 중복 제거 | 같은 위치·원인 병합 | P1 |
| F-603 | 증분 스캔 | 특정 디렉터리·서비스만 | P2 |

### M7. Prioritizer - 후보 선별·우선순위화

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-701 | 점수화 | Sink 유사도·경로 길이·Guard 부재·도달성 신뢰도·LLM 검토 항 | P0 |
| F-702 | 상위 N 출력 | 점수 근거와 함께 상위 10~20건 | P0 |
| F-705 | 오탐 필터 | 5종, 탈락해도 사유 기록, 해석 불가는 `unknown`(감점만) | P0 |
| F-704 | LLM 검토 | 상위 K 만 질문 3개(Guard·다른 검사·도달성) 분해, 근거 대조, **판정은 코드가 계산** | P0 |
| F-706 | 교차 모델 비판 | `likely` 후보만 다른 계열 LLM 이 반박 시도 → 근거 있는 반박이면 `unsure` | P1 |
| F-703 | 수동 라벨링 | TP/FP/보류, 라벨 판정 기준표 적용, 다음 실행에 반영 | P0 |

### M9. Reporter - 보고서

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-901 | Markdown 보고서 | CVE 요약, 패치·수정 유형, 경로, S·G·S, 규칙·오라클 결과, 후보(점수 근거·LLM 검토·라벨), **한계(범위 밖 사유 수치)** | P0 |
| F-902 | HTML 보고서 | 같은 내용 + diff 하이라이트 | P0 |
| F-905 | JSON 보고서 | `report.json` | P0 |
| F-903 | 근거 링크 | googlesource 줄 링크 | P1 |
| F-904 | 공개용 마스킹 | 미공개 후보의 코드·위치·경로를 제거한 `_public` | P1 |
| F-906 | 한/영 전환 | 템플릿 2종 | P1 |

### M10. Web Dashboard - 최종 산출물

Streamlit 단독. 미리 생성된 JSON 만 읽고, 쓰는 것은 `labels.json` 뿐.

| ID | 화면 (탭) | 보여주는 것 | 우선순위 |
| --- | --- | --- | --- |
| D-1 | 사이드바 | CVE 목록, 트랙·후보 수 요약 | P0 |
| D-3·D-4 | 개요 | CVE 정보, 패치 diff, **수정 유형**, 진입점 경로, 원인(`inferred`) | P0 |
| D-6 | 취약 패턴 | Source·Guard·Sink 카드 | P0 |
| D-5 | 탐지 규칙 | 규칙 원문, 시도별 **차분 오라클 결과**, 일반화 수준 | P0 |
| D-7 | 변종 후보 | 점수·근거 코드·LLM 검토·배지(`flag_gated`·`superseded`·`synthesized`·`exploratory`)·TP/FP 라벨(기준표) | P0 |
| D-9 | 보고서 | 한/영, 다운로드 (공개 모드는 `_public` 만) | P0 |
| D-10 | 평가 | 트랙별 지표, 회고 검증, 베이스라인 비교 | P1 |
| D-13 | API 사용 점검 | 트랙 C 결과 (Precision 지표와 분리) | P1 |
| D-2 | 새 분석 실행 | 대시보드에서 파이프라인 실행 | P2 |
| ~~D-8~~ | ~~검증 결과~~ | 동적 검증 화면 | **후속** |

| ID | 기능 | 설명 | 우선순위 |
| --- | --- | --- | --- |
| F-1004 | CLI | `run`/`collect`/`analyze`/`binder-path`/`root-cause`/`pattern`/`scan`/`prioritize`/`report`/`eval`/`dataset`/`index`/`dashboard` | P0 |
| F-1005 | 설정 파일 | `config.yaml`(커밋 금지)에 AOSP 경로·스캔 스냅샷·LLM provider/model/키 환경변수 **이름** | P0 |
| F-1006 | 공개 모드 | `_public` JSON 만 읽는 발표용 모드 | P1 |
| F-1003 | 단계별 재실행 | `run --start <단계>`, 실패해도 입력이 준비된 단계는 계속 (순서: collect → analyze → binder-path → root-cause → pattern → scan → prioritize → report) | P1 |

### M11. Evaluation

| ID | 지표 | 측정 방법 | 우선순위 |
| --- | --- | --- | --- |
| F-1105 | 정답 데이터 | `baselines/<CVE-ID>.json` 수동 정답 | P0 |
| F-1101 | 분석 정확도 | 변경 메서드·원인 일치율 | P1 |
| F-1103 | Precision | 상위 후보 TP 비율 (라벨 기준표, 상위 후보 2인 독립 라벨 + κ) | P0 |
| F-1106 | 회고 검증 | 과거 스냅샷 스캔 후보가 이후 공지 패치와 일치하는가. **주 결과는 LLM 끔** (L3) | P0 |
| F-1107 | 베이스라인 비교 | **Vanir** 실행 결과와 비교, Vanir 가 놓친 정탐 수 (L7) | P0 |
| F-1108 | 규칙 채택률 | 트랙·T 단계별 차분 오라클 통과율 | P0 |
| F-1109 | 템플릿 밖 형식 대응 실험 | E1 템플릿 끈 hold-out · E2 범위 밖 패치 · E3 라이브러리 효과 | P1 |
| F-1104 | 시간 절감 | 수동 분석 대비 소요 시간 | P1 |

## 4. 공통 데이터 (JSON 스키마)

정본은 [`aosp1day/schemas.py`](../aosp1day/schemas.py) 와 [design.md](design.md) §2.1 (v0.4 필드 추가분). 이 장은 요약이다.

**[v0.5] 1주차 공통 형식.** 1주차 E2E 는 단계별 산출물 대신 아래 공통 형식 하나로 연결한다 (`patterns/<CVE>.json`, `baselines/ground_truth.json`). 유형마다 필요한 필드만 채우고 나머지는 `null`. 위치가 여러 곳일 수 있는 값(`sink`·`precondition`·`target_api`·`unsafe_api`·`safe_api`)은 리스트.

```jsonc
{ "patch": { "cve": "", "commit": "", "parent_commit": "", "repository": "",
             "changed_files": [], "support_status": "READY|NEEDS_WORK|HISTORICAL|EXCLUDED", "exclude_reason": "" },
  "vuln_pattern": { "pattern_type": "GUARD_ADDITION|PRECONDITION_ADDITION|API_REPLACEMENT|OTHER",
                    "source": null, "guard": null, "sink": null,          // GUARD_ADDITION: Source-Guard-Sink
                    "precondition": null, "target_api": null,             // PRECONDITION_ADDITION
                    "unsafe_api": null, "safe_api": null,                 // API_REPLACEMENT
                    "evidence": [] },
  "rule": { "template_id": "T1|T2|T3", "rule_body": "",
            "before_target_match": false, "after_target_match": false,
            "after_other_match_count": 0, "validation_status": "PASS|WARN|FAIL" } }
```

아래는 단계별 산출물(2주차 이후) 요약이다. 산출물은 `output/<CVE-ID>/` 아래 (평가는 `output/eval.json`, 데이터셋은 `output/dataset.csv`).

```jsonc
// meta - 재현성·추적성
{ "schema_version": "0.4", "generated_at": "", "tool_version": "", "stage": "",
  "inputs": { "<입력 산출물>": "<sha256>" } }

// CodeRef - revision = 이 코드가 실제로 있는 커밋 (before: parent / after: 패치 / aosp: 스캔 스냅샷)
{ "revision": "", "patch_commit": "", "file": "", "side": "before|after|aosp",
  "start_line": 0, "end_line": 0, "snippet": "", "diff_path": "", "class": "", "method": "" }

// Evidence = CodeRef + claim / Claim = text + [Evidence]

// patch_analysis.json (M2) - 주요 필드
{ "changes": [{ "id": "chg-1", "method": "", "pattern_type": "GUARD_ADDITION|PRECONDITION_ADDITION|API_REPLACEMENT|OTHER",
    "added_guards": [Evidence], "sink_candidates": [Evidence], "flag_gated": ["Flags.xxx()"],
    "hunks": [{ "before": CodeRef, "after": CodeRef }] }] }

// pattern.json (M5) - 주요 필드
{ "patterns": [{ "pattern_id": "", "track": "A|B|C|T2|T3", "rule_origin": "template|synthesized|exploratory",
    "adopted": true, "tags": ["seed_only|llm_generalized|broad|narrow"],
    "attempts": [{ "origin": "seed|llm", "check": { "target_hit": true, "patched_hits": 0, "control_hits": 0, "passed": true }, "feedback": "" }] }] }

// candidates.json / ranked_candidates.json - 주요 필드
{ "candidates": [{ "id": "", "pattern_id": "", "location": CodeRef, "call_path": [CodeRef],
    "missing_guard": "", "reachability": "resolved|partial|unknown", "scan_snapshot": "",
    "status": "open|superseded|reported", "flag_gated": false,
    "review": { "answers": {}, "verdict": "likely|unlikely|unsure", "verdict_source": "code" },
    "label": "unreviewed|tp|fp|hold", "public": false }] }
```

## 5. 비기능 요구사항

| 항목 | 요구사항 |
| --- | --- |
| 재현성 | 같은 입력이면 같은 결과. 모든 산출물에 `meta`, LLM 은 temperature 고정 + provider·model·prompt hash 기록, 프롬프트 원문 저장 |
| 추적성 | 모든 주장·후보·판정에 근거(`CodeRef`) 연결 |
| LLM 결과 | 확정 판정이 아니라 `inferred` 분석 초안. 규칙 채택·후보 탈락·라벨은 LLM 이 정하지 않음 ([llm-verification.md](llm-verification.md)) |
| 비밀값 | API 키는 환경변수로만. `config.yaml`·`.env` 는 `.gitignore`. 키를 결과·로그·프롬프트 기록·대시보드에 넣지 않음 |
| 모듈성 | 단계별 독립 실행, JSON 으로만 연결 |
| 공개·배포 | 대시보드는 로컬/팀 내부. 미공개 후보의 코드·위치·경로는 외부 공개 금지, 발표는 `_public` 만. 실제 미패치 결함은 **책임 있는 공개 절차**(design §17) |
| 실행 환경 | Python 3.11+ (PyYAML·Streamlit 필수, Tree-sitter `[analysis]` 선택), Semgrep CE (로컬 CLI, T2 전용), AOSP 소스 체크아웃(스캔 스냅샷). **가상 기기·ADB 불필요** |
| 윤리 | 실제 공격용 exploit 미포함 |

## 6. 결정 사항

| 항목 | 결정 | 근거 |
| --- | --- | --- |
| 목표 | 공개 패치 → 규칙 생성·검증 → 유사 결함 후보 탐지 | 제안서, 11/11 피드백 |
| **동적 재현** | **후속 범위** (M8·테스트 APK·가상 기기 제외). 코드 뼈대만 유지 | 11/11 피드백, 11/23 리뷰 |
| 대상 | 지원 대상에 해당하는 AOSP 공개 보안 패치 (Java P0·Kotlin P1) | [scope-v2.3.md](scope-v2.3.md) |
| 규칙 엔진 | T1 = Tree-sitter Query + Python matcher, T2 = Semgrep CE 규칙 (로컬). 채택은 차분 오라클 | v2.1 R1, [novel-patterns.md](novel-patterns.md) |
| 정적 분석 범위 | 스캔 스냅샷(`android-latest-release` + 이후 공지 패치), `scan_repos` | v2.4 L1 |
| LLM | `LlmClient` 인터페이스, 키는 환경변수, 결과는 `inferred`, 검증 계층 | [llm-verification.md](llm-verification.md) |
| 대시보드 | Streamlit 단독, 미리 생성된 JSON 만 읽음 | PR #20 |
| 데이터 계약 | 모든 코드 위치는 `CodeRef`, 근거는 `Evidence` | PR #30 |
| 베이스라인 | Vanir | v2.4 L7 |

## 7. 남은 논의

- [ ] 범위 확장(v2.3) 확정 - 팀 리뷰 (PR #31)
- [x] 기준선 CVE 확정 → CVE-2023-40105 · CVE-2024-0037 (v0.5)
- [ ] `ground_truth.json` 셋 합의
- [ ] 차분 검증 N값 (WARN 기준)
- [ ] 템플릿 이름 겹침 정리: 1주차 T1~T3 vs [novel-patterns.md](novel-patterns.md) T2(LLM 합성)·T3(탐색형)
- [ ] 2주차 방향·담당 (1주차 주말 점검: 전체 스캔 vs 데이터·분석기 보완)
- [ ] LLM provider·model 선정, CVE 당 호출 상한
- [ ] `max_control_hits`·`max_scan_hits` 초기값

---

## 부록 A. 후속 범위 - 동적 재현 (이번 프로젝트 제외)

v0.3.1 까지 P0 였던 아래 항목은 11/11 피드백(재현은 4주 안에 어렵다)과 11/23 리뷰에 따라 **이번 프로젝트의 산출물·평가·일정에서 제외**한다. 프로젝트 이후 확장할 때 출발점으로 쓰도록 코드 뼈대(`aosp1day/stages/m08_harness.py`, `m08_verifier.py`)와 스키마(`TestCase`, `ValueSpec`, `ExpectedResult`, `Verification`)만 저장소에 남긴다.

| 항목 (v0.3.1 기능 ID) | 내용 |
| --- | --- |
| F-801 · F-803 | Cuttlefish/Emulator 초기화, 설치 → 실행 → logcat 수집 자동화 |
| F-802 · F-807 · F-810 | Harness: 기준선 TestCase 검증, 가설 기반 테스트 자동 생성, 커스텀 빌드 |
| F-804 · F-805 · F-806 | 패치 전후 차등 판정, 실패 원인 분류, 재시도 |
| F-808 | 복수 CVE 재현 |
| F-809 | 공용 instrumentation APK |
| D-8 | 검증 결과 화면 |
| 결정 사항 | 검증 기기(Cuttlefish 1차), CI 사전 빌드 이미지, 이미지 분리, 동적 검증 준비 순서, Harness 범위, 테스트 실행 방식, TestCase 구조, 실행 순서(Harness·Verifier 를 RootCause 뒤) |
| 남은 논의 | Cuttlefish 실행 PC, 패치 전·후 이미지 확보, 테스트 APK 구성 |

이번 프로젝트에서 후보의 실제 악용 가능성은 **정적 근거 + 라벨 판정 기준표 + 사람 판정**으로만 다루고, 결과는 항상 "후보" 로 표현한다 ([limitations.md](limitations.md) L4).
