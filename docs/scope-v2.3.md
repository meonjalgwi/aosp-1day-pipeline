# 범위 확장 v2.3 — 지원 대상에 해당하는 AOSP 공개 보안 패치로

> 2026-11-23 · 김나연 · **팀 리뷰 후 확정** (이 문서는 제안)
> 관련: [design.md](design.md) · [walkthrough-cve-2023-40105.md](walkthrough-cve-2023-40105.md) (표본 측정 근거) · [llm-verification.md](llm-verification.md)

## 0. 결정과 이유

**결정:** 이 도구는 분석가의 1-Day 후속 분석 **효율을 높이는 도구**이므로, 한 영역의 전문성보다 **넓은 효용성**을 우선한다. 대상을 "system_server 의 권한 검사 누락"에서 **"지원 대상에 해당하는 AOSP 공개 보안 패치"**(1절 정의: 보안 공지에 AOSP 커밋 링크가 있고 Java·Kotlin 코드 변경으로 결함을 고친 패치)로 넓힌다. **모든 AOSP 패치를 처리한다는 뜻이 아니다.** Source–Guard–Sink 구조는 그대로 두고 **Source·Guard 의 정의를 일반화**한다.

새 패치가 들어온다는 것은 모델을 재학습한다는 뜻이 아니라, 그 패치에서 탐지 규칙을 새로 생성하고 차분 오라클로 검증한다는 뜻이다. 이 문서들에서는 이 처리 방식을 **패치 기반 규칙 생성 파이프라인**이라고 부른다.

**근거 (11/23 diff 확인):**

1. 기존 범위로는 대상이 너무 적다. 보안 공지 3개월치 Framework `frameworks/base` 커밋 17건 중 system_server + 권한 Guard 추가는 1건(CVE-2023-40105)이었다.
2. 같은 검사가 여러 컴포넌트에 **반복해서** 추가되는 계열이 실제로 있다 — 이 프로젝트가 말하는 "변종 반복"의 직접 증거다. 아이콘·이미지 URI 의 사용자 경계 검사:

| 공지 | CVE | 위치 | 언어 | 추가된 검사 (diff 확인) |
| --- | --- | --- | --- | --- |
| 2023-11 | CVE-2023-40124 | SystemUI Device Controls | **Kotlin** (변경 파일 전부) | `ContentProvider.getUserIdFromUri(icon.uri, currentUserId) == currentUserId` |
| 2024-02 | CVE-2024-0037 | Autofill (`services/autofill`, system_server) | Java | 새 `sanitizeSlice`: 이미지 `Icon` 이 URI 타입이면 `getUserIdFromUri(uri, userId) != userId` 일 때 차단. **기존 `sanitizeRemoteView` 검사가 빠져 있던 SaveUi 경로에도 적용** — 한 CVE 안의 "같은 Guard 가 다른 경로에 누락" 사례 |
| 2024-03 | CVE-2024-0053 | `PrintManagerService` (system_server) | Java | 새 `validateIconUserBoundary`: URI 타입 `Icon` 의 사용자 정보(`getEncodedUserInfo`)를 정수로 읽어 `resolveCallingUserEnforcingPermissions` 로 확인한 뒤, **그 사용자의 프로필 부모(`resolveCallingProfileParentLocked`)를 현재 사용자(`getCurrentUserId()`)와 비교**해 다르면 `null` 반환. 사용자 정보가 없는 URI 는 통과 |
| 2024-11 | CVE-2024-43082 | SettingsLib `EditUserPhotoController` | Java | `getUserIdFromUri(pictureUri)` 와 `UserHandle.myUserId()` 비교 |
| 2025-04 | CVE-2025-22416 | `ChooserActivity` (`core/java`) | Java | 새 `hasValidIcon`: URI 아이콘에 대해 `checkGrantUriPermission_ignoreNonSystem(...)` 로 읽기 권한 확인 |

같은 결함(앱이 준 URI 를 다른 사용자 것인지 확인 없이 로드)이 1년 반 동안 5개 컴포넌트에서 따로 고쳐졌다. **Java 로 된 첫 패치(CVE-2024-0037, 2024-02)에서 규칙을 만들어 그 시점 코드를 스캔했다면 이후 3곳을 미리 찾을 수 있었는가** 가 이 프로젝트의 가장 설득력 있는 회고 검증이 된다(§5). 가장 이른 CVE-2023-40124 는 Kotlin 이라 출발점에서 뺐다.

**같은 계열이지만 다른 방식으로 고친 것** (URI_USER Guard 추가가 아니라 트랙 A 템플릿 대상은 아님, `NOVEL` 로 처리): CVE-2024-49722 (EditUserPhotoController 인텐트 대상 명시 — `OTHER`) · CVE-2025-0083 (Telecom StatusHints, 기존 cross-user 검사의 파싱 수정 — `CONDITION_CHANGE`) · CVE-2024-43090 (SystemUI, 앱 제공 단축키 아이콘 정리 — `OTHER`). 이 문서의 위 표와 이 목록이 URI 반복 사례의 기준 목록이다 ([walkthrough](walkthrough-cve-2023-40105.md) 0.1 은 표본 17건 안의 것만 언급).

3. 표본의 "기타" 13건 중 상당수는 **특정 API 호출 앞에 검사를 추가하거나, 위험한 API 를 안전한 API 로 바꾼** 패치다. 권한 카탈로그 없이도 "같은 API 를 같은 검사 없이 쓰는 다른 곳" 을 찾는 방식으로 다룰 수 있다(Track B·C).

---

> **템플릿에 없는 형식은?** 지원 대상 패치라면 아래 트랙 A·B·C 에 맞지 않아도 범위 밖으로 버리지 않는다. 템플릿 없이 LLM 이 규칙 전체를 합성하는 T2, 그것도 안 되면 탐색형 T3 로 처리하고, 승인된 규칙은 패턴 라이브러리에 쌓는다 → [novel-patterns.md](novel-patterns.md)

## 1. 대상 범위

### 1.1 지원 대상 정의

| 구분 | 기준 |
| --- | --- |
| **지원 대상** | ① Android 보안 공지(2023~2025)에 AOSP 커밋 링크가 있음 ② 그 커밋이 **Java(P0)·Kotlin(P1) 코드**를 바꿔 결함을 고침 ③ 수정 지점이 diff 에서 분리됨 |
| **지원 대상 밖** (사유와 함께 기록) | 네이티브(C/C++)·커널·벤더/비공개 수정, 리소스·설정만 변경, 생성 코드만 변경, 수정 지점을 분리할 수 없는 대규모 리팩터링 |
| **후속 범위** | 동적 재현·패치 전후 실행 검증 (M8) |

### 1.2 v2.2 → v2.3 변경

| 항목 | v2.2 | v2.3 |
| --- | --- | --- |
| 패치 출처 | Framework CVE 중 system_server | 보안 공지의 AOSP 커밋 링크 중 **1.1 지원 대상** (2023~2025). 저장소는 `frameworks/base`, `packages/*`, `packages/modules/*` 등 |
| 스캔 대상 코드 | `services/**`, `core/java/**` | 패치가 나온 저장소 + **같은 검사가 반복될 만한 저장소** (기본: `frameworks/base` 전체, `packages/apps/Settings`, `packages/modules/*` 중 Java). 저장소 목록은 `scan_repos` 설정 |
| 언어 | Java | **Java (P0)**, Kotlin (P1), C/C++ (P2, 범위 밖으로 기록) |
| 패턴 | 권한 검사 누락 2종 | **3개 트랙** (아래) |

## 2. 구조 일반화 — 3개 트랙

Source–Guard–Sink 는 그대로 쓰고, 트랙마다 각 요소를 정하는 방법만 다르다.

| | Track A 권한형 Guard | Track B 검사형 (패치 유래) | Track C API 교체형 |
| --- | --- | --- | --- |
| 무엇을 찾나 | 카탈로그에 있는 보안 검사가 경로에 없는 곳 | 패치가 어떤 API 호출 앞에 추가한 검사가 **같은 API 의 다른 호출 지점**에 없는 곳 | 패치가 안전한 API 로 바꾼 **위험한 API 가 아직 쓰이는 곳** |
| Guard | 카탈로그: PERMISSION · UID · PACKAGE · APPOPS · CROSS_USER · **URI_USER(신규)** | 패치가 추가한 조건식을 정규화한 것 (조건에 쓰인 메서드·상수 집합) | 없음 (교체 자체가 수정) |
| Sink | 민감 동작 카탈로그 + 패치 근거 | 패치에서 그 조건이 보호하는 API 호출 (정확한 메서드) | 패치 전 API 시그니처 |
| Source | `BINDER_PARAM` 또는 **`APP_OBJECT`(신규)** | 요구하지 않음 (도달성은 점수로만) | 요구하지 않음 |
| 예 (diff 확인) | CVE-2023-40105 (PACKAGE), CVE-2024-0037·0053 (URI_USER) | CVE-2023-40111: `setMediaButtonReceiver` 앞에 `pi.isActivity()` 차단 추가 · CVE-2025-0086: 인증자가 돌려준 계정 타입 확인 추가 · CVE-2024-49740: 문자열 길이·리스트 크기 상한 추가 | CVE-2023-40109: `readParcelableArray(ClassLoader)` → 타입 지정 오버로드 |
| 정밀도 기대 | 높음 | 중간 | 낮음~중간 (lint 성격) |

**Source 일반화:**

| Source 종류 | 의미 | 판별 |
| --- | --- | --- |
| `BINDER_PARAM` | Binder 진입점 파라미터 | 기존 `StubMap` |
| `APP_OBJECT` | 다른 앱이 채운 객체에서 꺼낸 값 (`Icon`, `Uri`, `PendingIntent`, `RemoteViews`, `Slice` …) | **신뢰 경계 컨테이너 타입 카탈로그** `config/app_objects.yaml` (예: `Notification`, `ChooserTarget`, `PrinterInfo`/custom printer icon, `Slice`, `RemoteViews`, `WalletCard`, `Control`, `StatusHints`). 기준선 diff 에서 시작해 늘린다 |
| `ANY` | Track B·C. 출처를 따지지 않음 | — |

**`fix_kind` 확장 (M2 `classify_fix`):**

| 값 | 조건 | 트랙 |
| --- | --- | --- |
| `ADDED_GUARD` | 패치 후에만 있는 **카탈로그** Guard 유형 존재 | A |
| `ADDED_CHECK` | 카탈로그엔 없지만, + 줄에 `if (조건) { return/throw/continue/null 반환 }` 가 생겼고 그 뒤에 특정 API 호출이 있음 | B |
| `API_REPLACE` | − 줄의 호출과 + 줄의 호출이 같은 이름·다른 인자 수/타입, 또는 문서상 대체 API | C |
| `NOVEL` | 위 셋과 패턴 라이브러리 어디에도 맞지 않는 코드 변경 (`CONDITION_CHANGE`·`BYPASS`·`OTHER` 포함) | **T2 열린 합성 → T3 탐색형** ([novel-patterns.md](novel-patterns.md)) |

**표본 17건 재분류 (추정, diff 요약 기준):** A 3건(40105, 40124, 43082) · B 3건(40111, 0086, 49740) · C 1건(40109) · 범위 밖 10건. **대상 비율 약 6% → 약 40%(7/17).** 단 CVE-2023-40124 는 Kotlin 이라, Kotlin(P1)이 빠지면 **약 35%(6/17)** 로 줄어든다. 나머지 6건의 언어와 정확한 값은 `dataset` 전수(파일 확장자 집계)로 확인한다.

---

## 3. 단계별 변경

| 모듈 | 변경 | 우선순위 |
| --- | --- | --- |
| M1 Collector | Gitiles 저장소를 `frameworks/base` 고정에서 커밋 URL 의 저장소로 일반화. 다중 저장소 커밋(예: Telecom + base) 처리 | P0 |
| `dataset` | 보안 공지 전체에서 AOSP 커밋 수집 → `prefilter` 로 `fix_kind` 1차 분류 → 트랙별 개수 리포트 | P0 (5주 초) |
| M2 | `classify_fix` 확장, Track B 용 `extract_added_check(change) -> (조건 정규형, 보호 API)`, Track C 용 `extract_replaced_api(change)` | P0 |
| M3 | Track A 만 실행. `APP_OBJECT` Source 는 같은 메서드 안 데이터 흐름(지역 변수 1단계)으로 판별 | P0 |
| M4 | Track A 만 LLM 사용. Track B·C 는 패치 diff 자체가 S·G·S 라 LLM 생략 | P0 |
| M5 | 템플릿 3종: `perm_guard.scm`(A), `api_guard.scm`(B: 같은 API 호출 + 앞쪽 동등 조건 부재), `api_usage.scm`(C). 자가 검증·대조군·LLM 일반화 루프는 공통. **Track C 는 LLM 일반화 금지** (seed 만) | P0 (A·C), P1 (B 일반화) |
| M6 | `scan_repos` 다중 저장소 인덱스. 패턴별 스캔 예산(R1) 유지 | P0 |
| M7 | 필터 공통. LLM 질문을 트랙별로: A 는 기존 3질문, B 는 "같은 API 를 같은 의도로 쓰는가 / 다른 형태로 같은 검사가 있는가", C 는 검토 생략(정적 결과만) | P0 (A), P1 (B) |
| M10 | 변종 후보 탭에 **트랙 필터**, Track C 는 "API 사용 점검" 별도 탭 (Precision 지표와 분리) | P0 |
| M11 | 트랙별 지표 분리. 회고 검증은 Track A URI_USER 계열 우선(§5) | P0 |

---

## 4. 위험과 대응

| # | 위험 | 미리 알 수 있는 신호 (측정) | 대응 | 결정 시점·담당 |
| --- | --- | --- | --- | --- |
| K1 | **오탐 폭증** — Track B·C 는 범용 API 를 다뤄 후보가 수백 개 나올 수 있음 | 패턴별 Match 수 (`CandidateSet.stats`), 대조군 히트 | ① Sink 는 패치의 **정확한 API** 로 고정(seed), Track B 일반화는 P1·예산 안에서만 ② Track C 는 LLM 일반화 금지 ③ 패턴별 `max_scan_hits` 초과 시 같은 패키지·같은 클래스 우선으로 잘라 보고 ④ Track C 는 별도 탭으로 분리해 Precision 지표를 흐리지 않게 | 6주 첫 스캔 직후 · 서진 |
| K2 | **Kotlin 미지원** — SystemUI 일부, 최근 모듈 다수가 Kotlin | `dataset` 단계에서 패치 파일 확장자 비율 | ① `analysis/` 를 **언어 어댑터 인터페이스**(`LangAst`: methods·calls·ifs·clear_identity_ranges)로 감싸 Java 먼저 구현 ② Kotlin 은 tree-sitter-kotlin 으로 같은 인터페이스를 P1 구현 ③ 미지원 파일은 `stats.skipped_kotlin` 으로 남겨 보고서 "한계"에 수치로 표시 ④ 대표 회고 검증(5절)은 Java 패치 CVE-2024-0037 에서 시작해 Kotlin 지연과 분리 | 5주 초 비율 확인 · 현아 |
| K3 | **Source 판별 불확실** — `APP_OBJECT` 의 값이 정말 다른 앱에서 왔는지 정적으로 확정하기 어려움 | 후보 중 `source_status=unknown` 비율 | ① 신뢰 경계 컨테이너 타입 카탈로그로 근사 (기준선 5건 diff 에서 시작) ② 확정 못 하면 `unknown` 으로 남기고 감점 (R3 와 같은 원칙) ③ M7 질문 `q_reach` 를 "이 값이 다른 앱에서 올 수 있는가" 로 바꿔 근거 줄 요구 | 6주 · 현아 |
| K4 | **같은 검사의 형태가 제각각** — URI_USER 만 해도 `getUserIdFromUri` 비교, `getEncodedUserInfo` 파싱, `checkGrantUriPermission` 3가지 | 기준선에서 seed 규칙이 서로를 못 잡는 비율 | ① 카탈로그 URI_USER 에 확인된 3형태 등록 ② 새 형태는 LLM 일반화가 제안 → 자가 검증 통과 + **사람 승인** 후 카탈로그에 추가 (`labels.json` 메모로 기록) ③ M7 `q_alt_check` 로 다른 형태 검사 감지 | 5~6주 · 서진 |
| K5 | **일정** — 트랙 3개, 저장소 다수 | 주차별 게이트 (아래) | **단계 게이트로 줄인다.** 5주: Track A 파일 모드 관통 2건 (40105 PACKAGE, 0037 URI_USER) + `dataset` 트랙별 개수. 6주: Track A 인덱스 스캔 + Track C seed. **6주 말 게이트**: Track A 후보가 나오면 Track B 진행, 아니면 Track B 를 P2 로 내리고 A 품질에 집중. 7주: 평가·회고. **줄이는 순서**: Track B 일반화 → Kotlin → M9 HTML·영문 → Track C 탭 | 매주 금요일 · 나연 |
| K6 | **스캔 규모·시간** — 저장소 확대로 인덱스 크기 증가 | 인덱스 빌드 시간·메모리 (`index` 명령) | ① 저장소별 인덱스 캐시(`output/_index/<repo>@<rev>`) ② 기본은 패치가 나온 저장소 + `frameworks/base`, 나머지는 옵션 ③ 파일 해시 기반 증분 갱신은 P2 | 6주 · 서진 |
| K7 | **평가 해석이 복잡해짐** — 트랙마다 정밀도가 다름 | — | 지표를 트랙별로 따로 낸다. 발표는 Track A 를 주 결과, B·C 는 "확장 가능성" 으로 제시 | 7주 · 서진 |
| K8 | **LLM 비용·호출 증가** — CVE 수 증가 | CVE 당 호출 수 (`LlmProvenance` 집계) | ① Track B·C 는 M4 LLM 생략 ② M7 상위 K 유지 ③ `max_calls_per_cve` 초과 시 LLM 없이 진행 ([llm-verification.md](llm-verification.md) 4절) | 상시 · 나연 |
| K9 | **멘토 기존 피드백과의 정합성** — 1·2차 면담은 system_server 권한 검사 중심 범위로 진행 | — | 3차 면담에서 표본 수치(17건 중 1건 → 약 40%)와 URI_USER 반복 계열 표를 근거로 범위 확장 이유를 설명. 2차 면담에서 합의한 변종 정의("A 코드에서 터진 것이 B 코드에서")는 그대로 유지됨을 강조 | 다음 면담 · 전원 |

---

## 5. 기준선과 회고 검증 (v2.3)

| 역할 | CVE | 트랙 · Guard | 이유 |
| --- | --- | --- | --- |
| 기준선 A-1 | CVE-2023-40105 | A · PACKAGE (Binder) | 관통 예시 완료 |
| 기준선 A-2 | CVE-2024-0037 | A · URI_USER (APP_OBJECT) | 한 CVE 안에서 "기존 Guard 가 다른 경로에 빠져 있던" 사례 → B 계열 회고에도 사용. **URI_USER 회고 검증의 출발점** (Java) |
| 기준선 A-3 | CVE-2024-0053 | A · URI_USER | system_server, Guard 형태가 다름 — 프로필 부모로 바꾼 뒤 현재 사용자와 비교 (K4 검증용) |
| 기준선 B-1 | CVE-2023-40111 | B · `isActivity()` 앞 `setMediaButtonReceiver` | Track B 구조 검증 |
| 기준선 C-1 | CVE-2023-40109 | C · `readParcelableArray(ClassLoader)` | Track C 구조 검증 |

**대표 회고 검증 — URI_USER 계열 시간순 재구성:**

1. **Java 로 된 가장 이른 패치 CVE-2024-0037 (2024-02, Autofill)** 로 규칙을 만든다. (결정 11/23: 가장 이른 CVE-2023-40124 는 변경 파일이 전부 Kotlin 이라, Kotlin(P1)이 일정상 빠지면 회고 검증이 시작부터 막힌다. 그래서 Kotlin 을 이 계열만 P0 로 올리는 대신 출발점을 Java 로 바꿨다.)
2. 2024-02 공지 직전 시점의 AOSP revision 을 스캔한다.
3. 이후 따로 고쳐진 3곳 (PrintManagerService 2024-03, SettingsLib EditUserPhotoController 2024-11, ChooserActivity 2025-04) 중 몇 곳이 후보에 나오는지 센다.
4. 결과를 "패치 공개 시점에 도구를 돌렸다면 몇 달 앞서 찾을 수 있었다" 로 발표한다. **주 결과는 LLM 을 끄고 규칙을 2024-02 시점에 고정한 스캔**으로 낸다 (LLM 시간 누수, [limitations.md](limitations.md) L3). 2026년 이후 시점은 공개 릴리스 단위로만 나눌 수 있다 (L1). 놓친 곳은 Guard 형태 차이(K4) 등 원인을 함께 보고한다.
5. (보조, Kotlin P1 이 구현됐을 때만) CVE-2023-40124 (2023-11) 를 출발점으로 같은 실험을 한 번 더 해, 2024-02 Autofill 까지 포함한 4곳 기준 결과를 덧붙인다.

---

## 6. 담당·일정 조정 (제안)

| 주차 | 나연 | 현아 | 서진 |
| --- | --- | --- | --- |
| 5주 (11/24~30) | `dataset` 전 저장소 수집·트랙별 집계, M1 저장소 일반화, LLM 구현체 | `LangAst` 인터페이스 + Java 구현, `classify_fix` 확장(A·B·C), Kotlin 비율 확인 | 템플릿 3종 seed, matcher 파일 모드, 기준선 A-1·A-2 자가 검증 |
| 6주 (12/1~7) | 대시보드 탭 1~3 + 트랙 필터, 인덱스 다중 저장소 | M3 `APP_OBJECT` 판별, M4 (Track A), M7 필터 | M6 인덱스 스캔 (A·C), 예산, **6주 말 Track B 게이트** |
| 7주 (12/8~14) | 대시보드 탭 4~5, M9 | M7 LLM 검토 (A, 게이트 통과 시 B) | M11 트랙별 지표, URI_USER 시간순 회고 검증 |
| 8주 (12/15~21) | 통합·발표 | 후보 수동 검토 | 평가 정리 |

---

## 출처 (모두 11/23 diff 또는 공지 확인)

- 보안 공지: https://source.android.com/docs/security/bulletin/2023-11-01 · 2024-11-01 · 2025-03-01
- CVE-2024-0037: 현재 2024-02 공지 페이지 표에는 보이지 않고, CVE 레코드에서 공지·커밋이 연결돼 있다 (11/23 리뷰 확인). NVD https://nvd.nist.gov/vuln/detail/CVE-2024-0037 · CVE.org https://www.cve.org/CVERecord?id=CVE-2024-0037
- CVE-2024-0053 Guard 상세: https://android.googlesource.com/platform/frameworks/base/+/74b03835a7fac15e854d08159922418c99e27e77
- CVE-2023-40124 `86c8421c` · CVE-2024-0037 `55fc00a0` · CVE-2024-0053 `74b03835` · CVE-2024-43082 `6aa1b4fb` · CVE-2025-22416 `82aa8527` · CVE-2023-40111 `55d3d57c` · CVE-2025-0086 `c1aa9e66` · CVE-2024-49740 `bcb13168` · CVE-2023-40109 `387d258c` (모두 `platform/frameworks/base`)
- 같은 계열, 다른 방식으로 고친 것: CVE-2024-49722 (`e480e189`, `OTHER`), CVE-2025-0083 (Telecom StatusHints, `CONDITION_CHANGE`), CVE-2024-43090 (SystemUI, `OTHER`) — 2절 목록 참고
