# 용어 정리

기능명세서([feature-spec.md](feature-spec.md))와 로드맵([roadmap.md](roadmap.md))에 나오는 번호·용어를 짧게 정리한 문서.

## 번호 체계

| 표기 | 뜻 | 예시 |
| --- | --- | --- |
| **M1~M11** | 모듈 번호. 툴을 기능 단위로 나눈 덩어리 | M1 = Collector |
| **P0 / P1 / P2** | 우선순위 | P0 = 반드시 구현 |
| **F-xxx** | 기능 번호. 앞자리가 모듈 번호 | F-101 = M1의 1번 기능 |
| **D-xx** | 대시보드 화면 번호 | D-1 = CVE 목록 화면 |

## 모듈 (M1~M11)

앞 단계 결과(JSON)를 받아 다음 단계로 넘기는 순서.

| 번호 | 이름 | 한 줄 설명 |
| --- | --- | --- |
| M1 | Collector | CVE 번호로 보안 공지와 패치 커밋을 찾아 저장 |
| M2 | Patch Analyzer | 패치에서 뭐가 바뀌었는지(메서드, 권한 검사 등) 추출 |
| M3 | Binder Path / Source | 외부 앱(또는 앱이 넘긴 객체)이 그 코드까지 어떻게 들어오는지 경로 찾기 |
| M4 | Root Cause | AI가 "왜 취약했는지" 원인과 발생 조건을 정리 |
| M5 | Pattern / Rule | 패치에서 "이런 모양이면 취약" 탐지 규칙을 생성하고 패치 전·후 코드로 검증 |
| M6 | Scanner | 규칙으로 AOSP 전체에서 비슷한 코드 찾기 |
| M7 | Prioritizer | 찾은 후보를 위험한 순으로 정렬 |
| M8 | Verifier | **후속 범위 (이번 프로젝트 제외)** — 가상 기기에서 패치 전·후를 실제로 실행해 확인 |
| M9 | Reporter | 결과를 HTML/Markdown 보고서로 생성 |
| M10 | Dashboard | 모든 결과를 웹에서 보는 화면 (최종 산출물) |
| M11 | Evaluation | 툴의 정확도·탐지율·오탐률 측정 |

## 우선순위 (P0~P2)

| 표기 | 뜻 |
| --- | --- |
| **P0** | 반드시 구현 (없으면 MVP·발표 불가) |
| **P1** | 시간 되면 구현 |
| **P2** | 여유 있으면 구현 |
| **후속** | 이번 프로젝트에서 제외, 이후 확장용 (예: 동적 재현) |

## 기술 용어

| 용어 | 설명 |
| --- | --- |
| **1-Day 취약점** | 패치가 이미 공개된 취약점. 패치 diff로 원인을 거꾸로 추적할 수 있음 |
| **CVE** | 공개 취약점 고유 번호 (예: CVE-2024-xxxxx) |
| **ASB** | Android Security Bulletin. 매달 나오는 안드로이드 보안 공지 |
| **AOSP / `frameworks/base`** | 안드로이드 오픈소스 코드 / 그중 Framework·System Service가 있는 저장소 |
| **system_server** | 안드로이드 핵심 시스템 서비스(ActivityManager, PackageManager 등)가 도는 프로세스 |
| **Binder / AIDL** | 앱 ↔ 시스템 서비스 간 통신 방식 / 그 인터페이스를 정의하는 언어. 외부 앱이 시스템 코드에 들어오는 입구 |
| **Stub** | AIDL에서 생성되는, 서비스 쪽 구현이 상속하는 클래스 |
| **Tree-sitter** | 코드를 문법 구조(AST)로 읽어주는 도구. 코드 분석과 패턴 탐지에 사용 |
| **Tree-sitter Query** | Tree-sitter에서 AST 노드를 찾는 쿼리 문법(`.scm`). M5·M6 탐지 규칙에 사용 |
| **AST** | 추상 구문 트리. 코드를 문법 단위(클래스·메서드·조건문)로 나눈 구조 |
| **Semgrep** | 패턴 기반 코드 검색 도구. T1 템플릿 규칙은 Tree-sitter, 템플릿에 없는 형식의 T2 규칙 합성에만 Semgrep CE(로컬 CLI)를 씀 |
| **Source–Guard–Sink** | 취약 패턴을 보는 방식. 외부 입력(source)이 검사(guard)를 거쳐 위험 동작(sink)에 닿는 구조. guard가 빠지면 취약. **이름은 우리 팀이 붙인 것**이고, 개념은 taint 분석(source→sink)과 안드로이드 접근 통제 연구(Kratos·AceDroid·Invetter·ACMiner·Axplorer)에서 왔다. Vanir 와는 무관 ([final-demo.md](final-demo.md) §4.1) |
| **Vanir** | Google 의 패치 누락 탐지 도구. "같은 코드에 이 패치가 적용됐나"를 본다. 우리 결과의 비교 대상(베이스라인) ([final-demo.md](final-demo.md) §3.2) |
| **보안 불변식** | "이 동작 전에는 반드시 X 검사가 있어야 한다" 같은 항상 지켜져야 하는 규칙 |
| **UID–packageName 불일치** | 호출한 앱의 실제 UID와 주장하는 패키지 이름을 대조하지 않는 취약 패턴 |
| **Cross-user** | 다른 사용자(멀티유저/업무 프로필)의 데이터에 접근하는 취약 패턴 |
| **Streamlit** | 파이썬 코드만으로 웹 화면을 만드는 도구 |
| **TP / FP** | True Positive(진짜 취약) / False Positive(오탐) |
| **diff hunk** | diff 안에서 연속으로 바뀐 한 덩어리 (`@@ ... @@` 단위) |
| **CodeRef** | 코드 위치 + 내용을 담는 공통 구조: 커밋, 파일, 패치 전/후(side), 줄 범위, 실제 코드(snippet) |
| **provenance (출처)** | 결과가 어떤 커밋·파일·줄에서 나왔는지에 대한 기록. 근거를 다시 찾아갈 수 있게 함 |
| **Evidence** | 주장 하나를 뒷받침하는 CodeRef + 그 주장 |
| **meta** | 모든 산출물 JSON의 공통 헤더 (스키마 버전, 생성 시각, 입력 파일 해시) |
| **Baseline (기준선)** | 사람이 직접 분석한 정답 데이터. 도구 결과를 채점하는 기준 |
| **LlmClient** | 특정 LLM 업체에 묶이지 않도록 둔 인터페이스 (`generate_structured`) |
| **revision** | `CodeRef`에서 그 코드가 실제로 존재하는 커밋. 패치 전 코드는 패치 커밋의 parent, 패치 후 코드는 패치 커밋 |
| **inferred** | LLM이 추론한 미확정 결과. 최종 판단은 사람이 함 |
| **마스킹** | 미공개 후보의 코드·위치·호출 경로를 공개본에서 제거하는 것 |

## 설계 v2.1~v2.4 용어

| 용어 | 설명 |
| --- | --- |
| **지원 대상** | Android 보안 공지에 AOSP 커밋 링크가 있는 패치 중 Java(P0)·Kotlin(P1) 코드 변경으로 결함을 고친 것. 네이티브·커널·비공개 수정·리소스/설정 전용·대규모 리팩터링은 대상 밖 |
| **패치 기반 규칙 생성 파이프라인** | 새 패치가 들어오면 모델을 재학습하는 것이 아니라, 그 패치에서 탐지 규칙을 생성하고 차분 오라클로 검증하는 이 도구의 처리 방식 |
| **차분 오라클** | 규칙 채택 기준: 패치 전 코드의 수정 지점을 잡고, 패치 후 코드의 그 지점은 잡지 않으며, 패치 후 다른 곳(대조군)을 예산 이상 잡지 않아야 함. 취약점 유형과 무관 |
| **`fix_kind` (수정 유형)** | M2 가 판정: `ADDED_GUARD`(권한형 Guard 추가) · `ADDED_CHECK`(API 앞 검사 추가) · `API_REPLACE`(API 교체) · `NOVEL`(템플릿에 없는 형식) · 범위 밖 사유 |
| **트랙 A·B·C** | 템플릿 규칙 종류: A 권한형 Guard, B 검사형, C API 교체형 |
| **T1 · T2 · T3** | 규칙 생성 단계: T1 템플릿, T2 LLM 이 규칙 전체 합성(Semgrep), T3 규칙 없이 탐색형. 템플릿 종류 이름으로는 쓰지 않는다 |
| **`perm_guard` · `api_guard` · `api_usage`** | T1 템플릿 3종: `perm_guard` Guard 없는 Sink(트랙 A, `GUARD_ADDITION`) · `api_guard` API 앞 검사 누락(트랙 B, `PRECONDITION_ADDITION`) · `api_usage` 위험 API 잔존(트랙 C, `API_REPLACEMENT`). 1주차 계획서의 "T1·T2·T3 템플릿"이 이 셋 |
| **패턴 라이브러리** | 사람이 승인한 생성 규칙을 파일로 저장해 다음 CVE 에 재사용하는 것 (재학습 아님) |
| **대조군 예산 (`control_hits`)** | 패치 후 파일에서 패치된 메서드 밖 히트 수의 상한. 규칙이 지나치게 넓어지는 것을 막음 |
| **스캔 스냅샷** | 스캔 기준 코드: `android-latest-release` + 이후 보안 공지 패치 적용본 |
| **`flag_gated`** | 수정 코드가 기능 플래그 조건 아래에 있음. 플래그 켜짐 기준으로 판정 |
| **`superseded`** | 스캔 이후 공지에서 이미 고쳐진 후보 |
| **URI_USER** | 앱이 준 URI 가 다른 사용자 영역인지 확인하는 Guard 유형 |
| **`APP_OBJECT`** | 다른 앱이 채운 객체(`Icon`·`Uri` 등)에서 온 값을 Source 로 보는 것 |
