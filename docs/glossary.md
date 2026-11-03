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
| M3 | Binder Path | 외부 앱이 그 코드까지 어떻게 들어오는지 경로 찾기 |
| M4 | Root Cause | AI가 "왜 취약했는지" 원인과 발생 조건을 정리 |
| M5 | Pattern / Rule | 원인을 "이런 모양이면 취약" 탐지 규칙으로 변환 |
| M6 | Scanner | 규칙으로 AOSP 전체에서 비슷한 코드 찾기 |
| M7 | Prioritizer | 찾은 후보를 위험한 순으로 정렬 |
| M8 | Verifier | 가상 기기에서 패치 전·후를 실제로 실행해 확인 |
| M9 | Reporter | 결과를 HTML/Markdown 보고서로 생성 |
| M10 | Dashboard | 모든 결과를 웹에서 보는 화면 (최종 산출물) |
| M11 | Evaluation | 툴의 정확도·탐지율·오탐률 측정 |

## 우선순위 (P0~P2)

| 표기 | 뜻 |
| --- | --- |
| **P0** | 반드시 구현 (없으면 MVP·발표 불가) |
| **P1** | 시간 되면 구현 |
| **P2** | 여유 있으면 구현 |

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
| **Semgrep** | 패턴 기반 코드 검색 도구. 검토했으나 Tree-sitter로 통일하기로 함 |
| **Source–Guard–Sink** | 취약 패턴을 보는 방식. 외부 입력(source)이 검사(guard)를 거쳐 위험 동작(sink)에 닿는 구조. guard가 빠지면 취약 |
| **보안 불변식** | "이 동작 전에는 반드시 X 검사가 있어야 한다" 같은 항상 지켜져야 하는 규칙 |
| **UID–packageName 불일치** | 호출한 앱의 실제 UID와 주장하는 패키지 이름을 대조하지 않는 취약 패턴 |
| **Cross-user** | 다른 사용자(멀티유저/업무 프로필)의 데이터에 접근하는 취약 패턴 |
| **Harness** | 가설을 실제로 확인하는 테스트 APK / instrumentation test |
| **Cuttlefish** | AOSP 공식 가상 기기. 직접 빌드한 AOSP 검증에 적합, Linux+KVM 필요 |
| **Emulator** | Android Studio 에뮬레이터. 설치가 쉽고 snapshot 저장·복원 가능 |
| **logcat** | 안드로이드 로그. 예외·크래시 확인에 사용 |
| **Streamlit** | 파이썬 코드만으로 웹 화면을 만드는 도구 |
| **TP / FP** | True Positive(진짜 취약) / False Positive(오탐) |
| **diff hunk** | diff 안에서 연속으로 바뀐 한 덩어리 (`@@ ... @@` 단위) |
| **CodeRef** | 코드 위치 + 내용을 담는 공통 구조: 커밋, 파일, 패치 전/후(side), 줄 범위, 실제 코드(snippet) |
| **provenance (출처)** | 결과가 어떤 커밋·파일·줄에서 나왔는지에 대한 기록. 근거를 다시 찾아갈 수 있게 함 |
| **Evidence** | 주장 하나를 뒷받침하는 CodeRef + 그 주장 |
| **meta** | 모든 산출물 JSON의 공통 헤더 (스키마 버전, 생성 시각, 입력 파일 해시) |
| **Baseline (기준선)** | 사람이 직접 분석한 정답 데이터. 도구 결과를 채점하는 기준 |
| **LlmClient** | 특정 LLM 업체에 묶이지 않도록 둔 인터페이스 (`generate_structured`) |
| **inferred** | LLM이 추론한 미확정 결과. 최종 판단은 사람이 함 |
| **마스킹** | 미공개 후보의 코드·위치·재현 입력을 공개본에서 제거하는 것 |
