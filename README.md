# aosp-1day-pipeline (먼잘귀)

AOSP Framework / system_server 1-Day 취약점의 패치 기반 재현·원인 분석 자동화

가천대학교 P-실무프로젝트 팀 "먼잘귀(meonjalgwi)"의 프로젝트 리포지토리입니다.

## 팀

| 이름 | GitHub |
| --- | --- |
| 김나연 | [@zv9uvr](https://github.com/zv9uvr) |
| 김현아 | [@gusdkcjs4](https://github.com/gusdkcjs4) |
| 조서진 | [@seojinn0713](https://github.com/seojinn0713) |

## 프로젝트 개요

AOSP Framework 또는 system_server 영역에서 공개 패치가 존재하는 1-Day 취약점(권한 검증 누락, 입력값 검증 오류, 잘못된 Intent/Binder 처리, 정보 노출·서비스 크래시 등)을 대상으로, CVE 번호 입력만으로 패치 기반 취약점 재현과 원인 분석을 자동화하는 멀티 에이전트 파이프라인을 만듭니다.

대상 범위: 공개 패치가 존재하는 2023~2025년 AOSP Framework/system_server CVE

## 시스템 구성 (Agent)

- **Collector Agent** — 보안 공지·AOSP 패치 수집, CVE별 영향 버전/컴포넌트/패치 커밋을 구조화된 JSON으로 저장
- **Patch Analyst Agent** — 변경된 클래스·메서드·조건문 분석 및 취약점 발생 조건 가설 생성 (Hypothesis 기능 포함)
- **Harness Agent** — 가설을 검증할 테스트 APK / instrumentation test 생성
- **Executor Agent** — Emulator 초기화, APK 설치, ADB 실행, 로그 수집 자동화
- **Verifier Agent** — logcat·예외·서비스 상태를 패치 전후로 비교해 재현 여부 판정
- **Reporter Agent** — 근거 로그·diff를 포함한 HTML/Markdown 분석 보고서 생성

## 진행 방식

- **1~6주차 (설계·프로토타입 단계)**: 담당자별로 자기 Agent를 설계·구현하고, 서로 PR로 리뷰하며 설계를 보완합니다.
  - 나연 — Collector Agent
  - 현아 — Patch Analyst Agent
  - 서진 — Harness Agent
- **7~14주차 (통합·구현 단계, 마지막 2개월)**: 나연이 Executor/Verifier/Reporter Agent 구현과 전체 파이프라인 통합을 담당합니다.

자세한 주차별 계획은 [docs/roadmap.md](docs/roadmap.md) 참고.

## 협업 규칙

1. 작업 전 GitHub Issue를 만들고 담당자를 배정합니다.
2. 이슈별로 브랜치를 만들어 작업합니다. (예: `feature/collector-agent`)
3. 작업이 끝나면 PR을 생성하고, 팀원 최소 1명의 리뷰 승인을 받은 뒤 main에 merge합니다.
4. PR 본문에 관련 이슈를 연결합니다. (`Closes #이슈번호`)

## 디렉터리 구조

```
agents/
  collector/       # Collector Agent
  patch-analyst/   # Patch Analyst Agent (Hypothesis 포함)
  harness/         # Harness Agent
  executor/        # Executor Agent
  verifier/        # Verifier Agent
  reporter/        # Reporter Agent
docs/
  roadmap.md        # 14주차 계획 및 담당자
```
