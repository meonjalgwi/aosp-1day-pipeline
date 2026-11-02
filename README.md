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

## 시스템 구성 (모듈)

```
CVE/패치 입력 → 패치 분석 → Binder/AIDL 경로 분석 → 취약 패턴 추출
→ AOSP 유사 코드 스캔 → 후보 우선순위화 → 패치 전후 검증 → HTML/Markdown 보고서
```

- **M1 Collector** — CVE/패치 커밋의 메타데이터·부모 커밋·diff·변경 파일을 JSON으로 저장
- **M2 Patch Analyzer** — Tree-sitter로 변경 클래스·메서드·조건문·권한 검사·예외 처리 추출
- **M3 Binder Path Analyzer** — AIDL ↔ 구현 클래스 연결, 외부 진입점부터 변경 함수까지 호출 경로
- **M4 Root Cause Analyzer (AI)** — 패치 증거 기반 근본 원인·보안 불변식·발생 조건 생성
- **M5 Pattern / Rule Generator** — source·guard·sink 패턴을 Semgrep/Tree-sitter 규칙으로 변환
- **M6 Scanner / M7 Prioritizer** — `frameworks/base` 스캔 후 후보 점수화, 상위 10~20건 출력
- **M8 Verifier** — Emulator 초기화 → APK 설치 → 테스트 → 로그 수집, 패치 전후 차등 판정
- **M9 Reporter** — 근거 로그·diff를 포함한 HTML/Markdown 보고서
- **M10 Web Dashboard (최종 산출물)** — CVE 입력·진행 상태·분석 결과·후보·검증·보고서를 보는 웹 대시보드
- **M11 Evaluation** — 정확도·탐지율·오탐률·시간 절감 평가

기능 상세는 [docs/feature-spec.md](docs/feature-spec.md) 참고.

## 진행 방식

- 총 **8주** (10/26 ~ 12/21). 1주차에 범위·설계를 확정하고, 2~7주차에 모듈을 순서대로 구현, 8주차에 통합·평가·발표.
- 담당
  - @zv9uvr — Collector (M1)
  - @gusdkcjs4 — Patch Analyst (M2 패치 분석 + M4 발생 조건 가설)
  - @seojinn0713 — Harness (M8의 테스트 APK / instrumentation test 생성)
  - 나머지 모듈은 추후 배정

자세한 주차별 계획은 [docs/roadmap.md](docs/roadmap.md) 참고.

## 협업 규칙

1. 작업 전 GitHub Issue를 만들고 담당자를 배정합니다.
2. 이슈별로 브랜치를 만들어 작업합니다. (예: `feature/collector-agent`)
3. 작업이 끝나면 PR을 생성하고, 팀원 최소 1명의 리뷰 승인을 받은 뒤 main에 merge합니다.
4. PR 본문에 관련 이슈를 연결합니다. (`Closes #이슈번호`)

## 디렉터리 구조

```
modules/
  m01-collector/          # M1. Collector
  m02-patch-analyzer/     # M2. Patch Analyzer
  m03-binder-path/        # M3. Binder Path Analyzer
  m04-root-cause/         # M4. Root Cause Analyzer
  m05-pattern-generator/  # M5. Pattern / Rule Generator
  m06-scanner/            # M6. Scanner
  m07-prioritizer/        # M7. Prioritizer
  m08-verifier/           # M8. Verifier
  m09-reporter/           # M9. Reporter
  m10-dashboard/          # M10. Web Dashboard (최종 산출물)
  m11-evaluation/         # M11. Evaluation
docs/
  roadmap.md        # 8주 계획
  feature-spec.md   # 기능명세서
```
