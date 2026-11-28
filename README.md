# aosp-1day-pipeline (먼잘귀)

공개 패치 기반 AOSP 유사 취약점 탐지 - 패치 기반 규칙 생성 파이프라인

가천대학교 P-실무프로젝트 팀 "먼잘귀(meonjalgwi)"의 프로젝트 리포지토리입니다.

## 팀

| 이름 | GitHub |
| --- | --- |
| 김나연 | [@zv9uvr](https://github.com/zv9uvr) |
| 김현아 | [@gusdkcjs4](https://github.com/gusdkcjs4) |
| 조서진 | [@seojinn0713](https://github.com/seojinn0713) |

## 프로젝트 개요

공개된 AOSP 보안 패치를 입력하면, 패치가 고친 결함 구조(Source–Guard–Sink)를 **탐지 규칙으로 생성하고 패치 전·후 코드로 검증(차분 오라클)** 한 뒤, 같은 결함이 남아 있는 다른 AOSP 코드 후보를 찾아 근거와 함께 대시보드로 보여주는 도구를 만듭니다. 1-Day 패치 이후의 유사 결함 분석을 빠르게 하는 것이 목적입니다.

- **지원 대상:** Android 보안 공지(2023~2025)에 AOSP 커밋 링크가 있는 패치 중 **Java(P0)·Kotlin(P1) 코드 변경으로 결함을 고친 것**. 템플릿에 없는 형식도 패치에서 규칙을 새로 생성·검증해 처리합니다 (모델 재학습이 아님).
- **지원 대상 밖:** 네이티브(C/C++)·커널·벤더/비공개 수정, 리소스·설정만 바꾼 패치, 수정 지점을 분리할 수 없는 대규모 리팩터링 → 사유별 개수를 보고서 "한계"에 기록
- **후속 범위 (이번 프로젝트 제외):** 동적 재현·패치 전후 실행 검증 (M8)

## 시스템 구성 (모듈)

```
CVE/패치 입력 → 패치 분석(수정 유형 분류) → 진입점·Source 경로 분석 → 결함 구조 정리
→ 탐지 규칙 생성 + 차분 오라클 검증 → AOSP 유사 코드 스캔 → 후보 선별·우선순위화 → 보고서·대시보드
```

- **M1 Collector** - CVE/패치 커밋의 메타데이터·부모 커밋·diff·전/후 소스 저장, 지원 대상 데이터셋 구축
- **M2 Patch Analyzer** - 변경 위치·보안 검사 추출, 수정 유형(`fix_kind`) 분류, 기능 플래그 처리
- **M3 Binder Path / Source** - Binder 진입점·앱 제공 객체(Source)에서 변경 코드까지 경로, 도달성 3값
- **M4 Root Cause (LLM)** - 근거 기반 Source–Guard–Sink 초안 (권한형 트랙)
- **M5 Pattern / Rule** - 템플릿 규칙(T1)·LLM 합성 규칙(T2) 생성, 차분 오라클(패치 전 탐지·후 미탐지·대조군 예산)로 채택
- **M6 Scanner / M7 Prioritizer** - 스캔 스냅샷 전체 스캔, 오탐 필터·점수·LLM 질문 분해 검토, 상위 후보 출력
- **M9 Reporter** - 근거 diff·한계를 포함한 HTML/Markdown/JSON 보고서
- **M10 Web Dashboard (최종 산출물)** - 개요·취약 패턴·탐지 규칙·변종 후보·보고서 5개 탭, 후보 라벨 (미리 생성된 JSON 만 읽음)
- **M11 Evaluation** - 규칙 채택률, Precision, 회고 검증, Vanir 베이스라인 비교
- ~~M8 Verifier~~ - 후속 범위 (코드 뼈대만 유지)

기능 상세는 [docs/feature-spec.md](docs/feature-spec.md), 설계는 [docs/design.md](docs/design.md) 참고.

## 진행 방식

- 10/26\~11/23 범위·설계 확정 후, **11/24부터 4주 계획(1\~4주차, \~12/21)** 으로 진행.
  - 1주차: 기준선 E2E (패치 수집 → 패턴 추출 → 규칙 생성 → 차분 검증)
  - 2주차: 스캔·선별 (잠정) · 3주차: 검토·평가 (잠정) · 4주차: 통합·평가·발표
- 1주차 담당 (2주차부터는 주말 점검 후 확정)
  - @seojinn0713 (서진) - A: CVE 데이터 정제·유형 커버리지
  - @zv9uvr (나연) - B: 수정 유형 분석·패턴 추출
  - @gusdkcjs4 (현아) - C: 규칙 템플릿·차분 검증

자세한 주차별 계획은 [docs/roadmap.md](docs/roadmap.md) 참고.

## 협업 규칙

1. 작업 전 GitHub Issue를 만들고 담당자를 배정합니다.
2. 이슈별로 브랜치를 만들어 작업합니다. (예: `feature/collector-agent`)
3. 작업이 끝나면 PR을 생성하고, 팀원 최소 1명의 리뷰 승인을 받은 뒤 main에 merge합니다.
4. PR 본문에 관련 이슈를 연결합니다. (`Closes #작업이슈`, `Refs #주차이슈`)

## 디렉터리 구조

```
modules/
  m01-collector/          # M1. Collector
  m02-patch-analyzer/     # M2. Patch Analyzer
  m03-binder-path/        # M3. Binder Path / Source
  m04-root-cause/         # M4. Root Cause
  m05-pattern-generator/  # M5. Pattern / Rule
  m06-scanner/            # M6. Scanner
  m07-prioritizer/        # M7. Prioritizer
  m08-verifier/           # M8. Verifier - 후속 범위 (이번 프로젝트 제외)
  m09-reporter/           # M9. Reporter
  m10-dashboard/          # M10. Web Dashboard (최종 산출물)
  m11-evaluation/         # M11. Evaluation
docs/
  roadmap.md        # 8주 계획
  feature-spec.md   # 기능명세서 (v0.4)
  glossary.md       # 용어 정리 (M·P·F 번호, 기술 용어)
  design.md         # 상세 설계서 (모듈·클래스·메서드)
  architecture.md   # 시스템 구조도 (Mermaid) + 참고 연구·도구
  llm-verification.md  # LLM 사용·검증 구조와 근거 문헌
  walkthrough-cve-2023-40105.md  # 실제 CVE 한 건 관통 예시 (기준선 1순위)
  scope-v2.3.md     # 범위 확장: 지원 대상에 해당하는 AOSP 공개 패치, 3개 트랙, 위험 대응
  novel-patterns.md # 패치 기반 규칙 생성 파이프라인: 차분 오라클, T1 템플릿 → T2 규칙 합성 → T3 탐색, 패턴 라이브러리
  limitations.md    # 한계와 대응 L1~L8, 라벨 판정 기준표, 책임 있는 공개 절차
```
