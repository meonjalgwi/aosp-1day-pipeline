# 8주 로드맵

프로젝트 "aosp-1day-pipeline (먼잘귀)"의 주차별 목표와 산출물입니다.
기능별 상세(기능 ID, 우선순위, JSON 스키마)는 [feature-spec.md](feature-spec.md)를 참고하세요.

- 담당자 표기: 나연 = @zv9uvr, 현아 = @gusdkcjs4, 서진 = @seojinn0713
- 담당자는 팀 논의 후 기입 (현재 `TBD`)

## 대상 범위

- `frameworks/base`의 Framework / System Service **Java** 취약점
- 후보 CVE 6~8개 + 기준선 CVE 1개

## 주차별 계획

| 주차 | 기간 | 목표 | 관련 모듈 | 구체적인 작업과 산출물 | 담당 |
| --- | --- | --- | --- | --- | --- |
| 1주 | 10/26~11/1 | 범위 및 설계 확정 | 전체 | 대상 범위를 `frameworks/base`의 Framework/System Service Java 취약점으로 제한. 후보 CVE 6~8개와 기준선 CVE 1개 선정. 툴 입출력, JSON 스키마, 시스템 구조도 작성 | 전원 |
| 2주 | 11/2~11/8 | 환경 및 수집기 구축 | M1 Collector, M8 환경 | Linux 기반 AOSP 분석 환경, SDK·ADB·Emulator 또는 Cuttlefish 준비. 테스트 APK 설치와 `logcat` 수집 확인. 패치 커밋을 입력하면 메타데이터·부모 커밋·diff·변경 파일을 JSON으로 저장하는 CLI 구현 | TBD |
| 3주 | 11/9~11/15 | 수동 기준선 및 Patch Analyzer | M2 Patch Analyzer | 기준선 CVE 1개를 사람이 직접 분석하여 정답 데이터 작성. Tree-sitter 기반으로 변경 클래스·메서드·조건문·권한 검사·예외 처리를 추출하는 Patch Analyzer 구현. 수동 분석 결과와 비교 | TBD |
| 4주 | 11/16~11/23 | Binder 분석 및 AI 보조 분석 | M3 Binder Path, M4 Root Cause | AIDL 인터페이스와 구현 클래스를 연결하고 외부 진입점부터 변경 함수까지 호출 경로 추출. 패치 증거를 기반으로 근본 원인·보안 불변식·발생 조건을 JSON으로 생성. CVE 1건의 end-to-end 분석 완료 | TBD |
| 5주 | 11/24~11/30 | 취약 패턴 및 탐지 규칙 생성 | M5 Pattern/Rule | 패치에서 source·guard·sink와 보안 불변식을 추출. 권한 검사, UID–packageName, Cross-user 등 패턴 3종 이상 구현. Tree-sitter 또는 Semgrep 규칙으로 변환하고 취약·패치 버전에서 규칙 검증 | TBD |
| 6주 | 12/1~12/7 | AOSP 유사 취약점 스캔 | M6 Scanner, M7 Prioritizer, M10 CLI | 생성된 규칙을 `frameworks/base`에 적용. Binder 노출 여부, 민감 동작, 검증 누락 여부로 후보 점수화. 상위 후보 10~20건을 출력하는 Scanner와 간단한 CLI/Streamlit 화면 구현 | TBD |
| 7주 | 12/8~12/14 | 재현 및 동적 검증 | M8 Verifier | 공개 CVE 2~3건에 테스트 APK 또는 instrumentation template 적용. Emulator 초기화 → APK 설치 → 테스트 → 로그 수집을 자동화. 취약·패치 버전 차등 판정. 신규 후보는 상위 항목부터 수동·동적 검토 | TBD |
| 8주 | 12/15~12/21 | 통합·평가·발표 | M9 Reporter, M11 Evaluation | 기능 동결 후 Collector, Analyzer, Pattern Generator, Scanner, Verifier 통합. 정확도·탐지율·시간 절감·오탐률 평가. HTML 보고서, 최종 발표, 데모 영상, 책임 있는 공개용 자료 작성 | 전원 |

## 협업 규칙

1. 매 주차 시작 전 GitHub Issue를 만들고 담당자를 배정합니다.
2. 이슈별로 브랜치를 만들어 작업합니다.
3. 작업 완료 후 PR을 생성하고, 팀원 최소 1명의 리뷰 승인을 받은 뒤 merge합니다.
4. PR 본문에 `Closes #이슈번호`로 관련 이슈를 연결합니다.
