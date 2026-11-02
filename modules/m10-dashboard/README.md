# M10. Web Dashboard — 최종 산출물

- 주차: 6주 (v1) · 8주 (완성)
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) M10 (화면 D-1~D-11, 기능 F-1001~F-1006)

## 입력 / 출력

- 입력: 사용자 조작 (CVE 입력, 라벨링) + `output/<CVE-ID>/*.json`
- 출력: 브라우저 대시보드, 보고서 다운로드

## 진행 상태

- [ ] 기술 스택 결정
- [ ] Backend API (분석 실행·상태·결과 조회)
- [ ] 비동기 작업 실행 + 진행 상태 표시
- [ ] D-1 CVE 목록 / D-2 새 분석 실행
- [ ] D-3 패치 diff / D-4 원인 분석
- [ ] D-6 패턴·규칙 / D-7 유사 후보 (라벨링)
- [ ] D-8 검증 결과 / D-9 보고서
- [ ] D-10 평가 / 데모 모드

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/dashboard/`](../../aosp1day/dashboard/)
- 클래스: `DashboardApp`
- CLI: `aosp1day serve <CVE-ID>`
