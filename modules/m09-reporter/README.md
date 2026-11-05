# M9. Reporter — 보고서 생성

- 주차: 8주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-901~F-904

## 입력 / 출력

- 입력: 모든 단계의 JSON
- 출력: `report.md`, `report.html`

## 진행 상태

- [ ] Markdown 보고서 템플릿
- [ ] HTML 보고서 (diff 하이라이트)
- [ ] 근거 링크
- [ ] 공개용 마스킹 버전

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m09_reporter.py`](../../aosp1day/stages/m09_reporter.py)
- 클래스: `Reporter`
- CLI: `aosp1day report <CVE-ID>`
