# M10. Web Dashboard — 최종 산출물

- 주차: 6주 (v1) · 8주 (완성)
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) M10 (Streamlit 단독, P0 화면 D-1·D-3·D-4·D-6~D-9)

## 입력 / 출력

- 입력: 미리 생성된 `output/<CVE-ID>/*.json`
- 출력: 브라우저 대시보드, 보고서 다운로드

## 진행 상태

- [ ] D-1 CVE 목록
- [ ] D-3 패치 / D-4 Root Cause (inferred 표시, 근거 코드)
- [ ] D-6 Source–Guard–Sink 패턴
- [ ] D-7 후보 순위와 코드 근거
- [ ] D-8 검증 결과 / D-9 보고서 다운로드
- [ ] (P1) 공개용 마스킹 모드, D-5 호출 경로, D-10 평가, 후보 라벨링

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/dashboard/app.py`](../../aosp1day/dashboard/app.py) (Streamlit, 화면별 `page_*` 함수)
- CLI: `aosp1day dashboard [--port 8501]`
- Backend API·작업 큐 없음 — `output/<CVE-ID>/*.json` 만 읽음
