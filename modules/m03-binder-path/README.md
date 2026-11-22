# M3. Binder Path Analyzer — 진입점 경로 분석

- 주차: 4주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-301~F-304

## 입력 / 출력

- 입력: `patch_analysis.json` + AOSP 소스
- 출력: `call_path.json`

## 진행 상태

- [ ] AIDL 인터페이스 ↔ Stub 구현 클래스 매핑
- [ ] 외부 진입점 → 변경 함수 호출 경로 추출
- [ ] 일반 앱 노출 여부 판정

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m03_binder_path.py`](../../aosp1day/stages/m03_binder_path.py)
- 클래스: `BinderPathAnalyzer`
- CLI: `aosp1day binder-path <CVE-ID>`
