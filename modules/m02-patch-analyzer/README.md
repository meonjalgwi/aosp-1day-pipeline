# M2. Patch Analyzer — 패치 분석

- 주차: 3주
- 담당: 현아 ([@gusdkcjs4](https://github.com/gusdkcjs4))
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-201~F-204

## 입력 / 출력

- 입력: `cve.json`
- 출력: `patch_analysis.json`

## 진행 상태

- [ ] 기준선 CVE 수동 분석 정답 데이터 작성
- [ ] Tree-sitter로 변경 클래스·메서드 추출
- [ ] 변경 유형 분류 (권한 검사/입력 검증/조건문/예외 처리)
- [ ] 권한 검사 API 인식
- [ ] 정답 데이터와 비교

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m02_patch_analyzer.py`](../../aosp1day/stages/m02_patch_analyzer.py)
- 클래스: `PatchAnalyzer`
- CLI: `aosp1day analyze <CVE-ID>`
