# M5. Pattern / Rule Generator — 취약 패턴·탐지 규칙

- 주차: 5주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-501~F-505

## 입력 / 출력

- 입력: `root_cause.json` + `patch_analysis.json`(자가 검증용 전/후 소스)
- 출력: `pattern.json`(패턴 목록) + Tree-sitter Query 규칙 파일(`rules/*.scm`)

## 진행 상태

- [ ] source·guard·sink 추출
- [ ] 패턴 2종 (권한 검사 누락 / UID–packageName) — Cross-user는 P1
- [ ] Tree-sitter Query + Python matcher 규칙 변환
- [ ] 취약·패치 버전에서 규칙 자가 검증

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m05_pattern_generator.py`](../../aosp1day/stages/m05_pattern_generator.py)
- 클래스: `PatternGenerator`
- CLI: `aosp1day pattern <CVE-ID>`
