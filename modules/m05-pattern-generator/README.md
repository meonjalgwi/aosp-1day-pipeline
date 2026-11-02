# M5. Pattern / Rule Generator — 취약 패턴·탐지 규칙

- 주차: 5주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-501~F-505

## 입력 / 출력

- 입력: `root_cause.json`
- 출력: `pattern.json` + Semgrep/Tree-sitter 규칙 파일

## 진행 상태

- [ ] source·guard·sink 추출
- [ ] 패턴 3종 (권한 검사 누락 / UID–packageName / Cross-user)
- [ ] 규칙 변환
- [ ] 취약·패치 버전에서 규칙 자가 검증
