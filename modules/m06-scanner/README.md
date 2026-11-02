# M6. Scanner — AOSP 유사 코드 스캔

- 주차: 6주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-601~F-603

## 입력 / 출력

- 입력: 규칙 파일 + `frameworks/base`
- 출력: `candidates.json`

## 진행 상태

- [ ] `frameworks/base` 전체 스캔
- [ ] 중복 결과 병합

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m06_scanner.py`](../../aosp1day/stages/m06_scanner.py)
- 클래스: `Scanner`
- CLI: `aosp1day scan <CVE-ID>`
