# M1. Collector — CVE/패치 수집

- 주차: 2주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-101~F-106

## 입력 / 출력

- 입력: CVE ID 또는 AOSP 패치 커밋 URL/해시
- 출력: `cve.json` (메타데이터, 부모 커밋, diff, 변경 파일)

## 진행 상태

- [ ] 보안 공지(Android Security Bulletin) 파싱
- [ ] 패치 커밋 메타데이터·부모 커밋 수집
- [ ] diff 및 변경 전/후 파일 저장
- [ ] 잘못된 링크·비공개 버그 예외 처리
- [ ] CLI 서브커맨드 `collect`
