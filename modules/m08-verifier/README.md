# M8. Verifier — 패치 전후 동적 검증

- 주차: 2주(환경) · 7주
- 담당: 테스트 생성(Harness, F-802) — 서진 ([@seojinn0713](https://github.com/seojinn0713)) / 실행·판정 — TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-801~F-806

## 입력 / 출력

- 입력: CVE/후보 + 테스트 템플릿
- 출력: `verification.json` + 로그

## 진행 상태

- [ ] Emulator/Cuttlefish 환경 및 스냅샷 초기화
- [ ] (Harness) 가설 → 테스트 APK / instrumentation test 자동 생성 (Intent·Binder 호출 조합)
- [ ] 초기화 → 설치 → 테스트 → logcat 수집 자동화
- [ ] 취약·패치 버전 차등 판정
- [ ] 실패 원인 분류
