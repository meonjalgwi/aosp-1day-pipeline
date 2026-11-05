# M8. Verifier — 패치 전후 동적 검증

- 주차: 2주(환경) · 7주
- 담당: 테스트 생성(Harness, F-802) — 서진 ([@seojinn0713](https://github.com/seojinn0713)) / 실행·판정 — TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-801~F-810 (P0: F-801, F-803, F-804, F-807, F-809)

## 입력 / 출력

- 입력: P0 `baselines/<CVE-ID>.tests.json`(사람 작성) / P1 `root_cause.json`(가설) + `call_path.json` → Harness → `test_cases.json`
- 출력: `verification.json` + logcat

## 진행 상태

- [ ] Cuttlefish 환경 (11/8까지 부팅·adb·APK 설치·logcat, 안 되면 Emulator)
- [ ] 기준선 CVE 1건 TestCase 작성 + Harness 형식 검증 (P0, F-807)
- [ ] 공용 instrumentation APK (권한 변형별) + 파라미터 JSON 해석 (P0, F-809)
- [ ] (Harness, P1) 가설 → 테스트 APK / instrumentation test 자동 생성 (Intent·Binder 호출 조합)
- [ ] 초기화 → 설치 → 테스트 → logcat 수집 자동화
- [ ] 취약·패치 버전 차등 판정
- [ ] 실패 원인 분류
