# M8. Verifier — 패치 전후 동적 검증

- 주차: 2주(환경) · 7주
- 담당: 테스트 생성(Harness, F-802) — 서진 ([@seojinn0713](https://github.com/seojinn0713)) / 실행·판정 — TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-801~F-806

## 입력 / 출력

- 입력: `root_cause.json`(가설) + `call_path.json` → Harness → `test_cases.json`
- 출력: `verification.json` + logcat

## 진행 상태

- [ ] Cuttlefish 환경 (11/8까지 부팅·adb·APK 설치·logcat, 안 되면 Emulator)
- [ ] 기준선 CVE 1건 테스트 작성 (P0)
- [ ] (Harness, P1) 가설 → 테스트 APK / instrumentation test 자동 생성 (Intent·Binder 호출 조합)
- [ ] 초기화 → 설치 → 테스트 → logcat 수집 자동화
- [ ] 취약·패치 버전 차등 판정
- [ ] 실패 원인 분류

## 설계 뼈대 (코드)

- Harness (서진): [`aosp1day/stages/m08_harness.py`](../../aosp1day/stages/m08_harness.py) — 클래스 `Harness`, CLI `aosp1day harness <CVE-ID> [--tests 파일]`
  - P0 (F-807): `baselines/<CVE-ID>.tests.json`(사람 작성, 예시 `baselines/example.tests.json`)을 검증해 `test_cases.json`으로 내보냄
  - P1 (F-802): 위 파일이 없으면 `root_cause.json`(hypotheses) + `call_path.json`으로 자동 생성, 못 만든 가설은 `skipped`
  - 테스트별 파라미터 `tests/<id>.json` 생성 → 공용 instrumentation APK가 읽음 (테스트별 APK 빌드 없음)
- 실행·판정: [`aosp1day/stages/m08_verifier.py`](../../aosp1day/stages/m08_verifier.py) — 클래스 `Verifier`, CLI `aosp1day verify <CVE-ID>`
  - 입력 `test_cases.json` → 출력 `verification.json`(`TestVerdict` 목록, 빌드 정보·logcat 경로 포함)
