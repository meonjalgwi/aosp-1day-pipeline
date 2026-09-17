# Executor Agent

담당: 나연 ([@zv9uvr](https://github.com/zv9uvr)) — 7주차부터 통합·구현 단계에서 작업

## 역할

Emulator 스냅샷 복원 → APK 설치 → Harness Agent가 만든 테스트 실행 → logcat/예외/서비스 상태 수집 → 초기화까지의 전 과정을 한 명령으로 자동 실행합니다.

## 입력 / 출력

- 입력: Harness Agent가 생성한 테스트 APK/instrumentation test
- 출력: 실행 로그(logcat, 예외, 서비스 상태)

## 진행 상태

- [ ] Emulator 스냅샷 복원/초기화 스크립트
- [ ] APK 설치 자동화
- [ ] 테스트 실행 및 로그 수집
- [ ] 전체 과정 단일 명령화
