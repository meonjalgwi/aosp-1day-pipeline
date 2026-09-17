# Harness Agent

담당: 서진 ([@seojinn0713](https://github.com/seojinn0713))

## 역할

Patch Analyst Agent가 세운 가설(예: "이 Intent를 이런 값으로 보내면 크래시난다")을 실제로 검증할 수 있는 테스트 APK 또는 instrumentation test 코드를 자동 생성합니다.

## 입력 / 출력

- 입력: Patch Analyst Agent의 취약점 발생 조건 가설
- 출력: 실행 가능한 테스트 APK / instrumentation test 코드

## 구현 방향

- APK/instrumentation 테스트 템플릿을 먼저 구축
- 입력값, Intent, Binder 호출 등을 템플릿 안에서 조합하도록 구현

## 진행 상태

- [ ] 테스트 템플릿 설계
- [ ] Intent/Binder 호출 조합 로직
- [ ] 가설 → 테스트 코드 매핑
- [ ] 샘플 CVE로 테스트 생성 검증
