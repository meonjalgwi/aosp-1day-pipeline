# M4. Root Cause Analyzer — AI 보조 원인 분석

- 주차: 4주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-401~F-404

## 입력 / 출력

- 입력: M2·M3 결과
- 출력: `root_cause.json` (근본 원인, 발생 조건, 보안 불변식, 근거)

## 진행 상태

- [ ] LLM 프롬프트 설계
- [ ] 근거(diff 줄·파일 위치) 연결
- [ ] JSON 스키마 검증 및 재시도
- [ ] CVE 1건 end-to-end 분석
