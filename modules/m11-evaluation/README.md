# M11. Evaluation — 평가

- 주차: 8주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-1101~F-1104

## 입력 / 출력

- 입력: `baselines/<CVE-ID>.json`(수동 정답) + 각 단계 결과
- 출력: `output/eval.json`

## 진행 상태

- [ ] 분석 정확도
- [ ] 탐지율
- [ ] 오탐률
- [ ] 시간 절감

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m11_evaluation.py`](../../aosp1day/stages/m11_evaluation.py)
- 클래스: `Evaluator`
- CLI: `aosp1day eval <CVE-ID>`
