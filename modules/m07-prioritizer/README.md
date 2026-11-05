# M7. Prioritizer — 후보 우선순위화

- 주차: 6주
- 담당: TBD
- 기능명세: [docs/feature-spec.md](../../docs/feature-spec.md) F-701~F-703

## 입력 / 출력

- 입력: `candidates.json`
- 출력: `ranked_candidates.json`

## 진행 상태

- [ ] 점수화 (Binder 노출 + 민감 동작 + 검증 누락)
- [ ] 상위 10~20건 출력 및 근거 표시
- [ ] 수동 라벨링 (TP/FP/보류)

## 설계 뼈대 (코드)

- 구현 위치: [`aosp1day/stages/m07_prioritizer.py`](../../aosp1day/stages/m07_prioritizer.py)
- 클래스: `Prioritizer`
- CLI: `aosp1day prioritize <CVE-ID>`
