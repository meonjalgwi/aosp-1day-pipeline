"""M11. Evaluation — 평가 (8주차, F-1101~F-1104).

입력: baselines/<CVE-ID>.json (Baseline) + 각 CVE 의 산출물
출력: output/eval.json (CVE 디렉터리가 아니라 output 최상위)
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import Baseline, CveEval, Evaluation, PatchAnalysis, RankedCandidates, RootCause
from ..storage import Store
from .base import PipelineContext, Stage, StageResult


class Evaluator(Stage):
    name = "eval"
    module = "M11"
    reads = ()  # 여러 CVE 결과 + 정답 데이터를 모아서 평가 (단일 CVE 산출물에 묶이지 않음)
    writes = (Evaluation.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        baselines_dir = Path(ctx.params.get("baselines", "baselines"))
        result = Evaluation()
        for baseline in self.load_baselines(baselines_dir):
            result.per_cve.append(self.evaluate_cve(baseline, Store(ctx.config.output_root, baseline.cve_id)))
        self.aggregate(result)
        root = Store(ctx.config.output_root, "")          # output/eval.json
        path = root.save(result, stage=self.name)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def load_baselines(self, baselines_dir: Path) -> list[Baseline]:
        raise NotImplementedError

    def evaluate_cve(self, baseline: Baseline, store: Store) -> CveEval:
        """CVE 하나: 변경 메서드 일치율, 원인 일치(사람 판정), 재현 여부, 소요 시간."""
        raise NotImplementedError

    def aggregate(self, result: Evaluation) -> None:
        """F-1101~F-1104 지표 계산해 result 에 채움."""
        raise NotImplementedError

    def method_match(self, analysis: PatchAnalysis, baseline: Baseline) -> float:
        """F-1101. 정답 changed_methods 대비 일치율."""
        raise NotImplementedError

    def detection_rate(self, ranked: RankedCandidates, known: list[Baseline]) -> float:
        """F-1102. 알려진 CVE 위치를 규칙이 다시 찾아내는 비율."""
        raise NotImplementedError

    def false_positive_rate(self, ranked: RankedCandidates) -> float:
        """F-1103. 라벨된 상위 후보 중 fp 비율."""
        raise NotImplementedError

    def time_saved(self, baseline: Baseline, tool_minutes: float) -> float:
        """F-1104. 수동(Baseline.analysis_minutes) 대비 절감 비율."""
        raise NotImplementedError
