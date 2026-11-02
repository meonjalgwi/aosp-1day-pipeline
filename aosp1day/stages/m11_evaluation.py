"""M11. Evaluation — 평가 (8주차, F-1101~F-1104).

입력: 정답 데이터 + 각 단계 결과
출력: eval.json, 평가표
"""

from __future__ import annotations

from ..schemas import Evaluation, PatchAnalysis, RankedCandidates
from .base import PipelineContext, Stage, StageResult


class Evaluator(Stage):
    name = "eval"
    module = "M11"
    reads = ()  # 여러 CVE 결과 + 정답 데이터를 모아서 평가 (단일 CVE 산출물에 묶이지 않음)
    writes = (Evaluation.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        groundtruth = ctx.params.get("groundtruth")
        result = self.evaluate(groundtruth, ctx)
        path = ctx.store.save(result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def evaluate(self, groundtruth, ctx: PipelineContext) -> Evaluation:
        """네 지표를 묶어 Evaluation 생성."""
        raise NotImplementedError

    def analysis_accuracy(self, analysis: PatchAnalysis, groundtruth) -> float:
        """F-1101. 기준선 정답 대비 변경 함수·원인 일치율."""
        raise NotImplementedError

    def detection_rate(self, ranked: RankedCandidates, known_cves) -> float:
        """F-1102. 알려진 CVE 를 규칙이 다시 찾아내는 비율."""
        raise NotImplementedError

    def false_positive_rate(self, ranked: RankedCandidates) -> float:
        """F-1103. 상위 후보 중 FP 비율 (수동 라벨 기준)."""
        raise NotImplementedError

    def time_saved(self, manual_sec: float, tool_sec: float) -> float:
        """F-1104. 수동 분석 시간 vs 도구 소요 시간."""
        raise NotImplementedError
