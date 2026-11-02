"""M7. Prioritizer — 후보 우선순위화 (6주차, F-701~F-703).

입력: candidates.json
출력: ranked_candidates.json

점수 = Binder 노출 여부 + 민감 동작 여부 + 검증 누락 여부.
"""

from __future__ import annotations

from ..schemas import Candidate, CandidateSet, RankedCandidates, ScoreReason
from .base import PipelineContext, Stage, StageResult


class Prioritizer(Stage):
    name = "prioritize"
    module = "M7"
    reads = (CandidateSet.ARTIFACT,)
    writes = (RankedCandidates.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        candidates = ctx.store.load(CandidateSet)
        top_n = int(ctx.params.get("top_n", 20))
        ranked = self.rank(candidates, top_n)
        path = ctx.store.save(ranked)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def score(self, reason: ScoreReason) -> float:
        """F-701. 노출+민감 동작+검증 누락 가중합으로 점수 계산."""
        raise NotImplementedError

    def rank(self, candidates: CandidateSet, top_n: int) -> RankedCandidates:
        """F-702. 점수순 정렬 후 상위 N(10~20)건, 산정 근거 포함."""
        raise NotImplementedError

    def apply_label(self, candidate: Candidate, label: str) -> Candidate:
        """F-703. 사람이 TP/FP/보류로 표시한 결과 반영 (대시보드 D-7과 연동)."""
        raise NotImplementedError
