"""M7. Prioritizer — 후보 우선순위화 (6주차, F-701~F-703).

입력: candidates.json
출력: ranked_candidates.json

점수 = Binder 노출 여부 + 민감 동작 여부 + 검증 누락 여부 (가중치는 결과에 기록).
"""

from __future__ import annotations

from ..schemas import Candidate, CandidateSet, RankedCandidates, ScoreReason
from .base import PipelineContext, Stage, StageResult

DEFAULT_WEIGHTS = {"binder_exposed": 0.4, "sensitive_sink": 0.3, "guard_missing": 0.3}


class Prioritizer(Stage):
    name = "prioritize"
    module = "M7"
    reads = (CandidateSet.ARTIFACT,)
    writes = (RankedCandidates.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        candidates = ctx.store.load(CandidateSet)
        top_n = int(ctx.params.get("top_n", 20))
        ranked = self.rank(candidates, top_n, DEFAULT_WEIGHTS)
        path = self.save(ctx, ranked)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def explain(self, candidate: Candidate) -> ScoreReason:
        """각 요소 판정 (Binder 노출은 M3 로직 재사용)."""
        raise NotImplementedError

    def score(self, reason: ScoreReason, weights: dict[str, float]) -> float:
        """F-701. 가중합 점수."""
        return sum(w for k, w in weights.items() if getattr(reason, k, False))

    def rank(self, candidates: CandidateSet, top_n: int, weights: dict[str, float]) -> RankedCandidates:
        """F-702. 점수순 정렬 후 상위 N(10~20)건, weights 와 산정 근거 포함."""
        raise NotImplementedError

    def apply_label(self, candidate: Candidate, label: str) -> Candidate:
        """F-703. 사람이 tp/fp/hold 로 표시한 결과 반영 (대시보드 후보 화면과 연동)."""
        raise NotImplementedError
