"""M6. Scanner — AOSP 유사 코드 스캔 (6주차, F-601~F-603).

입력: pattern.json (PatternSet, 자가 검증 통과한 규칙만) + frameworks/base 중 config.scan_paths
출력: candidates.json
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import CandidateSet, Pattern, PatternSet
from .base import PipelineContext, Stage, StageResult


class Scanner(Stage):
    name = "scan"
    module = "M6"
    reads = (PatternSet.ARTIFACT,)
    writes = (CandidateSet.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        patterns = ctx.store.load(PatternSet)
        result = CandidateSet(cve_id=patterns.cve_id, aosp_revision=self.aosp_revision(ctx.config.aosp_root))
        for pattern in patterns.patterns:
            if pattern.check.passed:
                result.candidates.extend(self.scan(pattern, ctx.config.aosp_root).candidates)
        result = self.dedup(result)
        path = self.save(ctx, result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def aosp_revision(self, aosp_root: Path) -> str:
        """스캔 대상 frameworks/base 의 git HEAD (재현성)."""
        raise NotImplementedError

    def scan(self, pattern: Pattern, aosp_root: Path) -> CandidateSet:
        """F-601. 규칙을 frameworks/base 의 config.scan_paths 범위에 적용 (AOSP 전체 아님).

        후보마다 location(CodeRef, side="aosp", snippet 포함)과 matched(source/sink 위치) 채움.
        """
        raise NotImplementedError

    def dedup(self, candidates: CandidateSet) -> CandidateSet:
        """F-602. 같은 위치/같은 원인 결과 병합."""
        raise NotImplementedError

    def scan_incremental(self, pattern: Pattern, subdir: Path) -> CandidateSet:
        """F-603(P2). 특정 디렉터리·서비스만 스캔."""
        raise NotImplementedError
