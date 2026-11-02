"""M6. Scanner — AOSP 유사 코드 스캔 (6주차, F-601~F-603).

입력: 규칙 파일(M5) + frameworks/base
출력: candidates.json
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import CandidateSet, Pattern
from .base import PipelineContext, Stage, StageResult


class Scanner(Stage):
    name = "scan"
    module = "M6"
    reads = (Pattern.ARTIFACT,)
    writes = (CandidateSet.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        pattern = ctx.store.load(Pattern)
        candidates = self.scan(pattern.rule_file, ctx.config.aosp_root)
        candidates = self.dedup(candidates)
        path = ctx.store.save(candidates)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def scan(self, rule_file: str, aosp_root: Path) -> CandidateSet:
        """F-601. 생성된 규칙을 frameworks/base 전체에 적용."""
        raise NotImplementedError

    def dedup(self, candidates: CandidateSet) -> CandidateSet:
        """F-602. 같은 위치/같은 원인 결과 병합."""
        raise NotImplementedError

    def scan_incremental(self, rule_file: str, subdir: Path) -> CandidateSet:
        """F-603(P2). 특정 디렉터리·서비스만 스캔."""
        raise NotImplementedError
