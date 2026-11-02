"""M4. Root Cause Analyzer — AI 보조 원인 분석 (4주차, F-401~F-404).

입력: M2(patch_analysis.json) + M3(call_path.json)
출력: root_cause.json

패치 증거를 LLM 에 넣어 근본 원인·보안 불변식·발생 조건을 생성하되,
모든 주장에 diff 줄·파일 위치 근거를 붙인다 (근거 없는 주장 금지).
"""

from __future__ import annotations

from ..config import LlmConfig
from ..schemas import CallPath, PatchAnalysis, RootCause
from .base import PipelineContext, Stage, StageResult


class RootCauseAnalyzer(Stage):
    name = "root-cause"
    module = "M4"
    reads = (PatchAnalysis.ARTIFACT, CallPath.ARTIFACT)
    writes = (RootCause.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        analysis = ctx.store.load(PatchAnalysis)
        call_path = ctx.store.load(CallPath)
        result = self.infer(analysis, call_path, ctx.config.llm)
        path = ctx.store.save(result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def build_prompt(self, analysis: PatchAnalysis, call_path: CallPath) -> str:
        """M2·M3 증거를 LLM 프롬프트로 조립."""
        raise NotImplementedError

    def infer(self, analysis: PatchAnalysis, call_path: CallPath, llm: LlmConfig) -> RootCause:
        """F-401/F-402. 근본 원인·발생 조건·보안 불변식 생성."""
        raise NotImplementedError

    def attach_evidence(self, result: RootCause, analysis: PatchAnalysis) -> RootCause:
        """F-403. 모든 주장에 diff 줄·파일 위치 근거 연결, 근거 없으면 표시."""
        raise NotImplementedError

    def validate_schema(self, raw: dict, max_retry: int = 2) -> RootCause:
        """F-404. LLM 출력이 스키마를 따르는지 검사, 실패 시 재시도."""
        raise NotImplementedError
