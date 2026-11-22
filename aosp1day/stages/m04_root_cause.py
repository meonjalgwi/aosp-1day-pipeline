"""M4. Root Cause Analyzer — AI 보조 원인 분석 (4주차, F-401~F-404).

입력: M2(patch_analysis.json) + M3(call_path.json)
출력: root_cause.json

패치 증거(hunk 의 before/after 코드)와 호출 경로를 LLM 에 넣어 근본 원인·보안 불변식·
발생 조건·재현 가설을 생성한다.
- 모든 주장(Claim)에 Evidence(CodeRef + claim)를 연결하고, 없으면 "근거 없음"으로 남긴다.
- 결과는 확정 판정이 아니라 status="inferred" 분석 초안이며, 최종 판단은 사람이 한다.
"""

from __future__ import annotations

from ..llm import LlmClient, get_client
from ..schemas import CallPath, Claim, PatchAnalysis, RootCause
from .base import PipelineContext, Stage, StageResult


class RootCauseAnalyzer(Stage):
    name = "root-cause"
    module = "M4"
    reads = (PatchAnalysis.ARTIFACT, CallPath.ARTIFACT)
    writes = (RootCause.ARTIFACT, "prompts/root_cause.txt")

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        analysis = ctx.store.load(PatchAnalysis)
        call_path = ctx.store.load(CallPath)
        client = get_client(ctx.config.llm)
        prompt = self.build_prompt(analysis, call_path)
        prompt_path = ctx.store.save_text("prompts/root_cause.txt", prompt)   # 키·비밀값 없음
        result = self.infer(client, prompt, analysis)
        result.llm = client.provenance(prompt, str(prompt_path))
        result.status = "inferred"
        path = self.save(ctx, result)
        return StageResult(self.name, ok=True, artifacts=[path, prompt_path])

    # --- 세부 기능 ---------------------------------------------------------

    def build_prompt(self, analysis: PatchAnalysis, call_path: CallPath) -> str:
        """hunk 별 before/after snippet(+commit·파일·줄 범위)과 호출 경로를 프롬프트로 조립.

        각 hunk 에 change_id 를 붙여, LLM 이 근거를 change_id + 줄 범위로 답하게 한다.
        """
        raise NotImplementedError

    def infer(self, client: LlmClient, prompt: str, analysis: PatchAnalysis) -> RootCause:
        """F-401/F-402. client.generate_structured() 로 RootCause 초안 생성 (F-404 검증 포함)."""
        raise NotImplementedError

    def attach_evidence(self, claim: Claim, analysis: PatchAnalysis) -> Claim:
        """F-403. LLM 이 답한 change_id·줄 범위를 실제 hunk CodeRef 로 치환·검증.

        존재하지 않는 위치를 가리키면 그 근거는 버리고, 근거가 0개인 주장은 그대로 표시.
        """
        raise NotImplementedError

    def validate_schema(self, raw: dict, max_retry: int = 2) -> RootCause:
        """F-404. LLM 출력이 스키마를 따르는지 검사, 실패 시 재시도."""
        raise NotImplementedError
