"""M9. Reporter — 보고서 생성 (8주차, F-901~F-904).

입력: 모든 단계의 JSON (없는 단계는 건너뜀)
출력: report.json(묶음) + report.md + report.html  /  --public 시 *_public.*

각 주장마다 근거(CodeRef: 파일·줄·snippet, logcat 줄)를 붙이고, 미공개 후보의 코드·위치·
재현 입력을 제거한 공개용(마스킹) 버전도 생성한다 (책임 있는 공개).
"""

from __future__ import annotations

from ..schemas import (
    CallPath,
    CveRecord,
    Evidence,
    PatchAnalysis,
    PatternSet,
    RankedCandidates,
    RootCause,
    TestCases,
    Verification,
)
from .base import PipelineContext, Stage, StageResult

# 보고서에 넣을 산출물 (있으면 포함)
SECTIONS = (CveRecord, PatchAnalysis, CallPath, RootCause, PatternSet, RankedCandidates, TestCases, Verification)


class Reporter(Stage):
    name = "report"
    module = "M9"
    reads = (CveRecord.ARTIFACT,)
    writes = ("report.json", "report.md", "report.html")

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        bundle = self.collect_artifacts(ctx)
        public = bool(ctx.params.get("public", False))
        if public:
            bundle = self.mask_for_public(bundle)
        suffix = "_public" if public else ""
        paths = [
            ctx.store.save_text(f"report{suffix}.json", self.render_json(bundle)),
            ctx.store.save_text(f"report{suffix}.md", self.render_markdown(bundle)),
            ctx.store.save_text(f"report{suffix}.html", self.render_html(bundle)),
        ]
        return StageResult(self.name, ok=True, artifacts=paths)

    # --- 세부 기능 ---------------------------------------------------------

    def collect_artifacts(self, ctx: PipelineContext) -> dict:
        """SECTIONS 중 존재하는 산출물을 로드해 {ARTIFACT: obj} 로 모음."""
        return {cls.ARTIFACT: ctx.store.load(cls) for cls in SECTIONS if ctx.store.exists(cls.ARTIFACT)}

    def render_json(self, bundle: dict) -> str:
        """대시보드·정적 데모가 읽는 단일 JSON."""
        raise NotImplementedError

    def render_markdown(self, bundle: dict) -> str:
        """F-901. CVE 요약·패치 분석·호출 경로·근본 원인(inferred 표시)·패턴·후보·검증."""
        raise NotImplementedError

    def render_html(self, bundle: dict) -> str:
        """F-902. 같은 내용 + diff 하이라이트, 로그 접기/펼치기."""
        raise NotImplementedError

    def link_evidence(self, evidence: Evidence) -> str:
        """F-903. 근거 → 파일:줄 링크 + snippet."""
        raise NotImplementedError

    def mask_for_public(self, bundle: dict) -> dict:
        """F-904. public=False 후보의 코드·위치, TestCase.call_args, 로그 원문 제거."""
        raise NotImplementedError
