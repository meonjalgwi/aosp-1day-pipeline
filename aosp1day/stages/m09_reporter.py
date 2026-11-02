"""M9. Reporter — 보고서 생성 (8주차, F-901~F-904).

입력: 모든 단계의 JSON
출력: report.md, report.html

각 주장마다 diff 줄·로그 위치 링크를 달고, 미공개 후보·위험 입력을 제거한
공개용(마스킹) 버전도 생성한다 (책임 있는 공개).
"""

from __future__ import annotations

from ..schemas import (
    CveRecord,
    PatchAnalysis,
    RankedCandidates,
    RootCause,
    Verification,
)
from .base import PipelineContext, Stage, StageResult


class Reporter(Stage):
    name = "report"
    module = "M9"
    # 있는 산출물을 모아 보고서를 만든다. 일부가 없어도 가능한 부분까지 렌더.
    reads = (CveRecord.ARTIFACT,)
    writes = ("report.md", "report.html")

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        bundle = self.collect_artifacts(ctx)
        public = bool(ctx.params.get("public", False))
        md = self.render_markdown(bundle, public=public)
        html = self.render_html(bundle, public=public)
        p_md = ctx.store.save_text("report_public.md" if public else "report.md", md)
        p_html = ctx.store.save_text("report_public.html" if public else "report.html", html)
        return StageResult(self.name, ok=True, artifacts=[p_md, p_html])

    # --- 세부 기능 ---------------------------------------------------------

    def collect_artifacts(self, ctx: PipelineContext) -> dict:
        """존재하는 단계 산출물(cve/patch/root_cause/ranked/verification)을 모은다."""
        raise NotImplementedError

    def render_markdown(self, bundle: dict, public: bool) -> str:
        """F-901. CVE 요약·패치 분석·호출 경로·근본 원인·패턴·후보·검증."""
        raise NotImplementedError

    def render_html(self, bundle: dict, public: bool) -> str:
        """F-902. 같은 내용 + diff 하이라이트, 로그 접기/펼치기."""
        raise NotImplementedError

    def link_evidence(self, claim: str, evidence) -> str:
        """F-903. 각 주장마다 diff 줄·로그 위치 링크."""
        raise NotImplementedError

    def mask_for_public(self, bundle: dict) -> dict:
        """F-904. 미공개 후보·위험 입력 제거한 공개용 버전."""
        raise NotImplementedError
