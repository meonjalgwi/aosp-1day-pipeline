"""M3. Binder Path Analyzer — 진입점 경로 분석 (4주차, F-301~F-304).

입력: patch_analysis.json + AOSP 소스
출력: call_path.json

AIDL 인터페이스 <-> Stub 구현 클래스를 연결하고, 외부 진입점(Binder 메서드)부터
패치된 함수까지의 호출 경로를 추출한다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import CallPath, CallPathNode, PatchAnalysis
from .base import PipelineContext, Stage, StageResult


class BinderPathAnalyzer(Stage):
    name = "binder-path"
    module = "M3"
    reads = (PatchAnalysis.ARTIFACT,)
    writes = (CallPath.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        analysis = ctx.store.load(PatchAnalysis)
        call_path = self.build_call_path(analysis, ctx.config.aosp_root)
        path = ctx.store.save(call_path)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def map_aidl_to_impl(self, aosp_root: Path) -> dict[str, str]:
        """F-301. .aidl 인터페이스 ↔ Stub 구현 클래스(Service) 매핑."""
        raise NotImplementedError

    def build_call_path(self, analysis: PatchAnalysis, aosp_root: Path) -> CallPath:
        """F-302. 외부 진입점 -> 변경 함수까지 호출 경로 추출."""
        raise NotImplementedError

    def is_app_reachable(self, entrypoint: str, aosp_root: Path) -> bool:
        """F-303. 일반 앱에서 호출 가능한지 (서비스 등록·권한 요구 여부)."""
        raise NotImplementedError

    def to_diagram(self, call_path: CallPath) -> str:
        """F-304(P2). 호출 그래프를 보고서용 다이어그램(Mermaid 등)으로."""
        raise NotImplementedError
