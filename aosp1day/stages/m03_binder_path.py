"""M3. Binder Path Analyzer — 진입점 경로 분석 (4주차, F-301~F-304).

입력: patch_analysis.json + AOSP 소스
출력: call_path.json

AIDL 인터페이스 <-> Stub 구현 클래스를 연결하고, 외부 진입점(Binder 메서드)부터
패치된 함수(PatchChange)까지의 호출 경로를 추출한다. P0 범위는 "제한된" 분석:
변경 메서드에서 거꾸로 같은 서비스 클래스 안의 Binder 메서드까지만 따라간다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import CallPath, CallPathEntry, PatchAnalysis, PatchChange
from .base import PipelineContext, Stage, StageResult


class BinderPathAnalyzer(Stage):
    name = "binder-path"
    module = "M3"
    reads = (PatchAnalysis.ARTIFACT,)
    writes = (CallPath.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        analysis = ctx.store.load(PatchAnalysis)
        aidl_map = self.map_aidl_to_impl(ctx.config.aosp_root)
        result = CallPath(cve_id=analysis.cve_id)
        for change in analysis.changes:
            entries = self.find_paths(change, aidl_map, ctx.config.aosp_root)
            if entries:
                result.paths.extend(entries)
            else:
                result.unresolved.append(change.id)
        path = self.save(ctx, result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def map_aidl_to_impl(self, aosp_root: Path) -> dict[str, str]:
        """F-301. .aidl 인터페이스 이름 -> Stub 구현 클래스(Service) 매핑 (Tree-sitter)."""
        raise NotImplementedError

    def find_paths(self, change: PatchChange, aidl_map: dict[str, str], aosp_root: Path) -> list[CallPathEntry]:
        """F-302. 진입점 -> change 메서드까지 경로. 노드마다 CodeRef(+호출 위치)."""
        raise NotImplementedError

    def check_reachability(self, entry: CallPathEntry, aosp_root: Path) -> None:
        """F-303. 일반 앱에서 호출 가능한지, 요구 권한 → entry.app_reachable / required_permissions."""
        raise NotImplementedError

    def to_diagram(self, call_path: CallPath) -> str:
        """F-304(P2). 호출 그래프를 보고서용 Mermaid 로."""
        raise NotImplementedError
