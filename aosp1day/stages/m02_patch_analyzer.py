"""M2. Patch Analyzer — 패치 분석 (3주차, F-201~F-204).

입력: cve.json
출력: patch_analysis.json

Tree-sitter 로 변경된 클래스·메서드·조건문·권한 검사·예외 처리를 추출한다.
"""

from __future__ import annotations

from ..schemas import CveRecord, PatchAnalysis, PatchChange
from .base import PipelineContext, Stage, StageResult

# F-203. 권한/신원 검사로 인식할 API 목록 (확장 예정)
PERMISSION_APIS = (
    "enforceCallingPermission",
    "checkCallingOrSelfPermission",
    "checkCallingPermission",
    "Binder.getCallingUid",
    "Binder.getCallingPid",
    "clearCallingIdentity",
    "restoreCallingIdentity",
    "handleIncomingUser",
    "enforceCallingOrSelfPermission",
)


class PatchAnalyzer(Stage):
    name = "analyze"
    module = "M2"
    reads = (CveRecord.ARTIFACT,)
    writes = (PatchAnalysis.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        cve = ctx.store.load(CveRecord)
        analysis = self.analyze(cve)
        path = ctx.store.save(analysis)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def analyze(self, cve: CveRecord) -> PatchAnalysis:
        """diff 를 돌며 PatchChange 목록 생성."""
        raise NotImplementedError

    def extract_changed_units(self, diff: str, file: str) -> list[PatchChange]:
        """F-201. Tree-sitter 로 변경된 클래스·메서드 식별."""
        raise NotImplementedError

    def classify_change(self, change: PatchChange) -> str:
        """F-202. 조건문/권한 검사/예외 처리/입력 검증 추가 등으로 분류."""
        raise NotImplementedError

    def detect_permission_apis(self, snippet: str) -> list[str]:
        """F-203. PERMISSION_APIS 탐지."""
        raise NotImplementedError

    def compare_with_baseline(self, analysis: PatchAnalysis, baseline_path: str) -> float:
        """F-204. 수동 분석 정답 데이터와 비교해 일치율 반환."""
        raise NotImplementedError
