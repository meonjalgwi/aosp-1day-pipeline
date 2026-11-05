"""M2. Patch Analyzer — 패치 분석 (3주차, F-201~F-204).

입력: cve.json (+ M1이 저장한 diff, 패치 전/후 소스)
출력: patch_analysis.json

Tree-sitter(Java)로 변경된 클래스·메서드·조건문·권한 검사·예외 처리를 추출한다.
각 변경은 hunk 단위로 패치 전/후 코드(CodeRef: commit·side·줄 범위·snippet)를 함께 담아
M4가 프롬프트에 그대로 넣고 근거로 연결할 수 있게 한다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import Baseline, CveRecord, Hunk, PatchAnalysis, PatchChange, PatchCommit
from .base import PipelineContext, Stage, StageResult

# F-203. 권한/신원 검사로 인식할 API 목록 (확장 예정)
PERMISSION_APIS = (
    "enforceCallingPermission",
    "enforceCallingOrSelfPermission",
    "checkCallingOrSelfPermission",
    "checkCallingPermission",
    "Binder.getCallingUid",
    "Binder.getCallingPid",
    "clearCallingIdentity",
    "restoreCallingIdentity",
    "handleIncomingUser",
)


class PatchAnalyzer(Stage):
    name = "analyze"
    module = "M2"
    reads = (CveRecord.ARTIFACT,)
    writes = (PatchAnalysis.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        cve = ctx.store.load(CveRecord)
        analysis = PatchAnalysis(cve_id=cve.cve_id)
        for commit in cve.patch_commits:
            analysis.changes.extend(self.analyze_commit(commit, ctx.store.dir))
        if baseline := ctx.params.get("baseline"):
            analysis.baseline_match = self.compare_with_baseline(analysis, baseline)
        path = self.save(ctx, analysis)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def analyze_commit(self, commit: PatchCommit, store_dir: Path) -> list[PatchChange]:
        """commit.diff_path 의 hunk 를 before_dir/after_dir 소스와 매칭해 PatchChange 목록 생성."""
        raise NotImplementedError

    def split_hunks(self, diff_path: Path) -> list[Hunk]:
        """diff 를 hunk 단위로 나누고 before/after CodeRef(줄 범위·snippet) 채움.

        before.revision = commit.parent, after.revision = commit.hash, 둘 다 patch_commit = commit.hash.
        """
        raise NotImplementedError

    def extract_changed_units(self, hunk: Hunk, before_src: Path, after_src: Path) -> PatchChange:
        """F-201. Tree-sitter 로 hunk 를 감싸는 클래스·메서드 식별."""
        raise NotImplementedError

    def classify_change(self, change: PatchChange) -> str:
        """F-202. permission_check | input_validation | condition | exception | other."""
        raise NotImplementedError

    def detect_permission_apis(self, change: PatchChange) -> list[str]:
        """F-203. hunk before/after snippet 에서 PERMISSION_APIS 추가·삭제 탐지."""
        raise NotImplementedError

    def compare_with_baseline(self, analysis: PatchAnalysis, baseline_path: str) -> float:
        """F-204. baselines/<CVE>.json(Baseline)의 changed_methods 와 비교해 일치율 반환."""
        raise NotImplementedError

    def load_baseline(self, path: str) -> Baseline:
        raise NotImplementedError
