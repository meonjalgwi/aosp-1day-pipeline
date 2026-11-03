"""M5. Pattern / Rule Generator — 취약 패턴·탐지 규칙 (5주차, F-501~F-505).

입력: root_cause.json (+ patch_analysis.json 의 before/after 소스로 자가 검증)
출력: pattern.json (PatternSet) + rules/<pattern_id>.scm

패치에서 source·guard·sink 구조를 뽑아 패턴화하고, Tree-sitter Query + Python matcher
규칙으로 변환한 뒤, 패치 전 코드에서는 탐지·패치 후 코드에서는 미탐지인지 자가 검증한다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import PatchAnalysis, Pattern, PatternSet, RootCause, RuleCheck
from .base import PipelineContext, Stage, StageResult

# F-502. P0 는 2종, cross_user 는 P1
PATTERN_TYPES = ("missing_permission", "uid_pkg_mismatch", "cross_user")


class PatternGenerator(Stage):
    name = "pattern"
    module = "M5"
    reads = (RootCause.ARTIFACT, PatchAnalysis.ARTIFACT)
    writes = (PatternSet.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        root_cause = ctx.store.load(RootCause)
        analysis = ctx.store.load(PatchAnalysis)
        result = PatternSet(cve_id=root_cause.cve_id)
        artifacts = []
        for pattern in self.extract_patterns(root_cause, analysis):
            rule_path = self.to_rule(pattern, ctx.config.rules_dir)
            pattern.rule_file = str(rule_path)
            pattern.check = self.self_check(rule_path, analysis, ctx.store.dir)
            result.patterns.append(pattern)
            artifacts.append(rule_path)
        path = self.save(ctx, result)
        return StageResult(self.name, ok=True, artifacts=[path, *artifacts])

    # --- 세부 기능 ---------------------------------------------------------

    def extract_patterns(self, root_cause: RootCause, analysis: PatchAnalysis) -> list[Pattern]:
        """F-501. 불변식·변경 hunk 에서 source·guard·sink(PatternElement) 추출, 유형 판별."""
        raise NotImplementedError

    def to_rule(self, pattern: Pattern, rules_dir: Path) -> Path:
        """F-503. Tree-sitter Query(.scm) + matcher 설정으로 변환.

        Query 로 source/sink 노드를 찾고, matcher 가 같은 메서드 안에 guard 가 없는지 판정.
        """
        raise NotImplementedError

    def self_check(self, rule_path: Path, analysis: PatchAnalysis, store_dir: Path) -> RuleCheck:
        """F-504. M1이 저장한 before 소스=탐지, after 소스=미탐지 인지 확인."""
        raise NotImplementedError

    def split_overfit(self, pattern: Pattern) -> Pattern:
        """F-505. 특정 CVE 전용 조건과 일반 조건 분리 (generic 플래그)."""
        raise NotImplementedError
