"""M5. Pattern / Rule Generator — 취약 패턴·탐지 규칙 (5주차, F-501~F-505).

입력: root_cause.json
출력: pattern.json + Semgrep/Tree-sitter 규칙 파일

패치에서 source·guard·sink 구조를 뽑아 패턴화하고, 탐지 규칙으로 변환한 뒤
취약 버전에서는 탐지·패치 버전에서는 미탐지인지 자가 검증한다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import Pattern, RootCause
from .base import PipelineContext, Stage, StageResult

# F-502. 최소 3종 패턴
PATTERN_TYPES = ("missing_permission", "uid_pkg_mismatch", "cross_user")


class PatternGenerator(Stage):
    name = "pattern"
    module = "M5"
    reads = (RootCause.ARTIFACT,)
    writes = (Pattern.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        root_cause = ctx.store.load(RootCause)
        pattern = self.extract_pattern(root_cause)
        rule_path = self.to_rule(pattern, ctx.config.rules_dir)
        pattern.rule_file = str(rule_path)
        path = ctx.store.save(pattern)
        return StageResult(self.name, ok=True, artifacts=[path, rule_path])

    # --- 세부 기능 ---------------------------------------------------------

    def extract_pattern(self, root_cause: RootCause) -> Pattern:
        """F-501. 입력(source)·검사(guard)·민감 동작(sink) 구조로 패턴화."""
        raise NotImplementedError

    def to_rule(self, pattern: Pattern, rules_dir: Path) -> Path:
        """F-503. 패턴을 Semgrep 또는 Tree-sitter 쿼리 파일로 변환."""
        raise NotImplementedError

    def self_check(self, rule_path: Path, vulnerable_src: Path, patched_src: Path) -> bool:
        """F-504. 취약 버전=탐지 / 패치 버전=미탐지 인지 확인."""
        raise NotImplementedError

    def split_overfit(self, pattern: Pattern) -> Pattern:
        """F-505. 특정 CVE 전용 조건과 일반 조건 분리."""
        raise NotImplementedError
