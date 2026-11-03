"""단계 레지스트리.

파이프라인 실행 순서(M1 -> M9)와 CLI 서브커맨드 이름을 한 곳에서 관리한다.
M10(대시보드)은 Streamlit 앱(산출물 JSON만 읽음), M11(평가)은 여러 CVE를 모아 돌리므로 선형 순서에서 분리한다.
"""

from __future__ import annotations

from .base import PipelineContext, Stage, StageResult
from .m01_collector import Collector
from .m02_patch_analyzer import PatchAnalyzer
from .m03_binder_path import BinderPathAnalyzer
from .m04_root_cause import RootCauseAnalyzer
from .m05_pattern_generator import PatternGenerator
from .m06_scanner import Scanner
from .m07_prioritizer import Prioritizer
from .m08_harness import Harness
from .m08_verifier import Verifier
from .m09_reporter import Reporter
from .m11_evaluation import Evaluator

# CVE 한 건에 대해 순서대로 도는 핵심 파이프라인 (M1 -> M9)
PIPELINE: tuple[type[Stage], ...] = (
    Collector,
    PatchAnalyzer,
    BinderPathAnalyzer,
    RootCauseAnalyzer,
    PatternGenerator,
    Scanner,
    Prioritizer,
    Harness,
    Verifier,
    Reporter,
)

# 선형 파이프라인에 속하지 않는 단계
STANDALONE: tuple[type[Stage], ...] = (Evaluator,)

# 서브커맨드 이름 -> Stage 클래스
REGISTRY: dict[str, type[Stage]] = {
    s.name: s for s in (*PIPELINE, *STANDALONE)
}

__all__ = [
    "Stage",
    "StageResult",
    "PipelineContext",
    "PIPELINE",
    "STANDALONE",
    "REGISTRY",
]
