"""파이프라인 단계 사이를 오가는 JSON 산출물의 데이터 계약(dataclass).

feature-spec.md 4장 "공통 데이터 (JSON 스키마 초안)"을 그대로 타입으로 옮긴 것이다.
모든 모듈은 이 dataclass들만 주고받으며, 실제 저장/로드는 ``storage`` 가 담당한다.

skeleton 단계이므로 필드는 스펙 기준으로 채워 두되, 세부 조정(선택/필수, 중첩 구조)은
각 모듈 구현 시 확정한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# --- M1. Collector -> cve.json -------------------------------------------------

@dataclass
class PatchCommit:
    repo: str = ""
    hash: str = ""
    parent: str = ""
    url: str = ""


@dataclass
class CveRecord:
    """F-101~F-104. Collector 산출물."""

    cve_id: str = ""
    bulletin: str = ""
    severity: str = ""
    component: str = ""
    affected_versions: list[str] = field(default_factory=list)
    patch_commits: list[PatchCommit] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)

    ARTIFACT = "cve.json"


# --- M2. Patch Analyzer -> patch_analysis.json --------------------------------

# 변경 유형: permission_check | input_validation | condition | exception
ChangeType = str


@dataclass
class PatchChange:
    file: str = ""
    cls: str = ""          # JSON 키는 "class" (storage에서 매핑)
    method: str = ""
    change_type: ChangeType = ""
    added_lines: list[int] = field(default_factory=list)
    removed_lines: list[int] = field(default_factory=list)


@dataclass
class PatchAnalysis:
    """F-201~F-204. Patch Analyzer 산출물."""

    cve_id: str = ""
    changes: list[PatchChange] = field(default_factory=list)

    ARTIFACT = "patch_analysis.json"


# --- M3. Binder Path Analyzer -> call_path.json -------------------------------

@dataclass
class CallPathNode:
    file: str = ""
    cls: str = ""
    method: str = ""


@dataclass
class CallPath:
    """F-301~F-304. 외부 진입점 -> 변경 함수 호출 경로."""

    cve_id: str = ""
    aidl_interface: str = ""
    stub_impl: str = ""
    entrypoint: str = ""                 # Binder로 노출된 진입 메서드
    path: list[CallPathNode] = field(default_factory=list)
    app_reachable: Optional[bool] = None  # 일반 앱에서 호출 가능한지

    ARTIFACT = "call_path.json"


# --- M4. Root Cause Analyzer -> root_cause.json -------------------------------

@dataclass
class Evidence:
    file: str = ""
    line: int = 0


@dataclass
class RootCause:
    """F-401~F-403. AI 보조 근본 원인 분석."""

    cve_id: str = ""
    root_cause: str = ""
    trigger_conditions: list[str] = field(default_factory=list)
    security_invariant: str = ""
    evidence: list[Evidence] = field(default_factory=list)

    ARTIFACT = "root_cause.json"


# --- M5. Pattern / Rule Generator -> pattern.json -----------------------------

# 패턴 유형: missing_permission | uid_pkg_mismatch | cross_user
PatternType = str


@dataclass
class Pattern:
    """F-501~F-505. source·guard·sink 패턴과 생성된 규칙 파일."""

    pattern_id: str = ""
    type: PatternType = ""
    source: str = ""
    guard: str = ""
    sink: str = ""
    rule_file: str = ""   # 생성된 Semgrep/Tree-sitter 규칙 경로

    ARTIFACT = "pattern.json"


# --- M6. Scanner -> candidates.json / M7. Prioritizer -> ranked_candidates.json

@dataclass
class ScoreReason:
    binder_exposed: bool = False
    sensitive_sink: bool = False
    guard_missing: bool = False


@dataclass
class Candidate:
    id: str = ""
    file: str = ""
    method: str = ""
    pattern_id: str = ""
    score: float = 0.0
    score_reason: ScoreReason = field(default_factory=ScoreReason)
    label: str = "unreviewed"   # unreviewed | tp | fp


@dataclass
class CandidateSet:
    """M6. Scanner 산출물 (F-601~F-603). 점수 매기기 전 후보 목록."""

    candidates: list[Candidate] = field(default_factory=list)

    ARTIFACT = "candidates.json"


@dataclass
class RankedCandidates:
    """M7. Prioritizer 산출물 (F-701~F-703). 점수순 정렬 후보."""

    candidates: list[Candidate] = field(default_factory=list)

    ARTIFACT = "ranked_candidates.json"


# --- M8. Verifier -> verification.json ----------------------------------------

@dataclass
class BuildResult:
    result: str = ""   # ex) "SecurityException", "crash", "ok"
    log: str = ""      # logcat 경로 또는 요약


@dataclass
class Verification:
    """F-801~F-806. 패치 전후 차등 판정."""

    target: str = ""
    vulnerable_build: BuildResult = field(default_factory=BuildResult)
    patched_build: BuildResult = field(default_factory=BuildResult)
    verdict: str = ""          # reproduced | not_reproduced | error
    failure_reason: str = ""   # env | build | hypothesis | test

    ARTIFACT = "verification.json"


# --- M11. Evaluation -> eval.json ---------------------------------------------

@dataclass
class Evaluation:
    """F-1101~F-1104."""

    analysis_accuracy: Optional[float] = None
    detection_rate: Optional[float] = None
    false_positive_rate: Optional[float] = None
    time_saved: Optional[float] = None

    ARTIFACT = "eval.json"


# JSON 키가 파이썬 예약어("class")와 겹치는 dataclass 필드 매핑.
# storage의 직렬화/역직렬화에서 사용한다.
FIELD_ALIASES = {
    "cls": "class",
}
