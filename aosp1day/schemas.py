"""파이프라인 단계 사이를 오가는 JSON 산출물의 데이터 계약(dataclass).

feature-spec.md 4장 "공통 데이터 (JSON 스키마)"를 타입으로 옮긴 것이다.
모든 모듈은 이 dataclass들만 주고받으며, 실제 저장/로드는 ``storage`` 가 담당한다.

설계 원칙
- 다음 단계가 실제로 쓸 정보를 담는다 (줄 번호만이 아니라 코드·커밋·전/후 구분까지).
- 코드 위치는 전부 ``CodeRef`` 하나로 표현한다 (M2 변경, M3 경로 노드, M4 근거, M6 후보, M8 판정 근거).
  ``CodeRef.revision`` 은 그 코드가 실제로 존재하는 리비전이다 (before=parent, after=패치 커밋).
- 모든 산출물은 ``meta`` (스키마 버전·생성 시각·입력 해시)를 가진다 → 재현성.
- LLM이 만든 결과는 ``status = "inferred"`` 로 저장하고, 사람이 확인해야 ``confirmed`` 가 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

SCHEMA_VERSION = "0.3"


# --- 공통 ---------------------------------------------------------------------

@dataclass
class ArtifactMeta:
    """모든 산출물 공통 헤더 (재현성·추적성)."""

    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""                 # ISO 8601
    tool_version: str = ""                 # aosp1day.__version__
    stage: str = ""                        # 생성한 단계 이름 (예: "analyze")
    inputs: dict[str, str] = field(default_factory=dict)   # 입력 산출물 파일명 -> sha256


@dataclass
class CodeRef:
    """코드 위치 + 내용 (provenance). 모든 단계가 같은 구조로 코드를 가리킨다.

    ``revision`` 은 **이 코드가 실제로 존재하는 커밋**이다. 이 값으로 원본 파일·줄을 다시 조회한다.
      - side="before": 패치 커밋의 parent (취약 버전)
      - side="after" : 패치 커밋
      - side="aosp"  : M6이 스캔한 frameworks/base HEAD
    어느 패치에서 나온 코드인지는 ``patch_commit`` 으로 따로 남긴다.
    """

    revision: str = ""        # 이 코드가 실제로 존재하는 커밋 (위 규칙)
    patch_commit: str = ""    # 관련 패치 커밋 (side=aosp 이면 비움)
    file: str = ""            # frameworks/base 기준 상대 경로
    side: str = ""            # before | after | aosp
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""         # 해당 범위의 실제 코드
    diff_path: str = ""       # 저장된 diff 파일 경로 (선택)
    cls: str = ""             # JSON 키 "class" (선택)
    method: str = ""          # (선택)


@dataclass
class LlmProvenance:
    """LLM 호출 기록. API 키는 절대 담지 않는다."""

    provider: str = ""
    model: str = ""
    temperature: float = 0.0
    prompt_hash: str = ""     # sha256(prompt)
    prompt_path: str = ""     # 저장된 프롬프트 파일 (키·비밀값 제거본)


# 분석 결과 상태: LLM 추론은 inferred, 사람이 확인하면 confirmed / rejected
Status = str  # inferred | confirmed | rejected


# --- M1. Collector -> cve.json -------------------------------------------------

@dataclass
class PatchCommit:
    repo: str = ""                 # 예: platform/frameworks/base
    hash: str = ""
    parent: str = ""
    url: str = ""
    branch: str = ""               # 예: android14-qpr2-release
    message: str = ""
    authored_at: str = ""
    changed_files: list[str] = field(default_factory=list)
    diff_path: str = ""            # output/<CVE>/patches/<hash>.diff
    before_dir: str = ""           # 변경 파일의 패치 전 원본 저장 위치
    after_dir: str = ""            # 변경 파일의 패치 후 원본 저장 위치


@dataclass
class CveRecord:
    """F-101~F-104. Collector 산출물."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    bulletin: str = ""             # 예: 2024-03-01
    bulletin_url: str = ""
    severity: str = ""
    type: str = ""                 # ASB 표기 (EoP, ID, DoS ...)
    component: str = ""
    affected_versions: list[str] = field(default_factory=list)
    patch_commits: list[PatchCommit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)   # F-105 예외 처리 기록 (깨진 링크, 비공개 버그 등)

    ARTIFACT = "cve.json"


# --- M2. Patch Analyzer -> patch_analysis.json --------------------------------

# 변경 유형: permission_check | input_validation | condition | exception | other
ChangeType = str


@dataclass
class Hunk:
    """diff hunk 하나. 전/후 코드를 짝지어 보관."""

    before: CodeRef = field(default_factory=CodeRef)   # side="before"
    after: CodeRef = field(default_factory=CodeRef)    # side="after"


@dataclass
class PatchChange:
    id: str = ""                    # 예: "chg-1" — M3/M4/M8 이 참조
    patch_commit: str = ""          # 이 변경이 들어 있는 패치 커밋 (hunk 의 before.revision 은 그 parent)
    file: str = ""
    cls: str = ""                   # JSON 키는 "class" (storage에서 매핑)
    method: str = ""
    change_type: ChangeType = ""
    security_apis: list[str] = field(default_factory=list)  # F-203: 추가/삭제된 권한 검사 API
    hunks: list[Hunk] = field(default_factory=list)


@dataclass
class PatchAnalysis:
    """F-201~F-204. Patch Analyzer 산출물."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    changes: list[PatchChange] = field(default_factory=list)
    baseline_match: Optional[float] = None   # F-204: 정답 대비 일치율

    ARTIFACT = "patch_analysis.json"


# --- M3. Binder Path Analyzer -> call_path.json -------------------------------

@dataclass
class CallPathNode:
    ref: CodeRef = field(default_factory=CodeRef)   # side="before" 권장 (취약 버전 기준)
    call_site: Optional[CodeRef] = None             # 다음 노드를 호출하는 위치


@dataclass
class CallPathEntry:
    target_change: str = ""          # PatchChange.id
    aidl_interface: str = ""         # 예: android.content.pm.IPackageManager
    aidl_file: str = ""
    stub_impl: str = ""              # 예: com.android.server.pm.PackageManagerService
    entrypoint: str = ""             # Binder로 노출된 메서드 이름
    nodes: list[CallPathNode] = field(default_factory=list)   # 진입점 -> 변경 함수 순서
    app_reachable: Optional[bool] = None
    required_permissions: list[str] = field(default_factory=list)


@dataclass
class CallPath:
    """F-301~F-304. 외부 진입점 -> 변경 함수 호출 경로 (변경마다 0개 이상)."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    paths: list[CallPathEntry] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)   # 경로를 못 찾은 PatchChange.id

    ARTIFACT = "call_path.json"


# --- M4. Root Cause Analyzer -> root_cause.json -------------------------------

@dataclass
class Evidence(CodeRef):
    """주장 하나를 뒷받침하는 코드 근거. CodeRef + 어떤 주장인지."""

    claim: str = ""                 # 이 근거가 뒷받침하는 주장
    change_id: str = ""             # 관련 PatchChange.id (선택)


@dataclass
class Claim:
    id: str = ""                    # 예: "rc-1", "hyp-1" — 리포트·대시보드·TestCase 가 참조
    text: str = ""
    evidence: list[Evidence] = field(default_factory=list)   # 비어 있으면 "근거 없음"으로 표시 (F-403)


@dataclass
class RootCause:
    """F-401~F-404. AI 보조 근본 원인 분석. 확정 판정이 아니라 분석 초안."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    status: Status = "inferred"
    root_cause: Claim = field(default_factory=Claim)
    trigger_conditions: list[Claim] = field(default_factory=list)
    security_invariant: Claim = field(default_factory=Claim)
    hypotheses: list[Claim] = field(default_factory=list)    # M8 Harness로 넘길 재현 가설
    llm: LlmProvenance = field(default_factory=LlmProvenance)
    reviewed_by: str = ""                                     # confirmed/rejected 처리한 사람

    ARTIFACT = "root_cause.json"


# --- M5. Pattern / Rule Generator -> pattern.json -----------------------------

# 패턴 유형: missing_permission | uid_pkg_mismatch | cross_user
PatternType = str


@dataclass
class PatternElement:
    """source / guard / sink 하나. 규칙으로 바꿀 수 있게 구조화."""

    kind: str = ""                  # binder_method_param | api_call | field_access ...
    apis: list[str] = field(default_factory=list)   # 예: ["Binder.getCallingUid"]
    description: str = ""


@dataclass
class RuleCheck:
    """F-504. 규칙 자가 검증 결과."""

    vulnerable_hits: int = 0        # 패치 전 코드에서 탐지 수 (>=1 이어야 함)
    patched_hits: int = 0           # 패치 후 코드에서 탐지 수 (0 이어야 함)
    passed: bool = False


@dataclass
class Pattern:
    pattern_id: str = ""
    type: PatternType = ""
    source: PatternElement = field(default_factory=PatternElement)
    guard: PatternElement = field(default_factory=PatternElement)   # "있어야 하는데 없는" 검사
    sink: PatternElement = field(default_factory=PatternElement)
    invariant: str = ""             # RootCause.security_invariant 요약
    rule_file: str = ""             # Tree-sitter 쿼리(.scm) + matcher 설정 경로
    generic: bool = True            # F-505: False면 이 CVE 전용 조건
    check: RuleCheck = field(default_factory=RuleCheck)
    derived_from: list[Evidence] = field(default_factory=list)


@dataclass
class PatternSet:
    """F-501~F-505. CVE 하나에서 나온 패턴 목록."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    patterns: list[Pattern] = field(default_factory=list)

    ARTIFACT = "pattern.json"


# --- M6. Scanner -> candidates.json / M7. Prioritizer -> ranked_candidates.json

@dataclass
class ScoreReason:
    binder_exposed: bool = False
    sensitive_sink: bool = False
    guard_missing: bool = False
    notes: str = ""


@dataclass
class Candidate:
    id: str = ""
    pattern_id: str = ""
    location: CodeRef = field(default_factory=CodeRef)        # side="aosp", snippet 포함
    matched: dict[str, CodeRef] = field(default_factory=dict) # "source"/"sink" 등 매칭된 노드 위치
    score: float = 0.0
    score_reason: ScoreReason = field(default_factory=ScoreReason)
    label: str = "unreviewed"   # unreviewed | tp | fp | hold
    public: bool = False        # 공개 가능 여부 (기본 비공개, 마스킹 대상)


@dataclass
class CandidateSet:
    """M6. Scanner 산출물 (F-601~F-603). 점수 매기기 전 후보 목록."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    aosp_revision: str = ""     # 스캔한 frameworks/base 커밋
    candidates: list[Candidate] = field(default_factory=list)

    ARTIFACT = "candidates.json"


@dataclass
class RankedCandidates:
    """M7. Prioritizer 산출물 (F-701~F-703). 점수순 정렬 후보."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    weights: dict[str, float] = field(default_factory=dict)   # 점수 가중치 (재현용)
    candidates: list[Candidate] = field(default_factory=list)

    ARTIFACT = "ranked_candidates.json"


# --- M8. Verifier (Harness 포함) -> test_cases.json / verification.json -------

# 실행 결과 / 기대 결과 공용 값 목록. RunResult.outcome 과 ExpectedResult.outcome 이 같은 값을 쓴다.
OUTCOMES = (
    "ok",                   # 정상 반환 (예외 없음)
    "returned_data",        # 정상 반환 + 반환값 검사 대상
    "security_exception",   # SecurityException 등 권한 거부
    "exception",            # 그 밖의 예외
    "crash",                # 테스트 앱 또는 system_server 크래시
    "timeout",
)
Outcome = str  # OUTCOMES 중 하나


@dataclass
class ValueSpec:
    """테스트 인자 하나. 공용 instrumentation APK 가 이 구조를 읽어 실제 Java 객체로 조립한다.

    P0 지원 type: null | bool | int | long | float | string | array | bundle | intent | ref
    (임의 Parcelable 은 P1)
      - array : items 에 원소 ValueSpec
      - bundle: entries 에 key -> ValueSpec
      - intent: entries 의 action/package/component/data/extras(bundle) 키 사용
      - ref   : 앞선 호출 결과 참조 (value = "<call_id>")
    """

    type: str = "null"
    value: Any = None                                         # 스칼라 값 (null/bool/int/long/float/string/ref)
    items: list["ValueSpec"] = field(default_factory=list)    # array
    entries: dict[str, "ValueSpec"] = field(default_factory=dict)  # bundle / intent
    java_type: str = ""                                       # 오버로드 구분용 (예: "int[]", "android.os.Bundle")


@dataclass
class CallStep:
    """호출 하나. TestCase.calls 순서대로 실행한다."""

    id: str = ""                    # 예: "call-1" (ValueSpec ref 로 참조)
    via: str = "binder"             # binder | intent (P0) / content_provider 등 (P1)
    service: str = ""               # ServiceManager 이름 (예: "package")
    interface: str = ""             # AIDL 인터페이스 (예: android.content.pm.IPackageManager)
    method: str = ""
    args: list[ValueSpec] = field(default_factory=list)       # 인자 순서대로


@dataclass
class CallerSpec:
    """호출 앱의 신원·권한. 패치 전/후 빌드에서 같은 조건을 만들어야 차등 판정이 의미가 있다."""

    kind: str = "untrusted_app"     # untrusted_app | privileged_app | shell
    package: str = ""               # 테스트 APK 패키지
    apk_variant: str = "no_perms"   # 공용 APK 변형 (config.device.test_apks 의 키, 예: no_perms | with_perms)
    granted_permissions: list[str] = field(default_factory=list)   # 설치 후 pm grant (매니페스트에 선언된 것만 가능)
    user_id: int = 0
    target_sdk: Optional[int] = None


@dataclass
class ExpectedResult:
    """기대 결과. Verifier 가 RunResult 와 필드 단위로 비교해 자동 판정한다."""

    outcome: Outcome = ""
    exception_type: str = ""        # 예: java.lang.SecurityException
    return_value: Optional[ValueSpec] = None
    log_regex: str = ""             # 예: "Permission Denial"


@dataclass
class TestCase:
    """F-807(P0 기준선, 사람 작성) / F-802(P1 자동 생성). 가설 하나를 확인하는 테스트."""

    id: str = ""
    source: str = "manual"          # manual (baselines/<CVE>.tests.json) | generated (F-802)
    hypothesis_id: str = ""         # RootCause.hypotheses[].id
    change_id: str = ""             # PatchChange.id (= CallPathEntry.target_change)
    entrypoint: str = ""            # 사용한 Binder 진입점
    caller: CallerSpec = field(default_factory=CallerSpec)
    setup: list[str] = field(default_factory=list)      # reset 후·실행 전 adb shell 명령 (예: "pm create-user test")
    calls: list[CallStep] = field(default_factory=list)
    teardown: list[str] = field(default_factory=list)   # 실행 후 정리 adb shell 명령
    expected_vulnerable: ExpectedResult = field(default_factory=ExpectedResult)
    expected_patched: ExpectedResult = field(default_factory=ExpectedResult)
    template: str = ""              # 공용 APK 안의 템플릿 이름 (예: BinderCallTest)
    params_path: str = ""           # 기기에 push 할 파라미터 JSON (output/<CVE>/tests/<id>.json)


@dataclass
class SkippedHypothesis:
    hypothesis_id: str = ""
    reason: str = ""                # 예: "no_reachable_entrypoint", "unresolved_change", "unsupported_arg_type"


@dataclass
class TestCases:
    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    tests: list[TestCase] = field(default_factory=list)
    skipped: list[SkippedHypothesis] = field(default_factory=list)   # 테스트를 만들지 못한 가설

    ARTIFACT = "test_cases.json"


@dataclass
class BuildInfo:
    side: str = ""                  # vulnerable | patched
    device: str = ""                # cuttlefish | emulator
    image: str = ""                 # 이미지 이름/빌드 ID 또는 교체한 jar
    fingerprint: str = ""           # ro.build.fingerprint


@dataclass
class RunResult:
    build: BuildInfo = field(default_factory=BuildInfo)
    outcome: Outcome = ""           # OUTCOMES 중 하나
    exception_type: str = ""
    return_value: Any = None
    logcat_path: str = ""
    log_excerpt: list[str] = field(default_factory=list)   # 판정 근거 줄
    exit_code: Optional[int] = None


@dataclass
class TestVerdict:
    test_id: str = ""
    vulnerable: RunResult = field(default_factory=RunResult)
    patched: RunResult = field(default_factory=RunResult)
    verdict: str = ""               # reproduced | not_reproduced | error
    failure_reason: str = ""        # env | build | hypothesis | test


@dataclass
class Verification:
    """F-801~F-806. 패치 전후 차등 판정."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    target: str = ""                # P0: CVE ID 만. (Candidate.id 검증은 P1)
    results: list[TestVerdict] = field(default_factory=list)
    verdict: str = ""               # 전체 판정: 하나라도 reproduced 면 reproduced

    ARTIFACT = "verification.json"


# --- 정답 데이터 (3주차 수동 기준선) -> baselines/<CVE-ID>.json --------------

@dataclass
class Baseline:
    """사람이 직접 분석한 정답. M2(F-204)·M11(F-1101) 비교 기준."""

    cve_id: str = ""
    analyst: str = ""
    changed_methods: list[CodeRef] = field(default_factory=list)
    root_cause: str = ""
    security_invariant: str = ""
    trigger_conditions: list[str] = field(default_factory=list)
    entrypoint: str = ""
    repro_steps: list[str] = field(default_factory=list)
    expected_vulnerable: ExpectedResult = field(default_factory=ExpectedResult)
    expected_patched: ExpectedResult = field(default_factory=ExpectedResult)
    analysis_minutes: Optional[float] = None   # F-1104 시간 절감 비교용


# --- M11. Evaluation -> output/eval.json ---------------------------------------

@dataclass
class CveEval:
    cve_id: str = ""
    method_match: Optional[float] = None
    root_cause_match: Optional[bool] = None
    reproduced: Optional[bool] = None
    tool_minutes: Optional[float] = None


@dataclass
class Evaluation:
    """F-1101~F-1104. 여러 CVE를 모아 평가 (CVE 디렉터리가 아니라 output/ 최상위)."""

    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    per_cve: list[CveEval] = field(default_factory=list)
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
