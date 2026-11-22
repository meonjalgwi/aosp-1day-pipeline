# 상세 설계서 v2 — 모듈·클래스·메서드 명세

> 2026-11-18 · 김나연 (v2.1: 2026-11-23 실현 가능성 검토 반영 · v2.2: LLM 검증 구조 → [llm-verification.md](llm-verification.md))
> 기준: PR #20 기능명세서 v0.3.1 · PR #30 설계 뼈대(2차 리뷰 반영본) · 주제 제안서(공개 패치 기반 미패치 취약점 탐지) · 11/18 멘토 피드백
> 구조도는 [architecture.md](architecture.md), 기능 ID는 [feature-spec.md](feature-spec.md)를 따른다.

기존 뼈대(`aosp1day/`, M1~M11, `Stage`, `schemas.py`, `output/<CVE-ID>/`, Streamlit)는 그대로 쓰고, 목표만 "1-Day 재현"에서 "공개 패치의 결함 구조로 다른 System Service의 변종 후보 탐지"로 바꾼다. 코드에서 바뀌는 것은 세 가지다.

1. M8(Harness·Verifier)은 P0에서 빠진다. 코드와 스키마는 남기고 `PIPELINE`에서만 제외한다.
2. M5에 LLM 규칙 파라미터 초안과, 자가 검증 실패 시 재생성 루프가 들어간다.
3. M7에 오탐 필터와 LLM 후보 검토가, M11에 회고 검증이 들어간다.

### v2.1 (11/23) — 실현 가능성 검토 반영

| # | 문제 | 수정 | 위치 |
| --- | --- | --- | --- |
| R1 | 자가 검증이 "패치 전 탐지·후 미탐지"만 봐서, LLM이 규칙을 지나치게 넓혀도 통과한다 | 음성 대조군 예산(`control_hits`) 추가. LLM 시도가 예산을 넘으면 `TOO_BROAD` 로 **실패** 처리. M6 에서도 스캔 히트 예산을 넘으면 seed 규칙으로 되돌림 | §2.1 `RuleCheck`, §2.3 `RuleConfig`, §7.1·7.2, §8 |
| R2 | 기존 검사의 **호출 조건만 바꾼** 패치는 패치 전 코드에도 Guard 호출이 있어 "Guard 누락" 규칙으로 전·후를 구분할 수 없다 | M2 에서 수정 유형(`fix_kind`)을 P0 로 판정하고 `ADDED_GUARD` 만 M3 이후로 넘김. 나머지는 범위 밖으로 기록 | §2.1 `PatchChange`, §4 |
| R3 | Tree-sitter 근사 호출 그래프에서 해석 못 한 간선을 "경로 없음·Guard 없음"으로 처리하면 필터가 오탐·미탐을 만든다 | 도달성·상위 Guard 판정을 3값(`resolved`·`partial`·`unknown`)으로. `unknown` 은 탈락시키지 않고 점수만 낮춤 | §2.1 `Candidate`, §2.5 `callgraph`, §9 |
| R4 | Guard 카탈로그에 강제력이 없는 `@RequiresPermission` 포함, `clearCallingIdentity` 이후 호출자 기반 검사도 Guard 로 인정 | `@RequiresPermission` 제거, `@EnforcePermission` 생성 헬퍼 호출 인식, identity 해제 구간 안의 호출자 기반 검사는 Guard 로 세지 않음 | §2.5 `security_apis` |
| R5 | "판정은 결정적 절차" 원칙과 M7 LLM 재점수의 관계가 모호 | LLM 은 점수의 `review` 항만 바꾼다. 채택·필터·라벨은 절대 바꾸지 않는다고 명시 | §2.4, §9 |

---

## 0. 기존 결정과 v2 변경점

### 0.1 그대로 유지하는 결정

| 항목 | 결정 | 출처 |
| --- | --- | --- |
| 패키지·구조 | `aosp1day/`, `stages/mNN_*.py`, `Stage(name, reads, writes, run)` | PR #30 |
| 데이터 계약 | `schemas.py` dataclass. 코드 위치는 전부 `CodeRef`(revision·patch_commit·side), 근거는 `Evidence`, 모든 산출물에 `meta: ArtifactMeta` | PR #30 1·2차 리뷰 |
| 저장 | `output/<CVE-ID>/*.json`, `Store`만 경유 | PR #30 |
| LLM | `LlmClient.generate_structured(prompt, schema)`, 키는 환경변수만, 결과는 `status="inferred"` + `LlmProvenance` | PR #20 4번 |
| 규칙 엔진 | Tree-sitter Query(`.scm`) + Python matcher | PR #20 2번 |
| 대시보드 | Streamlit 단독, 미리 생성된 JSON만 읽음, 실행 기능 없음(F-1002 P2) | PR #20 5번 |
| 실행 | `run`은 앞 단계가 실패해도 `reads`가 충족된 단계는 계속 실행 | PR #30 서진 6번 |
| 의존성 | `PyYAML`·`streamlit` 필수, `tree-sitter`는 `[analysis]` 선택 | PR #30 현아 2번 |
| 분석 범위 | `scan_paths` = `services/*/java/com/android/server/**/*.java`, `core/java/android/**/*.aidl`, `core/java/android/**/*.java` | PR #20 2차 |
| 패턴 | P0 2종(권한 검사 누락, UID–packageName 불일치), Cross-user는 P1 | PR #20 |
| 배포 | 미공개 후보의 코드·위치 외부 공개 금지, 발표는 `_public` 마스킹본만 | PR #20 6번 |
| Collector 캐시 | `cve.json` + 모든 커밋의 diff·before·after가 실제로 있을 때만 캐시 사용 | PR #30 현아 5번 |

### 0.2 v2에서 바뀌는 것

| 항목 | v0.3.1 | v2 | 근거 |
| --- | --- | --- | --- |
| 목표 | 1-Day 재현·원인 분석 | 패치의 Source–Guard–Sink 구조로 다른 System Service의 변종 후보 탐지 | 제안서 |
| M8 Harness·Verifier | P0 (기준선 1건 동적 검증) | **P2**. 최종 발표 때 상위 후보를 수동 재현하는 선택 목표 | 11/11 피드백(재현 제외), 남은 기간 |
| M4 Root Cause | 근본 원인·불변식·재현 가설 | 근본 원인·불변식 + **S·G·S 초안**(`SgsDraft`). 가설(`hypotheses`)은 P2 | M8 제외 |
| M5 Pattern/Rule | 패턴 → 규칙 + 자가 검증 | + **LLM 규칙 파라미터 초안**, 검증 실패 시 피드백 재생성(최대 3회) | 제안서 "LLM은 규칙 초안" |
| M7 Prioritizer | 점수화·상위 N | + **오탐 필터**, + **LLM 후보 검토**(상위 K, `inferred`) | 11/18 멘토 피드백 |
| M11 Evaluation | 정확도·탐지율·오탐률·시간 | + **회고 검증**(이후 ASB 패치와 후보 대조) | 제안서 평가 방법 |
| 대시보드 | D-1·3·4·6·7·8·9 | D-8(동적 검증) P2, **D-5(규칙 검증)** 추가, 제안서 5개 탭에 매핑 | 제안서 산출물 |
| P0 8번 | 기준선 CVE 1건 패치 전후 동적 검증 | 기준선 CVE 3~5건 **규칙 자가 검증** 통과 | M8 제외 |
| M2 수정 유형 분류 | F-202 (P1) | **`fix_kind` P0**. `ADDED_GUARD` 만 이후 단계로 | v2.1 R2 |
| 도달성·상위 Guard 판정 | 있음/없음 | **3값**(`resolved`·`partial`·`unknown`), `unknown` 은 감점만 | v2.1 R3 |

### 0.3 실행 순서

```
collect → analyze → binder-path → root-cause → pattern → scan → prioritize → report
(독립) eval · dataset · index · dashboard        (P2) harness · verify
```

---

## 1. 디렉터리와 산출물

```
aosp1day/
├─ cli.py  pipeline.py  config.py  storage.py  schemas.py  llm.py
├─ llm_providers/anthropic.py          # LlmClient 구현체 (provider 확정 후)
├─ analysis/                           # [신규] 단계들이 공유하는 Tree-sitter 도구
│  ├─ javaast.py                       # JavaAst: 메서드·호출·if·clearCallingIdentity
│  ├─ security_apis.py                 # SecurityApiCatalog: Guard API 사전
│  ├─ sinks.py                         # SinkCatalog: 민감 동작 사전
│  ├─ aidl.py                          # AIDL ↔ Stub 매핑
│  ├─ index.py                         # CodeIndex: scan_paths 전체 인덱스 (M6)
│  └─ callgraph.py                     # CallGraph: 근사 호출 그래프 (M3·M6·M7)
├─ ruleengine/                         # [신규] 규칙 엔진
│  ├─ templates/missing_permission.scm
│  ├─ templates/uid_pkg_mismatch.scm
│  ├─ spec.py                          # Rule 로드·lint
│  └─ matcher.py                       # RuleMatcher (파일 모드 / 인덱스 모드)
├─ prompts/  root_cause.md  rule_params.md  candidate_review.md
├─ dataset.py                          # [신규] CVE 후보 목록 구축
├─ stages/  m01_collector.py … m11_evaluation.py   (m08_* 는 PIPELINE 제외)
└─ dashboard/app.py
config/
├─ security_apis.yaml                  # Guard 카탈로그
└─ sinks.yaml                          # Sink 카탈로그
rules/<CVE-ID>/<pattern_id>.scm, .yaml # 생성된 규칙 (config.rules_dir)
baselines/<CVE-ID>.json                # 수동 정답 (Baseline)
```

```
output/<CVE-ID>/
  cve.json                     M1
  patches/<hash>.diff          M1
  src/<hash>/before|after/...  M1
  patch_analysis.json          M2
  call_path.json               M3
  root_cause.json              M4 (+ prompts/root_cause.txt)
  pattern.json                 M5 (+ prompts/rule_params_<n>.txt)
  candidates.json              M6
  ranked_candidates.json       M7 (+ prompts/review_<id>.txt)
  labels.json                  대시보드 수동 라벨 (prioritize 재실행해도 유지)
  report.json/.md/.html        M9 (+ report_public.*)
  logs/<stage>.error.txt
output/_index/<revision>.json.gz   M6 인덱스 캐시
output/dataset.csv                 dataset
output/eval.json                   M11
```

---

## 2. 공통 모듈

### 2.1 `schemas.py`

PR #30의 `ArtifactMeta`, `CodeRef`, `LlmProvenance`, `Evidence`, `Claim`, `PatchCommit`, `CveRecord`, `Hunk`, `CallPathNode`, `CallPathEntry`, `CallPath`, `Baseline`, `Evaluation`은 **그대로** 쓴다. M8 관련(`TestCase` 등)도 지우지 않는다. 아래만 추가·수정한다. `SCHEMA_VERSION`은 `"0.4"`로 올린다.

```python
# --- M2: 패치가 추가한 Guard와 Sink 후보를 변경 단위로 보관 -----------------
@dataclass
class PatchChange:                       # 기존 필드 유지 + 3개 추가
    ...
    fix_kind: str = ""
        # [v2.1 R2] ADDED_GUARD | CONDITION_CHANGE | BYPASS | OTHER  (M2 classify_fix 가 결정)
        # ADDED_GUARD 만 M3 이후로 넘어간다. 나머지는 범위 밖 사유로 보고서에 남는다.
    added_guards: list[Evidence] = field(default_factory=list)
        # side="after". claim = Guard 유형(PERMISSION|UID|PACKAGE|APPOPS|CROSS_USER),
        # snippet = 추가된 검사 코드. "패치가 추가한 Guard"의 근거.
    sink_candidates: list[Evidence] = field(default_factory=list)
        # side="after". Guard 뒤에 오는 민감 호출 후보 (우선순위순, 최대 8개)

# --- M4: S·G·S 초안 -----------------------------------------------------------
@dataclass
class SgsDraft:
    change_id: str = ""                  # PatchChange.id
    pattern_type: str = ""               # missing_permission | uid_pkg_mismatch | cross_user(P1)
    source: Claim = field(default_factory=Claim)   # Binder 진입점. evidence = CallPathEntry 첫 노드
    guard: Claim = field(default_factory=Claim)    # evidence = added_guards 중 LLM이 고른 것
    sink: Claim = field(default_factory=Claim)     # evidence = sink_candidates 중 LLM이 고른 것

@dataclass
class RootCause:                         # 기존 필드 유지
    ...
    sgs: list[SgsDraft] = field(default_factory=list)   # [추가]
    # hypotheses 는 P2 (M8 복귀 시 사용)

# --- M5: 규칙 파라미터와 시도 기록 -----------------------------------------
@dataclass
class RuleParams:
    """LLM이 채우는 matcher 파라미터. rules/<CVE>/<pattern_id>.yaml 로 저장."""
    sink_calls: list[str] = field(default_factory=list)      # 메서드명 정규식. 예: "put\\w*"
    sink_receivers: list[str] = field(default_factory=list)  # 수신자 정규식. 예: "Settings\\.Secure"
    guard_types: list[str] = field(default_factory=list)     # PERMISSION 등
    guard_apis: list[str] = field(default_factory=list)      # security_apis.yaml 에 있는 이름만
    guard_args: list[str] = field(default_factory=list)      # 권한 이름. 비면 유형만 맞아도 인정
    guard_position: str = "before_sink"                      # before_sink | anywhere_in_path
    caller_depth: int = 1                                    # 진입점 → sink 메서드 최대 호출 깊이
    exclude_methods: list[str] = field(default_factory=list) # 예: "^dump$"

@dataclass
class RuleCheck:                         # 기존 3개 필드 유지 + 추가
    vulnerable_hits: int = 0
    patched_hits: int = 0
    passed: bool = False
    target_hit: bool = False             # [추가] before 히트 중 패치된 메서드가 있는가
    noise: int = 0                       # [추가] before 에서 타깃 외 히트 수 (참고용. B 계열에선 진짜 변종일 수 있음)
    control_hits: int = 0                # [v2.1 R1] 음성 대조군 히트 수: after 파일들에서 패치된 메서드를 뺀 히트
    errors: list[str] = field(default_factory=list)   # [추가] lint·컴파일 오류

@dataclass
class RuleAttempt:
    attempt: int = 0
    origin: str = "seed"                 # seed | llm
    params: RuleParams = field(default_factory=RuleParams)
    check: RuleCheck = field(default_factory=RuleCheck)
    feedback: str = ""                   # INVALID | MISSED_BEFORE | HIT_AFTER | TOO_BROAD + 상세
    llm: Optional[LlmProvenance] = None

@dataclass
class Pattern:                           # 기존 필드 유지 + 추가
    ...
    params: RuleParams = field(default_factory=RuleParams)     # [추가] 채택된 파라미터
    attempts: list[RuleAttempt] = field(default_factory=list)  # [추가]
    adopted: bool = False                                      # [추가] M6 사용 여부
    tags: list[str] = field(default_factory=list)              # [추가] seed_only | broad | llm_generalized

# --- M6·M7: 후보 ---------------------------------------------------------------
@dataclass
class ScoreReason:                       # 기존 필드 유지 + 추가
    binder_exposed: bool = False
    sensitive_sink: bool = False
    guard_missing: bool = False
    notes: str = ""
    sink_similarity: float = 0.0         # [추가] 같은 호출 1.0 / 같은 Sink 분류 0.6 / 정규식만 0.3
    path_length: int = 0                 # [추가] 진입점 → sink 메서드 호출 깊이
    other_guard_present: bool = False    # [추가] 요구 유형과 다른 검사가 경로에 있음
    reachability: str = "resolved"       # [v2.1 R3] resolved | partial | unknown (Candidate.reachability 복사)
    review_verdict: str = ""             # [추가] likely | unlikely | unsure | ""

@dataclass
class CandidateReview:
    """F-704. LLM 후보 검토. 확정 판정이 아니라 분석 초안."""
    verdict: str = ""                    # likely | unlikely | unsure
    reasoning: str = ""
    evidence: list[Evidence] = field(default_factory=list)   # 실제 줄과 대조 통과한 것만
    grounded: bool = False               # 근거가 하나라도 대조 실패하면 False, verdict="unsure"
    status: Status = "inferred"
    llm: LlmProvenance = field(default_factory=LlmProvenance)

@dataclass
class RetroMatch:
    """F-1106. 이후 공개된 패치와 후보의 일치."""
    later_cve: str = ""
    patch_commit: str = ""
    level: str = ""                      # file | method | guard (guard 만 성공으로 집계)

@dataclass
class Candidate:                         # 기존 필드 유지 + 추가
    id: str = ""                         # sha1(pattern_id + method + sink 줄)[:12]
    pattern_id: str = ""
    location: CodeRef = field(default_factory=CodeRef)    # side="aosp", sink 호출 위치
    matched: dict[str, CodeRef] = field(default_factory=dict)   # "source" / "sink"
    score: float = 0.0
    score_reason: ScoreReason = field(default_factory=ScoreReason)
    label: str = "unreviewed"            # unreviewed | tp | fp | hold
    public: bool = False
    call_path: list[CodeRef] = field(default_factory=list)      # [추가] 진입점 → sink 메서드
    missing_guard: str = ""                                     # [추가] 요구 Guard 유형
    present_guards: list[Evidence] = field(default_factory=list)  # [추가]
    filters: dict[str, str] = field(default_factory=dict)       # [추가] 필터명 → pass | unknown | 탈락 사유
    reachability: str = "resolved"
        # [v2.1 R3] 진입점 → sink 경로와 상위 caller 탐색이
        # resolved = 해석 못 한 간선 없이 끝남 / partial = 경로는 찾았지만 주변에 unresolved 간선 있음 /
        # unknown = 경로를 unresolved 간선 때문에 확정 못 함
    review: Optional[CandidateReview] = None                    # [추가] M7
    retro: Optional[RetroMatch] = None                          # [추가] M11

@dataclass
class Labels:
    """대시보드에서 단 수동 라벨. prioritize 를 다시 돌려도 유지된다."""
    meta: ArtifactMeta = field(default_factory=ArtifactMeta)
    cve_id: str = ""
    labels: dict[str, str] = field(default_factory=dict)   # Candidate.id → tp | fp | hold
    notes: dict[str, str] = field(default_factory=dict)
    ARTIFACT = "labels.json"
```

### 2.2 `storage.py` — `Store`

기존 `path`, `exists`, `save`, `load`, `save_text`는 그대로 쓰고, 아래만 추가한다.

| 메서드 | 역할 |
| --- | --- |
| `load_optional(cls) -> T \| None` | 없으면 None (대시보드·Reporter에서 일부 단계만 있을 때) |
| `has_all(paths: list[str]) -> bool` | Collector 캐시 검사용. diff·before·after 실제 존재 확인 |
| `save_public(obj, mask: Callable) -> Path` | `<artifact>_public.json` 저장 (F-904) |
| `list_cves(output_root) -> list[str]` (static) | `*/cve.json` 이 있는 디렉터리 (D-1) |

### 2.3 `config.py`

`Config`, `LlmConfig`, `DeviceConfig`(P2라 그대로 둠)는 유지하고, 아래를 추가한다.

```python
@dataclass
class RuleConfig:
    max_attempts: int = 3            # LLM 재생성 최대 횟수 (seed 제외)
    max_noise: int = 5               # 초과하면 채택은 하되 tags 에 "broad" (참고용)
    max_control_hits: int = 5        # [v2.1 R1] LLM 시도의 control_hits 가 넘으면 TOO_BROAD 실패
    max_scan_hits: int = 50          # [v2.1 R1] M6 에서 패턴 하나의 Match 수가 넘으면 seed 로 되돌림
    security_apis: Path = Path("config/security_apis.yaml")
    sinks: Path = Path("config/sinks.yaml")

@dataclass
class ScanConfig:
    aosp_revision: str = ""          # 스캔할 frameworks/base 커밋·태그. 비면 aosp_root HEAD
    index_cache: Path = Path("output/_index")
    top_n: int = 20                  # F-702
    review_top_k: int = 20           # F-704 LLM 검토 대상 수
    weights: dict[str, float] = field(default_factory=lambda: {
        "sink_similarity": 0.3, "path": 0.2, "guard_absence": 0.3, "review": 0.2})

@dataclass
class Config:                        # 기존 필드 유지
    ...
    rule: RuleConfig = field(default_factory=RuleConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
```

### 2.4 `llm.py`

인터페이스(`LlmClient.generate_structured`, `provenance`, `get_client`)는 그대로 둔다.

| 위치 | 이름 | 역할 |
| --- | --- | --- |
| `llm.py` | `render_prompt(name: str, **vars) -> str` | `prompts/<name>.md` 를 채움 |
| `llm.py` | `call_structured(client, store, name, prompt, schema, retries=2) -> tuple[dict, LlmProvenance]` | 프롬프트를 `output/<CVE>/prompts/<name>.txt` 에 저장한 뒤 호출. `jsonschema` 검증 실패 시 오류 문구를 붙여 재요청 (F-404) |
| `llm_providers/anthropic.py` | `AnthropicClient(LlmClient)` | `generate_structured` 구현. tool-use로 JSON 강제, `temperature=0` |
| `llm.py` | `get_client(config)` | `provider` 이름으로 구현체 반환 (기존 시그니처 유지) |

LLM 출력은 항상 "번호로 고르기"를 우선한다. M4는 Guard·Sink 후보 번호를 고르고, M5는 카탈로그에 있는 API 이름만 쓸 수 있으며, M7은 제공된 줄 번호만 근거로 인정한다. 없는 메서드나 호출을 LLM이 지어내도 다음 단계로 넘어가지 못하게 하려는 장치다.

**[v2.1 R5] LLM 이 결정하지 않는 것.** 규칙 채택(M5 `self_check` 통과 여부), 후보 탈락(M7 필터), 라벨(사람)은 코드나 사람만 정한다. LLM 결과가 바꿀 수 있는 값은 M4 의 S·G·S 선택(코드 대조 후), M5 의 규칙 파라미터 초안(검증 통과 시에만 사용), M7 의 `review_verdict`(점수의 `review` 항, 가중치 0.2) 세 가지뿐이다. 따라서 LLM 을 꺼도(`--no-review`, seed 만 사용) 파이프라인은 같은 형식의 결과를 낸다.

**[v2.2] LLM 검증 계층.** 호출 지점별 검증 계층(M4 표본 일치도, M7 질문 분해·`derive_verdict`·교차 모델 비판), 재현성·호출 상한, LLM 효과 비교 실험과 근거 문헌은 [llm-verification.md](llm-verification.md)에 둔다. 이에 따른 스키마·설정 추가분(`SgsDraft.agreement`, `ReviewAnswer`, `Critique`, `CandidateReview.answers`, `LlmConfig.consistency_samples`·`critic_*`·`max_calls_per_cve`)은 그 문서 6절을 따른다. 우선순위: 질문 분해·근거 대조·코드 판정은 **P0**, 표본 일치도·비판자·비교 실험은 **P1**, 라벨 기억은 **P2**.

### 2.5 `analysis/` — 공유 Tree-sitter 도구

#### `javaast.py`

```python
@dataclass
class MethodNode:
    fqn: str              # 'com.android.server.foo.FooService$BinderService.setBar(int)'
    cls: str; name: str
    param_types: list[str]; modifiers: set[str]; annotations: list[str]
    superclass: str | None
    start_line: int; end_line: int
    node: Node

@dataclass
class CallNode:  name: str; receiver: str | None; args: list[str]; line: int; node: Node
@dataclass
class IfNode:    cond: str; line: int; exits: bool; node: Node   # then 이 throw/return 으로 끝나는가

class JavaAst:
    def __init__(self, src: str, file: str)
    def methods(self) -> list[MethodNode]
    def method_at(self, line: int) -> MethodNode | None
    def calls(self, scope: Node | None = None) -> list[CallNode]
    def ifs(self, scope: Node | None = None) -> list[IfNode]
    def fields(self) -> dict[str, str]                   # 필드명 → 타입
    def clear_identity_ranges(self, m: MethodNode) -> list[tuple[int, int]]
    def to_coderef(self, start: int, end: int, revision: str, side: str,
                   patch_commit: str = "") -> CodeRef     # snippet 자동 채움
```

#### `security_apis.py` — `SecurityApiCatalog`

```yaml
# config/security_apis.yaml (초안)
PERMISSION:
  calls: [enforceCallingOrSelfPermission, enforceCallingPermission, checkCallingOrSelfPermission,
          checkCallingPermission, enforcePermission, checkPermission]
  call_regex: '\w+_enforcePermission'     # [v2.1 R4] @EnforcePermission 이 생성한 헬퍼 호출
  annotations: [EnforcePermission]        # [v2.1 R4] RequiresPermission 은 문서용(강제 안 함)이라 제외
  arg_regex: '(android\.)?Manifest\.permission\.\w+|"android\.permission\.\w+"'
UID:
  calls: [isSystemUid, enforceSystemOrRoot, isCallerSystem]
  cond_regex: 'Binder\.getCallingUid\(\)|callingUid|Process\.\w+_UID'
PACKAGE:
  calls: [checkPackage, getPackageUid, verifyCallingPackage, enforceCallingPackage, isSameApp]
APPOPS:
  calls: [noteOp, noteOpNoThrow, checkOp, checkOpNoThrow, startOp]
  receiver_regex: 'AppOps|mAppOps'
CROSS_USER:
  calls: [handleIncomingUser, enforceCrossUserPermission]
  arg_regex: 'INTERACT_ACROSS_USERS(_FULL)?'
  cond_regex: 'UserHandle\.getCallingUserId\(\)|getCallingUserId\(\)'   # [v2.1 R4] if (userId != 호출자) throw
identity_dependent:       # [v2.1 R4] 호출자 신원(Binder calling uid/pid)에 기대는 검사.
  calls: [enforceCallingPermission, checkCallingPermission, enforceCallingOrSelfPermission,
          checkCallingOrSelfPermission, handleIncomingUser, isCallerSystem]
  cond_regex: 'Binder\.getCalling(Uid|Pid)\(\)|getCallingUserId\(\)'
  # clearCallingIdentity ~ restoreCallingIdentity 구간 안에 있으면 호출자가 system 으로 바뀌어
  # 항상 통과하므로 Guard 로 세지 않는다. (구간 밖에서 미리 읽어 둔 callingUid 변수 비교는 인정)
pattern_type:            # Guard 유형 → 패턴 유형
  PERMISSION: missing_permission
  APPOPS: missing_permission
  UID: uid_pkg_mismatch
  PACKAGE: uid_pkg_mismatch
  CROSS_USER: cross_user
```

| 메서드 | 역할 |
| --- | --- |
| `load(path) -> SecurityApiCatalog` (classmethod) | |
| `match_call(c: CallNode) -> str \| None` | Guard 유형 또는 None |
| `match_if(i: IfNode) -> str \| None` | 조건식이 UID·CROSS_USER 비교이고 then 이 throw/return 이면 유형 |
| `match_annotation(name: str) -> str \| None` | |
| `guards_in(ast, m, before_line=None) -> list[tuple[str, int, str]]` | 메서드 안 Guard 전부 (유형, 줄, 코드). **[v2.1 R4]** `identity_dependent` 이고 `ast.clear_identity_ranges(m)` 안에 있는 것은 빼고, 대신 `ignored_guards` 로 따로 반환 |
| `is_identity_dependent(c_or_if) -> bool` | **[v2.1 R4]** |
| `pattern_type_of(guard_type) -> str` | |
| `api_names(types) -> set[str]` | M5 lint 에서 LLM이 쓴 API 이름 검사 |

M2의 `detect_permission_apis`(F-203), M5 matcher, M6 인덱스, M7 필터가 모두 이 카탈로그 하나를 쓴다.

#### `sinks.py` — `SinkCatalog`

```yaml
# config/sinks.yaml (초안)
SETTINGS_WRITE:    { receiver: 'Settings\.(Secure|Global|System)', call: 'put\w*' }
CROSS_USER_ACCESS: { call: '\w+AsUser|\w+ForUser' }
PACKAGE_STATE:     { receiver: 'mPm|mPackageManager\w*', call: 'set\w+|install\w*|delete\w*' }
ACTIVITY_START:    { call: 'startActivity\w*|sendBroadcast\w*' }
PERSIST_WRITE:     { call: 'write\w*Locked|save\w*Locked|schedulePersist\w*' }
```

| 메서드 | 역할 |
| --- | --- |
| `categorize(c: CallNode) -> str \| None` | Sink 분류 |
| `rank(ast, m, after_line) -> list[CallNode]` | 우선순위: clearCallingIdentity 블록 안 > 카탈로그 일치 > 다른 서비스 필드 호출 > 나머지 |

#### `aidl.py`

| 이름 | 역할 |
| --- | --- |
| `parse_aidl(paths) -> dict[str, set[str]]` | 인터페이스 FQN → 메서드명 (정규식 수준 파싱) |
| `StubMap.build(java_asts, aidl) -> StubMap` | `extends I\w+\.Stub` 클래스 ↔ 인터페이스 |
| `StubMap.is_entry(m: MethodNode) -> bool` | Stub 구현 클래스의 public non-static 메서드이고 AIDL 메서드명과 일치 |
| `StubMap.interface_of(cls) -> str \| None` | |

#### `index.py` — `CodeIndex`, `CodeIndexer` (M6)

```python
@dataclass
class MethodInfo:
    fqn: str; cls: str; name: str; file: str
    start_line: int; end_line: int
    modifiers: list[str]; annotations: list[str]
    calls: list[tuple[str, str | None, int]]          # (이름, 수신자, 줄)
    guards: list[tuple[str, int, str]]                # SecurityApiCatalog.guards_in 결과
    clear_identity: list[tuple[int, int]]
    is_entry: bool = False
    aidl_interface: str = ""

class CodeIndex:
    revision: str
    methods: dict[str, MethodInfo]
    classes: dict[str, ClassInfo]                     # superclass, fields, file
    def by_class(self, cls) -> list[MethodInfo]
    def resolve(self, cls, name, arity) -> list[MethodInfo]
    def snippet(self, fqn) -> CodeRef                 # side="aosp"

class CodeIndexer:
    def __init__(self, config: Config, catalog: SecurityApiCatalog)
    def build(self, aosp_root: Path, revision: str, workers: int = 8) -> CodeIndex
    def load_or_build(self, aosp_root, revision) -> CodeIndex   # output/_index/<rev>.json.gz
```

#### `callgraph.py` — `CallGraph`

타입 추론 없이 근사 그래프를 만든다. 이 한계와 미해결 비율은 보고서 한계 항목에 적는다.

| 메서드 | 역할 |
| --- | --- |
| `build(index) -> CallGraph` (classmethod) | 간선 규칙: 수신자 없음/`this.` → 같은 클래스·바깥 클래스의 같은 이름·인자 수, `mField.foo()` → 필드 타입이 인덱스에 있으면 그 클래스, `Outer.this.foo()` → 바깥 클래스. 나머지는 unresolved |
| `build_file(ast) -> CallGraph` (classmethod) | 파일 하나 안에서만 (M3 P0, M5 자가 검증) |
| `callees(fqn) -> list[tuple[str, int]]` | (피호출, 호출 줄) |
| `callers(fqn) -> list[tuple[str, int]]` | |
| `paths_from(fqn, depth) -> Iterator[list[str]]` | DFS, 순환 방지 |
| `paths_to(fqn, depth) -> Iterator[list[str]]` | |
| `unresolved_callers(fqn) -> list[tuple[str, int]]` | **[v2.1 R3]** 수신자를 해석 못 했지만 **이름·인자 수가 같은** 호출 지점 (이름 기반 근사). 인터페이스·Handler·람다 경유 호출이 여기 걸린다 |
| `reach(entries, fqn, depth) -> Reach` | **[v2.1 R3]** `Reach(status, path, unresolved_edges)`. 해석된 간선만으로 경로가 있고 주변에 unresolved 없음 → `resolved`, 경로는 있으나 경로 위 메서드에 `unresolved_callers` 있음 → `partial`, 해석된 경로는 없고 `unresolved_callers` 만 있음 → `unknown`, 둘 다 없음 → `none` |
| `unresolved_ratio() -> float` | |

**[v2.1 R3] 3값 원칙.** 해석 못 한 간선을 "경로 없음"이나 "Guard 없음"으로 바꾸지 않는다. `unknown` 은 필터에서 탈락시키지 않고 점수에서만 감점하며, 대시보드에 그대로 표시한다. 이 근사가 막히면(예: `unresolved_ratio` 가 0.5 이상) 대안은 Joern 같은 CPG 도구지만, 일정상 최후의 수단으로만 검토한다.

---

## 3. M1 Collector — `collect` (나연)

`reads=()`, `writes=("cve.json",)` + `patches/`, `src/`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | `is_cached` 면 건너뜀, 아니면 `collect` → `save_sources` → 저장 |
| `collect(source) -> CveRecord` | 유지 | CVE ID 면 OSV에서 수정 커밋 조회, URL·해시면 바로 수집 (F-101) |
| `parse_security_bulletin(cve_id) -> dict` | 유지 (P1) | ASB 표에서 type·severity·versions (F-102) |
| `fetch_patch_metadata(commit_url) -> PatchCommit` | 유지 | Gitiles `?format=JSON`: parent, message, authored_at, changed_files (F-103) |
| `save_sources(commit, store)` | 유지 | diff 와 변경 `.java` 의 before(parent)·after 원본 저장, 경로 기록 (F-104) |
| `handle_edge_cases(source, record)` | 유지 (P1) | 깨진 링크, 비공개 버그, 여러 브랜치 커밋 → `notes` (F-105) |
| `is_cached(ctx) -> bool` | 유지 | `Store.has_all` 로 diff·before·after 실제 확인 (F-106) |
| `in_scope(path) -> bool` | **추가** | `config.scan_paths` 매칭, test 경로 제외 |

보조 클래스 (`stages/m01_collector.py` 안 또는 `aosp1day/sources/`):

| 클래스 | 메서드 | 역할 |
| --- | --- | --- |
| `OsvClient` | `sync_dump() -> Path` | OSV Android 덤프 zip 을 `output/_cache/osv/` 에 받음. OSV ID가 `ASB-A-*` 이고 CVE는 alias 라서 로컬 색인이 필요 |
| | `lookup(cve_id) -> dict \| None` | CVE → OSV 레코드 |
| | `fix_commits(record) -> list[str]` | `references[type=FIX]`, `affected[].ranges[].events[fixed]` |
| `GitilesClient` | `parse_url(url) -> tuple[str, str]` (static) | `(repo, hash)` |
| | `get_commit(repo, hash) -> dict` | `/+/<hash>?format=JSON` (앞의 `)]}'` 제거) |
| | `get_diff(repo, hash) -> str` | `/+/<hash>%5E%21/?format=TEXT` base64 디코드 |
| | `get_file(repo, rev, path) -> str \| None` | `/+/<rev>/<path>?format=TEXT` |
| | `_get(url) -> bytes` | 재시도 3회, 요청 간격 제한, URL 키 디스크 캐시 |
| `AsbClient` (P1) | `fetch(month)`, `parse(html)`, `find(cve_id, hint_month)` | |

`aosp1day/dataset.py` (CLI `dataset`):

| 함수 | 역할 |
| --- | --- |
| `build_dataset(years=(2023, 2025)) -> list[DatasetRow]` | OSV 덤프에서 Framework/System 중 수정 커밋 공개된 CVE |
| `prefilter(row, gitiles, catalog) -> str` | diff `+` 줄에 Guard 카탈로그 API가 있는지로 Guard 유형 1차 분류 |
| `export_csv(rows, path)` | `output/dataset.csv`. 팀이 기준선 3~5건과 회고 검증용 세트를 고름 |

---

## 4. M2 Patch Analyzer — `analyze` (현아)

`reads=("cve.json",)`, `writes=("patch_analysis.json",)`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | 커밋마다 `analyze_commit`, `baseline` 인자가 있으면 비교 |
| `analyze_commit(commit, store_dir) -> list[PatchChange]` | 유지 | |
| `split_hunks(diff_path) -> list[Hunk]` | 유지 | hunk 별 before·after `CodeRef` (before.revision=parent, after.revision=patch) |
| `extract_changed_units(hunk, before_src, after_src) -> PatchChange` | 유지 | `JavaAst.method_at` 으로 클래스·메서드 식별 (F-201) |
| `classify_change(change) -> str` | 유지 (P1) | permission_check / input_validation / condition / exception / other (F-202) |
| `detect_permission_apis(change) -> list[str]` | 유지 | 추가·삭제된 Guard API 이름 (F-203). `SecurityApiCatalog` 사용 |
| `classify_fix(change, before_ast, after_ast) -> str` | **추가 (P0, v2.1 R2)** | 아래 규칙으로 `fix_kind` 결정. `find_added_guards` 보다 먼저 실행 |
| `find_added_guards(change, after_ast) -> list[Evidence]` | **추가** | after 메서드에서 `+` 줄에 걸친 호출·if·어노테이션 중 카탈로그 일치 → `Evidence(side="after", claim=<유형>)`. **`fix_kind == "ADDED_GUARD"` 일 때만** 채운다 |
| `find_sink_candidates(change, after_ast) -> list[Evidence]` | **추가** | Guard 줄 이후 호출을 `SinkCatalog.rank` 로 정렬, 최대 8개. Sink 가 같은 파일의 private 메서드 안이면 한 단계 따라감 |
| `compare_with_baseline(analysis, baseline_path) -> float` | 유지 (P1) | 변경 메서드 일치율 (F-204) |
| `load_baseline(path) -> Baseline` | 유지 | |

`added_guards` 가 빈 변경은 "Guard를 추가하지 않은 패치"(입력 길이 검증 등)라 이후 단계에서 빠진다. 이것이 도구 범위 밖이라는 근거로 보고서에 남는다.

**[v2.1 R2] `classify_fix` 판정 규칙.** 변경 메서드마다 `G_b = guards_in(before)`, `G_a = guards_in(after)` 의 **유형 집합**을 비교한다.

| 순서 | 조건 | `fix_kind` | 이후 |
| --- | --- | --- | --- |
| 1 | diff 가 `writeToParcel`·`createFromParcel`·`readFromParcel`·`Parcel`/`Bundle` 읽기·쓰기 API 를 주로 바꿈 | `BYPASS` | 범위 밖 (Parcel·Bundle 불일치 계열. P2 확장 후보) |
| 2 | `G_a − G_b` 가 비어 있지 않음 (패치 후에만 있는 Guard 유형) | `ADDED_GUARD` | M3 이후 진행 |
| 3 | `G_a == G_b` 이고 비어 있지 않음, 그런데 Guard 가 걸린 `if` 조건·인자·위치가 바뀜 | `CONDITION_CHANGE` | 범위 밖. 패치 전 코드에도 Guard 호출이 있어 "누락" 규칙으로 전·후를 구분할 수 없음 |
| 4 | 그 외 | `OTHER` | 범위 밖 |

같은 유형의 Guard 가 before 에 **다른 경로에만** 있고 after 에 패치된 경로로 옮겨진 경우는 2번(`ADDED_GUARD`)으로 본다(메서드 단위 비교이므로 자연히 그렇게 된다). 판정 결과와 이유는 `PatchChange.notes` 에 남기고, 대시보드 개요 탭과 보고서 "한계"에 "이 CVE 는 조건 변경형이라 탐지 범위 밖" 식으로 보여준다. 기준선 CVE 를 고를 때 이 판정을 먼저 돌려 `ADDED_GUARD` 인 것만 쓴다(§14).

---

## 5. M3 Binder Path Analyzer — `binder-path`

`reads=("patch_analysis.json",)`, `writes=("call_path.json",)`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | `added_guards` 가 있는 변경만 대상 |
| `map_aidl_to_impl(aosp_root) -> dict[str, str]` | 유지 | `aidl.parse_aidl` + `StubMap` (F-301). `config.scan_paths` 의 `.aidl` 사용 |
| `find_paths(change, aidl_map, aosp_root) -> list[CallPathEntry]` | 유지 | after 소스 파일에서 `CallGraph.build_file` → `paths_to(변경 메서드)` 중 진입점에서 시작하는 경로. P0는 같은 서비스 클래스 안까지, 못 찾으면 `unresolved` (F-302) |
| `check_reachability(entry, aosp_root)` | 유지 (P1) | `ServiceManager.addService`·`publishBinderService` 등록 여부 (F-303) |
| `to_diagram(call_path) -> str` | 유지 (P2) | mermaid 텍스트 (F-304) |

---

## 6. M4 Root Cause Analyzer — `root-cause` (현아, LLM)

`reads=("patch_analysis.json", "call_path.json")`, `writes=("root_cause.json", "prompts/root_cause.txt")`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | |
| `build_prompt(analysis, call_path) -> str` | 유지 | `prompts/root_cause.md` 에 hunk, 진입점 경로, **번호 붙인** `added_guards`·`sink_candidates` 를 넣음 |
| `infer(client, prompt, analysis) -> RootCause` | 유지 | `call_structured(..., ROOT_CAUSE_SCHEMA)`. 근본 원인·발생 조건·보안 불변식 (F-401·402) |
| `attach_evidence(claim, analysis) -> Claim` | 유지 | LLM이 든 근거를 실제 hunk 와 대조, 없는 위치는 버림. 근거 0개면 "근거 없음" 표시 (F-403) |
| `validate_schema(raw, max_retry=2) -> RootCause` | 유지 | (F-404) |
| `structure_sgs(raw, analysis, call_path) -> list[SgsDraft]` | **추가** | LLM 응답의 `guard_index`·`sink_index` 로 실제 `Evidence` 를 꺼내 S·G·S 구성. 범위 밖 번호면 그 변경은 `sgs` 에서 빠지고 `notes` 에 기록. `pattern_type` 은 Guard 유형에서 결정 (LLM이 정하지 않음) |

```json
// ROOT_CAUSE_SCHEMA 의 LLM 출력 (요약)
{
  "root_cause": {"text": "...", "evidence": [{"change_id": "chg-1", "side": "before", "start_line": 120, "end_line": 124}]},
  "trigger_conditions": [{"text": "...", "evidence": [...]}],
  "security_invariant": {"text": "Secure 설정 쓰기 전에 WRITE_SECURE_SETTINGS 검사가 있어야 한다", "evidence": [...]},
  "sgs": [{"change_id": "chg-1", "guard_index": 0, "sink_index": 2}]
}
```

결과는 전부 `status="inferred"` 이다.

---

## 7. M5 Pattern / Rule Generator — `pattern` (LLM 초안 + 결정적 검증)

`reads=("root_cause.json", "patch_analysis.json", "call_path.json")`, `writes=("pattern.json",)` + `rules/<CVE>/`

### 7.1 Stage 메서드

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | 패턴마다 `adopt_rule` |
| `extract_patterns(root_cause, analysis) -> list[Pattern]` | 유지 | `SgsDraft` → `Pattern` (source·guard·sink `PatternElement`, invariant, `derived_from`) (F-501) |
| `seed_params(pattern) -> RuleParams` | **추가** | **LLM 없이** 패턴을 그대로 옮김. sink = 정확한 호출명, guard = 같은 유형의 카탈로그 API 전체 |
| `draft_params(client, pattern, prev, feedback) -> tuple[RuleParams, LlmProvenance]` | **추가** | `prompts/rule_params.md`: 파라미터 의미, 예시 2개, 이전 파라미터, 피드백. 일반화 방향을 고정한다 — sink 는 같은 의미의 호출 계열까지(`putString` → `put\w*`), guard 는 같은 유형의 다른 API 허용, 변수·필드명 고정 금지 |
| `to_rule(pattern, params, rules_dir) -> Path` | 유지 (시그니처에 params 추가) | `templates/<type>.scm` 복사 + `params` 를 `.yaml` 로 저장 (F-503) |
| `self_check(rule_path, analysis, store_dir, origin) -> RuleCheck` | 유지 (v2.1 변경) | before·after 파일에 `RuleMatcher.match_file`. `target_hit` = before 히트 중 패치된 메서드 존재. `control_hits` = **after** 파일들의 히트 중 패치된 메서드가 아닌 것의 수. `passed = target_hit and 패치된 메서드의 after 히트 0 and (origin == "seed" or control_hits <= max_control_hits)` (F-504) |
| `feedback(check, pattern) -> str` | **추가** | 우선순위 `INVALID` → `MISSED_BEFORE` → `HIT_AFTER` → `TOO_BROAD`, 문제 히트 최대 5개 첨부. `TOO_BROAD` 에는 대조군 히트 메서드 이름을 붙여 "이 메서드들은 잡지 않도록 좁혀라" 로 전달 |
| `adopt_rule(ctx, client, pattern) -> Pattern` | **추가** | 아래 루프 |
| `split_overfit(pattern) -> Pattern` | 유지 (P1) | (F-505) |

### 7.2 채택 루프 (`adopt_rule`)

1. 시도 0: `seed_params` 로 규칙을 만들고 `self_check`. 실패하면 패턴 자체가 잘못된 것이므로 `adopted=False` 로 끝낸다.
2. 시도 1~`max_attempts`: `draft_params(이전 파라미터, 피드백)` → `spec.lint` → `to_rule` → `self_check`. 처음 통과한 것을 채택하고 `llm_generalized` 태그를 단다.
3. LLM 시도가 모두 실패하면 seed 를 채택하고 `seed_only` 태그를 단다. seed 는 정확한 호출명에 묶여 있어 변종 탐지 범위가 좁다는 뜻이다.
4. 채택 규칙의 `noise > max_noise` 면 `broad` 태그를 추가한다(참고용).

**[v2.1 R1] 왜 음성 대조군인가.** "패치 전 탐지·후 미탐지"만으로는 규칙의 **넓이**를 제한할 수 없다. 예를 들어 "Guard 없이 `put\w*` 를 부르는 모든 메서드"로 넓혀도 패치된 메서드는 after 에 Guard 가 있으니 통과한다. 그래서 after 파일(모든 수정 위치에 Guard 가 들어간 상태)에서 패치된 메서드 **밖** 히트 수에 예산을 둔다. 대조군 히트가 진짜 변종일 수도 있으므로 0 이 아니라 예산(`max_control_hits`)으로 두고, 히트 목록은 `RuleCheck` 와 대시보드 D-5 에 남긴다. seed 는 정확한 호출명이라 넓어질 수 없으므로 예산을 적용하지 않는다.

`before` 쪽 `noise` 는 벌점으로 쓰지 않는다. B 계열(한 CVE 가 여러 위치를 고친 경우)에서는 before 의 타깃 외 히트가 바로 다른 수정 위치, 즉 정답이기 때문이다.

모든 시도는 `Pattern.attempts` 에 남아 대시보드 D-5 에서 보인다. 규칙 채택률 = `adopted 패턴 수 / 전체 패턴 수`.

### 7.3 `ruleengine/`

`templates/*.scm` 은 패턴 유형별로 고정이고, CVE마다 바뀌는 건 `.yaml` 파라미터뿐이다.

```scheme
; templates/missing_permission.scm — 메서드와 그 안의 호출을 잡는다. 판정은 matcher 가 한다.
(method_declaration
  (modifiers)? @mods
  name: (identifier) @method
  body: (block) @body)
(method_invocation
  object: (_)? @receiver
  name: (identifier) @call) @invocation
```

| 위치 | 이름 | 역할 |
| --- | --- | --- |
| `spec.py` | `Rule` (dataclass) | `type`, `scm_path`, `params: RuleParams` |
| | `load_rule(path) -> Rule` | `.scm` + `.yaml` |
| | `lint(params, catalog) -> list[str]` | 정규식 컴파일, sink 비어 있음, `.*` 전체 매칭, 카탈로그에 없는 guard API, `caller_depth > 3` |
| `matcher.py` | `Match` (dataclass) | `entry`, `sink_method`, `sink_line`, `sink_call`, `path`, `missing_guard`, `present_guards` |
| | `RuleMatcher(catalog, sinks)` | |
| | `match_file(rule, ast, stub_map) -> list[Match]` | 파일 모드 (M5 자가 검증) |
| | `match_index(rule, index, cg) -> list[Match]` | 인덱스 모드 (M6) |
| | `_is_sink(rule, call) -> bool` | `sink_calls`·`sink_receivers` 정규식 |
| | `_guarded(rule, path, sink_line, guards_of) -> tuple[bool, list]` | |

`_match` 판정 순서 (두 모드 공통):

1. 진입점 `e` 마다 `paths_from(e, caller_depth)` 로 경로를 구한다.
2. 경로 끝 메서드의 호출 중 `_is_sink` 가 참인 것을 찾는다.
3. 경로 위 각 메서드에서 Guard 를 모은다. `before_sink` 면 다음 호출 지점(끝 메서드는 sink 줄) 이전 줄만 인정한다.
4. 모은 Guard 가 `guard_types`·`guard_apis`·`guard_args` 를 만족하지 않고 `exclude_methods` 에 걸리지 않으면 `Match` 를 만든다. 다른 유형 Guard 는 `present_guards` 에 남긴다.
5. `(pattern_id, sink_method, sink_line)` 으로 중복을 없애고 가장 짧은 경로를 남긴다.

---

## 8. M6 Scanner — `scan`

`reads=("pattern.json",)`, `writes=("candidates.json",)`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | `adopted=True` 패턴만 스캔 |
| `aosp_revision(aosp_root) -> str` | 유지 | `config.scan.aosp_revision` 또는 `git rev-parse HEAD` |
| `load_index(ctx) -> tuple[CodeIndex, CallGraph]` | **추가** | `CodeIndexer.load_or_build` + `StubMap` 으로 `is_entry` 표시 + `CallGraph.build` |
| `scan(pattern, aosp_root) -> CandidateSet` | 유지 | `RuleMatcher.match_index` → `to_candidate` (F-601) |
| `enforce_budget(pattern, matches) -> tuple[RuleParams, list[Match]]` | **추가 (v2.1 R1)** | `llm_generalized` 패턴의 Match 수가 `max_scan_hits` 를 넘으면 seed 파라미터로 다시 스캔하고 `tags` 에 `broad_fallback` 추가. seed 도 넘으면 그대로 두고 `stats` 에 경고 |
| `to_candidate(m: Match, pattern, index) -> Candidate` | **추가** | `location`(sink, side="aosp"), `matched["source"/"sink"]`, `call_path`, `missing_guard`, `present_guards`, **`reachability`**(`CallGraph.reach` 결과) 채움. `public=False` |
| `exclude_origin(cands, pattern, analysis) -> list[Candidate]` | **추가** | 원본 CVE 가 고친 메서드와 같은 FQN 은 제외. 스캔 리비전이 패치 이전이면 제외하지 않고 `notes="origin"` (통합 테스트용) |
| `dedup(candidates) -> CandidateSet` | 유지 (P1) | 같은 sink 메서드·같은 원인 병합 (F-602) |
| `scan_incremental(pattern, subdir) -> CandidateSet` | 유지 (P2) | (F-603) |

`CandidateSet` 에 `stats: dict`(파일·메서드·진입점 수, 패턴별 히트, `unresolved_ratio`, 소요 초)를 추가한다.

---

## 9. M7 Prioritizer — `prioritize` (필터 + 점수 + LLM 검토)

`reads=("candidates.json", "pattern.json", "patch_analysis.json")`, `writes=("ranked_candidates.json",)`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `run(ctx)` | 유지 | 필터 → 점수 → 상위 K 검토 → 재점수 → `rank` → `labels.json` 병합 |
| `apply_filters(cands, index, cg) -> list[Candidate]` | **추가** | 아래 필터. 탈락해도 지우지 않고 `filters` 에 사유를 남김 (F-705) |
| `explain(candidate) -> ScoreReason` | 유지 | |
| `score(reason, weights) -> float` | 유지 | 아래 식 (F-701) |
| `review(client, candidate, pattern, analysis, index) -> CandidateReview` | **추가** | `prompts/candidate_review.md`: 원본 diff, 패턴 S·G·S, 후보 경로 메서드 본문(줄 번호 포함), 발견된 Guard. 질문은 세 가지로 고정 — Guard 가 정말 없는가, 다른 형태의 검사가 있는가, 일반 앱이 도달 가능한가 (F-704) |
| `derive_verdict(answers) -> str` | **추가 (v2.2, P0)** | 질문별 답(`q_guard`·`q_alt_check`·`q_reach`)에서 코드 규칙으로 `likely`/`unlikely`/`unsure` 계산. LLM 의 전체 판정은 받지 않음 ([llm-verification.md](llm-verification.md) 3.3) |
| `critique(critic, candidate, review) -> Critique` | **추가 (v2.2, P1)** | `likely` 후보만. 반박 근거가 대조를 통과하면 `unsure` 로 낮춤 |
| `ground_review(raw, candidate, index) -> CandidateReview` | **추가** | 근거 줄이 제공한 메서드 범위 안 실제 줄인지 확인. 하나라도 아니면 `grounded=False`, `verdict="unsure"` |
| `rank(candidates, top_n, weights) -> RankedCandidates` | 유지 | (F-702) |
| `apply_label(candidate, label) -> Candidate` | 유지 (P1) | `labels.json` 에서 읽어 반영 (F-703) |

필터 (`stages/m07_filters.py`, 시그니처 `(cand, index, cg, config) -> str` — `"pass"`, `"unknown"`, 또는 탈락 사유):

| 함수 | 탈락 조건 | `unknown` (탈락 안 함, v2.1 R3) |
| --- | --- | --- |
| `f_guard_in_callers` | 해석된 상위 caller(`paths_to`)에 요구 유형 Guard 있음 | 해석된 caller 에는 없지만 `unresolved_callers` 가 있음 |
| `f_unreachable` | `reach(...).status == "none"` | `reach(...).status == "unknown"` |
| `f_annotation_guard` | 진입점에 `@EnforcePermission` (v2.1 R4: `@RequiresPermission` 은 강제력이 없어 제외) | — |
| `f_service_gate` | 같은 Stub 의 `onTransact` 오버라이드나 공통 헬퍼가 모든 진입점을 검사 |
| `f_debug_entry` | `dump`, `onShellCommand` 등 셸·덤프 전용 |

점수:

```
score = w.sink_similarity × sink_similarity
      + w.path            × {0: 1.0, 1: 0.7, 2: 0.4}[path_length] × conf[reachability]
      + w.guard_absence   × (0.4 if other_guard_present else 1.0) × conf[reachability]
      + w.review          × {likely: 1.0, unsure: 0.5, unlikely: 0.0, "": 0.5}[review_verdict]

conf = {resolved: 1.0, partial: 0.7, unknown: 0.4}     # [v2.1 R3]
```

LLM 검토 전 점수로 상위 `review_top_k` 를 고르고, 검토 후 다시 점수를 매긴다. **[v2.1 R5]** LLM 검토가 바꾸는 것은 `review` 항뿐이다. `unlikely` 라도 후보를 지우거나 필터 결과·라벨을 바꾸지 않으며, 검토 결과는 항상 `inferred` 배지와 함께 보인다. `reachability == "unknown"` 후보는 LLM 검토 프롬프트의 "도달 가능한가" 질문에 unresolved 호출 지점 목록을 함께 넣는다(사람이 판단할 근거를 모으는 용도). 가중치는 `config.scan.weights` 에서 오고 `RankedCandidates.weights` 에 기록된다(재현용). 초기값은 회고 검증 세트로 조정한다.

---

## 10. M9 Reporter — `report`

`reads=("cve.json",)` (나머지는 `load_optional`), `writes=("report.json", "report.md", "report.html")`

LLM을 쓰지 않는다. 템플릿만으로 만든다.

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `collect_artifacts(ctx) -> dict` | 유지 | 있는 산출물만 모음 |
| `render_json(bundle) -> str` | 유지 | (F-905) |
| `render_markdown(bundle, lang="ko") -> str` | 유지 + `lang` | 섹션: CVE 요약 → 패치 변경 → 진입점 경로 → 근본 원인(inferred) → S·G·S → 규칙·자가 검증 → 상위 후보(점수 근거·LLM 검토·라벨) → 한계(미해결 호출 비율, 범위 밖 패치). 한/영 템플릿 (F-901) |
| `render_html(bundle, lang="ko") -> str` | 유지 + `lang` | diff 하이라이트, 접기 (F-902) |
| `link_evidence(evidence) -> str` | 유지 (P1) | `android.googlesource.com/.../+/<revision>/<file>#<line>` (F-903) |
| `mask_for_public(bundle) -> dict` | 유지 (P1) | `public=False` 후보의 location·snippet·call_path 제거 (F-904) |

---

## 11. M11 Evaluation — `eval`

| 메서드 | 상태 | 역할 |
| --- | --- | --- |
| `load_baselines(dir) -> list[Baseline]` | 유지 | |
| `evaluate_cve(baseline, store) -> CveEval` | 유지 | |
| `method_match(analysis, baseline) -> float` | 유지 (P1) | (F-1101) |
| `detection_rate(ranked, known) -> float` | 유지 (P1) | 알려진 CVE 를 규칙이 다시 찾는 비율 (F-1102) |
| `false_positive_rate(ranked) -> float` | 유지 (P1) | `fp / (tp + fp)`, 라벨 기준 (F-1103) |
| `time_saved(baseline, tool_minutes) -> float` | 유지 (P1) | (F-1104) |
| `rule_adoption_rate(pattern_sets) -> float` | **추가** | |
| `retro_match(candidate, later: list[CveRecord], store) -> RetroMatch \| None` | **추가** | file → method → guard 순으로 일치 수준. guard = 그 메서드에 같은 유형 Guard 가 추가됨 (F-1106) |
| `retro_eval(old_revision, cves_before, after_month) -> dict` | **추가** | 과거 리비전을 스캔해 이후 ASB 패치와 guard 수준으로 일치하는 후보 수 (F-1106) |

평가 지표와 제안서의 검증 단계 대응:

| 제안서 검증 단계 | 지표 | 출처 |
| --- | --- | --- |
| 규칙 유효성 | 패치 전 탐지·후 미탐지, 규칙 채택률 | `RuleCheck`, `rule_adoption_rate` |
| 유사 결함 탐지 | 후보 수, 필터별 탈락 수, 분석 범위(파일·진입점 수) | `CandidateSet.stats`, `Candidate.filters` |
| 후보 정확성 | 확인된 실제 취약점 수, Precision, FP | `labels.json` |
| 회고 검증 | guard 수준 일치 수, 통과율 | `retro_eval` |
| 운영 효율 | 수집~후보 소요 시간, LLM 호출 수 vs 수동 분석 시간 | `meta`, `Baseline.analysis_minutes` |

---

## 12. M10 Dashboard — Streamlit (`dashboard/app.py`)

미리 생성된 JSON만 읽는다. 쓰는 것은 수동 라벨(`labels.json`)뿐이다.

| 제안서 탭 | 함수 | 화면 ID | 읽는 파일 | 우선순위 |
| --- | --- | --- | --- | --- |
| (사이드바) | `page_cve_list()` | D-1 | `cve.json`, `ranked_candidates.json` 요약 | P0 |
| 개요 | `page_patch_and_root_cause(cve_id)` | D-3·D-4 | `cve.json`, `patch_analysis.json`, `call_path.json`, `root_cause.json` | P0 |
| 취약 패턴 | `page_patterns(cve_id)` | D-6 | `pattern.json` (S·G·S 카드, Guard 에 "패치가 추가" 표시) | P0 |
| 탐지 규칙 | `page_rules(cve_id)` **추가** | D-5 | `pattern.json` attempts, `rules/<CVE>/*.scm/.yaml` | P0 |
| 변종 후보 | `page_candidates(cve_id)` | D-7 | `ranked_candidates.json`, `labels.json` | P0 |
| 보고서 | `page_report(cve_id)` | D-9 | `report.*` (한/영 전환, 다운로드) | P0 |
| — | `page_verification(cve_id)` | D-8 | `verification.json` | P2 |

| 함수 | 역할 |
| --- | --- |
| `main()` | `st.sidebar` 에서 CVE 선택, `st.tabs` 로 5개 탭. `--public` 이면 `_public` 파일만 읽음 (F-1006) |
| `load(cve_id, cls) -> T \| None` | `@st.cache_data` + `Store.load_optional` |
| `render_coderef(ref: CodeRef)` | `st.code(snippet, language="java")` + 위치·리비전 |
| `render_inferred_badge(status)` | `inferred` 표시 |
| `candidate_table(ranked, labels) -> DataFrame` | 서비스·메서드·Sink·누락 Guard·점수·검토·라벨 컬럼, 필터 |
| `candidate_detail(c: Candidate)` | 경로별 코드, 점수 근거, LLM 검토 근거, 원본 패치 S·G·S 와 나란히 |
| `save_label(cve_id, cand_id, label, note)` | `labels.json` 갱신 (`st.radio` + 저장 버튼) |

---

## 13. CLI · Pipeline

`PIPELINE` 에서 `Harness`, `Verifier` 를 빼고 `STANDALONE` 에 둔다. `Pipeline.run_all` 은 그대로 쓴다.

```python
PIPELINE = (Collector, PatchAnalyzer, BinderPathAnalyzer, RootCauseAnalyzer,
            PatternGenerator, Scanner, Prioritizer, Reporter)
STANDALONE = (Evaluator, Harness, Verifier)    # Harness·Verifier 는 P2
```

| 명령 | 동작 | 변경 |
| --- | --- | --- |
| `aosp1day collect <CVE> [--source URL] [--force]` | M1 | 유지 |
| `aosp1day analyze / binder-path / root-cause / pattern / scan / prioritize <CVE>` | 단계별 | 유지 |
| `aosp1day prioritize <CVE> [--top-n 20] [--no-review]` | LLM 검토 끄기 | `--no-review` 추가 |
| `aosp1day report <CVE> [--public] [--lang ko\|en]` | M9 | `--lang` 추가 |
| `aosp1day run <CVE> [--start pattern]` | 위 PIPELINE | 순서 변경 |
| `aosp1day eval _ [--baselines baselines/] [--retro --old-rev REV --after 2025-06]` | M11 | `--retro` 추가 |
| `aosp1day dataset [--from 2023 --to 2025]` | `output/dataset.csv` | 추가 |
| `aosp1day index [--rev REV]` | M6 인덱스 미리 빌드 | 추가 |
| `aosp1day dashboard [--port 8501] [--public]` | Streamlit | `--public` 추가 |
| `aosp1day harness / verify <CVE>` | M8 | P2 |

---

## 14. 담당 · 일정 · 테스트

담당은 기존 1차 배정(나연 M1, 현아 M2+M4)을 유지한다. 서진은 Harness 가 빠졌으므로 규칙 엔진 쪽을 제안한다. 구현 전 재확정한다.

| 주차 | 나연 | 현아 | 서진 |
| --- | --- | --- | --- |
| 4주 (11/16~11/23) | `schemas` v0.4·`storage`·`config` 추가분, M1 완성(OSV·Gitiles), `dataset` | `analysis/javaast`·`security_apis`·`sinks`, M2 `find_added_guards`·`find_sink_candidates` | 기준선 CVE 3~5건 선정, `baselines/` 정답 작성, `ruleengine/spec`·템플릿 2종 |
| 5주 (11/24~11/30) | `llm.py` 구현체·`call_structured`, Pipeline·CLI 변경 | `analysis/aidl`·`callgraph`(파일 모드), M3, M4 | `ruleengine/matcher`(파일 모드), M5 `seed_params`·`self_check`·`adopt_rule` |
| 6주 (12/1~12/7) | 대시보드 탭 1~3, `analysis/index` | M5 `draft_params` 프롬프트, M7 필터 | `matcher`(인덱스 모드), M6 |
| 7주 (12/8~12/14) | 대시보드 탭 4~5·라벨, M9 | M7 `review`·`ground_review`·점수 | M11 회고 검증·지표 |
| 8주 (12/15~12/21) | 통합·발표 | 후보 수동 검토 | 평가 정리, (선택) 상위 후보 재현 |

**[v2.1] 5주차 마일스톤 — 수직 관통(vertical slice).** 5주 끝(11/30)까지 기준선 CVE **1건**을 파일 모드로 `collect → analyze → binder-path → root-cause → pattern` 까지 한 번 통과시킨다. 품질은 낮아도 된다(M4 는 LLM 대신 0번 후보 고정, M3 는 같은 클래스 안만). 목적은 `classify_fix`(R2)·`control_hits`(R1)·`unresolved_ratio`(R3) 문제가 6주차 인덱스 작업 전에 드러나게 하는 것이다. 일정이 밀리면 M9 HTML·영문판과 M8 부터 덜어낸다.

**기준선 CVE 선정 기준 (v2.1 R2).** ① `classify_fix == ADDED_GUARD` ② Guard 유형이 P0(PERMISSION·APPOPS·UID·PACKAGE) ③ 가능하면 한 CVE 가 여러 위치를 고친 B 계열(회고 검증에 바로 쓰임). 1순위는 diff 확인 후 확정한다. 11/23 확인 결과 CVE-2024-31312 는 SystemUI(Kotlin)의 잠금 화면 미디어 표시 로직 수정이라 **범위 밖**이고, CVE-2025-48549 는 frameworks/base 외에 frameworks/av(native) 수정이 포함돼 Java 쪽 커밋만 범위 안인지 확인이 필요하다. CVE-2023-21098 은 diff 확인 후 `CONDITION_CHANGE` 면 기준선에서 빼고 "범위 밖 예시"로 발표에 쓴다.

테스트 (`tests/`, pytest):

| 대상 | 방식 | 통과 기준 |
| --- | --- | --- |
| `analysis/javaast` | 작은 Java 문자열 | 메서드·호출·if·clearCallingIdentity 범위 정확 |
| `security_apis` | 카탈로그별 양성·음성 예 | 유형 분류 정확. `clearCallingIdentity` 구간 안의 `enforceCallingPermission` 은 Guard 아님, `@RequiresPermission` 은 Guard 아님 (R4) |
| M2 `classify_fix` | 작은 before/after 쌍 4종 | Guard 신규 추가 → `ADDED_GUARD`, 기존 검사의 if 조건만 변경 → `CONDITION_CHANGE`, Parcel 읽기·쓰기 변경 → `BYPASS` (R2) |
| `callgraph.reach` | 인터페이스 경유·Handler 경유 호출이 있는 Java 문자열 | 해당 경로가 `none` 이 아니라 `unknown`/`partial` (R3) |
| M1 | `tests/fixtures/<CVE>/` 에 Gitiles 응답 고정 (네트워크 모킹) | 커밋·파일·hunk 수 일치, 캐시 재사용 |
| M2 | 기준선 CVE | `added_guards` 유형이 `baselines` 정답과 일치 |
| M4 | LLM 응답 fixture 고정 | 범위 밖 번호·없는 줄은 버려짐 |
| M5 | 기준선 CVE 전부 | seed 규칙 `passed=True` |
| M5 대조군 | 일부러 넓힌 파라미터(`sink_calls: ["\\w+"]`) | `TOO_BROAD` 로 실패 (R1) |
| matcher | 파일 모드 vs 인덱스 모드 | 같은 파일에서 같은 Match |
| M6 | 패치 이전 리비전 스캔 | 원본 취약 메서드가 후보에 포함 (`notes="origin"`) |
| M7 | 필터별 양성·음성 예 | 사유 기록 |

---

## 15. feature-spec 반영 필요 항목 (PR #20 후속)

| 기능 ID | 변경 |
| --- | --- |
| P0 8번 | "기준선 CVE 1건 패치 전후 검증" → "기준선 CVE 3~5건 규칙 자가 검증 통과" |
| M8 전체 (F-801~F-810) | P2 |
| F-401 | 가설 생성 제거, S·G·S 초안(`sgs`) 추가 |
| F-504 | 피드백 기반 재생성 포함 |
| F-507 (신규, P0) | LLM 규칙 파라미터 초안 + 재생성(최대 3회), 실패 시 seed 채택 |
| F-704 (신규, P0) | LLM 후보 검토 (상위 K, `inferred`, 근거 대조) |
| F-705 (신규, P0) | 오탐 필터 5종, 탈락 사유 기록 |
| F-1106 (신규, P1) | 회고 검증 |
| F-202 | P1 → **P0**, `classify_fix`(`fix_kind`)로 대체 (v2.1 R2) |
| F-504 | 음성 대조군 예산(`control_hits`) 포함 (v2.1 R1) |
| F-705 | 필터 결과에 `unknown` 추가, `@RequiresPermission` 제외 (v2.1 R3·R4) |
| D-5 (신규, P0) | 규칙·자가 검증 화면 |
| D-8 | P2 |

## 16. 남은 논의

- 스캔할 `aosp_revision` 과 회고 검증용 과거 리비전
- LLM provider·model 과 CVE당 호출 상한 (M4 1회, M5 최대 3회, M7 최대 K회)
- 기준선 CVE 3~5건 선정 (§14 선정 기준 적용, ★ 3건 diff 확인부터)
- `max_control_hits`·`max_scan_hits` 초기값 (기준선 3~5건으로 조정)
- 담당 재확정
- PR #20·#30 머지 순서 (이 PR은 #30 위에 쌓임)
