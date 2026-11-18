# 시스템 구조도 (v2)

설계 뼈대(`aosp1day/`)와 v2 목표(공개 패치의 Source–Guard–Sink 구조로 다른 System Service의 변종 후보 탐지)를 Mermaid로 나타낸 것이다.
클래스·메서드 상세는 [design.md](design.md), 기능 ID는 [feature-spec.md](feature-spec.md), 데이터 계약은 [`aosp1day/schemas.py`](../aosp1day/schemas.py) 참고.

## 1. 파이프라인 단계와 산출물 (M1 → M9)

각 단계는 `output/<CVE-ID>/*.json` 으로만 연결되고, 앞 단계 JSON만 있으면 독립 실행된다.
모든 산출물은 `meta`(스키마 버전·생성 시각·입력 해시)를 가지고, 코드 위치는 전부 `CodeRef`(revision·side·줄 범위·snippet)로 표현한다.

실행 순서는 `collect → analyze → binder-path → root-cause → pattern → scan → prioritize → report`. `run`은 한 단계가 실패해도 입력이 준비된 단계는 계속 실행한다. M8(Harness·Verifier)은 P2로 `PIPELINE`에서 빠졌다.

주황색 단계만 LLM을 쓴다. LLM 출력은 항상 결정적 검사(근거 대조, 규칙 자가 검증, 근거 줄 확인)를 거친다.

```mermaid
flowchart TD
    IN([CVE ID / 패치 커밋 URL]):::io

    subgraph CORE["핵심 파이프라인 (CLI 서브커맨드)"]
        direction TB
        M1["M1 Collector<br/>collect"]:::stage
        M2["M2 Patch Analyzer<br/>analyze"]:::stage
        M3["M3 Binder Path<br/>binder-path"]:::stage
        M4["M4 Root Cause (LLM)<br/>root-cause"]:::llm
        M5["M5 Pattern/Rule (LLM 초안)<br/>pattern"]:::llm
        M6["M6 Scanner<br/>scan"]:::stage
        M7["M7 Prioritizer (LLM 검토)<br/>prioritize"]:::llm
        M9["M9 Reporter<br/>report"]:::stage
    end

    SRC[("patches/*.diff<br/>src/&lt;hash&gt;/before·after")]:::io
    IDX[("output/_index/&lt;rev&gt;<br/>CodeIndex + CallGraph")]:::io
    LAB[("labels.json<br/>수동 TP/FP")]:::io

    IN --> M1
    M1 -- cve.json --> M2
    M1 -.-> SRC
    SRC -.-> M2
    SRC -. "자가 검증 (전·후)" .-> M5
    M2 -- "patch_analysis.json<br/>(added_guards · sink_candidates)" --> M3
    M2 -- patch_analysis.json --> M4
    M3 -- call_path.json --> M4
    M4 -- "root_cause.json<br/>(inferred, sgs 초안)" --> M5
    M5 -- "pattern.json (adopted 규칙)<br/>+ rules/&lt;CVE&gt;/*.scm·yaml" --> M6
    IDX --> M6
    M6 -- candidates.json --> M7
    M7 -- ranked_candidates.json --> M9
    LAB -.-> M7
    M9 --> OUT([report.json / .md / .html<br/>+ _public 마스킹본]):::io

    classDef stage fill:#1f6feb,stroke:#0b2a66,color:#fff;
    classDef llm fill:#d85a30,stroke:#712b13,color:#fff;
    classDef io fill:#eaeef2,stroke:#57606a,color:#24292f;
```

## 2. 전체 시스템 (대시보드 · 평가 포함)

대시보드(M10)는 Streamlit 단독이며 별도 Backend API·작업 큐가 없다. 미리 생성된 JSON만 읽고, 쓰는 것은 수동 라벨(`labels.json`)뿐이다.

```mermaid
flowchart LR
    CLI["CLI<br/>aosp1day run / dataset / index ..."]
    PIPE["Pipeline 오케스트레이터<br/>M1 → M9"]
    STORE[("output/&lt;CVE-ID&gt;/*.json")]
    BASE[("baselines/&lt;CVE-ID&gt;.json<br/>기준선 정답")]
    AOSP[("AOSP frameworks/base<br/>scan_paths, 고정 revision")]
    OSV[("OSV · Gitiles · ASB")]
    LLM["LlmClient<br/>generate_structured"]
    M11["M11 Evaluation<br/>eval (+ 회고 검증)"]
    DASH["M10 Dashboard<br/>Streamlit 5탭"]
    PUB["공개용<br/>report_public.* / 정적 데모"]

    CLI --> PIPE
    PIPE <--> STORE
    PIPE -- "M1" --> OSV
    PIPE -- "M3/M6 Tree-sitter" --> AOSP
    PIPE -- "M4 · M5 · M7" --> LLM
    STORE --> M11
    BASE --> M11
    M11 -- "output/eval.json" --> DASH
    STORE -- 결과 읽기 --> DASH
    DASH -- "labels.json" --> STORE
    STORE -- 마스킹 --> PUB

    classDef svc fill:#1f6feb,stroke:#0b2a66,color:#fff;
    classDef data fill:#eaeef2,stroke:#57606a,color:#24292f;
    class PIPE,CLI,M11,DASH,LLM svc;
    class STORE,BASE,AOSP,OSV,PUB data;
```

## 3. 코드 뼈대 매핑 (`aosp1day/`)

```mermaid
flowchart TB
    cli["cli.py<br/>서브커맨드 파싱"] --> pipe["pipeline.py<br/>Pipeline (실패 시 ok=False)"]
    cli --> dash["dashboard/app.py<br/>Streamlit"]
    pipe --> reg["stages/__init__.py<br/>PIPELINE · STANDALONE"]
    reg --> stages["stages/m01..m07, m09, m11<br/>(m08_* 는 STANDALONE, P2)"]
    stages --> analysis["analysis/<br/>javaast · security_apis · sinks · aidl · index · callgraph"]
    stages --> engine["ruleengine/<br/>templates/*.scm · spec · matcher"]
    engine --> analysis
    stages --> schemas["schemas.py<br/>CodeRef · Evidence · meta (v0.4)"]
    stages --> storage["storage.py<br/>output/ 읽기·쓰기"]
    stages --> llm["llm.py + llm_providers/<br/>generate_structured"]
    storage --> schemas
    pipe --> cfg["config.py<br/>Config · RuleConfig · ScanConfig"]
    dash --> storage

    classDef f fill:#ffffff,stroke:#1f6feb,color:#24292f;
    class cli,pipe,dash,reg,stages,analysis,engine,schemas,storage,cfg,llm f;
```

## 4. M5 규칙 채택 루프

```mermaid
sequenceDiagram
    participant S as PatternGenerator
    participant L as LlmClient
    participant R as ruleengine
    participant F as before·after 소스

    S->>S: seed_params(pattern)  (LLM 없음)
    S->>R: to_rule + self_check
    R->>F: match_file(before), match_file(after)
    R-->>S: RuleCheck (target_hit, patched_hits)
    alt seed 실패
        S-->>S: adopted = False (패턴 오류)
    else seed 통과
        loop 시도 1..max_attempts
            S->>L: draft_params(이전 파라미터, feedback)
            L-->>S: RuleParams (inferred)
            S->>R: lint → to_rule → self_check
            R-->>S: RuleCheck
            Note over S: 통과하면 채택 (llm_generalized)<br/>실패하면 feedback 만들어 재시도
        end
        S-->>S: LLM 모두 실패 → seed 채택 (seed_only)
    end
```

## 5. RuleMatcher 판정 (진입점 하나 기준)

```mermaid
flowchart TD
    A["Binder 진입점 e<br/>(StubMap.is_entry)"] --> B["CallGraph.paths_from(e, caller_depth)"]
    B --> C{"경로 끝 메서드에<br/>sink 호출?"}
    C -- 없음 --> X["Match 없음"]
    C -- 있음 --> D["경로 위 Guard 수집<br/>(before_sink면 호출 지점 이전 줄만)"]
    D --> E{"guard_types · apis · args<br/>만족?"}
    E -- 예 --> X
    E -- 아니오 --> F{"exclude_methods?"}
    F -- 예 --> X
    F -- 아니오 --> H["Match<br/>missing_guard · present_guards · path"]
```

## 6. M7 후보 선별

```mermaid
flowchart LR
    C[("candidates.json")] --> F["필터 5종<br/>탈락 사유 기록"]
    F --> S1["점수 (검토 전)"]
    S1 --> K{"상위 K?"}
    K -- 예 --> R["LLM 검토<br/>review + ground_review"]
    K -- 아니오 --> S2
    R --> S2["재점수"]
    S2 --> RK["rank 상위 N<br/>+ labels.json 병합"]
    RK --> O[("ranked_candidates.json")]
```
