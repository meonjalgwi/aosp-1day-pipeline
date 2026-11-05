# 시스템 구조도

PR #20의 모듈 구성(M1~M11)과 설계 뼈대(`aosp1day/`)를 Mermaid로 나타낸 것이다.
기능 상세는 [feature-spec.md](feature-spec.md), 데이터 계약은 feature-spec 4장과 [`aosp1day/schemas.py`](../aosp1day/schemas.py) 참고.

## 1. 파이프라인 단계와 산출물 (M1 → M9)

각 단계는 `output/<CVE-ID>/*.json` 으로만 연결되고, 앞 단계 JSON만 있으면 독립 실행된다.
모든 산출물은 `meta`(스키마 버전·생성 시각·입력 해시)를 가지고, 코드 위치는 전부 `CodeRef`(revision·file·side·줄 범위·snippet)로 표현한다. `revision`은 그 코드가 실제로 있는 커밋(before=parent, after=패치 커밋)이다.

실행 순서는 `collect → analyze → binder-path → root-cause → harness → verify → pattern → scan → prioritize → report`. 기준선 검증(Harness·Verifier)을 전체 스캔보다 먼저 두고, `run`은 한 단계가 실패해도 입력이 준비된 단계는 계속 실행한다.

```mermaid
flowchart TD
    IN([CVE ID / 패치 커밋 URL]):::io

    subgraph CORE["핵심 파이프라인 (CLI 서브커맨드)"]
        direction TB
        M1["M1 Collector<br/>collect"]:::stage
        M2["M2 Patch Analyzer<br/>analyze"]:::stage
        M3["M3 Binder Path<br/>binder-path"]:::stage
        M4["M4 Root Cause (LLM)<br/>root-cause"]:::stage
        M5["M5 Pattern/Rule<br/>pattern"]:::stage
        M6["M6 Scanner<br/>scan"]:::stage
        M7["M7 Prioritizer<br/>prioritize"]:::stage
        M8H["M8 Harness<br/>harness"]:::stage
        M8["M8 Verifier<br/>verify"]:::stage
        M9["M9 Reporter<br/>report"]:::stage
    end

    SRC[("patches/*.diff<br/>src/&lt;hash&gt;/before·after")]:::io
    MAN[("baselines/&lt;CVE&gt;.tests.json<br/>수동 기준선 TestCase (P0)")]:::io
    APK[("공용 instrumentation APK<br/>(권한 변형별)")]:::io

    IN --> M1
    M1 -- cve.json --> M2
    M1 -.-> SRC
    SRC -.-> M2
    SRC -. 자가 검증 .-> M5
    M2 -- "patch_analysis.json<br/>(hunk별 before/after CodeRef)" --> M3
    M2 -- patch_analysis.json --> M4
    M3 -- call_path.json --> M4
    M4 -- "root_cause.json<br/>(status=inferred, 근거 CodeRef)" --> M5
    M5 -- "pattern.json (PatternSet)<br/>+ rules/*.scm" --> M6
    M6 -- candidates.json --> M7
    MAN -- "P0" --> M8H
    M4 -. "hypotheses (P1 자동 생성)" .-> M8H
    M3 -. "진입점 (P1)" .-> M8H
    M8H -- "test_cases.json<br/>+ tests/*.json 파라미터" --> M8
    APK --> M8
    M7 -- ranked_candidates.json --> M9
    M8 -- verification.json --> M9
    M9 --> OUT([report.json / .md / .html<br/>+ _public 마스킹본]):::io

    classDef stage fill:#1f6feb,stroke:#0b2a66,color:#fff;
    classDef io fill:#eaeef2,stroke:#57606a,color:#24292f;
```

## 2. 전체 시스템 (대시보드 · 평가 포함)

대시보드(M10)는 Streamlit 단독이며 별도 Backend API·작업 큐가 없다. 미리 생성된 JSON만 읽는다.

```mermaid
flowchart LR
    CLI["CLI<br/>aosp1day run / collect ..."]
    PIPE["Pipeline 오케스트레이터<br/>M1 → M9"]
    STORE[("output/&lt;CVE-ID&gt;/*.json")]
    BASE[("baselines/&lt;CVE-ID&gt;.json<br/>수동 정답")]
    AOSP[("AOSP frameworks/base")]
    DEV[("Cuttlefish (1차)<br/>또는 Emulator")]
    LLM["LlmClient<br/>(provider 교체 가능)"]
    M11["M11 Evaluation<br/>eval"]
    DASH["M10 Dashboard<br/>Streamlit"]
    PUB["공개용<br/>report_public.* / 정적 데모"]

    CLI --> PIPE
    PIPE <--> STORE
    PIPE -- "M3/M6 Tree-sitter" --> AOSP
    PIPE -- "M4" --> LLM
    PIPE -- "M8 동적 검증" --> DEV
    STORE --> M11
    BASE --> M11
    M11 -- "output/eval.json" --> DASH
    STORE -- 결과 읽기 --> DASH
    STORE -- 마스킹 --> PUB

    classDef svc fill:#1f6feb,stroke:#0b2a66,color:#fff;
    classDef data fill:#eaeef2,stroke:#57606a,color:#24292f;
    class PIPE,CLI,M11,DASH,LLM svc;
    class STORE,BASE,AOSP,DEV,PUB data;
```

## 3. 코드 뼈대 매핑 (`aosp1day/`)

```mermaid
flowchart TB
    cli["cli.py<br/>서브커맨드 파싱"] --> pipe["pipeline.py<br/>Pipeline (실패 시 ok=False)"]
    cli --> dash["dashboard/app.py<br/>Streamlit"]
    pipe --> reg["stages/__init__.py<br/>REGISTRY · PIPELINE"]
    reg --> base["stages/base.py<br/>Stage · PipelineContext"]
    reg --> stages["stages/m01..m09, m08_harness, m11<br/>단계별 클래스"]
    stages --> schemas["schemas.py<br/>JSON 데이터 계약 (CodeRef · meta)"]
    stages --> storage["storage.py<br/>output/ 읽기·쓰기 + meta 기록"]
    stages --> llm["llm.py<br/>LlmClient 인터페이스"]
    storage --> schemas
    pipe --> cfg["config.py<br/>Config (config.yaml)"]
    dash --> storage

    classDef f fill:#ffffff,stroke:#1f6feb,color:#24292f;
    class cli,pipe,dash,reg,base,stages,schemas,storage,cfg,llm f;
```
