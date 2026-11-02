# 시스템 구조도

PR #20에서 확정한 모듈 구성(M1~M11)과 설계 뼈대(`aosp1day/`)를 Mermaid로 나타낸 것이다.
기능 상세는 [feature-spec.md](feature-spec.md), 주차 계획은 [roadmap.md](roadmap.md) 참고.

## 1. 파이프라인 단계와 산출물 (M1 → M9)

각 단계는 `output/<CVE-ID>/*.json` 으로만 연결되고, 앞 단계 JSON만 있으면 독립 실행된다.

```mermaid
flowchart TD
    IN([CVE ID / 패치 커밋 URL]):::io

    subgraph CORE["핵심 파이프라인 (CLI 서브커맨드)"]
        direction TB
        M1["M1 Collector<br/>collect"]:::stage
        M2["M2 Patch Analyzer<br/>analyze"]:::stage
        M3["M3 Binder Path<br/>binder-path"]:::stage
        M4["M4 Root Cause (AI)<br/>root-cause"]:::stage
        M5["M5 Pattern/Rule<br/>pattern"]:::stage
        M6["M6 Scanner<br/>scan"]:::stage
        M7["M7 Prioritizer<br/>prioritize"]:::stage
        M8["M8 Verifier<br/>verify"]:::stage
        M9["M9 Reporter<br/>report"]:::stage
    end

    IN --> M1
    M1 -- cve.json --> M2
    M2 -- patch_analysis.json --> M3
    M2 -- patch_analysis.json --> M4
    M3 -- call_path.json --> M4
    M4 -- root_cause.json --> M5
    M5 -- "pattern.json + 규칙파일" --> M6
    M6 -- candidates.json --> M7
    M4 -- root_cause.json --> M8
    M7 -- ranked_candidates.json --> M8
    M8 -- verification.json --> M9
    M9 --> OUT([report.html / report.md]):::io

    %% M9 Reporter는 위 모든 단계의 JSON을 모아 보고서를 만든다.

    classDef stage fill:#1f6feb,stroke:#0b2a66,color:#fff;
    classDef io fill:#eaeef2,stroke:#57606a,color:#24292f;
```

## 2. 전체 시스템 (대시보드 · 평가 포함)

`output/<CVE-ID>/*.json` 을 중심으로 CLI, 대시보드(M10), 평가(M11)가 붙는다.

```mermaid
flowchart LR
    subgraph FE["M10 Web Dashboard (최종 산출물)"]
        BROWSER([브라우저<br/>D-1~D-11 화면])
        API["Backend API<br/>/api/analyses ..."]
        JOBS["비동기 작업 큐<br/>진행률 폴링"]
    end

    CLI["CLI<br/>aosp1day run / collect ..."]
    PIPE["Pipeline 오케스트레이터<br/>M1 → M9"]
    STORE[("output/&lt;CVE-ID&gt;/*.json")]
    AOSP[("AOSP frameworks/base")]
    EMU[("Emulator / Cuttlefish")]
    M11["M11 Evaluation<br/>eval"]

    BROWSER <--> API
    API --> JOBS
    JOBS --> PIPE
    CLI --> PIPE
    PIPE <--> STORE
    PIPE -- "M3/M6 스캔" --> AOSP
    PIPE -- "M8 동적 검증" --> EMU
    API -- 결과 읽기 --> STORE
    STORE --> M11
    M11 -- eval.json --> API

    classDef svc fill:#1f6feb,stroke:#0b2a66,color:#fff;
    classDef data fill:#eaeef2,stroke:#57606a,color:#24292f;
    class API,JOBS,PIPE,CLI,M11 svc;
    class STORE,AOSP,EMU data;
```

## 3. 코드 뼈대 매핑 (`aosp1day/`)

```mermaid
flowchart TB
    cli["cli.py<br/>서브커맨드 파싱"] --> pipe["pipeline.py<br/>Pipeline"]
    cli --> api["dashboard/api.py<br/>serve"]
    pipe --> reg["stages/__init__.py<br/>REGISTRY · PIPELINE"]
    reg --> base["stages/base.py<br/>Stage · PipelineContext"]
    reg --> stages["stages/m01..m09, m11<br/>단계별 클래스"]
    stages --> schemas["schemas.py<br/>JSON 데이터 계약"]
    stages --> storage["storage.py<br/>output/ 읽기·쓰기"]
    storage --> schemas
    pipe --> cfg["config.py<br/>Config (config.yaml)"]
    api --> jobs["dashboard/jobs.py<br/>JobQueue"]
    jobs --> pipe

    classDef f fill:#ffffff,stroke:#1f6feb,color:#24292f;
    class cli,pipe,api,reg,base,stages,schemas,storage,cfg,jobs f;
```
