"""M10. Web Dashboard — Backend API (F-1001, 6·8주차).

feature-spec "Backend API 초안" 그대로의 엔드포인트 뼈대.
파이프라인을 작업 큐(jobs.py)로 실행하고, 결과는 output/<CVE-ID>/*.json 을 읽어 반환한다.
프론트엔드(화면 D-1~D-11)는 이 API 만 호출한다.

기술 스택(FastAPI vs Streamlit 등)은 feature-spec 6장 "리뷰할 것"에서 확정.
아래는 프레임워크 중립적인 라우트 명세 + 핸들러 스텁이다.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..storage import Store

# 단계 이름 -> 결과 JSON 파일 (GET /api/analyses/{cve_id}/{stage})
STAGE_ARTIFACTS = {
    "patch": "patch_analysis.json",
    "call_path": "call_path.json",
    "root_cause": "root_cause.json",
    "pattern": "pattern.json",
    "candidates": "ranked_candidates.json",
    "verification": "verification.json",
}


@dataclass
class Route:
    method: str
    path: str
    handler: str
    desc: str


# 문서화·프론트 계약용 라우트 테이블 (feature-spec Backend API 초안과 1:1)
ROUTES = [
    Route("POST",  "/api/analyses",                          "create_analysis",  "새 분석 실행"),
    Route("GET",   "/api/analyses",                          "list_analyses",    "분석 목록"),
    Route("GET",   "/api/analyses/{cve_id}",                 "get_analysis",     "진행 상태 + 단계별 요약"),
    Route("GET",   "/api/analyses/{cve_id}/{stage}",         "get_stage_result", "단계 결과 JSON"),
    Route("PATCH", "/api/candidates/{id}",                   "label_candidate",  "후보 라벨 수정 (TP/FP/보류)"),
    Route("GET",   "/api/analyses/{cve_id}/report",          "get_report",       "보고서 다운로드"),
    Route("GET",   "/api/eval",                              "get_eval",         "평가 지표"),
]


class DashboardApp:
    """프레임워크에 묶이지 않은 핸들러 모음. 실제 서버는 이들을 라우트에 연결."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def _store(self, cve_id: str) -> Store:
        return Store(self.config.output_root, cve_id)

    def create_analysis(self, cve_id: str | None = None, commit_url: str | None = None) -> dict:
        """POST /api/analyses — 작업 큐에 등록하고 job id 반환."""
        raise NotImplementedError

    def list_analyses(self) -> list[dict]:
        """GET /api/analyses — D-1 CVE 목록."""
        raise NotImplementedError

    def get_analysis(self, cve_id: str) -> dict:
        """GET /api/analyses/{cve_id} — D-2 진행 상태 + 단계별 요약."""
        raise NotImplementedError

    def get_stage_result(self, cve_id: str, stage: str) -> dict:
        """GET /api/analyses/{cve_id}/{stage} — D-3~D-8 상세 화면 데이터."""
        raise NotImplementedError

    def label_candidate(self, candidate_id: str, label: str) -> dict:
        """PATCH /api/candidates/{id} — D-7 라벨링."""
        raise NotImplementedError

    def get_report(self, cve_id: str, fmt: str = "html", public: bool = False):
        """GET /api/analyses/{cve_id}/report — D-9 보고서 다운로드."""
        raise NotImplementedError

    def get_eval(self) -> dict:
        """GET /api/eval — D-10 평가."""
        raise NotImplementedError


def serve(host: str, port: int, config: Config) -> None:
    """Backend 서버 기동 (CLI `aosp1day serve`).

    TODO: 선택한 웹 프레임워크로 ROUTES 를 DashboardApp 핸들러에 연결해 기동.
    """
    raise NotImplementedError("대시보드 Backend 서버 구현 (기술 스택 확정 후)")
