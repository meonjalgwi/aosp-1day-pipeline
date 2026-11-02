"""M1. Collector — CVE/패치 수집 (2주차, F-101~F-106).

입력: CVE ID 또는 AOSP 패치 커밋 URL/해시
출력: cve.json
"""

from __future__ import annotations

from ..schemas import CveRecord, PatchCommit
from .base import PipelineContext, Stage, StageResult


class Collector(Stage):
    name = "collect"
    module = "M1"
    reads = ()
    writes = (CveRecord.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        source = ctx.params.get("source") or ctx.cve_id
        record = self.collect(source)
        path = ctx.store.save(record)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def collect(self, source: str) -> CveRecord:
        """F-101. CVE ID 또는 커밋 URL/해시를 받아 CveRecord 조립."""
        raise NotImplementedError

    def parse_security_bulletin(self, cve_id: str) -> dict:
        """F-102. Android Security Bulletin 에서 컴포넌트·심각도·영향 버전·패치 링크."""
        raise NotImplementedError

    def fetch_patch_metadata(self, commit_url: str) -> PatchCommit:
        """F-103. 커밋 메시지·작성일·부모 커밋·변경 파일 목록."""
        raise NotImplementedError

    def fetch_diff(self, commit: PatchCommit) -> str:
        """F-104. 패치 diff 와 변경 전/후 파일 원본 저장."""
        raise NotImplementedError

    def handle_edge_cases(self, source: str) -> None:
        """F-105. 잘못된 링크, 비공개 버그, 여러 브랜치에 나뉜 패치."""
        raise NotImplementedError

    def is_cached(self, cve_id: str) -> bool:
        """F-106. 이미 수집한 CVE 는 재다운로드하지 않음."""
        raise NotImplementedError
