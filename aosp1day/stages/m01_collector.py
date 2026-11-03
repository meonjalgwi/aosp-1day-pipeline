"""M1. Collector — CVE/패치 수집 (2주차, F-101~F-106).

입력: CVE ID 또는 AOSP 패치 커밋 URL/해시
출력: cve.json + patches/<hash>.diff + src/<hash>/{before,after}/<변경 파일>
"""

from __future__ import annotations

from ..schemas import CveRecord, PatchCommit
from ..storage import Store
from .base import PipelineContext, Stage, StageResult


class Collector(Stage):
    name = "collect"
    module = "M1"
    reads = ()
    writes = (CveRecord.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        source = ctx.params.get("source") or ctx.cve_id
        if self.is_cached(ctx):
            return StageResult(self.name, ok=True, artifacts=[ctx.store.path(CveRecord.ARTIFACT)], message="cached")
        record = self.collect(source)
        for commit in record.patch_commits:
            self.save_sources(commit, ctx.store)     # diff_path / before_dir / after_dir 채움
        path = self.save(ctx, record)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def collect(self, source: str) -> CveRecord:
        """F-101. CVE ID 또는 커밋 URL/해시를 받아 CveRecord 조립 (F-102·F-103 호출)."""
        raise NotImplementedError

    def parse_security_bulletin(self, cve_id: str) -> dict:
        """F-102. Android Security Bulletin 에서 컴포넌트·심각도·유형·영향 버전·패치 링크."""
        raise NotImplementedError

    def fetch_patch_metadata(self, commit_url: str) -> PatchCommit:
        """F-103. 커밋 메시지·작성일·브랜치·부모 커밋·변경 파일 목록."""
        raise NotImplementedError

    def save_sources(self, commit: PatchCommit, store: Store) -> None:
        """F-104. diff 와 변경 파일의 패치 전(parent)/후(commit) 원본을 저장하고 경로를 commit 에 기록.

        저장 위치:
          patches/<hash>.diff
          src/<hash>/before/<frameworks/base 기준 경로>
          src/<hash>/after/<frameworks/base 기준 경로>
        """
        raise NotImplementedError

    def handle_edge_cases(self, source: str, record: CveRecord) -> None:
        """F-105. 잘못된 링크, 비공개 버그, 여러 브랜치에 나뉜 패치 → record.notes 에 기록."""
        raise NotImplementedError

    def is_cached(self, ctx: PipelineContext) -> bool:
        """F-106. cve.json 과 diff 가 이미 있으면 재다운로드하지 않음 (params.force 로 무시)."""
        return bool(ctx.store.exists(CveRecord.ARTIFACT) and not ctx.params.get("force"))
