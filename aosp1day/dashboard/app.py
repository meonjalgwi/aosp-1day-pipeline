"""M10. Web Dashboard — Streamlit 앱 (6주차 v1 · 8주차 완성).

실행: ``aosp1day dashboard`` 또는 ``streamlit run aosp1day/dashboard/app.py``

- 별도 Backend API·작업 큐 없음. 미리 생성된 ``output/<CVE-ID>/*.json`` 만 읽는다.
- 공개 시연은 ``--public`` (마스킹된 report_public.json 만 읽음).

P0 화면 (feature-spec M10)
  D-1 분석된 CVE 목록
  D-3 패치 결과 (hunk 별 before/after)  /  D-4 Root Cause (inferred 표시, 근거 링크)
  D-6 Source–Guard–Sink 패턴
  D-7 후보 순위와 코드 근거
  D-8 동적 검증 결과
  D-9 보고서 다운로드
"""

from __future__ import annotations

from pathlib import Path

OUTPUT_ROOT = Path("output")


def list_cves(output_root: Path = OUTPUT_ROOT) -> list[str]:
    """D-1. cve.json 이 있는 디렉터리 목록."""
    return sorted(p.parent.name for p in output_root.glob("*/cve.json"))


def page_cve_list() -> None:
    raise NotImplementedError


def page_patch_and_root_cause(cve_id: str) -> None:
    raise NotImplementedError


def page_patterns(cve_id: str) -> None:
    raise NotImplementedError


def page_candidates(cve_id: str) -> None:
    raise NotImplementedError


def page_verification(cve_id: str) -> None:
    raise NotImplementedError


def page_report(cve_id: str) -> None:
    raise NotImplementedError


def main() -> None:
    """Streamlit 진입점: 사이드바에서 CVE·화면 선택 후 해당 page_* 호출."""
    raise NotImplementedError


if __name__ == "__main__":
    main()
