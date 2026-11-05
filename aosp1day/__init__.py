"""aosp1day — AOSP Framework/system_server 1-Day 패치 기반 분석 파이프라인.

모듈 구성 (feature-spec.md 참고):
  M1 Collector · M2 Patch Analyzer · M3 Binder Path · M4 Root Cause ·
  M5 Pattern/Rule · M6 Scanner · M7 Prioritizer · M8 Verifier ·
  M9 Reporter · M10 Web Dashboard · M11 Evaluation

각 단계는 output/<CVE-ID>/*.json 으로만 연결되며 독립 실행 가능하다.
"""

__version__ = "0.0.1"
