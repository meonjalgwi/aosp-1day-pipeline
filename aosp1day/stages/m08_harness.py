"""M8. Verifier — Harness: 가설 → 테스트 생성 (7주차, F-802). 담당: 서진.

입력: root_cause.json 의 hypotheses + call_path.json 의 진입점
출력: test_cases.json + 빌드된 테스트 APK

가설("이 Binder 메서드를 이 인자로 부르면 다른 사용자 데이터가 나온다")을
TestCase(대상 서비스·메서드, 인자, 호출자 권한, 패치 전/후 기대 결과)로 바꾸고,
APK / instrumentation 템플릿에 채워 빌드한다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import CallPath, Claim, RootCause, TestCase, TestCases
from .base import PipelineContext, Stage, StageResult


class Harness(Stage):
    name = "harness"
    module = "M8"
    reads = (RootCause.ARTIFACT, CallPath.ARTIFACT)
    writes = (TestCases.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        root_cause = ctx.store.load(RootCause)
        call_path = ctx.store.load(CallPath)
        result = TestCases(cve_id=root_cause.cve_id)
        for hypothesis in root_cause.hypotheses:
            test = self.to_test_case(hypothesis, call_path)
            test.apk_path = str(self.build_apk(test, ctx.store.dir))
            result.tests.append(test)
        path = self.save(ctx, result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def to_test_case(self, hypothesis: Claim, call_path: CallPath) -> TestCase:
        """가설 + 진입점 정보로 TestCase 채움 (target_*, call_args, expected_*)."""
        raise NotImplementedError

    def select_template(self, test: TestCase) -> str:
        """Intent 호출 / Binder 직접 호출 / instrumentation 중 템플릿 선택."""
        raise NotImplementedError

    def build_apk(self, test: TestCase, out_dir: Path) -> Path:
        """템플릿에 파라미터 주입 후 APK 빌드 → output/<CVE>/apks/<test_id>.apk"""
        raise NotImplementedError
