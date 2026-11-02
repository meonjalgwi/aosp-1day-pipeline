"""CLI 진입점 (F-1004).

대시보드 없이도 단계별로 실행할 수 있어야 한다:
    aosp1day collect   CVE-2024-xxxx --source <commit_url>
    aosp1day analyze   CVE-2024-xxxx
    aosp1day binder-path CVE-2024-xxxx
    aosp1day root-cause  CVE-2024-xxxx
    aosp1day pattern   CVE-2024-xxxx
    aosp1day scan      CVE-2024-xxxx
    aosp1day prioritize CVE-2024-xxxx --top-n 20
    aosp1day verify    CVE-2024-xxxx
    aosp1day report    CVE-2024-xxxx [--public]
    aosp1day run       CVE-2024-xxxx [--start pattern]   # 전체 또는 특정 단계부터
    aosp1day serve     [--host 0.0.0.0 --port 8000]      # M10 대시보드 Backend
"""

from __future__ import annotations

import argparse

from .config import Config
from .pipeline import Pipeline
from .stages import PIPELINE, STANDALONE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aosp1day", description="AOSP 1-Day 패치 기반 분석 파이프라인")
    parser.add_argument("--config", default="config.yaml", help="설정 파일 경로")
    sub = parser.add_subparsers(dest="command", required=True)

    # 단계별 서브커맨드 (M1~M9, M11)
    for stage_cls in (*PIPELINE, *STANDALONE):
        sp = sub.add_parser(stage_cls.name, help=f"{stage_cls.module} 실행")
        sp.add_argument("cve_id")
        _add_stage_args(stage_cls.name, sp)

    # 전체 실행
    run = sub.add_parser("run", help="M1~M9 전체 실행")
    run.add_argument("cve_id")
    run.add_argument("--start", help="이 단계부터 재실행")
    run.add_argument("--source", help="CVE ID 대신 커밋 URL/해시")

    # 대시보드 Backend
    serve = sub.add_parser("serve", help="M10 Web Dashboard Backend 실행")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    return parser


def _add_stage_args(name: str, sp: argparse.ArgumentParser) -> None:
    if name == "collect":
        sp.add_argument("--source", help="커밋 URL/해시 (없으면 cve_id로 조회)")
    if name == "prioritize":
        sp.add_argument("--top-n", type=int, default=20)
    if name == "report":
        sp.add_argument("--public", action="store_true", help="공개용 마스킹 버전")


def _params(args: argparse.Namespace) -> dict:
    keys = ("source", "top_n", "public", "target", "groundtruth")
    return {k: getattr(args, k) for k in keys if getattr(args, k, None) is not None}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load(args.config)
    pipeline = Pipeline(config)

    if args.command == "serve":
        from .dashboard.api import serve
        serve(host=args.host, port=args.port, config=config)
        return 0

    if args.command == "run":
        run = pipeline.run_all(args.cve_id, start=args.start, params=_params(args))
        print(f"[run] {args.cve_id}: ok={run.ok} ({len(run.results)} stages)")
        return 0 if run.ok else 1

    result = pipeline.run_stage(args.command, args.cve_id, params=_params(args))
    print(f"[{result.stage}] ok={result.ok} -> {[str(p) for p in result.artifacts]}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
