"""설정 로더 (F-1005).

AOSP 경로, LLM, 검증 기기 설정을 ``config.yaml`` 로 관리한다 (리포에는 config.example.yaml 만 커밋).
API 키는 config 에 쓰지 않는다 — 환경변수 이름(api_key_env)만 기록하고 값은 실행 시 환경변수에서 읽는다.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_SCAN_PATHS = (
    "services/*/java/com/android/server/**/*.java",   # services/core 외 devicepolicy·accessibility 등 포함
    "core/java/android/**/*.aidl",                    # Binder/AIDL 진입점
    "core/java/android/**/*.java",                    # Stub·Manager (진입점과 연결된 것만 M3에서 사용)
)


@dataclass
class LlmConfig:
    provider: str = ""                # 예: anthropic | openai — 팀 결정 후 config.yaml 에 기록
    model: str = ""
    temperature: float = 0.0          # 재현성: temperature 고정
    api_key_env: str = "LLM_API_KEY"  # 키 값이 아니라 환경변수 "이름"

    @property
    def api_key(self) -> str | None:
        """실행 시점에만 읽는다. 로그·JSON 에 남기지 말 것."""
        return os.environ.get(self.api_key_env)


@dataclass
class DeviceConfig:
    kind: str = "cuttlefish"          # cuttlefish (1차) | emulator (2주차 기준 미달 시)
    env_image: str = ""               # 환경 확인용: 최신 공식 CI 사전 빌드 이미지 (2주차)
    host_package: str = ""            # 같은 빌드의 cvd-host_package.tar.gz
    # 동적 재현용: 기준선 CVE에 맞춰 고정 (사전 빌드 이미지 또는 교체할 모듈 jar). 확보 후 확정
    vulnerable_image: str = ""        # 패치 전
    patched_image: str = ""           # 패치 후
    swap_modules: list[str] = field(default_factory=list)   # 모듈 교체 방식일 때 (예: system/framework/services.jar)
    snapshot: str = "clean"           # emulator 일 때만
    boot_timeout_sec: int = 300
    # 미리 빌드한 공용 instrumentation APK 변형 (TestCase.caller.apk_variant -> APK 경로)
    test_apks: dict[str, str] = field(default_factory=dict)
    # hidden API 정책 완화 여부 — 켠다면 패치 전/후 빌드에 똑같이 적용한다
    relax_hidden_api: bool = False


@dataclass
class Config:
    aosp_root: Path = Path("aosp/frameworks/base")
    # 정적 분석(M3·M6) 범위 — aosp_root 기준 glob. feature-spec 1장 "대상 (정적 분석)"
    scan_paths: list[str] = field(default_factory=lambda: list(DEFAULT_SCAN_PATHS))
    output_root: Path = Path("output")
    rules_dir: Path = Path("rules")
    baselines_dir: Path = Path("baselines")
    llm: LlmConfig = field(default_factory=LlmConfig)
    device: DeviceConfig = field(default_factory=DeviceConfig)

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        """config.yaml 로드. 파일이 없으면 기본값."""
        p = Path(path)
        if not p.is_file():
            return cls()
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as e:
            raise RuntimeError("config.yaml 을 읽으려면 PyYAML 이 필요합니다: pip install pyyaml") from e
        return cls.from_dict(yaml.safe_load(p.read_text()) or {})

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        cfg = cls()
        for f in dataclasses.fields(cls):
            if f.name not in data:
                continue
            value = data[f.name]
            current = getattr(cfg, f.name)
            if dataclasses.is_dataclass(current):
                setattr(cfg, f.name, type(current)(**value))
            elif isinstance(current, Path):
                setattr(cfg, f.name, Path(value))
            else:
                setattr(cfg, f.name, value)
        return cfg
