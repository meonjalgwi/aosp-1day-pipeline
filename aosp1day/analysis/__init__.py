"""정적 분석 공통 모듈 (Tree-sitter 기반). M2 추출기·Guard 사전이 여기 있다."""

from .extractor import Extractor, extract_to_file
from .guards import GuardDictionary

__all__ = ["Extractor", "GuardDictionary", "extract_to_file"]
