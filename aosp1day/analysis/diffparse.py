"""unified diff -> 파일별 변경 줄 번호.

patch.diff 가 있으면 그것을 쓰고, 없으면 before/after 파일을 difflib 로 비교한다.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class FileDiff:
    path: str
    removed: set[int] = field(default_factory=set)   # before 줄 번호 ("-" 줄)
    added: set[int] = field(default_factory=set)     # after 줄 번호 ("+" 줄)
    removed_text: dict[int, str] = field(default_factory=dict)
    added_text: dict[int, str] = field(default_factory=dict)


def parse_unified(text: str) -> dict[str, FileDiff]:
    files: dict[str, FileDiff] = {}
    cur: FileDiff | None = None
    old = new = 0
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            cur = files.setdefault(path, FileDiff(path))
            continue
        if line.startswith("--- ") or line.startswith("diff --git") or line.startswith("index "):
            continue
        m = _HUNK.match(line)
        if m:
            old, new = int(m.group(1)), int(m.group(3))
            continue
        if cur is None or not line:
            if cur is not None and not line:  # 빈 context 줄 (공백이 잘린 경우)
                old += 1
                new += 1
            continue
        tag, body = line[0], line[1:]
        if tag == "-":
            cur.removed.add(old)
            cur.removed_text[old] = body
            old += 1
        elif tag == "+":
            cur.added.add(new)
            cur.added_text[new] = body
            new += 1
        elif tag == "\\":
            continue
        else:
            old += 1
            new += 1
    return files


def diff_files(before: Path | None, after: Path | None, rel: str) -> FileDiff:
    a = before.read_text().splitlines() if before and before.is_file() else []
    b = after.read_text().splitlines() if after and after.is_file() else []
    fd = FileDiff(rel)
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            for i in range(i1, i2):
                fd.removed.add(i + 1)
                fd.removed_text[i + 1] = a[i]
        if tag in ("replace", "insert"):
            for j in range(j1, j2):
                fd.added.add(j + 1)
                fd.added_text[j + 1] = b[j]
    return fd
