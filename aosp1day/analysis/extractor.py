"""패치 전·후 소스에서 수정 패턴을 뽑는 추출기 (5주차 B, F-201~F-203).

입력: ``sources/<CVE>/{before,after}/<저장소 상대 경로>.java`` (+ 있으면 ``sources/<CVE>/patch.diff``)
출력: ``patterns/<CVE>.json`` - 팀 공통 JSON 형식 (``patch`` / ``vuln_pattern`` / ``rule``).
      ``rule`` 은 C(규칙 템플릿·차분 검증)가 채운다. 추출 세부 결과(변경 메서드, 추가·삭제 조건문,
      호출 API 변화, 추가된 보안 검사, sink 후보)는 ``analysis`` 에 둔다.

판정은 전부 결정적 규칙이다 (LLM 없음). 분류할 수 없으면 추측하지 않고 ``OTHER``.

pattern_type 규칙 (변경 메서드 하나 기준, 위에서부터 처음 맞는 것):
  1. GUARD_ADDITION - 패치 후 Guard 호출 지점(유형, 호출 이름)이 패치 전보다 많아짐.
     같은 변경 묶음(커밋)에 정의된 헬퍼 메서드는 ``follow_depth`` 단계까지 따라가 본문의 Guard 를 센다.
     BINDER_IDENTITY(clearCallingIdentity 류)만 늘어난 것은 Guard 추가로 보지 않는다.
  2. PRECONDITION_ADDITION - 사전에 없는 조건이지만 then 쪽이 return/throw/continue/break 인 if 가 추가됨.
  3. API_REPLACEMENT - 같은 이름의 호출이 인자 수만 바뀌어 빠지고 들어옴.
  4. OTHER - 그 밖 (형식만 바뀐 경우 ``formatting_only`` 표시).
CVE 전체 pattern_type 는 헬퍼가 아닌 변경 중 가장 높은 것 (GUARD_ADDITION > PRECONDITION_ADDITION > API_REPLACEMENT > OTHER).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .diffparse import FileDiff, diff_files, parse_unified
from .guards import GuardDictionary
from .java_ast import Call, Method, normalize, parse_methods

FIX_KINDS = ("GUARD_ADDITION", "PRECONDITION_ADDITION", "API_REPLACEMENT", "OTHER")
# 패치 유형 -> C 의 T1 템플릿 3종 (perm_guard: Guard 없는 Sink, api_guard: API 앞 검사 누락, api_usage: 위험 API 잔존)
TEMPLATE_OF = {"GUARD_ADDITION": "perm_guard", "PRECONDITION_ADDITION": "api_guard",
               "API_REPLACEMENT": "api_usage", "OTHER": None}
SCHEMA_VERSION = "0.1"


@dataclass
class GuardHit:
    type: str
    api: str            # 호출 지점의 메서드 이름 (헬퍼면 헬퍼 이름)
    line: int
    snippet: str
    via: list[str]      # 헬퍼를 따라간 경로, 예: ["enforceCallingPackage", "getPackageUid"]

    def to_dict(self) -> dict:
        d = {"type": self.type, "api": self.api, "line": self.line, "snippet": self.snippet}
        if self.via:
            d["via_helper"] = " → ".join(self.via)
        return d


class Extractor:
    def __init__(self, dictionary: GuardDictionary | None = None, follow_depth: int = 2) -> None:
        self.gd = dictionary or GuardDictionary.load()
        self.follow_depth = follow_depth

    # --- 진입점 ------------------------------------------------------------

    def extract(self, sources: Path | str, cve_id: str = "", commit: str = "", parent: str = "",
                repository: str = "") -> dict:
        sources = Path(sources)
        before_root, after_root = sources / "before", sources / "after"
        diffs = self._load_diffs(sources, before_root, after_root)
        java = sorted(p for p in diffs if p.endswith(".java"))
        skipped = sorted(p for p in diffs if not p.endswith(".java"))

        methods = {"before": {}, "after": {}}
        for side, root in (("before", before_root), ("after", after_root)):
            for rel in java:
                f = root / rel
                methods[side][rel] = parse_methods(f, rel) if f.is_file() else []
        index = {side: self._index(ms) for side, ms in methods.items()}

        changes: list[dict] = []
        non_method: list[dict] = []
        for rel in java:
            fd = diffs[rel]
            pairs, loose_removed, loose_added = self._pair_changed(methods["before"][rel], methods["after"][rel], fd)
            for b, a in pairs:
                changes.append(self._analyze(b, a, fd, index))
            non_method.extend(self._non_method(rel, fd, loose_removed, loose_added))

        for i, c in enumerate(changes, 1):
            c["id"] = f"chg-{i}"
        self._mark_helpers(changes)

        primary = [c for c in changes if c["role"] != "helper"] or changes
        kind = next((k for k in FIX_KINDS if any(c["pattern_type"] == k for c in primary)), "OTHER")
        guard_types = self.gd.order({g["type"] for c in changes for g in c["added_guards"]
                                     if not self.gd.is_identity_only(g["type"])})
        return {
            "schema_version": SCHEMA_VERSION,
            "patch": {
                "cve": cve_id,
                "commit": commit,
                "parent_commit": parent,
                "repository": repository,
                "changed_files": sorted(diffs),
                "support_status": "",        # A 가 cve_inventory.json 에서 정함 (READY 등)
                "exclude_reason": "",
            },
            "vuln_pattern": self._vuln_pattern(kind, guard_types, changes),
            "rule": {
                "template_id": "",           # 이하 C 가 채움
                "rule_body": "",
                "before_target_match": False,
                "after_target_match": False,
                "after_other_match_count": 0,
                "validation_status": "",
            },
            "analysis": {
                "generator": "aosp1day.analysis.extractor",
                "sources": str(sources),
                "suggested_template": TEMPLATE_OF[kind],
                "added_guard_types": guard_types,
                "changes": changes,
                "non_method_changes": non_method,
                "skipped_files": skipped,
            },
        }

    # --- 입력 ---------------------------------------------------------------

    def _load_diffs(self, sources: Path, before_root: Path, after_root: Path) -> dict[str, FileDiff]:
        patch = sources / "patch.diff"
        if patch.is_file():
            return parse_unified(patch.read_text(encoding="utf-8", errors="replace"))
        rels = {str(p.relative_to(r)) for r in (before_root, after_root) if r.is_dir()
                for p in r.rglob("*") if p.is_file()}
        out = {}
        for rel in sorted(rels):
            fd = diff_files(before_root / rel, after_root / rel, rel)
            if fd.added or fd.removed:
                out[rel] = fd
        return out

    @staticmethod
    def _index(by_file: dict[str, list[Method]]) -> dict[str, list[Method]]:
        idx: dict[str, list[Method]] = defaultdict(list)
        for ms in by_file.values():
            for m in ms:
                idx[m.name].append(m)
        return idx

    # --- 변경 메서드 찾기 ---------------------------------------------------

    @staticmethod
    def _touched(m: Method, lines: set[int]) -> bool:
        return any(m.start_line <= l <= m.end_line for l in lines)

    def _pair_changed(self, before: list[Method], after: list[Method], fd: FileDiff):
        """변경 줄을 포함하는 메서드를 전·후로 짝짓는다. 가장 안쪽 메서드만 센다."""
        tb = self._innermost(before, fd.removed)
        ta = self._innermost(after, fd.added)
        # 한쪽만 바뀌어도(예: 줄 추가만) 반대쪽 같은 메서드를 찾아 짝지음
        b_by_key = {m.key: m for m in before}
        a_by_key = {m.key: m for m in after}
        keys: list[str] = []
        for m in tb + ta:
            if m.key not in keys:
                keys.append(m.key)
        pairs, used_b, used_a = [], set(), set()
        for k in keys:
            b, a = b_by_key.get(k), a_by_key.get(k)
            pairs.append((b, a))
            used_b.add(k)
            used_a.add(k)
        # 시그니처가 바뀐 메서드: 이름이 같은 removed/added 하나씩이면 짝지음
        only_b = [p for p in pairs if p[1] is None]
        only_a = [p for p in pairs if p[0] is None]
        for pb in list(only_b):
            cands = [pa for pa in only_a if pa[1].name == pb[0].name and pa[1].cls == pb[0].cls]
            if len(cands) == 1:
                pa = cands[0]
                pairs.remove(pb)
                pairs[pairs.index(pa)] = (pb[0], pa[1])
                only_a.remove(pa)
        in_b = {l for m in tb for l in range(m.start_line, m.end_line + 1)}
        in_a = {l for m in ta for l in range(m.start_line, m.end_line + 1)}
        loose_removed = sorted(fd.removed - in_b)
        loose_added = sorted(fd.added - in_a)
        return pairs, loose_removed, loose_added

    def _innermost(self, ms: list[Method], lines: set[int]) -> list[Method]:
        out = []
        for l in sorted(lines):
            hits = [m for m in ms if m.start_line <= l <= m.end_line]
            if hits:
                m = min(hits, key=lambda m: m.end_line - m.start_line)
                if m not in out:
                    out.append(m)
        return out

    def _non_method(self, rel: str, fd: FileDiff, removed: list[int], added: list[int]) -> list[dict]:
        out = []
        for side, lines, texts in (("before", removed, fd.removed_text), ("after", added, fd.added_text)):
            for grp in _groups(lines):
                body = [texts.get(l, "") for l in grp]
                code = [t for t in body if t.strip()]
                if not code:
                    continue                # 빈 줄만 바뀐 것은 기록하지 않는다
                if all(t.strip().startswith("import ") for t in code):
                    kind = "import"
                else:
                    kind = "class_member"   # 필드 선언·형식 변경 등 메서드 밖 코드
                out.append({"file": rel, "side": side, "start_line": grp[0], "end_line": grp[-1],
                            "kind": kind, "snippet": "\n".join(body)})
        return out

    # --- 변경 하나 분석 -----------------------------------------------------

    def _analyze(self, b: Method | None, a: Method | None, fd: FileDiff, index) -> dict:
        ref = a or b
        status = "modified" if (a and b) else ("added" if a else "removed")
        c: dict[str, Any] = {
            "id": "",
            "file": ref.file,
            "class": ref.cls,
            "method": ref.name,
            "signature": ref.signature,
            "params": [{"type": t, "name": n} for t, n in ref.params],
            "status": status,
            "before": _range(b), "after": _range(a),
        }

        cb = b.conditions() if b else []
        ca = a.conditions() if a else []
        add_conds = _multiset_minus(ca, cb, key=lambda x: x.text)
        rem_conds = _multiset_minus(cb, ca, key=lambda x: x.text)
        c["added_conditions"] = [_cond(x) for x in add_conds]
        c["removed_conditions"] = [_cond(x) for x in rem_conds]

        callsb = [x for x in (b.calls() if b else []) if not self.gd.is_noise(x)]
        callsa = [x for x in (a.calls() if a else []) if not self.gd.is_noise(x)]
        add_calls = _multiset_minus(callsa, callsb, key=_call_key)
        rem_calls = _multiset_minus(callsb, callsa, key=_call_key)
        c["added_calls"] = [_call(x) for x in add_calls]
        c["removed_calls"] = [_call(x) for x in rem_calls]
        c["replaced_calls"] = _replaced(rem_calls, add_calls)

        gb = self._guards(b, index["before"]) if b else []
        ga = self._guards(a, index["after"]) if a else []
        c["guards_before"] = self.gd.order({g.type for g in gb})
        c["guards_after"] = self.gd.order({g.type for g in ga})
        added_g = _multiset_minus(ga, gb, key=lambda g: (g.type, g.api))
        removed_g = _multiset_minus(gb, ga, key=lambda g: (g.type, g.api))
        # 개수가 늘어난 키에서는 실제로 + 줄에 있는 호출 지점을 근거로 고른다
        added_g = _prefer_lines(added_g, ga, fd.added)
        c["added_guards"] = [g.to_dict() for g in added_g]
        c["removed_guards"] = [g.to_dict() for g in removed_g]

        real_guards = [g for g in added_g if not self.gd.is_identity_only(g.type)]
        early = [x for x in add_conds if x.early_exit]
        if real_guards:
            kind = "GUARD_ADDITION"
        elif early:
            kind = "PRECONDITION_ADDITION"
        elif c["replaced_calls"]:
            kind = "API_REPLACEMENT"
        else:
            kind = "OTHER"
        c["pattern_type"] = kind
        c["formatting_only"] = bool(a and b and normalize(a.text) == normalize(b.text))
        c["role"] = "changed"

        anchor = [g.line for g in real_guards] + [x.line for x in early]
        c["sink_candidates"] = self._sinks(a, min(anchor)) if (a and anchor) else []
        c["evidence"] = {
            "before_snippet": _lines_of(b, fd.removed, fd.removed_text),
            "after_snippet": _lines_of(a, fd.added, fd.added_text),
        }
        return c

    def _guards(self, m: Method, index: dict[str, list[Method]], depth: int | None = None,
                seen: frozenset = frozenset()) -> list[GuardHit]:
        depth = self.follow_depth if depth is None else depth
        hits: list[GuardHit] = []
        seen = seen | {m.key}
        for call in m.calls():
            types: dict[str, list[str]] = {t: [] for t in self.gd.match(call)}
            if depth > 0:
                for h in index.get(call.name, []):
                    if h.key in seen:
                        continue
                    for sub in self._guards(h, index, depth - 1, seen):
                        if not types.get(sub.type):   # 헬퍼 경로가 있으면 근거로 남긴다
                            types[sub.type] = [call.name] + (sub.via or [sub.api])
            for t in self.gd.apply_suppression(set(types)):
                hits.append(GuardHit(type=t, api=call.name, line=call.line, snippet=call.text,
                                     via=types[t]))
        return hits

    def _sinks(self, a: Method, anchor_line: int, top: int = 5) -> list[dict]:
        calls = a.calls()
        clear = [x.line for x in calls if x.name in ("clearCallingIdentity",)]
        restore = [x.line for x in calls if x.name in ("restoreCallingIdentity",)]
        regions = [(s, min([r for r in restore if r > s], default=a.end_line)) for s in clear]
        params = {n for _, n in a.params}
        out = []
        for x in calls:
            if x.line <= anchor_line or self.gd.is_noise(x) or self.gd.is_guard_api(x.name):
                continue
            in_id = any(s < x.line < e for s, e in regions)
            uses = sorted({p for p in params for arg in x.args if _mentions(arg, p)})
            score = 2 * in_id + len(uses)
            if score == 0:
                continue
            reasons = []
            if in_id:
                reasons.append("clearCallingIdentity 구간 안")
            if uses:
                reasons.append("메서드 파라미터 사용: " + ", ".join(uses))
            out.append({"call": x.name, "line": x.line, "snippet": x.text, "score": score,
                        "reason": " · ".join(reasons)})
        out.sort(key=lambda s: (-s["score"], s["line"]))
        for i, s in enumerate(out[:top], 1):
            s["rank"] = i
        return out[:top]

    def _mark_helpers(self, changes: list[dict]) -> None:
        """다른 변경에서 새로 호출되는 추가 메서드는 helper 로 표시."""
        called = {x["name"] for c in changes for x in c["added_calls"]}
        for c in changes:
            if c["status"] == "added" and c["method"] in called:
                c["role"] = "helper"

    def _vuln_pattern(self, kind: str, guard_types: list[str], changes: list[dict]) -> dict:
        """공통 형식 vuln_pattern. 유형마다 필요한 필드만 채우고 나머지는 null.

        위치가 여러 곳일 수 있는 값(sink, precondition, target_api, unsafe_api, safe_api)은 리스트.
        source 는 정적으로 확정하지 않는다: 변경 메서드 파라미터를 후보로만 남기고, 확정은 ground_truth 에서 한다.
        """
        main = [c for c in changes if c["role"] != "helper" and c["pattern_type"] == kind]
        vp: dict[str, Any] = {"pattern_type": kind, "source": None, "guard": None, "sink": None,
                              "precondition": None, "target_api": None,
                              "unsafe_api": None, "safe_api": None, "evidence": []}

        def loc(c, **kw):
            return {"file": c["file"], "method": c["signature"], **kw}

        def top_sinks():
            return [loc(c, call=s["call"], line=s["line"], snippet=s["snippet"], reason=s["reason"])
                    for c in main for s in c["sink_candidates"][:1]]

        if kind == "GUARD_ADDITION":
            vp["source"] = {"status": "candidate",
                            "candidates": [loc(c, params=c["params"]) for c in main]}
            hits = [(c, g) for c in main for g in c["added_guards"] if not self.gd.is_identity_only(g["type"])]
            vp["guard"] = {"types": guard_types, "apis": sorted({g["api"] for _, g in hits}),
                           "locations": [loc(c, **{k: g[k] for k in ("type", "api", "line", "snippet", "via_helper")
                                                   if k in g}) for c, g in hits]}
            vp["sink"] = top_sinks()
            vp["evidence"] = [loc(c, side="after", line=g["line"], snippet=g["snippet"], what="added_guard")
                              for c, g in hits]
        elif kind == "PRECONDITION_ADDITION":
            conds = [(c, x) for c in main for x in c["added_conditions"] if x["early_exit"]]
            vp["precondition"] = [loc(c, text=x["text"], line=x["line"], exit=x.get("exit", "")) for c, x in conds]
            vp["target_api"] = top_sinks()
            vp["evidence"] = [loc(c, side="after", line=x["line"], snippet=x["text"], what="added_condition")
                              for c, x in conds]
        elif kind == "API_REPLACEMENT":
            reps = [(c, r) for c in main for r in c["replaced_calls"]]
            vp["unsafe_api"] = [loc(c, name=r["name"], argc=r["before_argc"], line=r["before_line"], snippet=r["before"])
                                for c, r in reps]
            vp["safe_api"] = [loc(c, name=r["name"], argc=r["after_argc"], line=r["after_line"], snippet=r["after"])
                              for c, r in reps]
            vp["evidence"] = [loc(c, side="after", line=r["after_line"], snippet=r["after"], what="replaced_call")
                              for c, r in reps]
        else:
            vp["evidence"] = [loc(c, side="after", snippet=c["evidence"]["after_snippet"], what="diff")
                              for c in changes if not c["formatting_only"]]
        return vp


# --- 작은 도우미 ---------------------------------------------------------------

def _range(m: Method | None) -> dict | None:
    if m is None:
        return None
    return {"start_line": m.start_line, "end_line": m.end_line}


def _cond(x) -> dict:
    d = {"kind": x.kind, "text": x.text, "line": x.line, "early_exit": x.early_exit}
    if x.exit_kind:
        d["exit"] = x.exit_kind
    return d


def _call_key(x: Call) -> tuple[str, int]:
    return (x.name, len(x.args))


def _call(x: Call) -> dict:
    return {"name": x.name, "argc": len(x.args), "receiver": x.receiver, "line": x.line, "snippet": x.text}


def _multiset_minus(xs: list, ys: list, key) -> list:
    """xs 에서 ys 에 있는 만큼 뺀 나머지 (순서 유지)."""
    budget = Counter(key(y) for y in ys)
    out = []
    for x in xs:
        k = key(x)
        if budget[k] > 0:
            budget[k] -= 1
        else:
            out.append(x)
    return out


def _prefer_lines(picked: list[GuardHit], all_after: list[GuardHit], added_lines: set[int]) -> list[GuardHit]:
    out = []
    for g in picked:
        same = [h for h in all_after if (h.type, h.api) == (g.type, g.api) and h.line in added_lines
                and h not in out]
        out.append(same[0] if same else g)
    return out


def _replaced(removed: list[Call], added: list[Call]) -> list[dict]:
    out = []
    rem_by = defaultdict(list)
    for r in removed:
        rem_by[r.name].append(r)
    for a in added:
        for r in rem_by.get(a.name, []):
            if len(r.args) != len(a.args):
                out.append({"name": a.name, "before_argc": len(r.args), "after_argc": len(a.args),
                            "before": r.text, "after": a.text, "before_line": r.line, "after_line": a.line})
                rem_by[a.name].remove(r)
                break
    return out


def _mentions(arg: str, name: str) -> bool:
    import re
    return re.search(rf"(?<![\w.]){re.escape(name)}(?!\w)", arg) is not None


def _groups(lines: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for l in lines:
        if out and l == out[-1][-1] + 1:
            out[-1].append(l)
        else:
            out.append([l])
    return out


def _lines_of(m: Method | None, lines: set[int], texts: dict[int, str]) -> str:
    if m is None:
        return ""
    picked = [l for l in sorted(lines) if m.start_line <= l <= m.end_line]
    return "\n".join(f"{l}: {texts.get(l, '')}" for l in picked)


def extract_to_file(sources: Path | str, out: Path | str, **kw) -> Path:
    data = Extractor(follow_depth=kw.pop("follow_depth", 2)).extract(sources, **kw)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out
