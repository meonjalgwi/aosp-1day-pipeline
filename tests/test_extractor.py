"""추출기 테스트: 기준선 2건은 ground_truth.json 과 비교, 나머지 유형은 작은 합성 소스로 확인."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aosp1day.analysis import Extractor

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sources"
TRUTH = {c["patch"]["cve"]: c for c in json.loads((ROOT / "baselines" / "ground_truth.json").read_text())["cases"]}


@pytest.fixture(scope="module")
def results():
    ex = Extractor()
    return {cve: ex.extract(FIXTURES / cve, cve_id=cve) for cve in TRUTH}


def _by_sig(d):
    return {(c["file"], c["signature"]): c for c in d["analysis"]["changes"]}


@pytest.mark.parametrize("cve", sorted(TRUTH))
def test_common_format_matches_ground_truth(results, cve):
    got, want = results[cve], TRUTH[cve]
    assert set(got) >= {"patch", "vuln_pattern", "rule"}
    assert set(got["vuln_pattern"]) == set(want["vuln_pattern"])
    assert got["patch"]["changed_files"] == want["patch"]["changed_files"]
    gv, wv = got["vuln_pattern"], want["vuln_pattern"]
    assert gv["pattern_type"] == wv["pattern_type"]
    assert gv["guard"]["types"] == wv["guard"]["types"]
    assert gv["guard"]["apis"] == wv["guard"]["apis"]
    assert got["analysis"]["suggested_template"] == want["rule"]["template_id"]


@pytest.mark.parametrize("cve", sorted(TRUTH))
def test_changed_methods_match_ground_truth(results, cve):
    got = _by_sig(results[cve])
    want = {(m["file"], m["signature"]): m for m in TRUTH[cve]["manual"]["changed_methods"]}
    assert set(got) == set(want), "변경 메서드 집합이 정답과 다름"
    for k, w in want.items():
        g = got[k]
        assert g["status"] == w["status"], k
        assert g["role"] == w["role"], k
        assert g["pattern_type"] == w["pattern_type"], k
        assert g["before"] == w["before"], k
        assert g["after"] == w["after"], k
        gg = [(x["type"], x["api"], x["line"], x.get("via_helper")) for x in g["added_guards"]]
        ww = [(x["type"], x["api"], x["line"], x.get("via_helper")) for x in w["added_guards"]]
        assert gg == ww, k


@pytest.mark.parametrize("cve", sorted(TRUTH))
def test_sink_matches_ground_truth(results, cve):
    got = {(s["file"], s["method"], s["call"], s["line"]) for s in results[cve]["vuln_pattern"]["sink"]}
    want = {(s["file"], s["method"], s["call"], s["after_line"]) for s in TRUTH[cve]["vuln_pattern"]["sink"]}
    assert got == want


def test_non_method_changes_are_not_methods(results):
    kinds = {(n["file"], n["kind"]) for n in results["CVE-2024-0037"]["analysis"]["non_method_changes"]}
    want = {(n["file"], n["kind"]) for n in TRUTH["CVE-2024-0037"]["manual"]["non_method_changes"]}
    assert want <= kinds


# --- 합성 소스: PRECONDITION_ADDITION / API_REPLACEMENT / OTHER / CALLER_UID --------------------

def _make(tmp_path: Path, before: str, after: str) -> Path:
    for side, body in (("before", before), ("after", after)):
        p = tmp_path / side / "pkg" / "Svc.java"
        p.parent.mkdir(parents=True)
        p.write_text("package pkg;\nclass Svc {\n" + body + "\n}\n")
    return tmp_path


def _one(tmp_path, before, after):
    d = Extractor().extract(_make(tmp_path, before, after), cve_id="T")
    assert len(d["analysis"]["changes"]) == 1
    return d, d["analysis"]["changes"][0]


def test_precondition_addition(tmp_path):
    before = "  void set(PendingIntent pi) {\n    mSession.setMediaButtonReceiver(pi);\n  }"
    after = ("  void set(PendingIntent pi) {\n    if (pi != null && pi.isActivity()) {\n      return;\n    }\n"
             "    mSession.setMediaButtonReceiver(pi);\n  }")
    d, c = _one(tmp_path, before, after)
    vp = d["vuln_pattern"]
    assert c["pattern_type"] == vp["pattern_type"] == "PRECONDITION_ADDITION"
    assert vp["precondition"][0]["text"] == "pi != null && pi.isActivity()"
    assert vp["target_api"][0]["call"] == "setMediaButtonReceiver"
    assert vp["guard"] is None and vp["sink"] is None
    assert d["analysis"]["suggested_template"] == "T2"


def test_api_replace(tmp_path):
    before = "  Object[] read(Parcel p) {\n    return p.readParcelableArray(mLoader);\n  }"
    after = "  Object[] read(Parcel p) {\n    return p.readParcelableArray(mLoader, Foo.class);\n  }"
    d, c = _one(tmp_path, before, after)
    vp = d["vuln_pattern"]
    assert c["pattern_type"] == vp["pattern_type"] == "API_REPLACEMENT"
    assert vp["unsafe_api"][0]["argc"] == 1 and vp["safe_api"][0]["argc"] == 2
    assert vp["safe_api"][0]["name"] == "readParcelableArray"
    assert d["analysis"]["suggested_template"] == "T3"


def test_unclassifiable_is_other(tmp_path):
    before = "  int f(int x) {\n    return x + 1;\n  }"
    after = "  int f(int x) {\n    return x + 2;\n  }"
    d, c = _one(tmp_path, before, after)
    assert c["pattern_type"] == d["vuln_pattern"]["pattern_type"] == "OTHER"
    assert d["analysis"]["suggested_template"] is None
    assert not c["formatting_only"]


def test_formatting_only_is_flagged(tmp_path):
    before = "  int f(int x,\n      int y) {\n    return x + y;\n  }"
    after = "  int f(\n      int x, int y) {\n    return x + y;\n  }"
    _, c = _one(tmp_path, before, after)
    assert c["pattern_type"] == "OTHER" and c["formatting_only"]


def test_calling_uid_counts_only_in_condition(tmp_path):
    before = "  void f() {\n    int uid = Binder.getCallingUid();\n    doIt(uid);\n  }"
    after = ("  void f() {\n    int uid = Binder.getCallingUid();\n"
             "    if (Binder.getCallingUid() != Process.SYSTEM_UID) {\n      throw new SecurityException();\n    }\n"
             "    doIt(uid);\n  }")
    d, c = _one(tmp_path, before, after)
    assert [g["type"] for g in c["added_guards"]] == ["CALLER_UID"]
    assert d["vuln_pattern"]["pattern_type"] == "GUARD_ADDITION"


def test_identity_only_is_not_a_guard(tmp_path):
    before = "  void f(String p) {\n    mStore.put(p);\n  }"
    after = ("  void f(String p) {\n    final long id = Binder.clearCallingIdentity();\n    try {\n"
             "      mStore.put(p);\n    } finally {\n      Binder.restoreCallingIdentity(id);\n    }\n  }")
    d, c = _one(tmp_path, before, after)
    assert {g["type"] for g in c["added_guards"]} == {"BINDER_IDENTITY"}
    assert c["pattern_type"] != "GUARD_ADDITION"
    assert d["analysis"]["added_guard_types"] == []
