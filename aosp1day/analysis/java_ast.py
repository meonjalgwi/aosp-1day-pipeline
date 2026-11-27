"""Tree-sitter(Java) 위에 얇게 감싼 구문 정보 추출.

M2 추출기가 쓰는 것만 담는다: 메서드 목록(클래스 경로·시그니처·줄 범위), 메서드 안의
호출(이름·receiver·인자·조건식 안 여부), 조건문(if/while/삼항)과 조기 종료 여부.
줄 번호는 모두 1부터 시작한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

try:
    import tree_sitter_java as _tsjava
    from tree_sitter import Language, Node, Parser
except ImportError as e:  # pragma: no cover - 안내용
    raise ImportError('Tree-sitter 가 필요합니다: pip install -e ".[analysis]"') from e


@lru_cache(maxsize=1)
def _parser() -> Parser:
    return Parser(Language(_tsjava.language()))


_WS = re.compile(r"\s+")
_PUNCT_WS = re.compile(r"\s*([()\[\]{},;.])\s*")
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def normalize(code: str) -> str:
    """주석·공백 차이를 없앤 비교용 문자열."""
    s = _WS.sub(" ", _COMMENT.sub(" ", code)).strip()
    return _PUNCT_WS.sub(r"\1", s).replace(",", ", ")


_CLASS_TYPES = ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration")
_METHOD_TYPES = ("method_declaration", "constructor_declaration")
_COND_PARENTS = ("if_statement", "while_statement", "do_statement", "ternary_expression")
_COMPARE_OPS = ("==", "!=", "<", ">", "<=", ">=")
_EXIT_TYPES = ("return_statement", "throw_statement", "continue_statement", "break_statement")


@dataclass
class Call:
    name: str
    receiver: str
    args: list[str]
    line: int
    text: str
    in_condition: bool


@dataclass
class Condition:
    kind: str           # if | while | do | ternary
    text: str           # 조건식 원문 (괄호 제외, 공백 정규화)
    line: int
    early_exit: bool    # then 쪽이 return/throw/continue/break 로 끝남
    exit_kind: str = ""


@dataclass
class Method:
    file: str
    cls: str            # 바깥 클래스부터 '.' 로 이은 경로 (예: Outer.Inner)
    name: str
    params: list[tuple[str, str]]   # (타입, 이름)
    start_line: int
    end_line: int
    node: Node = field(repr=False)
    source: bytes = field(repr=False)

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(t for t, _ in self.params)})"

    @property
    def key(self) -> str:
        return f"{self.cls}.{self.signature}"

    @property
    def text(self) -> str:
        return self.source[self.node.start_byte:self.node.end_byte].decode("utf-8", "replace")

    def body_text(self) -> str:
        body = self.node.child_by_field_name("body")
        return _txt(self.source, body) if body else ""

    def calls(self) -> list[Call]:
        return list(_iter_calls(self.node, self.source))

    def conditions(self) -> list[Condition]:
        return list(_iter_conditions(self.node, self.source))


def _txt(src: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _simple_type(t: str) -> str:
    t = re.sub(r"@\w+(\([^)]*\))?\s*", "", t)          # 타입 어노테이션 제거
    t = re.sub(r"<.*>", "", t)                          # 제네릭 제거
    return t.split(".")[-1].replace(" ", "")


def _params(node: Node, src: bytes) -> list[tuple[str, str]]:
    out = []
    plist = node.child_by_field_name("parameters")
    if plist is None:
        return out
    for p in plist.named_children:
        if p.type not in ("formal_parameter", "spread_parameter"):
            continue
        t = p.child_by_field_name("type")
        n = p.child_by_field_name("name")
        tt = _simple_type(_txt(src, t)) if t else ""
        if p.type == "spread_parameter":
            tt += "..."
            if n is None:  # spread_parameter 는 variable_declarator 안에 이름이 있다
                for c in p.named_children:
                    if c.type == "variable_declarator":
                        n = c.child_by_field_name("name")
        out.append((tt, _txt(src, n)))
    return out


def _class_path(node: Node, src: bytes) -> str:
    names = []
    cur = node.parent
    while cur is not None:
        if cur.type in _CLASS_TYPES:
            names.append(_txt(src, cur.child_by_field_name("name")))
        cur = cur.parent
    return ".".join(reversed(names))


def parse_methods(path: Path | str, rel: str = "") -> list[Method]:
    """파일 하나의 메서드·생성자 목록. 익명 클래스 안 메서드도 포함."""
    src = Path(path).read_bytes()
    return parse_methods_src(src, rel or str(path))


def parse_methods_src(src: bytes, rel: str) -> list[Method]:
    tree = _parser().parse(src)
    out: list[Method] = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in _METHOD_TYPES:
            name = _txt(src, n.child_by_field_name("name"))
            out.append(Method(file=rel, cls=_class_path(n, src), name=name, params=_params(n, src),
                              start_line=_start_line_with_doc(n), end_line=n.end_point[0] + 1,
                              node=n, source=src))
        stack.extend(reversed(n.children))
    out.sort(key=lambda m: m.start_line)
    return out


def _start_line_with_doc(n: Node) -> int:
    """메서드 앞 javadoc 은 diff 에서 메서드 일부로 보이므로 범위에 포함한다."""
    line = n.start_point[0] + 1
    prev = n.prev_sibling
    while prev is not None and prev.type in ("block_comment", "line_comment") \
            and prev.end_point[0] + 1 >= line - 1:
        line = prev.start_point[0] + 1
        prev = prev.prev_sibling
    return line


def _in_condition(node: Node) -> bool:
    cur = node
    while cur.parent is not None:
        p = cur.parent
        if p.type in _METHOD_TYPES or p.type in ("lambda_expression", "class_body"):
            return False
        if p.type == "binary_expression":
            op = p.child_by_field_name("operator")
            if op is not None and op.type in _COMPARE_OPS:
                return True
        if p.type in _COND_PARENTS and p.child_by_field_name("condition") == cur:
            return True
        cur = p
    return False


def _iter_calls(root: Node, src: bytes):
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "method_invocation":
            args_node = n.child_by_field_name("arguments")
            args = [normalize(_txt(src, a)) for a in args_node.named_children] if args_node else []
            yield Call(name=_txt(src, n.child_by_field_name("name")),
                       receiver=normalize(_txt(src, n.child_by_field_name("object"))),
                       args=args, line=n.start_point[0] + 1,
                       text=normalize(_txt(src, n)), in_condition=_in_condition(n))
        elif n.type == "object_creation_expression":
            pass
        stack.extend(reversed(n.children))


def _exit_of(stmt: Node | None) -> str:
    """then 블록이 조기 종료로 끝나면 그 종류."""
    if stmt is None:
        return ""
    if stmt.type in _EXIT_TYPES:
        return stmt.type.replace("_statement", "")
    if stmt.type == "block":
        kids = [c for c in stmt.named_children if c.type not in ("line_comment", "block_comment")]
        if kids:
            return _exit_of(kids[-1])
    return ""


def _iter_conditions(root: Node, src: bytes):
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in _COND_PARENTS:
            cond = n.child_by_field_name("condition")
            text = normalize(_txt(src, cond))
            if text.startswith("(") and text.endswith(")"):
                text = text[1:-1].strip()
            exit_kind = _exit_of(n.child_by_field_name("consequence")) if n.type == "if_statement" else ""
            yield Condition(kind=n.type.split("_")[0], text=text, line=n.start_point[0] + 1,
                            early_exit=bool(exit_kind), exit_kind=exit_kind)
        stack.extend(reversed(n.children))
