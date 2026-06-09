"""
Parsers for tshark output.

Two formats matter:

1. PIPE-SEPARATED ROWS — produced by `tshark -T fields -e ... -E separator=|`.
   Each line is one packet/event with fields delimited by `|`. We parse these
   into list[dict] for the frontend's packet table.

2. DISSECTION TREE — produced by `tshark -V`. Indented hierarchical text where
   each level is indented by 4 spaces. We parse into a nested tree so the
   frontend can render an expand/collapse view.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# --- Pipe-separated row parser --------------------------------------------


def parse_pipe_rows(text: str, column_keys: list[str]) -> list[dict]:
    """Parse | separated lines into row dicts using the given column keys.

    Skips empty lines and our own truncation marker ("... [truncated").
    """
    rows: list[dict] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("..."):
            continue
        parts = line.split("|")
        # Pad if a field at the end was empty (tshark omits trailing empty fields).
        if len(parts) < len(column_keys):
            parts = parts + [""] * (len(column_keys) - len(parts))
        elif len(parts) > len(column_keys):
            # Extra pipes inside the last field (e.g. inside Info column).
            head = parts[: len(column_keys) - 1]
            tail = "|".join(parts[len(column_keys) - 1 :])
            parts = head + [tail]
        row = {key: parts[i].strip() for i, key in enumerate(column_keys)}
        rows.append(row)
    return rows


# --- Dissection-tree parser ----------------------------------------------


@dataclass
class TreeNode:
    """One node in a parsed dissection tree."""

    text: str
    children: list["TreeNode"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "children": [c.to_dict() for c in self.children],
        }


def parse_dissection_tree(text: str) -> list[dict]:
    """Parse `tshark -V` output into a hierarchical tree.

    tshark -V indents children with leading spaces. The root level starts at
    column 0 ("Frame 1234:", "Ethernet II,", "Internet Protocol Version 4,",
    etc.). Each deeper level is typically 4 more spaces, but we don't assume
    a fixed step — we use the actual indent values to nest.
    """
    root_children: list[TreeNode] = []
    # Stack of (parent_children_list, indent_of_those_children's_parent).
    # Indent -1 represents the virtual root above column 0.
    stack: list[tuple[list[TreeNode], int]] = [(root_children, -1)]

    for raw in text.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.lstrip(" ")

        # Pop deeper-or-equal levels off the stack.
        while stack and stack[-1][1] >= indent:
            stack.pop()
        if not stack:
            # Should not happen; recover by attaching to root.
            stack.append((root_children, -1))

        parent_children = stack[-1][0]
        node = TreeNode(text=content)
        parent_children.append(node)
        stack.append((node.children, indent))

    return [n.to_dict() for n in root_children]
