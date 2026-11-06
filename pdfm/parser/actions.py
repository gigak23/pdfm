"""Resolve which actions run, and what triggers them.

Keyword counts say "this file has /JavaScript and an /OpenAction" but not
whether the OpenAction runs the JavaScript or just sets the zoom level. This
module walks every trigger point to the action dictionaries it fires, so
analyzers can tell "JS runs the moment the file opens" from "JS validates a
form field". Requires pikepdf; raw mode only gets keyword-level triage.
"""

from __future__ import annotations

from dataclasses import dataclass

import pikepdf

MAX_DEPTH = 32

# Document-level /AA events (ISO 32000-1 table 197) and page events (table 195).
DOC_EVENTS = {"/WC": "before close", "/WS": "before save", "/DS": "after save",
              "/WP": "before print", "/DP": "after print"}
PAGE_EVENTS = {"/O": "page open", "/C": "page close"}


@dataclass
class Action:
    trigger: str  # human-readable, e.g. "OpenAction" or "Page 1 /AA page open"
    type: str  # value of /S, e.g. "JavaScript", "URI", "Launch"
    ref: str  # the action's own ref if indirect, else the object that contains it
    on_open: bool  # runs without user interaction when the document is opened
    obj: pikepdf.Dictionary


def _ref(obj: pikepdf.Object, fallback: str) -> str:
    if obj.is_indirect:
        num, gen = obj.objgen
        return f"{num} {gen} R"
    return fallback


def _name(value) -> str:
    return str(value).lstrip("/") if isinstance(value, pikepdf.Name) else "?"


class _Resolver:
    def __init__(self) -> None:
        self.actions: list[Action] = []
        self.seen: set[tuple[int, int]] = set()
        self.holders: set[tuple[int, int]] = set()

    def first_visit(self, holder: pikepdf.Object) -> bool:
        """Widget annotations are also form fields; only process each holder once."""
        if not holder.is_indirect:
            return True
        if holder.objgen in self.holders:
            return False
        self.holders.add(holder.objgen)
        return True

    def visit(self, action, trigger: str, container: str, on_open: bool, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            return
        if isinstance(action, pikepdf.Array):
            for item in action:
                self.visit(item, trigger, container, on_open, depth + 1)
            return
        if not isinstance(action, pikepdf.Dictionary) or "/S" not in action:
            return  # e.g. an OpenAction that is just a destination array
        if action.is_indirect:
            if action.objgen in self.seen:  # /Next loops are a known parser-DoS trick
                return
            self.seen.add(action.objgen)
        ref = _ref(action, container)
        self.actions.append(Action(trigger, _name(action.get("/S")), ref, on_open, action))
        if "/Next" in action:
            self.visit(action.Next, f"{trigger} -> Next", ref, on_open, depth + 1)

    def visit_aa(self, aa, trigger: str, container: str, events: dict[str, str], open_keys=()) -> None:
        if not isinstance(aa, pikepdf.Dictionary):
            return
        for key, action in aa.items():
            label = events.get(key, key.lstrip("/"))
            self.visit(action, f"{trigger} /AA {label}", container, on_open=key in open_keys)


def resolve(pdf: pikepdf.Pdf) -> list[Action]:
    r = _Resolver()
    root = pdf.Root
    root_ref = _ref(root, "Root")

    if "/OpenAction" in root:
        r.visit(root.OpenAction, "OpenAction", root_ref, on_open=True)
    r.visit_aa(root.get("/AA"), "Document", root_ref, DOC_EVENTS)

    # Document-level scripts in the /Names /JavaScript tree run when the file opens.
    names = root.get("/Names")
    if isinstance(names, pikepdf.Dictionary) and "/JavaScript" in names:
        for action in _name_tree_values(names.JavaScript):
            r.visit(action, "Document-level script", root_ref, on_open=True)

    try:
        pages = list(pdf.pages)
    except (pikepdf.PdfError, TypeError):
        pages = []  # a broken page tree shouldn't stop the rest of the analysis
    for number, page in enumerate(pages, 1):
        page_obj = page.obj
        page_ref = _ref(page_obj, f"page {number}")
        # Only the first page is opened without user interaction.
        r.visit_aa(page_obj.get("/AA"), f"Page {number}", page_ref, PAGE_EVENTS,
                   open_keys=("/O",) if number == 1 else ())
        annots = page_obj.get("/Annots")
        if isinstance(annots, pikepdf.Array):
            for annot in annots:
                if not isinstance(annot, pikepdf.Dictionary) or not r.first_visit(annot):
                    continue
                annot_ref = _ref(annot, page_ref)
                subtype = _name(annot.get("/Subtype"))
                if "/A" in annot:
                    r.visit(annot.A, f"{subtype} annotation on page {number}", annot_ref, on_open=False)
                r.visit_aa(annot.get("/AA"), f"{subtype} annotation on page {number}", annot_ref, {})

    acroform = root.get("/AcroForm")
    if isinstance(acroform, pikepdf.Dictionary):
        for field in _walk_fields(acroform.get("/Fields")):
            if not r.first_visit(field):
                continue
            field_ref = _ref(field, "AcroForm")
            label = f"form field {field.get('/T', '?')}"
            if "/A" in field:
                r.visit(field.A, label, field_ref, on_open=False)
            r.visit_aa(field.get("/AA"), label, field_ref, {})
    return r.actions


def _name_tree_values(node, depth: int = 0):
    if depth > MAX_DEPTH or not isinstance(node, pikepdf.Dictionary):
        return
    names = node.get("/Names")
    if isinstance(names, pikepdf.Array):
        for i in range(1, len(names), 2):
            yield names[i]
    kids = node.get("/Kids")
    if isinstance(kids, pikepdf.Array):
        for kid in kids:
            yield from _name_tree_values(kid, depth + 1)


def _walk_fields(fields, depth: int = 0, seen: set | None = None):
    seen = set() if seen is None else seen
    if depth > MAX_DEPTH or not isinstance(fields, pikepdf.Array):
        return
    for field in fields:
        if not isinstance(field, pikepdf.Dictionary):
            continue
        if field.is_indirect:
            if field.objgen in seen:
                continue
            seen.add(field.objgen)
        yield field
        yield from _walk_fields(field.get("/Kids"), depth + 1, seen)
