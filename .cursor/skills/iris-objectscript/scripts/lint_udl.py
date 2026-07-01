#!/usr/bin/env python3
"""Static structural linter for InterSystems UDL class files (.cls).

It cannot check semantics (only IRIS can compile), but it catches the structural
mistakes that break compiles: unbalanced member braces, a missing/misnamed class
declaration, class name not matching the file path, and unrecognized members.

Key insight: in UDL, the *structural* braces — the class body and each member
body — sit alone on their own line at column 0. Inner ObjectScript blocks
({ } after If/For) and Python dict literals are indented, so counting only
column-0 brace lines validates structure without tripping over code or JSON.

Usage:  python3 lint_udl.py <path> [<path> ...]
Exit code 0 = clean (warnings allowed), 1 = errors found.
"""
import os
import re
import sys

MEMBER_RE = re.compile(
    r"^(Property|Relationship|Method|ClassMethod|ClientMethod|Parameter|Index|"
    r"ForeignKey|Trigger|Query|XData|Projection|Storage|Compiler)\b"
)
CLASS_RE = re.compile(r"^Class\s+([%A-Za-z0-9_.]+)\s+Extends\b")
HEADER_OK_AT_CLASS_LEVEL = re.compile(r"^(///|//|;|#|\}|\{|\)|\s*$)")


def lint_file(path, check_name=True):
    errors, warnings = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    # 1. class declaration present + name matches file path
    class_name = None
    for ln in lines:
        m = CLASS_RE.match(ln.strip())
        if m:
            class_name = m.group(1)
            break
    if class_name is None:
        errors.append("no 'Class <Name> Extends ...' declaration found")
    elif check_name:
        # file path .../Pkg/Sub/Class.cls  -> Pkg.Sub.Class
        rel = re.sub(r"\.cls$", "", path)
        parts = rel.replace("\\", "/").split("/")
        # take the trailing segments that match the dotted class name length
        expected = ".".join(parts[-(class_name.count(".") + 1):])
        if expected != class_name:
            warnings.append(
                f"class name '{class_name}' does not match path-derived "
                f"'{expected}' (ok for templates)"
            )

    # 2. column-0 structural braces: balance + depth tracking
    depth = 0
    seen_class_brace = False
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if line == "{":
            depth += 1
            if depth == 1:
                seen_class_brace = True
        elif line == "}":
            depth -= 1
            if depth < 0:
                errors.append(f"line {i}: unbalanced '}}' (negative brace depth)")
                depth = 0
        elif depth == 1:
            # class-body level: should be a member header or comment/blank
            if not HEADER_OK_AT_CLASS_LEVEL.match(stripped) and not MEMBER_RE.match(stripped):
                # allow members with leading doc already consumed; flag others
                warnings.append(f"line {i}: unrecognized class-level line: {stripped[:60]!r}")

    if depth != 0:
        errors.append(f"unbalanced braces: final column-0 brace depth = {depth}")
    if not seen_class_brace and class_name is not None:
        errors.append("class declared but no column-0 '{' class body found")

    # 3. advisory: hand-written Storage in source
    if any(l.strip().startswith("Storage ") for l in lines):
        warnings.append("hand-written Storage block present — prefer letting the "
                        "compiler generate it (ok only when mapping legacy globals)")

    return errors, warnings


def collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in names:
                    if n.endswith(".cls"):
                        files.append(os.path.join(root, n))
        elif p.endswith(".cls"):
            files.append(p)
    return sorted(files)


def main(argv):
    paths = argv[1:] or ["."]
    files = collect(paths)
    if not files:
        print("no .cls files found")
        return 0
    total_err = 0
    for f in files:
        # templates use __PKG__ placeholders, so don't enforce name==path there
        is_template = "__PKG__" in open(f, encoding="utf-8", errors="replace").read() \
                      or os.sep + "templates" + os.sep in f
        errs, warns = lint_file(f, check_name=not is_template)
        status = "FAIL" if errs else ("warn" if warns else "ok")
        print(f"[{status}] {f}")
        for e in errs:
            print(f"    ERROR  {e}")
        for w in warns:
            print(f"    warn   {w}")
        total_err += len(errs)
    print(f"\n{len(files)} file(s) checked, {total_err} error(s).")
    return 1 if total_err else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
