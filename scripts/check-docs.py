#!/usr/bin/env python3
"""Fixes and checks the Persian (RTL) Markdown rules of this repository.

  python scripts/check-docs.py          # check only (exit 1 on problems)
  python scripts/check-docs.py --fix    # insert missing RLM marks, then check

Rules (see the owner's global instructions):
  * No HTML direction wrappers (dir="rtl", align="right") and no [[_TOC_]].
  * A heading, list item, quote, paragraph, table header cell or first table cell whose first character with a
    direction is Latin text or code gets U+200F (RLM) right after its Markdown marker, so GitLab and VS Code
    pick right-to-left.
  * Every in-page link (#anchor) matches a heading. Anchor = heading lowercased, punctuation removed (including
    ZWNJ U+200C and RLM), spaces -> "-"; duplicate headings get -1, -2.
"""
import pathlib
import re
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parent.parent
RLM = "‏"
FILES = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
MARKER = re.compile(r"^(\s*(?:#{1,6} |[-*+] |\d+\. |> )?)(.*)$")
# Markup without a direction of its own: emphasis, link brackets, opening parentheses, quotes.
LEADING_MARKUP = re.compile(r"^(?:\*\*|__|\*|_|\[|\(|\"|')*")
SEPARATOR = re.compile(r"^\s*\|\s*:?-{3,}")


def needs_rlm(text: str) -> bool:
    """True when the first character with a direction is Latin or code (a backtick)."""
    if not text or text[0] == RLM:
        return False
    rest = text[LEADING_MARKUP.match(text).end():]
    return bool(rest) and (rest[0] == "`" or "A" <= rest[0] <= "Z" or "a" <= rest[0] <= "z")


def fix_line(line: str, header_row: bool) -> str:
    if line.lstrip().startswith("|"):
        if SEPARATOR.match(line):
            return line
        cells = line.split("|")
        # The header row decides the table's direction; the first cell decides each row's.
        last = len(cells) - 1 if header_row else min(2, len(cells) - 1)
        for i in range(1, last):
            stripped = cells[i].lstrip()
            if needs_rlm(stripped):
                cells[i] = cells[i][: len(cells[i]) - len(stripped)] + RLM + stripped
        return "|".join(cells)
    marker, rest = MARKER.match(line).groups()
    return marker + RLM + rest if needs_rlm(rest) else line


def anchor(heading: str) -> str:
    text = heading.strip().lower().replace("‌", "").replace(RLM, "")
    text = "".join(c for c in text if c in " -_" or not unicodedata.category(c).startswith(("P", "S")))
    return re.sub(r"\s", "-", text.strip())


def process(path: pathlib.Path, fix: bool) -> list[str]:
    lines = path.read_text(encoding="utf-8").split("\n")
    problems, out, fenced, anchors = [], [], False, set()
    seen: dict[str, int] = {}
    for index, line in enumerate(lines):
        number = index + 1
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append(line)
            continue
        if not fenced:
            header = line.lstrip().startswith("|") and index + 1 < len(lines) and SEPARATOR.match(lines[index + 1]) is not None
            fixed = fix_line(line, header)
            if fixed != line:
                if fix:
                    line = fixed
                else:
                    problems.append(f"{path.name}:{number}: missing RLM: {line.strip()[:70]}")
            if re.search(r"dir=\"?rtl|align=\"?right|\[\[_TOC_\]\]", line):
                problems.append(f"{path.name}:{number}: direction wrapper or [[_TOC_]]")
            if m := re.match(r"^#{1,6} (.+)$", line):
                base = anchor(m.group(1))
                count = seen.get(base, 0)
                seen[base] = count + 1
                anchors.add(base if count == 0 else f"{base}-{count}")
        out.append(line)
    fenced = False
    for number, line in enumerate(out, 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if fenced:
            continue
        for target in re.findall(r"\]\(#([^)]+)\)", line):
            if target not in anchors:
                problems.append(f"{path.name}:{number}: link #{target} matches no heading")
    if fix:
        path.write_text("\n".join(out), encoding="utf-8", newline="")
    return problems


def main() -> None:
    fix = "--fix" in sys.argv
    problems = [p for f in FILES for p in process(f, fix)]
    for p in problems:
        print(p)
    print(f"{len(FILES)} files, {len(problems)} problems")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
