#!/usr/bin/env python3
"""Consistency check and table generator for the specification sources.

Checks (exit status 1 on any error):
  * every requirement has a unique ID, a valid phase and at least one valid test,
    and none of its tests is first verified in a later phase than the requirement's;
  * every test is defined once and is cited by at least one requirement;
  * every identifier mentioned in the text is a defined requirement;
  * every threat and guarantee row names a requirement and a test;
  * every vector cites existing requirements that list the vector's test, and
    every test marked for vectors has at least one vector;
  * mapping.csv covers every version 1.3 requirement, and every requirement that
    is not marked new is the target of some mapping row.

Generated files: generated/traceability.tex, generated/mapping.tex,
generated/vectors.tex.
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PART_FILES = ["p00-overview.tex", "p01-decision-core.tex", "p02-enforcement.tex",
              "p03-content.tex", "p04-custody.tex", "p05-storage.tex",
              "p06-engineering.tex"]
TEXT_FILES = PART_FILES + ["appendix-scenarios.tex", "appendix-review.tex", "main.tex"]
PHASES = ["P0", "R1-A", "R1-B", "R1-C", "R2", "R3"]
ORDER = {p: i for i, p in enumerate(PHASES)}
EXPECT_VALUES = {
    "ALLOW", "DENY", "NEEDS_APPROVAL", "NEEDS_RESERVATION", "ERROR", "NOT_EXECUTED",
    "EXECUTED_ONCE", "REJECT_BUNDLE", "REJECT_ACTIVATION", "REJECT_BUILD", "REJECTED",
    "COMMITTED", "RESERVED", "RESERVATION_RELEASED", "UNKNOWN_RETAINED", "RECONCILE",
    "HELD", "ABORT_STREAM", "SAME_DIGEST", "EPOCH_INCREASES", "NOT_REUSED",
    "NOT_APPLIED", "RENDER_CANONICAL", "NOT_VISIBLE", "FILTERED", "RESERVATION_RETAINED",
    "MARK_RAISED_TO_MAX",
}
ID_RE = re.compile(r"\b[A-Z]{2,6}-\d{3}\b")
IGNORED_IDS = {"SHA-256", "SHA-384", "SHA-512", "AES-256", "AES-128"}
TEST_RE = re.compile(r"^T-\d\d$")
V13_COUNT = 85
DEFAULT_V13 = Path("/Users/jb-sec/Documents/fine-grained-access-spec/fine-grained-access-spec.tex")


def parse_group(text, start):
    """Return (contents, index after the group) for the brace group at text[start]."""
    depth, i = 0, start
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    raise ValueError("unbalanced braces")


def parse_macro(text, pos, nargs):
    args, i = [], pos
    for _ in range(nargs):
        while text[i] in " \t":
            i += 1
        group, i = parse_group(text, i)
        args.append(group)
    return args


def escape(s):
    table = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#",
             "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}",
             "^": r"\textasciicircum{}"}
    return "".join(table.get(c, c) for c in s)


def load_requirements(errors):
    reqs, tests = {}, {}
    for part, name in enumerate(PART_FILES):
        text = (ROOT / name).read_text()
        for m in re.finditer(r"^\\(reqn|req)\{", text, re.M):
            kind = m.group(1)
            try:
                rid, phase, tst, _ = parse_macro(text, m.end() - 1, 4)
            except ValueError:
                errors.append(f"{name}: unbalanced braces in requirement near offset {m.start()}")
                continue
            if rid in reqs:
                errors.append(f"duplicate requirement {rid}")
            tlist = [t.strip() for t in tst.split(",") if t.strip()]
            reqs[rid] = {"id": rid, "phase": phase.strip(), "tests": tlist, "new": kind == "reqn",
                         "part": part}
        for m in re.finditer(r"^\\testrow\{", text, re.M):
            tid, phase, _, vec = parse_macro(text, m.end() - 1, 4)
            if tid in tests:
                errors.append(f"duplicate test {tid}")
            tests[tid] = {"id": tid, "phase": phase.strip(), "vectors": vec.strip() == "yes",
                          "phases": [p.strip() for p in phase.split(",")]}
    return reqs, tests


def check_requirements(reqs, tests, errors):
    cited = defaultdict(list)
    for r in reqs.values():
        if r["phase"] not in PHASES:
            errors.append(f"{r['id']}: invalid phase {r['phase']!r}")
            continue
        if not r["tests"]:
            errors.append(f"{r['id']}: no test or REV/LINT")
        for t in r["tests"]:
            if t in ("REV", "LINT"):
                continue
            if not TEST_RE.match(t):
                errors.append(f"{r['id']}: invalid test token {t!r}")
            elif t not in tests:
                errors.append(f"{r['id']}: undefined test {t}")
            else:
                cited[t].append(r["id"])
                first = min(ORDER.get(p, 99) for p in tests[t]["phases"])
                claimed = max(ORDER.get(r["phase"], 0), ORDER["R1-A"])
                if first > claimed:
                    errors.append(f"{r['id']} ({r['phase']}): {t} is first verified in {PHASES[first]}")
    for t in tests:
        if not cited[t]:
            errors.append(f"{t}: no requirement cites this test")
    return cited


def check_text_ids(reqs, errors):
    for name in TEXT_FILES:
        for lineno, line in enumerate((ROOT / name).read_text().splitlines(), 1):
            for token in ID_RE.findall(line):
                if token not in IGNORED_IDS and token not in reqs:
                    errors.append(f"{name}:{lineno}: undefined identifier {token}")


def check_tables(errors):
    text = (ROOT / "p00-overview.tex").read_text().splitlines()
    for lineno, line in enumerate(text, 1):
        if re.match(r"^(TH-\d\d|G-\d\d) &", line):
            if "\\rr{" not in line or not re.search(r"\bT-\d\d\b", line):
                errors.append(f"p00-overview.tex:{lineno}: threat or guarantee row needs a requirement and a test")
        elif re.match(r"^N-\d\d &", line) and "\\rr{" not in line:
            errors.append(f"p00-overview.tex:{lineno}: non-guarantee row needs a requirement")


def check_vectors(reqs, tests, errors):
    data = json.loads((ROOT / "vectors" / "decisions.json").read_text())
    seen, by_test = set(), defaultdict(list)
    for v in data["vectors"]:
        vid = v["id"]
        if vid in seen:
            errors.append(f"duplicate vector {vid}")
        seen.add(vid)
        if v["test"] not in tests:
            errors.append(f"{vid}: undefined test {v['test']}")
        elif not tests[v["test"]]["vectors"]:
            errors.append(f"{vid}: test {v['test']} is not marked for vectors")
        by_test[v["test"]].append(v)
        for rid in v["requirements"]:
            if rid not in reqs:
                errors.append(f"{vid}: undefined requirement {rid}")
            elif v["test"] not in reqs[rid]["tests"]:
                errors.append(f"{vid}: {rid} does not list {v['test']}")
        expect = v["expect"] if isinstance(v["expect"], list) else [v["expect"]]
        for e in expect:
            if e not in EXPECT_VALUES:
                errors.append(f"{vid}: unknown expected outcome {e}")
        if not v["given"]:
            errors.append(f"{vid}: empty given")
    for tid, t in tests.items():
        if t["vectors"] and not by_test[tid]:
            errors.append(f"{tid}: marked for vectors but has none")
    return data["vectors"], by_test


def load_mapping(reqs, errors, v13_path):
    rows = list(csv.DictReader((ROOT / "mapping.csv").open()))
    old_ids = [r["v13_id"] for r in rows]
    if len(set(old_ids)) != len(old_ids):
        errors.append("mapping.csv has duplicate version 1.3 IDs")
    expected = None
    if v13_path.exists():
        expected = set(re.findall(r"\\req\{([A-Z]+-\d{3})\}", v13_path.read_text()))
    if expected is not None:
        for missing in sorted(expected - set(old_ids)):
            errors.append(f"mapping.csv: version 1.3 requirement {missing} is not mapped")
        for extra in sorted(set(old_ids) - expected):
            errors.append(f"mapping.csv: {extra} is not a version 1.3 requirement")
    elif len(old_ids) != V13_COUNT:
        errors.append(f"mapping.csv has {len(old_ids)} rows, expected {V13_COUNT}")
    targets = set()
    for r in rows:
        for rid in r["v2_ids"].split():
            targets.add(rid)
            if rid not in reqs:
                errors.append(f"mapping.csv: {r['v13_id']} targets undefined {rid}")
    for rid, r in reqs.items():
        if not r["new"] and rid not in targets:
            errors.append(f"{rid}: not marked new and not a mapping target")
    return rows, expected is not None


def write_traceability(reqs, tests, cited, vectors_by_test):
    out = ["\\Needspace{10\\baselineskip}", "\\subsection*{Requirements per phase}",
           "\\begin{longtable}{@{}P{0.14\\textwidth}P{0.16\\textwidth}P{0.12\\textwidth}@{}}",
           "\\toprule Phase & Requirements & New\\\\\\midrule"]
    for ph in PHASES:
        total = sum(1 for r in reqs.values() if r["phase"] == ph)
        new = sum(1 for r in reqs.values() if r["phase"] == ph and r["new"])
        out.append(f"{ph} & {total} & {new}\\\\")
    out.append(f"\\midrule Total & {len(reqs)} & {sum(1 for r in reqs.values() if r['new'])}\\\\")
    out += ["\\bottomrule", "\\end{longtable}", "",
            "\\Needspace{12\\baselineskip}", "\\subsection*{Requirements verified by each test}",
            "\\begin{longtable}{@{}P{0.07\\textwidth}P{0.10\\textwidth}P{0.64\\textwidth}P{0.08\\textwidth}@{}}",
            "\\toprule Test & Phase & Requirements & Vectors\\\\\\midrule\\endhead"]
    for tid in sorted(tests):
        ids = ", ".join(f"\\rr{{{i}}}" for i in sorted(cited[tid]))
        nvec = len(vectors_by_test.get(tid, []))
        out.append(f"\\hyperlink{{test:{tid}}}{{{tid}}} & {escape(tests[tid]['phase'])} & {ids} & {nvec}\\\\")
    out += ["\\bottomrule", "\\end{longtable}", "",
            "\\subsection*{Requirements verified by review or by the specification check}",
            ", ".join(f"\\rr{{{r['id']}}}" for r in sorted(reqs.values(), key=lambda r: r["id"])
                      if all(t in ("REV", "LINT") for t in r["tests"])) + "."]
    (ROOT / "generated" / "traceability.tex").write_text("\n".join(out) + "\n")


def write_mapping(rows, reqs):
    out = ["\\begin{longtable}{@{}P{0.16\\textwidth}P{0.09\\textwidth}P{0.37\\textwidth}P{0.28\\textwidth}@{}}",
           "\\toprule 1.3 ID & Result & 2.0 requirements & Note\\\\\\midrule\\endhead"]
    for r in rows:
        ids = ", ".join(f"\\rr{{{i}}}" for i in r["v2_ids"].split())
        out.append(f"{r['v13_id']} & {r['disposition']} & {ids} & {escape(r['note'])}\\\\")
    out += ["\\bottomrule", "\\end{longtable}", "",
            "\\subsection*{New in version 2.0}",
            ", ".join(f"\\rr{{{r['id']}}}" for r in sorted(reqs.values(), key=lambda r: r["id"]) if r["new"]) + "."]
    (ROOT / "generated" / "mapping.tex").write_text("\n".join(out) + "\n")


def write_vectors(vectors_by_test, tests):
    out = ["\\begin{longtable}{@{}P{0.08\\textwidth}P{0.40\\textwidth}P{0.24\\textwidth}P{0.16\\textwidth}@{}}",
           "\\toprule ID & Given & Expected & Requirements\\\\\\midrule\\endhead"]
    for tid in sorted(vectors_by_test):
        out.append(f"\\multicolumn{{4}}{{@{{}}l}}{{\\textbf{{{tid}}} ({escape(tests[tid]['phase'])})}}\\\\")
        for v in vectors_by_test[tid]:
            given = "; ".join(escape(g) for g in v["given"])
            if v.get("note"):
                given += "\\newline\\textit{" + escape(v["note"]) + "}"
            expect = v["expect"] if isinstance(v["expect"], list) else [v["expect"]]
            exp = ", ".join(f"\\code{{{e}}}" for e in expect)
            mark = "$^{\\dagger}$" if v.get("oracle") else ""
            reqs_cell = ", ".join(f"\\rr{{{r}}}" for r in v["requirements"])
            out.append(f"{v['id']}{mark} & {given} & {exp} & {reqs_cell}\\\\")
        out.append("\\midrule")
    out[-1] = "\\bottomrule"
    out.append("\\end{longtable}")
    (ROOT / "generated" / "vectors.tex").write_text("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v13", type=Path, default=DEFAULT_V13, help="version 1.3 LaTeX source for the mapping check")
    args = ap.parse_args()
    errors = []
    reqs, tests = load_requirements(errors)
    cited = check_requirements(reqs, tests, errors)
    check_text_ids(reqs, errors)
    check_tables(errors)
    vectors, by_test = check_vectors(reqs, tests, errors)
    rows, v13_checked = load_mapping(reqs, errors, args.v13)
    if not errors:
        (ROOT / "generated").mkdir(exist_ok=True)
        write_traceability(reqs, tests, cited, by_test)
        write_mapping(rows, reqs)
        write_vectors(by_test, tests)
    new = sum(1 for r in reqs.values() if r["new"])
    print(f"requirements: {len(reqs)} ({new} new), tests: {len(tests)}, vectors: {len(vectors)}, "
          f"mapping rows: {len(rows)} ({'checked against 1.3 source' if v13_checked else 'count only'})")
    for e in errors:
        print("ERROR:", e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
