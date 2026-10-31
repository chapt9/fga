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
  * every test family declares valid feature prerequisites; qualification binds
    case and family runs to one selected release manifest and configuration;
  * mapping.csv covers every version 1.3 requirement, and every requirement that
    is not marked new is the target of some mapping row.

Generated files: generated/traceability.tex, generated/mapping.tex,
generated/vectors.tex.
"""
import argparse
import csv
import hashlib
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
ID_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,5}-\d{3}\b")
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
    load_test_features(tests, errors)
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


def check_tables(reqs, tests, errors):
    text = (ROOT / "p00-overview.tex").read_text().splitlines()
    for lineno, line in enumerate(text, 1):
        if re.match(r"^(TH-\d\d|G-\d\d) &", line):
            row_requirements = re.findall(r"\\rr\{([^}]+)\}", line)
            row_tests = re.findall(r"\bT-\d\d\b", line)
            if not row_requirements or not row_tests:
                errors.append(f"p00-overview.tex:{lineno}: threat or guarantee row needs a requirement and a test")
            for tid in row_tests:
                if tid not in tests:
                    errors.append(f"p00-overview.tex:{lineno}: undefined test {tid}")
            for rid in row_requirements:
                if rid not in reqs:
                    errors.append(f"p00-overview.tex:{lineno}: undefined requirement {rid}")
        elif re.match(r"^N-\d\d &", line) and "\\rr{" not in line:
            errors.append(f"p00-overview.tex:{lineno}: non-guarantee row needs a requirement")


def check_vectors(reqs, tests, errors):
    data = json.loads((ROOT / "vectors" / "decisions.json").read_text())
    if data.get("schema") != "fga.vectors/v2":
        errors.append("vectors: expected fga.vectors/v2")
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
        phase = v.get("min_phase")
        features = v.get("features", [])
        if phase not in ORDER:
            errors.append(f"{vid}: missing or invalid minimum phase")
        if not isinstance(features, list) or "core" not in features or any(f not in FEATURES for f in features):
            errors.append(f"{vid}: invalid feature prerequisites")
        elif any(ORDER.get(phase, -1) < ORDER[FEATURES[f]] for f in features):
            errors.append(f"{vid}: feature prerequisite is later than its minimum phase")
        status = v.get("status")
        if status not in ("scenario_only", "fixture_ready"):
            errors.append(f"{vid}: invalid case status")
        if status == "fixture_ready":
            check_fixture(v, errors)
        elif "fixture" in v:
            errors.append(f"{vid}: scenario_only case cannot claim a fixture")
    for tid, t in tests.items():
        if t["vectors"] and not by_test[tid]:
            errors.append(f"{tid}: marked for vectors but has none")
    return data["vectors"], by_test


FEATURES = {"core": "R1-A", "mcp": "R2", "executor": "R2",
            "managed_client": "R2", "s3": "R3", "replication": "R3", "ha": "R1-B"}
FIXTURE_KINDS = {"policy", "grant_binding", "authority_order", "temporal_validity",
                 "recovery_authority", "lineage_freshness", "version_lifecycle",
                 "label_authority", "lineage_floor", "signer_lifecycle"}


def fixture_path(vector):
    path = (ROOT / "vectors" / vector.get("fixture", "")).resolve()
    if not path.is_relative_to((ROOT / "vectors" / "fixtures").resolve()):
        raise ValueError("fixture path must stay inside vectors/fixtures")
    return path


def check_fixture(vector, errors):
    """Validate reproducible inputs, not execution or correctness of an implementation."""
    vid = vector["id"]
    try:
        data = json.loads(fixture_path(vector).read_text())
    except (OSError, ValueError) as exc:
        errors.append(f"{vid}: fixture unavailable: {exc}")
        return
    if data.get("schema") != "fga.fixture/v1" or data.get("case_id") != vid:
        errors.append(f"{vid}: wrong fixture schema or binding")
    if data.get("kind") not in FIXTURE_KINDS:
        errors.append(f"{vid}: unknown fixture kind")
    if not isinstance(data.get("initial_state"), dict) or not data["initial_state"]:
        errors.append(f"{vid}: fixture needs concrete initial state")
    inputs = data.get("inputs", [])
    if not isinstance(inputs, list) or not inputs:
        errors.append(f"{vid}: fixture needs concrete inputs")
        inputs = []
    input_ids = set()
    for item in inputs:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item.get("operation"):
            errors.append(f"{vid}: invalid fixture input")
            continue
        if item["id"] in input_ids:
            errors.append(f"{vid}: duplicate fixture input {item['id']}")
        input_ids.add(item["id"])
    steps = data.get("schedule", [])
    if not isinstance(steps, list) or not steps:
        errors.append(f"{vid}: fixture needs an ordered schedule")
        steps = []
    step_names = []
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("step"), str):
            errors.append(f"{vid}: invalid schedule step")
            continue
        if step.get("request") not in input_ids:
            errors.append(f"{vid}: schedule references unknown input")
        step_names.append(step["step"])
    if len(set(step_names)) != len(step_names):
        errors.append(f"{vid}: duplicate schedule step")
    for step in steps:
        if isinstance(step, dict) and "must_complete_before" in step:
            target = step["must_complete_before"]
            if target not in step_names or step_names.index(target) <= step_names.index(step["step"]):
                errors.append(f"{vid}: invalid ordering constraint")
    assertions = data.get("assertions", [])
    if not isinstance(assertions, list) or not assertions:
        errors.append(f"{vid}: fixture needs explicit assertions")
        assertions = []
    for assertion in assertions:
        if (not isinstance(assertion, dict) or not assertion.get("path") or
                len(set(assertion) & {"equals", "not_equals", "at_most"}) != 1):
            errors.append(f"{vid}: invalid fixture assertion")


def load_test_features(tests, errors):
    """Attach explicit family prerequisites; missing declarations never imply core."""
    try:
        data = json.loads((ROOT / "vectors" / "test-families.json").read_text())
    except (OSError, ValueError) as exc:
        errors.append(f"test families: metadata unavailable: {exc}")
        return
    if not isinstance(data, dict) or data.get("schema") != "fga.test-families/v1":
        errors.append("test families: invalid metadata schema")
        return
    families = data.get("families")
    if not isinstance(families, list):
        errors.append("test families: expected a family list")
        return
    seen = set()
    for family in families:
        if not isinstance(family, dict) or family.get("id") not in tests:
            errors.append("test families: undefined test family")
            continue
        tid = family["id"]
        if tid in seen:
            errors.append(f"test families: duplicate {tid}")
        seen.add(tid)
        features = family.get("features")
        if (not isinstance(features, list) or "core" not in features or
                any(not isinstance(f, str) or f not in FEATURES for f in features) or
                len(features) != len(set(features))):
            errors.append(f"test families: {tid} has invalid feature prerequisites")
            continue
        first = min(ORDER.get(p, 99) for p in tests[tid]["phases"])
        if any(ORDER[FEATURES[f]] > first for f in features):
            errors.append(f"test families: {tid} feature is later than its first phase")
        tests[tid]["features"] = features
    for tid in sorted(set(tests) - seen):
        errors.append(f"test families: missing feature prerequisites for {tid}")


def evidence_runs(evidence, name, id_field, errors):
    """Reject ambiguous duplicate records instead of choosing whichever comes last."""
    records = evidence.get(name)
    if not isinstance(records, list):
        errors.append(f"qualification: {name} must be a list")
        return {}
    runs = {}
    for record in records:
        if (not isinstance(record, dict) or not isinstance(record.get(id_field), str) or
                not record[id_field]):
            errors.append(f"qualification: invalid {name} entry")
            continue
        rid = record[id_field]
        if rid in runs:
            errors.append(f"qualification: duplicate {name} record for {rid}")
        runs[rid] = record
    return runs


def check_run_binding(run, rid, phase, features, release_manifest_sha256, errors):
    if run.get("release_manifest_sha256") != release_manifest_sha256:
        errors.append(f"qualification: {rid} evidence does not bind the selected release manifest")
    run_features = run.get("features")
    if (run.get("phase") != phase or not isinstance(run_features, list) or
            any(not isinstance(f, str) for f in run_features) or
            len(run_features) != len(set(run_features)) or set(run_features) != features):
        errors.append(f"qualification: {rid} evidence does not bind the selected phase/features")


def check_qualification(vectors, tests, phase, features, evidence_path, errors,
                        release_manifest_sha256=None):
    """Require applicable evidence for exactly one selected release and configuration."""
    if not isinstance(release_manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", release_manifest_sha256):
        errors.append("qualification: --release-manifest-sha256 requires a SHA-256 digest")
        return
    try:
        evidence = json.loads(evidence_path.read_text())
    except (OSError, ValueError) as exc:
        errors.append(f"qualification: evidence unavailable: {exc}")
        return
    if not isinstance(evidence, dict) or evidence.get("schema") != "fga.evidence/v2":
        errors.append("qualification: invalid evidence schema; expected fga.evidence/v2")
        return
    case_runs = evidence_runs(evidence, "case_runs", "case_id", errors)
    test_runs = evidence_runs(evidence, "test_runs", "test_id", errors)
    for vector in vectors:
        if ORDER.get(vector.get("min_phase"), 99) > ORDER[phase] or not set(vector.get("features", [])) <= features:
            continue
        vid = vector["id"]
        if vector.get("status") != "fixture_ready":
            errors.append(f"qualification: {vid} is applicable but scenario_only")
            continue
        run = case_runs.get(vid, {})
        if run.get("result") != "PASS" or not run.get("run_record"):
            errors.append(f"qualification: {vid} has no passing implementation evidence")
            continue
        check_run_binding(run, vid, phase, features, release_manifest_sha256, errors)
        expected_digest = hashlib.sha256(fixture_path(vector).read_bytes()).hexdigest()
        if run.get("fixture_sha256") != expected_digest:
            errors.append(f"qualification: {vid} evidence does not bind the current fixture")
        if vector.get("oracle") and not run.get("oracle_record"):
            errors.append(f"qualification: {vid} lacks its required pinned-oracle record")
    for tid, test in tests.items():
        if not isinstance(test.get("features"), list):
            errors.append(f"qualification: {tid} has no validated feature prerequisites")
            continue
        applicable = any(ORDER.get(p, 99) <= ORDER[phase] for p in test["phases"])
        if not applicable or not set(test["features"]) <= features:
            continue
        # Family evidence additionally covers obligations without individual vectors.
        run = test_runs.get(tid, {})
        if run.get("result") != "PASS" or not run.get("run_record"):
            errors.append(f"qualification: {tid} lacks passing evidence for the selected phase/features")
            continue
        check_run_binding(run, tid, phase, features, release_manifest_sha256, errors)


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
           "\\toprule 1.3 ID & Result & 2.6 requirements & Note\\\\\\midrule\\endhead"]
    for r in rows:
        ids = ", ".join(f"\\rr{{{i}}}" for i in r["v2_ids"].split())
        out.append(f"{r['v13_id']} & {r['disposition']} & {ids} & {escape(r['note'])}\\\\")
    out += ["\\bottomrule", "\\end{longtable}", "",
            "\\subsection*{New or strengthened since version 1.3}",
            ", ".join(f"\\rr{{{r['id']}}}" for r in sorted(reqs.values(), key=lambda r: r["id"]) if r["new"]) + "."]
    (ROOT / "generated" / "mapping.tex").write_text("\n".join(out) + "\n")


def write_vectors(vectors_by_test, tests):
    out = ["\\begin{longtable}{@{}P{0.08\\textwidth}P{0.40\\textwidth}P{0.24\\textwidth}P{0.16\\textwidth}@{}}",
           "\\toprule ID & Given & Expected & Requirements\\\\\\midrule\\endhead"]
    for tid in sorted(vectors_by_test):
        out.append(f"\\multicolumn{{4}}{{@{{}}l}}{{\\textbf{{{tid}}} ({escape(tests[tid]['phase'])})}}\\\\")
        last_scope = None
        for v in vectors_by_test[tid]:
            scope = (v["min_phase"], tuple(v["features"]))
            if scope != last_scope:
                caption = v["min_phase"] + "; " + ", ".join(v["features"])
                out.append(f"\\multicolumn{{4}}{{@{{}}l}}{{\\footnotesize {escape(caption)}}}\\\\")
                last_scope = scope
            given = "; ".join(escape(g) for g in v["given"])
            if v.get("note"):
                given += "\\newline\\textit{" + escape(v["note"]) + "}"
            expect = v["expect"] if isinstance(v["expect"], list) else [v["expect"]]
            exp = ", ".join(f"\\code{{{e}}}" for e in expect)
            mark = "$^{\\dagger}$" if v.get("oracle") else ""
            if v.get("status") == "fixture_ready":
                mark += "$^{f}$"
            reqs_cell = ", ".join(f"\\rr{{{r}}}" for r in v["requirements"])
            out.append(f"{v['id']}{mark} & {given} & {exp} & {reqs_cell}\\\\")
        out.append("\\midrule")
    out[-1] = "\\bottomrule"
    out.append("\\end{longtable}")
    (ROOT / "generated" / "vectors.tex").write_text("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v13", type=Path, default=DEFAULT_V13, help="version 1.3 LaTeX source for the mapping check")
    ap.add_argument("--check-only", action="store_true", help="validate without regenerating tables")
    ap.add_argument("--qualify", choices=PHASES[1:], help="also require applicable executable inputs and implementation evidence")
    ap.add_argument("--features", default="core", help="comma-separated enabled features; core is required")
    ap.add_argument("--evidence", type=Path, default=ROOT / "vectors" / "execution-evidence.json")
    ap.add_argument("--release-manifest-sha256", metavar="SHA256",
                    help="required for qualification: SHA-256 of the selected immutable release manifest")
    args = ap.parse_args()
    errors = []
    reqs, tests = load_requirements(errors)
    cited = check_requirements(reqs, tests, errors)
    check_text_ids(reqs, errors)
    check_tables(reqs, tests, errors)
    vectors, by_test = check_vectors(reqs, tests, errors)
    rows, v13_checked = load_mapping(reqs, errors, args.v13)
    if args.qualify:
        features = set(args.features.split(","))
        if "core" not in features or not features <= set(FEATURES):
            errors.append("qualification: invalid enabled features")
        elif any(ORDER[FEATURES[f]] > ORDER[args.qualify] for f in features):
            errors.append("qualification: feature is not available in selected phase")
        elif not errors:
            check_qualification(vectors, tests, args.qualify, features, args.evidence, errors,
                                args.release_manifest_sha256)
    if not errors and not args.check_only:
        (ROOT / "generated").mkdir(exist_ok=True)
        write_traceability(reqs, tests, cited, by_test)
        write_mapping(rows, reqs)
        write_vectors(by_test, tests)
    new = sum(1 for r in reqs.values() if r["new"])
    print(f"requirements: {len(reqs)} ({new} new), tests: {len(tests)}, vectors: {len(vectors)}, "
          f"mapping rows: {len(rows)} ({'checked against 1.3 source' if v13_checked else 'count only'})")
    print(f"case inputs: {sum(v.get('status') == 'fixture_ready' for v in vectors)} fixture_ready, "
          f"{sum(v.get('status') == 'scenario_only' for v in vectors)} scenario_only; "
          "structural validation is not implementation qualification")
    for e in errors:
        print("ERROR:", e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
