#!/usr/bin/env python3
"""Regression tests for specification validation, not product conformance tests."""
import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name('check_spec.py')
spec = importlib.util.spec_from_file_location('check_spec', MODULE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
SOURCE_ROOT = checker.ROOT
RELEASE_MANIFEST = "a" * 64


class CheckerRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='fga-checker-')
        self.root = Path(self.tmp.name)
        errors = []
        self.reqs, self.tests = checker.load_requirements(errors)
        self.assertFalse(errors)
        shutil.copy2(SOURCE_ROOT / 'p00-overview.tex', self.root / 'p00-overview.tex')
        shutil.copytree(SOURCE_ROOT / 'vectors', self.root / 'vectors')
        checker.ROOT = self.root
        self.catalogue = json.loads((self.root / 'vectors/decisions.json').read_text())

    def tearDown(self):
        checker.ROOT = SOURCE_ROOT
        self.tmp.cleanup()

    def write_catalogue(self):
        (self.root / 'vectors/decisions.json').write_text(json.dumps(self.catalogue))

    def test_current_tables_accept_known_ids(self):
        errors = []
        checker.check_tables(self.reqs, self.tests, errors)
        self.assertEqual(errors, [])

    def test_unknown_guarantee_test_is_rejected(self):
        path = self.root / 'p00-overview.tex'
        lines = path.read_text().splitlines()
        changed = False
        for i, line in enumerate(lines):
            if line.startswith('G-01 &'):
                lines[i] = line.replace('T-01, T-04', 'T-99')
                changed = lines[i] != line
        self.assertTrue(changed)
        path.write_text('\n'.join(lines))
        errors = []
        checker.check_tables(self.reqs, self.tests, errors)
        self.assertTrue(any('undefined test T-99' in e for e in errors), errors)

    def test_later_feature_cannot_claim_earlier_phase(self):
        case = next(v for v in self.catalogue['vectors'] if v['id'] == 'V-002')
        case['min_phase'] = 'R1-A'
        self.write_catalogue()
        errors = []
        checker.check_vectors(self.reqs, self.tests, errors)
        self.assertTrue(any('V-002: feature prerequisite is later' in e for e in errors), errors)

    def test_fixture_must_bind_case_and_have_inputs(self):
        case = next(v for v in self.catalogue['vectors'] if v['id'] == 'V-001')
        path = checker.fixture_path(case)
        fixture = json.loads(path.read_text())
        fixture['case_id'] = 'V-999'
        fixture['inputs'] = []
        path.write_text(json.dumps(fixture))
        errors = []
        checker.check_fixture(case, errors)
        self.assertTrue(any('wrong fixture schema or binding' in e for e in errors), errors)
        self.assertTrue(any('needs concrete inputs' in e for e in errors), errors)

    def test_scenario_only_case_cannot_qualify(self):
        case = next(v for v in self.catalogue['vectors'] if v['id'] == 'V-003')
        errors = []
        checker.check_qualification([case], {}, 'R1-A', {'core'},
                                    self.root / 'vectors/execution-evidence.json', errors,
                                    RELEASE_MANIFEST)
        self.assertTrue(any('V-003 is applicable but scenario_only' in e for e in errors), errors)

    def test_later_optional_case_does_not_gate_r1(self):
        case = next(v for v in self.catalogue['vectors'] if v['id'] == 'V-002')
        errors = []
        checker.check_qualification([case], {}, 'R1-C', {'core'},
                                    self.root / 'vectors/execution-evidence.json', errors,
                                    RELEASE_MANIFEST)
        self.assertEqual(errors, [])

    def test_execution_evidence_must_bind_fixture_bytes(self):
        case = next(v for v in self.catalogue['vectors'] if v['id'] == 'V-141')
        path = self.root / 'vectors/execution-evidence.json'
        path.write_text(json.dumps({'schema': 'fga.evidence/v2', 'test_runs': [],
            'case_runs': [{'case_id': 'V-141', 'result': 'PASS',
                          'release_manifest_sha256': RELEASE_MANIFEST,
                          'phase': 'R1-B', 'features': ['core'], 'run_record': 'test-run',
                          'fixture_sha256': '0' * 64}]}))
        errors = []
        checker.check_qualification([case], {}, 'R1-B', {'core'}, path, errors, RELEASE_MANIFEST)
        self.assertTrue(any('does not bind the current fixture' in e for e in errors), errors)


    def qualification_sample(self):
        cases = [v for v in self.catalogue['vectors'] if v['id'] in ('V-141', 'V-142')]
        binding = {'release_manifest_sha256': RELEASE_MANIFEST, 'phase': 'R1-B',
                   'features': ['core'], 'result': 'PASS', 'run_record': 'test-only-record'}
        evidence = {'schema': 'fga.evidence/v2', 'case_runs': [],
                    'test_runs': [dict(binding, test_id='T-03')]}
        for case in cases:
            digest = hashlib.sha256(checker.fixture_path(case).read_bytes()).hexdigest()
            evidence['case_runs'].append(dict(binding, case_id=case['id'], fixture_sha256=digest))
        return cases, evidence

    def qualify_sample(self, cases, evidence, manifest=RELEASE_MANIFEST):
        path = self.root / 'vectors/execution-evidence.json'
        path.write_text(json.dumps(evidence))
        errors = []
        checker.check_qualification(cases, {'T-03': self.tests['T-03']}, 'R1-B', {'core'},
                                    path, errors, manifest)
        return errors

    def test_matching_release_and_configuration_qualify(self):
        cases, evidence = self.qualification_sample()
        self.assertEqual(self.qualify_sample(cases, evidence), [])

    def test_mixed_release_manifests_are_rejected(self):
        cases, baseline = self.qualification_sample()
        for records, index in (('case_runs', 0), ('case_runs', 1), ('test_runs', 0)):
            with self.subTest(records=records, index=index):
                evidence = copy.deepcopy(baseline)
                evidence[records][index]['release_manifest_sha256'] = 'b' * 64
                errors = self.qualify_sample(cases, evidence)
                self.assertTrue(any('selected release manifest' in e for e in errors), errors)

    def test_case_and_family_configuration_mismatches_are_rejected(self):
        cases, baseline = self.qualification_sample()
        for records in ('case_runs', 'test_runs'):
            for field, value in (('phase', 'R3'), ('features', ['core', 'mcp']),
                                 ('features', ['core', 'core']), ('features', None)):
                with self.subTest(records=records, field=field, value=value):
                    evidence = copy.deepcopy(baseline)
                    evidence[records][0][field] = value
                    errors = self.qualify_sample(cases, evidence)
                    self.assertTrue(any('selected phase/features' in e for e in errors), errors)

    def test_release_selection_is_required_and_validated(self):
        cases, evidence = self.qualification_sample()
        for manifest in (None, '', 'test-build', 'g' * 64):
            with self.subTest(manifest=manifest):
                errors = self.qualify_sample(cases, evidence, manifest)
                self.assertTrue(any('--release-manifest-sha256' in e for e in errors), errors)

    def test_legacy_or_duplicate_evidence_is_rejected(self):
        cases, baseline = self.qualification_sample()
        legacy = copy.deepcopy(baseline)
        legacy['schema'] = 'fga.evidence/v1'
        self.assertTrue(any('invalid evidence schema' in e
                            for e in self.qualify_sample(cases, legacy)))
        for records in ('case_runs', 'test_runs'):
            with self.subTest(records=records):
                evidence = copy.deepcopy(baseline)
                evidence[records].append(copy.deepcopy(evidence[records][0]))
                errors = self.qualify_sample(cases, evidence)
                self.assertTrue(any('duplicate' in e for e in errors), errors)

    def test_optional_family_requires_evidence_only_when_enabled(self):
        path = self.root / 'vectors/execution-evidence.json'
        path.write_text(json.dumps({'schema': 'fga.evidence/v2', 'case_runs': [], 'test_runs': []}))
        for tid, feature, other in (('T-17', 'replication', 's3'), ('T-07', 's3', 'replication')):
            with self.subTest(tid=tid):
                errors = []
                checker.check_qualification([], {tid: self.tests[tid]}, 'R3', {'core', other},
                                            path, errors, RELEASE_MANIFEST)
                self.assertEqual(errors, [])
                errors = []
                checker.check_qualification([], {tid: self.tests[tid]}, 'R3', {'core', feature},
                                            path, errors, RELEASE_MANIFEST)
                self.assertTrue(any(tid + ' lacks passing evidence' in e for e in errors), errors)
                path.write_text(json.dumps({'schema': 'fga.evidence/v2', 'case_runs': [],
                    'test_runs': [{'test_id': tid, 'result': 'PASS', 'phase': 'R3',
                        'features': ['core', feature], 'release_manifest_sha256': RELEASE_MANIFEST,
                        'run_record': 'test-only-record'}]}))
                errors = []
                checker.check_qualification([], {tid: self.tests[tid]}, 'R3', {'core', feature},
                                            path, errors, RELEASE_MANIFEST)
                self.assertEqual(errors, [])
                path.write_text(json.dumps({'schema': 'fga.evidence/v2', 'case_runs': [], 'test_runs': []}))

    def test_mcp_session_binding_gates_baseline_mcp(self):
        case = next(v for v in self.catalogue['vectors'] if v['id'] == 'V-115')
        errors = []
        checker.check_qualification([case], {}, 'R2', {'core', 'mcp'},
                                    self.root / 'vectors/execution-evidence.json', errors,
                                    RELEASE_MANIFEST)
        self.assertTrue(any('V-115 is applicable but scenario_only' in e for e in errors), errors)

    def test_family_metadata_must_be_complete_and_unambiguous(self):
        path = self.root / 'vectors/test-families.json'
        baseline = json.loads(path.read_text())
        for mutation in ('missing', 'duplicate', 'unknown_feature'):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(baseline)
                if mutation == 'missing':
                    data['families'] = [f for f in data['families'] if f['id'] != 'T-17']
                elif mutation == 'duplicate':
                    data['families'].append(copy.deepcopy(data['families'][0]))
                else:
                    data['families'][0]['features'].append('unknown')
                path.write_text(json.dumps(data))
                errors = []
                checker.load_test_features(copy.deepcopy(self.tests), errors)
                self.assertTrue(errors)


if __name__ == '__main__':
    unittest.main()
