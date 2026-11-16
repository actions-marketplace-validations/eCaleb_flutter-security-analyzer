"""
Tests for the SARIF reporter.

GitHub code scanning rejects or misplaces results when the SARIF log breaks
its rules, so these tests check the parts it relies on: one rule per id, a
ruleIndex that points at the right rule, valid levels, a security-severity
score in the right band, line numbers of 1 or more, and file paths written
relative to the repository root with forward slashes.

Author: Caleb Elebhose
Module: WB7103/WB7104 MSc Cybersecurity Project
University of Chester
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / 'src'))

from flutter_security_analyzer import __version__  # noqa: E402
from flutter_security_analyzer.core.config import ScannerConfig  # noqa: E402
from flutter_security_analyzer.core.scanner import SecurityScanner  # noqa: E402
from flutter_security_analyzer.reporters.sarif_reporter import SarifReporter  # noqa: E402


SAMPLES = REPO_ROOT / 'samples'
LEVELS = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}
SEVERITY_BANDS = {
    'critical': (9.0, 10.0),
    'high': (7.0, 8.9),
    'medium': (4.0, 6.9),
    'low': (0.1, 3.9),
    'info': (0.1, 3.9),
}


def build_log(path):
    """Scan a path and return the SARIF log as a dictionary."""
    results = SecurityScanner(ScannerConfig()).scan(Path(path))
    return results, SarifReporter().build_log(results)


class TestSarifStructure(unittest.TestCase):
    """Checks on a scan of the sample apps, run from the repository root."""

    @classmethod
    def setUpClass(cls):
        cls._old_cwd = os.getcwd()
        os.chdir(REPO_ROOT)
        cls.results, cls.log = build_log('samples')
        cls.sarif_run = cls.log['runs'][0]
        cls.rules = cls.sarif_run['tool']['driver']['rules']

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls._old_cwd)

    def test_top_level_fields(self):
        self.assertEqual(self.log['version'], '2.1.0')
        self.assertIn('sarif-2.1.0', self.log['$schema'])
        self.assertEqual(len(self.log['runs']), 1)

    def test_driver_reports_the_package_version(self):
        driver = self.sarif_run['tool']['driver']
        self.assertEqual(driver['name'], 'Flutter Security Analyzer')
        self.assertEqual(driver['version'], __version__)
        self.assertEqual(driver['semanticVersion'], __version__)

    def test_rule_ids_are_unique(self):
        ids = [rule['id'] for rule in self.rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 25)

    def test_rules_have_text_and_severity(self):
        for rule in self.rules:
            with self.subTest(rule=rule['id']):
                self.assertTrue(rule['shortDescription']['text'])
                self.assertTrue(rule['fullDescription']['text'])
                self.assertTrue(rule['help']['text'])
                self.assertIn('security', rule['properties']['tags'])
                self.assertTrue(rule['name'].isalnum())
                float(rule['properties']['security-severity'])

    def test_one_result_per_finding(self):
        self.assertEqual(len(self.sarif_run['results']), len(self.results.findings))
        self.assertGreater(len(self.sarif_run['results']), 0)

    def test_rule_index_points_at_the_rule(self):
        for result in self.sarif_run['results']:
            self.assertEqual(self.rules[result['ruleIndex']]['id'], result['ruleId'])

    def test_levels_match_severity(self):
        for result in self.sarif_run['results']:
            severity = result['properties']['severity']
            self.assertEqual(result['level'], LEVELS[severity])

    def test_security_severity_falls_in_githubs_band(self):
        for result in self.sarif_run['results']:
            rule = self.rules[result['ruleIndex']]
            score = float(rule['properties']['security-severity'])
            low, high = SEVERITY_BANDS[result['properties']['severity']]
            self.assertTrue(low <= score <= high, f"{rule['id']} scored {score}")

    def test_locations_are_relative_with_forward_slashes(self):
        for result in self.sarif_run['results']:
            location = result['locations'][0]['physicalLocation']
            uri = location['artifactLocation']['uri']
            self.assertEqual(location['artifactLocation']['uriBaseId'], '%SRCROOT%')
            self.assertTrue(uri.startswith('samples/'), uri)
            self.assertNotIn('\\', uri)
            self.assertGreaterEqual(location['region']['startLine'], 1)

    def test_fingerprints_ignore_line_numbers(self):
        for result in self.sarif_run['results']:
            fingerprint = result['partialFingerprints']['flutterSecurityAnalyzer/v1']
            self.assertEqual(len(fingerprint), 64)

    def test_log_is_json_serialisable(self):
        json.loads(json.dumps(self.log))


class TestSarifPaths(unittest.TestCase):
    """File paths in unusual places."""

    def setUp(self):
        self._old_cwd = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        project = Path(self.temp_dir) / 'my app' / 'lib'
        project.mkdir(parents=True)
        shutil.copy(SAMPLES / 'vulnerable_app.dart', project / 'main.dart')

    def tearDown(self):
        os.chdir(self._old_cwd)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_spaces_are_percent_encoded(self):
        os.chdir(self.temp_dir)
        _, log = build_log('my app')
        uris = {r['locations'][0]['physicalLocation']['artifactLocation']['uri']
                for r in log['runs'][0]['results']}
        self.assertEqual(uris, {'my%20app/lib/main.dart'})

    def test_paths_outside_the_current_directory_become_file_uris(self):
        os.chdir(REPO_ROOT)
        _, log = build_log(Path(self.temp_dir) / 'my app')
        location = log['runs'][0]['results'][0]['locations'][0]['physicalLocation']
        self.assertTrue(location['artifactLocation']['uri'].startswith('file://'))
        self.assertNotIn('uriBaseId', location['artifactLocation'])


class TestSarifEmptyScan(unittest.TestCase):
    """A clean project still produces a valid log with the rule list."""

    def test_no_findings(self):
        temp_dir = tempfile.mkdtemp()
        try:
            Path(temp_dir, 'main.dart').write_text("void main() {}\n", encoding='utf-8')
            _, log = build_log(temp_dir)
            run = log['runs'][0]
            self.assertEqual(run['results'], [])
            self.assertGreaterEqual(len(run['tool']['driver']['rules']), 25)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSarifCommandLine(unittest.TestCase):
    """The -f sarif option writes a file and keeps the usual exit codes."""

    def test_cli_writes_sarif(self):
        temp_dir = tempfile.mkdtemp()
        try:
            output = Path(temp_dir) / 'results.sarif'
            env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / 'src'))
            completed = subprocess.run(
                [sys.executable, '-m', 'flutter_security_analyzer',
                 str(SAMPLES / 'vulnerable_app.dart'), '-f', 'sarif', '-o', str(output)],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            log = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(log['version'], '2.1.0')
            self.assertGreater(len(log['runs'][0]['results']), 0)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
