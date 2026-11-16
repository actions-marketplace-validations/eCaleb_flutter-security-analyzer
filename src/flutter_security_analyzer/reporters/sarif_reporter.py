"""
SARIF Reporter Module

Outputs scan results in SARIF 2.1.0, the format GitHub code scanning and
most security dashboards read. Uploaded to GitHub, each finding appears in
the repository's Security tab and as an annotation on the affected line in
pull requests.
"""

import hashlib
import json
import re
import sys
from pathlib import Path, PurePath
from typing import Dict, List, Optional
from urllib.parse import quote

from flutter_security_analyzer.core.scanner import Finding, ScanResults
from flutter_security_analyzer.patterns.pattern_registry import PatternRegistry


SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json'
SARIF_VERSION = '2.1.0'
TOOL_NAME = 'Flutter Security Analyzer'
INFORMATION_URI = 'https://github.com/eCaleb/flutter-security-analyzer'
MASVS_URI = 'https://mas.owasp.org/MASVS/'

# SARIF result levels for each scanner severity
LEVELS = {
    'critical': 'error',
    'high': 'error',
    'medium': 'warning',
    'low': 'note',
    'info': 'note',
}

# GitHub turns this score into the severity shown on an alert:
# 9.0 and above is critical, 7.0 to 8.9 high, 4.0 to 6.9 medium, below 4.0 low
SECURITY_SEVERITY = {
    'critical': '9.5',
    'high': '8.0',
    'medium': '5.5',
    'low': '3.0',
    'info': '1.0',
}


class SarifReporter:
    """
    Reporter that outputs findings as a SARIF 2.1.0 log.

    Every rule the scanner knows is listed, so an alert can always show the
    rule's description and remediation, even for rules with no findings.
    File paths are written relative to the current directory where possible,
    which in GitHub Actions is the repository root that code scanning expects.
    """

    def __init__(self, output_path: Optional[str] = None):
        """
        Initialize the SARIF reporter.

        Args:
            output_path: If provided, output will be written to this file
        """
        self.output_path = output_path
        self.pattern_registry = PatternRegistry()

    def generate(self, results: ScanResults):
        """
        Generate the SARIF report.

        Args:
            results: ScanResults object containing findings
        """
        sarif_output = json.dumps(self.build_log(results), indent=2)

        if self.output_path:
            self._write_to_file(sarif_output)
        else:
            print(sarif_output)

    def build_log(self, results: ScanResults) -> dict:
        """Build the SARIF log as a dictionary."""
        rules = self._build_rules(results.findings)
        rule_index = {rule['id']: index for index, rule in enumerate(rules)}

        return {
            '$schema': SARIF_SCHEMA,
            'version': SARIF_VERSION,
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': TOOL_NAME,
                            'version': results.scanner_version,
                            'semanticVersion': results.scanner_version,
                            'informationUri': INFORMATION_URI,
                            'rules': rules,
                        }
                    },
                    'invocations': [{'executionSuccessful': True}],
                    'results': [
                        self._build_result(finding, rule_index[finding.vulnerability_id])
                        for finding in results.findings
                    ],
                }
            ],
        }

    def _build_rules(self, findings: List[Finding]) -> List[dict]:
        """Describe every registered rule, plus any found only by project checks."""
        rules: Dict[str, dict] = {}

        for pattern in self.pattern_registry.get_all_patterns():
            rules[pattern.vulnerability_id] = self._build_rule(
                rule_id=pattern.vulnerability_id,
                title=pattern.title,
                description=pattern.description,
                severity=pattern.severity,
                masvs_category=pattern.masvs_category,
                masvs_control=pattern.masvs_control,
                remediation=pattern.remediation,
                cwe_id=pattern.cwe_id,
            )

        for finding in findings:
            if finding.vulnerability_id not in rules:
                rules[finding.vulnerability_id] = self._build_rule(
                    rule_id=finding.vulnerability_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    masvs_category=finding.masvs_category,
                    masvs_control=finding.masvs_control,
                    remediation=finding.remediation,
                    cwe_id=finding.cwe_id,
                )

        return [rules[rule_id] for rule_id in sorted(rules)]

    def _build_rule(self, rule_id: str, title: str, description: str, severity: str,
                    masvs_category: str, masvs_control: str, remediation: str,
                    cwe_id: str) -> dict:
        """Build one SARIF reportingDescriptor."""
        category = masvs_category if masvs_category.startswith('MASVS-') else f'MASVS-{masvs_category}'
        tags = ['security', category]
        cwe_number = self._cwe_number(cwe_id)
        if cwe_number:
            tags.append(f'external/cwe/cwe-{cwe_number}')

        help_text = f'{remediation}\n\nOWASP MASVS: {masvs_control}.'
        help_markdown = f'{remediation}\n\nOWASP MASVS: [{masvs_control}]({MASVS_URI})'
        if cwe_number:
            cwe_uri = f'https://cwe.mitre.org/data/definitions/{cwe_number}.html'
            help_text += f' {cwe_id}.'
            help_markdown += f', [{cwe_id}]({cwe_uri})'

        rule = {
            'id': rule_id,
            'name': self._rule_name(title),
            'shortDescription': {'text': title},
            'fullDescription': {'text': description},
            'help': {'text': help_text, 'markdown': help_markdown},
            'helpUri': f'https://cwe.mitre.org/data/definitions/{cwe_number}.html' if cwe_number else MASVS_URI,
            'defaultConfiguration': {'level': LEVELS.get(severity, 'warning')},
            'properties': {
                'tags': tags,
                'security-severity': SECURITY_SEVERITY.get(severity, '5.5'),
                'masvs-control': masvs_control,
            },
        }
        return rule

    def _build_result(self, finding: Finding, rule_index: int) -> dict:
        """Build one SARIF result."""
        uri, is_relative = self._artifact_uri(finding.file_path)
        artifact_location = {'uri': uri}
        if is_relative:
            artifact_location['uriBaseId'] = '%SRCROOT%'

        region = {'startLine': max(1, int(finding.line_number or 1))}
        snippet = (finding.code_snippet or '').strip()
        if snippet:
            region['snippet'] = {'text': snippet}

        return {
            'ruleId': finding.vulnerability_id,
            'ruleIndex': rule_index,
            'level': LEVELS.get(finding.severity, 'warning'),
            'message': {'text': f'{finding.title}: {finding.description}'},
            'locations': [
                {
                    'physicalLocation': {
                        'artifactLocation': artifact_location,
                        'region': region,
                    }
                }
            ],
            'partialFingerprints': {
                'flutterSecurityAnalyzer/v1': self._fingerprint(finding, uri, snippet),
            },
            'properties': {
                'severity': finding.severity,
                'confidence': finding.confidence,
                'masvs-category': finding.masvs_category,
                'masvs-control': finding.masvs_control,
            },
        }

    @staticmethod
    def _artifact_uri(file_path: str):
        """
        Return the file's URI and whether it is relative.

        Paths under the current directory become relative URIs with forward
        slashes, as code scanning expects. Anything else becomes a file:// URI.
        """
        absolute = Path(file_path).resolve()
        try:
            relative = absolute.relative_to(Path.cwd().resolve())
            return quote(PurePath(relative).as_posix()), True
        except ValueError:
            return absolute.as_uri(), False

    @staticmethod
    def _fingerprint(finding: Finding, uri: str, snippet: str) -> str:
        """
        Identify a finding without its line number, so an alert keeps its
        identity when code above it moves.
        """
        normalised = re.sub(r'\s+', ' ', snippet)
        key = '|'.join([finding.vulnerability_id, uri, normalised])
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    @staticmethod
    def _rule_name(title: str) -> str:
        """Turn a rule title into a PascalCase name, e.g. HardcodedAPIKeysSecrets."""
        words = re.findall(r'[A-Za-z0-9]+', title)
        return ''.join(word[:1].upper() + word[1:] for word in words)

    @staticmethod
    def _cwe_number(cwe_id: str) -> str:
        """Return the number from an id such as CWE-798, or an empty string."""
        match = re.search(r'(\d+)', cwe_id or '')
        return match.group(1) if match else ''

    def _write_to_file(self, sarif_output: str):
        """Write SARIF output to file."""
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                f.write(sarif_output)
        except IOError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
