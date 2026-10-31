"""Unit tests for the VulnClass plugin interface (S3). Detection-correctness
itself is unchanged and still covered end-to-end by test_analysis.py."""

import pytest

from routes_shared.remediation import Snapshot
from source_analyzer.vuln_classes import A01VulnClass, VULN_CLASSES, SqliVulnClass, XssVulnClass
from source_analyzer.vuln_classes.base import VulnClass


def test_registry_runs_sqli_first_because_the_others_depend_on_it():
    assert len(VULN_CLASSES) == 3
    assert isinstance(VULN_CLASSES[0], SqliVulnClass)
    assert isinstance(VULN_CLASSES[1], XssVulnClass)
    assert isinstance(VULN_CLASSES[2], A01VulnClass)


def test_each_plugin_satisfies_the_interface():
    for plugin in VULN_CLASSES:
        assert isinstance(plugin, VulnClass)
        assert isinstance(plugin.rule_prefix, str) and plugin.rule_prefix.startswith("routes.")


def test_unimplemented_pipeline_stages_raise_not_implemented():
    # build_snapshot (S4) and fix_constraints (S6) are real now. The rest
    # still await S7.
    for plugin in VULN_CLASSES:
        with pytest.raises(NotImplementedError):
            plugin.build_testbench({}, snapshot=None)
        with pytest.raises(NotImplementedError):
            plugin.exploit_assertions({})
        with pytest.raises(NotImplementedError):
            plugin.benign_assertions({})


def test_fix_constraints_derives_from_the_snapshot():
    snapshot = Snapshot(file="app/api/search/route.ts", start_line=4, end_line=8, code="...")
    for plugin in VULN_CLASSES:
        constraints = plugin.fix_constraints({}, snapshot)
        assert constraints.file == snapshot.file
        assert constraints.start_line == snapshot.start_line
        assert constraints.end_line == snapshot.end_line
        assert constraints.forbid_new_dependencies is True
        assert constraints.forbid_network_calls is True
