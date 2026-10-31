"""Unit tests for the VulnClass plugin interface (S3). Detection-correctness
itself is unchanged and still covered end-to-end by test_analysis.py."""

import pytest

from source_analyzer.vuln_classes import VULN_CLASSES, SqliVulnClass, XssVulnClass
from source_analyzer.vuln_classes.base import VulnClass


def test_registry_contains_exactly_sqli_then_xss():
    assert len(VULN_CLASSES) == 2
    assert isinstance(VULN_CLASSES[0], SqliVulnClass)
    assert isinstance(VULN_CLASSES[1], XssVulnClass)


def test_each_plugin_satisfies_the_interface():
    for plugin in VULN_CLASSES:
        assert isinstance(plugin, VulnClass)
        assert isinstance(plugin.rule_prefix, str) and plugin.rule_prefix.startswith("routes.")


def test_unimplemented_pipeline_stages_raise_not_implemented():
    # build_snapshot is real as of S4 - see test_snapshot.py. The rest still
    # await S6/S7.
    for plugin in VULN_CLASSES:
        with pytest.raises(NotImplementedError):
            plugin.build_testbench({}, snapshot=None)
        with pytest.raises(NotImplementedError):
            plugin.exploit_assertions({})
        with pytest.raises(NotImplementedError):
            plugin.benign_assertions({})
        with pytest.raises(NotImplementedError):
            plugin.fix_constraints({}, snapshot=None)
