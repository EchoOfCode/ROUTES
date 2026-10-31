from source_analyzer.vuln_classes.base import AnalysisContext, Assertion, FixConstraints, Snapshot, Testbench, VulnClass
from source_analyzer.vuln_classes.a01_plugin import A01VulnClass
from source_analyzer.vuln_classes.sqli_plugin import SqliVulnClass
from source_analyzer.vuln_classes.xss_plugin import XssVulnClass

# Order matters: XssVulnClass and A01VulnClass both depend on
# SqliVulnClass.detect() having already populated AnalysisContext.sqli_analyzer.
VULN_CLASSES: list[VulnClass] = [SqliVulnClass(), XssVulnClass(), A01VulnClass()]

__all__ = [
    "VulnClass",
    "AnalysisContext",
    "Snapshot",
    "Testbench",
    "Assertion",
    "FixConstraints",
    "SqliVulnClass",
    "A01VulnClass",
    "XssVulnClass",
    "VULN_CLASSES",
]
