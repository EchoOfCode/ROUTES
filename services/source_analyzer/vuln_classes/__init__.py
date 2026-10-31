from source_analyzer.vuln_classes.base import AnalysisContext, Assertion, FixConstraints, Snapshot, Testbench, VulnClass
from source_analyzer.vuln_classes.sqli_plugin import SqliVulnClass
from source_analyzer.vuln_classes.xss_plugin import XssVulnClass

# Order matters: XssVulnClass.detect() depends on SqliVulnClass.detect()
# having already populated AnalysisContext.sqli_analyzer.
VULN_CLASSES: list[VulnClass] = [SqliVulnClass(), XssVulnClass()]

__all__ = [
    "VulnClass",
    "AnalysisContext",
    "Snapshot",
    "Testbench",
    "Assertion",
    "FixConstraints",
    "SqliVulnClass",
    "XssVulnClass",
    "VULN_CLASSES",
]
