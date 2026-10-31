"""Broken access control (A01) behind the VulnClass interface.

Reuses the route map and DB-interaction attribution that SqliVulnClass
already built, so this must be registered after it (same coupling as
XssVulnClass).
"""

from __future__ import annotations

from source_analyzer.data_flow.access_control import detect_access_control
from source_analyzer.static_analysis.findings import a01_ownership_finding, a01_unprotected_finding
from source_analyzer.vuln_classes.base import AnalysisContext, VulnClass

BUILDERS = {"unprotected": a01_unprotected_finding, "ownership": a01_ownership_finding}


class A01VulnClass(VulnClass):
    rule_prefix = "routes.a01"

    def detect(self, ctx: AnalysisContext) -> list[dict]:
        analyzer = ctx.sqli_analyzer
        if analyzer is None:
            ctx.warnings.append("Access-control analysis was skipped: the route map was not built.")
            return []
        return [BUILDERS[f.kind](f) for f in detect_access_control(analyzer)]
