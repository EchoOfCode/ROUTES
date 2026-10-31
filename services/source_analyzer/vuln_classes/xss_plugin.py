"""XSS behind the VulnClass interface. XssAnalyzer and the finding builders
are unchanged - this is only a thinner call site.

Depends on SqliVulnClass having already run (reuses its parsed module ASTs
and discovered routes, see AnalysisContext's docstring); VULN_CLASSES orders
sqli before xss specifically for this reason.
"""

from __future__ import annotations

from source_analyzer.data_flow.xss import XssAnalyzer
from source_analyzer.static_analysis.findings import xss_dom_sink_finding, xss_reflected_finding
from source_analyzer.vuln_classes.base import AnalysisContext, VulnClass


class XssVulnClass(VulnClass):
    rule_prefix = "routes.xss"

    def detect(self, ctx: AnalysisContext) -> list[dict]:
        if ctx.sqli_analyzer is None:
            raise RuntimeError("XssVulnClass requires SqliVulnClass to run first (see AnalysisContext docstring).")
        module_functions = {rel: list(mod.functions.values()) for rel, mod in ctx.sqli_analyzer.modules.items()}
        analyzer = XssAnalyzer(module_functions, ctx.sqli_analyzer.routes)
        analyzer.run()
        return [xss_dom_sink_finding(f) if f.rule == "dom_sink" else xss_reflected_finding(f)
                for f in analyzer.findings]
