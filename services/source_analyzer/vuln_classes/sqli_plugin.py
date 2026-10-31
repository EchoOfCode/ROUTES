"""SQLi behind the VulnClass interface. SqliAnalyzer and the finding builders
are unchanged - this is only a thinner call site."""

from __future__ import annotations

from source_analyzer.data_flow.sqli import SqliAnalyzer
from source_analyzer.static_analysis.findings import sqli_finding, sqli_inconclusive
from source_analyzer.vuln_classes.base import AnalysisContext, VulnClass


class SqliVulnClass(VulnClass):
    rule_prefix = "routes.sqli"

    def detect(self, ctx: AnalysisContext) -> list[dict]:
        analyzer = SqliAnalyzer(ctx.files, tsconfig_paths=ctx.tsconfig_paths, tsconfig_base=ctx.tsconfig_base)
        analyzer.run()
        ctx.sqli_analyzer = analyzer
        if analyzer.parse_errors:
            ctx.warnings.append(f"{len(analyzer.parse_errors)} file(s) could not be parsed completely.")

        uses_pg = ctx.pg_declared or any(m.imports_pg for m in analyzer.modules.values())
        if not uses_pg:
            return []
        findings: list[dict] = []
        for i in analyzer.interactions:
            if i.uses_user_input and i.construction in ("interpolated", "concatenated", "direct"):
                findings.append(sqli_finding(i))
        for exp in analyzer.helper_sinks_without_tainted_callers():
            findings.append(sqli_inconclusive(exp))
        return findings
