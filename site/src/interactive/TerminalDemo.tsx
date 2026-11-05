import React, { useState, useEffect, useRef } from 'react';

interface CommandOutput {
  id: string;
  command: string;
  timestamp: string;
  lines: Array<{
    text: string;
    type?: 'default' | 'cyan' | 'acid' | 'kraft' | 'dim' | 'error' | 'success';
  }>;
}

const PRESET_COMMANDS = [
  { label: 'routes doctor', cmd: 'routes doctor', desc: 'Environment & isolation checks' },
  { label: 'routes engine up', cmd: 'routes engine up', desc: 'Start sandbox manager & gateway' },
  { label: 'routes scan https://example.com', cmd: 'routes scan https://example.com', desc: 'Discover public web surface' },
  { label: 'routes analyze ./sample-app', cmd: 'routes analyze ./sample-app', desc: 'Next.js + pg taint analysis' },
  { label: 'routes findings', cmd: 'routes findings', desc: 'Table of assessment findings' },
  { label: 'routes findings --id 01', cmd: 'routes findings --id 01', desc: 'Inspect SQL injection trace' },
  { label: 'routes report --format html', cmd: 'routes report --format html', desc: 'Generate self-contained report' },
];

export const TerminalDemo: React.FC = () => {
  const [inputVal, setInputVal] = useState<string>('routes analyze ./sample-app');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState<number>(-1);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [activeStage, setActiveStage] = useState<string>('READY');
  const [outputs, setOutputs] = useState<CommandOutput[]>([
    {
      id: 'init-0',
      command: 'routes doctor',
      timestamp: '09:40:12',
      lines: [
        { text: 'ROUTES Doctor (Environment & Dependency Check)', type: 'acid' },
        { text: '------------------------------------------------------------', type: 'dim' },
        { text: '[✓] Python 3.12.2                 PASS (3.11+ required)', type: 'success' },
        { text: '[✓] Docker Engine 26.1.4           PASS (Compose v2 available)', type: 'success' },
        { text: '[✓] Docker Proxy API               PASS (default-deny filter active)', type: 'success' },
        { text: '[✓] Network Gateway                PASS (egress policy enforced)', type: 'success' },
        { text: '[✓] SQLite Storage (~/.routes)     PASS (routes.db initialized)', type: 'success' },
        { text: '[✓] Sandbox Image: discovery       PASS (read-only rootfs, UID 10001)', type: 'cyan' },
        { text: '[✓] Sandbox Image: analyzer        PASS (read-only rootfs, UID 10001)', type: 'cyan' },
        { text: 'STATUS: PASS — Environment is ready for isolated assessments.', type: 'acid' },
      ],
    },
  ]);

  const outputEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    outputEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [outputs, isProcessing]);

  const getSimulatedResponse = (rawCmd: string) => {
    const cmd = rawCmd.trim().toLowerCase().replace(/^\//, '');

    if (cmd === 'clear' || cmd === 'cls') {
      return null;
    }

    if (cmd.includes('doctor')) {
      return [
        { text: 'ROUTES Doctor (Environment & Dependency Check)', type: 'acid' as const },
        { text: '------------------------------------------------------------', type: 'dim' as const },
        { text: '[✓] Python 3.12.2                 PASS (3.11+ required)', type: 'success' as const },
        { text: '[✓] Docker Engine 26.1.4           PASS (Compose v2 available)', type: 'success' as const },
        { text: '[✓] Docker Proxy API               PASS (default-deny filter active)', type: 'success' as const },
        { text: '[✓] Network Gateway                PASS (egress policy enforced)', type: 'success' as const },
        { text: '[✓] SQLite Storage (~/.routes)     PASS (routes.db initialized)', type: 'success' as const },
        { text: '[✓] Sandbox Image: discovery       PASS (read-only rootfs, UID 10001)', type: 'cyan' as const },
        { text: '[✓] Sandbox Image: analyzer        PASS (read-only rootfs, UID 10001)', type: 'cyan' as const },
        { text: 'STATUS: PASS — Sandbox isolation boundary is fully operational.', type: 'acid' as const },
      ];
    }

    if (cmd.includes('engine up')) {
      return [
        { text: 'Starting ROUTES Sandbox Engine...', type: 'cyan' as const },
        { text: '[+] Network routes-control-net     Created (internal: true)', type: 'dim' as const },
        { text: '[+] Container routes-docker-proxy  Started (127.0.0.1 restricted socket)', type: 'success' as const },
        { text: '[+] Container routes-gateway       Started (RFC1918 & metadata blocked)', type: 'success' as const },
        { text: '[+] Container routes-manager       Started (127.0.0.1:8190, token auth)', type: 'success' as const },
        { text: 'Engine ready. Untrusted workloads restricted to disposable containers.', type: 'acid' as const },
        { text: 'Tip: Run `routes scan <url>` or `routes analyze <path>`', type: 'dim' as const },
      ];
    }

    if (cmd.includes('scan')) {
      return [
        { text: 'STARTING WEBSITE DISCOVERY SANDBOX', type: 'acid' as const },
        { text: 'Target: https://example.com', type: 'cyan' as const },
        { text: 'Developer authorization statement: CONFIRMED', type: 'dim' as const },
        { text: 'Creating disposable sandbox (UID 10001, tmpfs noexec, read-only rootfs)...', type: 'dim' as const },
        { text: 'Gateway session opened: exact hostname example.com:443 only.', type: 'dim' as const },
        { text: '[01] Root fetch (HTTP/2 200 OK)                   COMPLETE', type: 'success' as const },
        { text: '[02] Crawling sitemaps and robots.txt             COMPLETE', type: 'success' as const },
        { text: '[03] Page crawl (18/25 HTML pages)                COMPLETE', type: 'success' as const },
        { text: '[04] Form extraction (4 forms, fields cataloged)  COMPLETE', type: 'success' as const },
        { text: '[05] JavaScript bundle analysis (12 bundles)      COMPLETE', type: 'success' as const },
        { text: '[06] Technology detection (Next.js 14, Node.js)   COMPLETE', type: 'success' as const },
        { text: 'Discovery completed in 4.2s. Container routes-sbx-disc-901 cleaned up.', type: 'cyan' as const },
        { text: 'Gateway session closed. RFC 1918 destinations blocked: 0 leaks.', type: 'dim' as const },
        { text: 'FINDINGS: 0 (No active attack modules run in Phase 1 discovery)', type: 'dim' as const },
      ];
    }

    if (cmd.includes('analyze') || cmd.includes('analyse')) {
      return [
        { text: 'SOURCE ANALYSIS: ./sample-app', type: 'acid' as const },
        { text: 'Safe extraction into disposable container (read-only rootfs, tmpfs noexec)...', type: 'dim' as const },
        { text: 'Target profile:', type: 'cyan' as const },
        { text: '  Framework: Next.js 14 (App Router)', type: 'default' as const },
        { text: '  Language:  TypeScript', type: 'default' as const },
        { text: '  Database:  PostgreSQL (pg client Pool)', type: 'default' as const },
        { text: '  Verdict:   SUPPORTED (Full Phase 1 static analysis)', type: 'acid' as const },
        { text: '', type: 'default' as const },
        { text: '[01] Repository profiling                         COMPLETE', type: 'success' as const },
        { text: '[02] Route extraction (tree-sitter AST)           COMPLETE', type: 'success' as const },
        { text: '     -> app/api/search/route.ts (GET, POST)', type: 'dim' as const },
        { text: '     -> app/api/users/[id]/route.ts (GET)', type: 'dim' as const },
        { text: '[03] Query analysis (pg Pool sinks)               COMPLETE', type: 'success' as const },
        { text: '[04] Security rules (Semgrep offline rules)       COMPLETE', type: 'success' as const },
        { text: '[05] Intra-procedural taint propagation           COMPLETE', type: 'success' as const },
        { text: '', type: 'default' as const },
        { text: 'POTENTIAL FINDINGS: 02', type: 'acid' as const },
        { text: '  #01 SQL Injection (routes.sqli.pg-taint)       ▲ HIGH     POTENTIAL', type: 'cyan' as const },
        { text: '  #02 Exposed Key (routes.secrets.api-key)       ■ MEDIUM   POTENTIAL', type: 'dim' as const },
        { text: '', type: 'default' as const },
        { text: 'Run `routes findings --id 01` to view source evidence and taint trace.', type: 'dim' as const },
      ];
    }

    if (cmd.includes('findings --id 01') || cmd.includes('findings --id 1') || cmd.includes('findings 01') || cmd.includes('findings 1')) {
      return [
        { text: 'FINDING DETAIL: #01', type: 'acid' as const },
        { text: '============================================================', type: 'dim' as const },
        { text: 'CLASS:    SQL Injection (PostgreSQL / pg)', type: 'default' as const },
        { text: 'STATUS:   POTENTIAL (Static intra-procedural data flow)', type: 'acid' as const },
        { text: 'SEVERITY: HIGH', type: 'acid' as const },
        { text: 'FILE:     app/api/search/route.ts', type: 'cyan' as const },
        { text: 'LINES:    12-18', type: 'dim' as const },
        { text: '', type: 'default' as const },
        { text: 'TAINT TRACE EVIDENCE:', type: 'cyan' as const },
        { text: '  [1] TAINT SOURCE:', type: 'dim' as const },
        { text: '      const q = req.nextUrl.searchParams.get("q");  (Line 12)', type: 'default' as const },
        { text: '  [2] PROPAGATION:', type: 'dim' as const },
        { text: '      const sql = `SELECT * FROM items WHERE name ILIKE \'%${q}%\'`;  (Line 14)', type: 'error' as const },
        { text: '  [3] SINK (pg Pool):', type: 'dim' as const },
        { text: '      const res = await pool.query(sql);  (Line 16)', type: 'error' as const },
        { text: '', type: 'default' as const },
        { text: 'SUGGESTED REMEDIATION:', type: 'success' as const },
        { text: '  Use parameterized query arguments:', type: 'dim' as const },
        { text: '  const sql = "SELECT * FROM items WHERE name ILIKE $1";', type: 'success' as const },
        { text: '  const res = await pool.query(sql, [`%${q}%`]);', type: 'success' as const },
        { text: '', type: 'default' as const },
        { text: 'LIMITS OF ANALYSIS:', type: 'kraft' as const },
        { text: '  Phase 1 reports static potential evidence. Confirmed reproduction', type: 'kraft' as const },
        { text: '  requires dynamic test run with `routes verify`.', type: 'kraft' as const },
      ];
    }

    if (cmd.includes('findings')) {
      return [
        { text: 'ASSESSMENT FINDINGS (Latest Run)', type: 'acid' as const },
        { text: '============================================================', type: 'dim' as const },
        { text: 'ID   SEV     CLASS           STATUS     LOCATION', type: 'cyan' as const },
        { text: '------------------------------------------------------------', type: 'dim' as const },
        { text: '01   HIGH    SQL Injection   POTENTIAL  app/api/search/route.ts:14', type: 'default' as const },
        { text: '02   MED     Exposed Key     POTENTIAL  app/config/keys.ts:8', type: 'default' as const },
        { text: '------------------------------------------------------------', type: 'dim' as const },
        { text: 'Phase 1 static analysis produces POTENTIAL and INCONCLUSIVE findings.', type: 'dim' as const },
        { text: 'CONFIRMED status is reserved for isolated runtime reproduction.', type: 'dim' as const },
        { text: '', type: 'default' as const },
        { text: 'Run `routes findings --id 01` to inspect source evidence.', type: 'acid' as const },
      ];
    }

    if (cmd.includes('report')) {
      return [
        { text: 'Generating assessment report...', type: 'cyan' as const },
        { text: 'Format: HTML (Self-contained standalone report)', type: 'default' as const },
        { text: 'Written to: ~/.routes/reports/sample-app/report.html', type: 'success' as const },
        { text: '', type: 'default' as const },
        { text: 'REPORT METRICS:', type: 'acid' as const },
        { text: '  • Public endpoints cataloged: 18 pages, 4 forms, 2 API routes', type: 'default' as const },
        { text: '  • Technology stack: Next.js 14, Node.js, PostgreSQL (pg)', type: 'default' as const },
        { text: '  • Finding count: 2 Potential, 0 Inconclusive, 0 Confirmed', type: 'default' as const },
        { text: '  • Sandbox isolation: Preserved across all 4 execution stages', type: 'success' as const },
        { text: '  • Retention: 5 assessments kept per project in ~/.routes', type: 'dim' as const },
      ];
    }

    if (cmd.includes('help')) {
      return [
        { text: 'ROUTES SIMULATED WORKBENCH — AVAILABLE COMMANDS:', type: 'acid' as const },
        { text: '  routes doctor                 Check dependencies and sandbox health', type: 'cyan' as const },
        { text: '  routes engine up              Start sandbox manager & network gateway', type: 'cyan' as const },
        { text: '  routes scan <url>             Discover public pages, forms and API routes', type: 'cyan' as const },
        { text: '  routes analyze <path>         Next.js + pg static taint analysis', type: 'cyan' as const },
        { text: '  routes findings               Display table of security findings', type: 'cyan' as const },
        { text: '  routes findings --id 01       Inspect SQL injection flow & source lines', type: 'cyan' as const },
        { text: '  routes report --format html   Generate static HTML assessment report', type: 'cyan' as const },
        { text: '  clear                         Clear terminal output buffer', type: 'cyan' as const },
        { text: '', type: 'default' as const },
        { text: '* Deterministic simulator with representative security evidence.', type: 'dim' as const },
      ];
    }

    return [
      { text: `Command not recognized in simulated sandbox: "${rawCmd}"`, type: 'error' as const },
      { text: 'Try: routes doctor, routes engine up, routes scan, routes analyze, routes findings, or help', type: 'dim' as const },
    ];
  };

  const handleExecute = (cmdToRun: string) => {
    const trimmed = cmdToRun.trim();
    if (!trimmed) return;

    if (trimmed.toLowerCase() === 'clear' || trimmed.toLowerCase() === 'cls') {
      setOutputs([]);
      return;
    }

    setHistory((prev) => [...prev, trimmed]);
    setHistoryIdx(-1);
    setIsProcessing(true);
    setActiveStage('RUNNING');

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];

    setTimeout(() => {
      const result = getSimulatedResponse(trimmed);
      if (result) {
        setOutputs((prev) => [
          ...prev,
          {
            id: `cmd-${Date.now()}`,
            command: trimmed,
            timestamp: timeStr,
            lines: result,
          },
        ]);
      }
      setIsProcessing(false);
      setActiveStage('COMPLETED');
    }, 380);
  };

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    handleExecute(inputVal);
    setInputVal('');
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0) {
        const nextIdx = historyIdx + 1 < history.length ? historyIdx + 1 : historyIdx;
        setHistoryIdx(nextIdx);
        setInputVal(history[history.length - 1 - nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIdx > 0) {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setInputVal(history[history.length - 1 - nextIdx]);
      } else if (historyIdx === 0) {
        setHistoryIdx(-1);
        setInputVal('');
      }
    }
  };

  const handlePresetClick = (cmd: string) => {
    setInputVal(cmd);
    handleExecute(cmd);
  };

  const handleReset = () => {
    setOutputs([
      {
        id: 'reset-init',
        command: 'routes doctor',
        timestamp: '10:00:00',
        lines: [
          { text: 'ROUTES Sandbox Engine Reset.', type: 'acid' },
          { text: 'Session cleared. Ready for security assessment simulation.', type: 'dim' },
        ],
      },
    ]);
    setActiveStage('READY');
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
      {/* Left 5 Cols: Input Controls, Presets & Assessment Metadata */}
      <div className="lg:col-span-5 bg-paper torn-card-main p-6 sm:p-8 cutout-shadow border-2 border-xerox flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between border-b-2 border-xerox pb-3 mb-5">
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              COMMAND VECTOR // CLI
            </span>
            <span className="bg-acid text-xerox font-mono text-[11px] font-bold px-2.5 py-0.5 border border-xerox">
              STAGE: {activeStage}
            </span>
          </div>

          <p className="font-mono text-xs text-xerox/80 mb-4 leading-relaxed">
            Run real ROUTES commands against a deterministic sandbox model. Inspect website discovery, source AST parsing, Next.js + pg taint tracking, and potential findings.
          </p>

          {/* Form Input */}
          <form onSubmit={handleSubmit} className="mb-5">
            <div className="flex border-2 border-xerox bg-[#FFFDF9] cutout-shadow-sm">
              <span className="bg-xerox text-acid font-mono font-bold text-xs px-3 py-3 select-none flex items-center">
                $
              </span>
              <input
                ref={inputRef}
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="routes analyze ./sample-app"
                aria-label="ROUTES CLI input"
                className="w-full px-3 py-2.5 font-mono text-xs sm:text-sm text-xerox bg-transparent focus:outline-none"
              />
              <button
                type="submit"
                disabled={isProcessing}
                className="bg-cyan hover:bg-acid text-xerox font-mono font-bold text-xs px-4 border-l-2 border-xerox shrink-0 transition-none cursor-pointer disabled:opacity-50"
              >
                {isProcessing ? 'RUN...' : 'EXEC →'}
              </button>
            </div>
            <div className="flex items-center justify-between mt-1 text-[10px] font-mono text-xerox/70">
              <span>Press Enter or click Exec</span>
              <span>↑/↓ for history</span>
            </div>
          </form>

          {/* Preset Buttons */}
          <div className="mb-6">
            <span className="font-scrawl text-xs text-xerox/85 block mb-2.5">
              OR CLICK A COMMAND PRESET:
            </span>
            <div className="flex flex-wrap gap-2">
              {PRESET_COMMANDS.map((preset) => (
                <button
                  key={preset.cmd}
                  type="button"
                  onClick={() => handlePresetClick(preset.cmd)}
                  title={preset.desc}
                  className="bg-[#E6E2D8] hover:bg-xerox hover:text-acid text-xerox font-mono text-xs font-bold px-2.5 py-1.5 border border-xerox cutout-shadow-sm transition-none cursor-pointer text-left"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Security Controls & Sandbox Status */}
        <div className="border-t-2 border-xerox pt-4 space-y-2">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-xerox/80 font-bold">SANDBOX ISOLATION:</span>
            <span className="bg-xerox text-acid px-1.5 py-0.5">UID 10001 (NON-ROOT)</span>
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-xerox/80 font-bold">FILESYSTEM:</span>
            <span className="bg-xerox text-paper px-1.5 py-0.5">READ-ONLY + NOEXEC TMPFS</span>
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-xerox/80 font-bold">NETWORK GATEWAY:</span>
            <span className="bg-cyan text-xerox font-bold px-1.5 py-0.5">RFC1918 BLOCKED</span>
          </div>
          <div className="pt-2 flex justify-end">
            <button
              type="button"
              onClick={handleReset}
              className="bg-kraft hover:bg-xerox hover:text-paper text-xerox font-mono text-[10px] font-bold px-2.5 py-1 border border-xerox cursor-pointer transition-none"
            >
              [RESET SESSION]
            </button>
          </div>
        </div>
      </div>

      {/* Right 7 Cols: Simulated Terminal Screen */}
      <div className="lg:col-span-7 bg-xerox text-paper p-5 sm:p-7 cutout-shadow-hard relative flex flex-col justify-between border-2 border-xerox min-h-[500px]">
        {/* Terminal Header Bar */}
        <div className="flex items-center justify-between border-b border-paper/20 pb-3 mb-4 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-acid inline-block"></span>
            <span className="text-acid font-bold">ROUTES TERMINAL // SIMULATED RUNTIME</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="bg-[#2D2D2A] text-kraft px-2 py-0.5 text-[10px]">
              SAMPLE_DATA_ONLY
            </span>
            <button
              type="button"
              onClick={() => setOutputs([])}
              className="bg-paper text-xerox font-mono text-[10px] font-bold px-2 py-0.5 hover:bg-cyan cursor-pointer transition-none"
            >
              CLEAR
            </button>
          </div>
        </div>

        {/* Output Stream */}
        <div
          className="flex-1 font-mono text-xs leading-relaxed overflow-y-auto space-y-4 max-h-[520px] pr-2 select-text"
          role="region"
          aria-label="Terminal Output"
        >
          {outputs.map((out) => (
            <div key={out.id} className="border-b border-paper/10 pb-3">
              <div className="flex items-center gap-2 text-kraft text-[11px] mb-1.5">
                <span className="text-acid font-bold">$ {out.command}</span>
                <span className="opacity-60">[{out.timestamp}]</span>
              </div>
              <div className="space-y-0.5 pl-2 border-l border-paper/20">
                {out.lines.map((line, idx) => {
                  let colorClass = 'text-paper';
                  if (line.type === 'acid') colorClass = 'text-acid font-bold';
                  if (line.type === 'cyan') colorClass = 'text-cyan font-bold';
                  if (line.type === 'success') colorClass = 'text-[#64E572]';
                  if (line.type === 'error') colorClass = 'text-[#FF6B6B] font-bold';
                  if (line.type === 'dim') colorClass = 'text-paper/60';
                  if (line.type === 'kraft') colorClass = 'text-kraft';

                  return (
                    <div key={idx} className={`${colorClass} font-mono text-[11px] sm:text-xs whitespace-pre-wrap break-all`}>
                      {line.text}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}

          {isProcessing && (
            <div className="flex items-center gap-2 text-acid text-xs py-2 animate-pulse">
              <span>⠸</span>
              <span>ROUTES sandbox engine executing in disposable container...</span>
            </div>
          )}

          <div ref={outputEndRef} />
        </div>

        {/* Terminal Footer Bar */}
        <div className="mt-4 pt-3 border-t border-paper/20 flex flex-wrap items-center justify-between text-[11px] font-mono text-kraft gap-2">
          <span>TARGET: NEXT.JS + POSTGRESQL (PG)</span>
          <span className="text-cyan font-bold">STATUS: ISOLATED WORKLOAD</span>
        </div>
      </div>
    </div>
  );
};
