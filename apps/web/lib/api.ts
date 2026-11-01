/* Typed client for the ROUTES API. Requests go to the same origin (/api/*),
 * cookies are HttpOnly, and unsafe methods send the CSRF double-submit header. */

export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, string>;
  constructor(status: number, code: string, message: string, details: Record<string, string> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.split("; ").find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

let csrfPromise: Promise<string> | null = null;

async function csrfToken(): Promise<string> {
  const existing = readCookie("routes_csrf");
  if (existing) return existing;
  csrfPromise ??= fetch("/api/v1/auth/csrf", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((d) => d.csrf_token as string)
    .finally(() => {
      csrfPromise = null;
    });
  return csrfPromise;
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-CSRF-Token", await csrfToken());
  }
  const res = await fetch(`/api/v1${path}`, { ...init, method, headers, body, credentials: "same-origin" });
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (!res.ok) {
    const err = (data as { error?: { code: string; message: string; details?: Record<string, string> } })?.error;
    if (res.status === 401 && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")
        && !window.location.pathname.startsWith("/register")) {
      window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    }
    throw new ApiError(res.status, err?.code ?? "error", err?.message ?? `Request failed (${res.status}).`, err?.details ?? {});
  }
  return data as T;
}

// ------------------------------------------------------------------ types

export type User = { id: string; email: string; display_name: string; created_at: string };

export type Integration = {
  id: string;
  kind: "github_public" | "github_private" | "zip";
  repo_owner: string | null;
  repo_name: string | null;
  repo_ref: string | null;
  upload_filename: string | null;
  upload_size: number | null;
  match_status: "pending" | "confirmed" | "rejected";
  match_evidence: MatchEvidence[];
  match_decided_at: string | null;
  created_at: string;
};

export type MatchEvidence = { kind: string; detail: string; file: string | null; matches_target: boolean };

export type Project = {
  id: string;
  name: string;
  website_url: string;
  hostname: string;
  authorised_at: string;
  authorisation_statement: string;
  created_at: string;
  integration: Integration | null;
  latest_assessment: { id: string; status: AssessmentStatus; created_at: string; finished_at: string | null; findings_count: number } | null;
  framework: string | null;
};

export type AssessmentStatus =
  | "queued" | "running" | "discovering" | "analysing" | "completed" | "partially_completed" | "failed" | "cancelled";

export const ACTIVE_STATUSES: AssessmentStatus[] = ["queued", "running", "discovering", "analysing"];

export type Job = {
  id: string;
  kind: "discovery" | "source" | "results";
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "skipped";
  stage: string | null;
  message: string | null;
  stages_completed: string[];
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
};

export type DiscoverySummary = {
  stack?: { framework: string; language: string; runtime: string; database: string; confidence: string };
  pages_total?: number;
  pages_inspected?: number;
  pages_failed?: number;
  page_limit?: number;
  page_limit_reached?: boolean;
  rendered_pages?: number;
  login_pages?: string[];
  registration_pages?: string[];
  robots?: { found: boolean; disallow_rules: number; sitemaps: string[]; blocked_urls: string[] };
  sitemap_urls?: number;
  scripts_count?: number;
  scripts?: string[];
  external_hosts?: string[];
  openapi?: { url: string; title: string | null; version: string | null; paths_count: number }[];
  forms_count?: number;
  network?: { requests?: number; allowed?: number; denied?: number; denied_reasons?: string[]; destinations?: string[] };
  source_framework?: string;
  source_support?: string;
  correlated_endpoints?: number;
};

export type Assessment = {
  id: string;
  project_id: string;
  project_name: string;
  status: AssessmentStatus;
  target_url: string;
  source_kind: string | null;
  source_label: string | null;
  manifest_detected: boolean;
  manifest_data: { detected: boolean; valid: boolean; error: string | null; data: Record<string, unknown> | null } | null;
  discovery_summary: DiscoverySummary;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  jobs: Job[];
  counts: { pages: number; endpoints: number; forms: number; technologies: number; findings: number };
  severity_counts: Record<string, number>;
};

export type Page = {
  id: string; url: string; status_code: number | null; title: string | null; content_type: string | null;
  depth: number; rendered: boolean; is_login: boolean; is_registration: boolean; links_count: number;
  forms_count: number; scripts_count: number; error: string | null;
};

export type Endpoint = {
  id: string; method: string; url: string; path: string;
  origin: "form" | "link_query" | "js_reference" | "openapi" | "source_route";
  parameters: string[]; details: Record<string, unknown>; evidence: string; page_url: string | null;
};

export type Technology = {
  id: string; name: string; category: string; version: string | null; confidence: string;
  source: "website" | "repository"; evidence: string[];
};

export type SourceResult = {
  source_kind: string; support_status: "supported" | "partial" | "unsupported"; support_reason: string;
  framework: string; runtime: string;
  profile: { languages?: Record<string, number>; framework_version?: string | null; package_manager?: string | null;
             lockfiles?: string[]; typescript?: boolean; router?: string | null; dependencies?: { name: string; version: string | null; dev: boolean }[];
             database_libraries?: string[]; total_files?: number; analysed_files?: number };
  routes: { path: string; methods: string[]; file: string; line: number | null; router: string; handler: string | null }[];
  db_interactions: { file: string; line: number; call: string; client: string; query_construction: string;
                     uses_user_input: boolean; endpoint: string | null; method: string | null }[];
  input_sources: { file: string; line: number; kind: string; name: string | null }[];
  config_refs: { file: string; line: number | null; kind: string; name: string }[];
  env_var_names: string[];
  match_evidence: MatchEvidence[];
  warnings: string[];
};

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Snapshot = { file: string; start_line: number; end_line: number; code: string };

export type Finding = {
  id: string; assessment_id: string; type: string; status: "potential" | "confirmed" | "inconclusive";
  severity: Severity; confidence: "high" | "medium" | "low"; title: string; file: string | null; line: number | null;
  end_line: number | null; endpoint: string | null; method: string | null; rule_id: string; plain_description: string;
  evidence_summary: string; technical_details: Record<string, unknown>; recommendation: string;
  fingerprint: string; snapshot: Snapshot | null; created_at: string;
  project_id?: string; project_name?: string;
};

export type RemediationStatus = "pending" | "running" | "succeeded" | "needs_human_review" | "failed" | "cancelled";

export const ACTIVE_REMEDIATION_STATUSES: RemediationStatus[] = ["pending", "running"];

export type RemediationIteration = {
  id: string; round_no: number | null; candidate_hash: string | null; candidate_code: string | null;
  test_results: { status?: string; tests?: { name: string; category: "exploit" | "benign"; passed: boolean; message: string }[] };
  rescan_diff: { fingerprint_gone?: boolean; new_fingerprints?: string[] };
  failure_output: string | null; created_at: string;
};

export type RemediationVerdict =
  | "verified_fixed" | "partially_remediated" | "human_review" | "inconclusive" | "failed" | "cancelled";

export type RemediationFinding = {
  finding_id: string; is_primary: boolean; resolution: string; resolution_reason: string | null;
  gates: Record<string, boolean>; residual_risk: string | null;
};

export type Remediation = {
  id: string; finding_id: string; status: RemediationStatus; finding_status: string; cancel_requested: boolean;
  error: string | null; started_at: string | null; finished_at: string | null; created_at: string;
  iterations: RemediationIteration[];
  // Recorded since migration 0008: workflow stage and the evidence-based verdict.
  project_id: string; assessment_id: string; stage: string; verdict: RemediationVerdict | null;
  verdict_reason: string | null; failure_category: string | null; attempts_total: number; max_attempts: number;
  version: number; findings: RemediationFinding[];
};

export type Overview = {
  projects: number; assessments: number; active_assessments: number; open_findings: number;
  severity_counts: Record<string, number>; recent_assessments: Assessment[]; recent_findings: Finding[];
};
