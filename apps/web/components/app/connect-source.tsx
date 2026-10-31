"use client";

import { FileArchive, Github, Lock } from "lucide-react";
import * as React from "react";

import { Notice } from "@/components/app/layout-parts";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError, type Integration } from "@/lib/api";
import { cn } from "@/lib/utils";

type Mode = "public" | "private" | "zip";

const MODES: { id: Mode; label: string; icon: typeof Github }[] = [
  { id: "public", label: "Public GitHub repository", icon: Github },
  { id: "private", label: "Private GitHub repository", icon: Lock },
  { id: "zip", label: "ZIP upload", icon: FileArchive },
];

export function ConnectSource({
  projectId, onConnected,
}: { projectId: string; onConnected: (r: { integration: Integration; assessment_id: string }) => void }) {
  const [mode, setMode] = React.useState<Mode>("public");
  const [error, setError] = React.useState<ApiError | null>(null);
  const [pending, setPending] = React.useState(false);
  const [progress, setProgress] = React.useState<number | null>(null);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setPending(true);
    setError(null);
    try {
      let result: { integration: Integration; assessment_id: string };
      if (mode === "zip") {
        const file = form.get("file");
        if (!(file instanceof File) || file.size === 0) throw new ApiError(400, "invalid", "Choose a .zip file to upload.");
        if (file.size > 100 * 1024 * 1024) throw new ApiError(413, "too_large", "ZIP uploads are limited to 100 MB.");
        result = await uploadZip(projectId, file, setProgress);
      } else {
        result = await api(`/projects/${projectId}/integrations/github`, {
          method: "POST",
          json: {
            repo_url: form.get("repo_url"),
            ref: form.get("ref") || null,
            visibility: mode,
            token: mode === "private" ? form.get("token") : null,
          },
        });
      }
      (e.target as HTMLFormElement).reset();
      onConnected(result);
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "network", "Could not reach ROUTES."));
    } finally {
      setPending(false);
      setProgress(null);
    }
  }

  return (
    <div className="rounded-md border border-line bg-surface">
      <div className="flex border-b border-line" role="tablist">
        {MODES.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={mode === id}
            onClick={() => { setMode(id); setError(null); }}
            className={cn(
              "-mb-px flex flex-1 items-center justify-center gap-2 border-b-2 px-3 py-2.5 text-[12.5px] font-medium",
              mode === id ? "border-ink text-ink" : "border-transparent text-muted hover:text-ink",
            )}
          >
            <Icon className="size-3.5" /> {label}
          </button>
        ))}
      </div>
      <form onSubmit={submit} className="space-y-4 p-5" key={mode}>
        {error && <Notice tone="bad">{Object.values(error.details)[0] ?? error.message}</Notice>}
        {mode !== "zip" && (
          <div className="grid gap-4 sm:grid-cols-[1fr_180px]">
            <div className="space-y-1.5">
              <Label htmlFor="repo_url">Repository URL</Label>
              <Input id="repo_url" name="repo_url" placeholder="https://github.com/owner/repository" required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ref">Branch or tag <span className="font-normal text-faint">(optional)</span></Label>
              <Input id="ref" name="ref" placeholder="default branch" />
            </div>
          </div>
        )}
        {mode === "private" && (
          <div className="space-y-1.5">
            <Label htmlFor="token">Fine-grained personal access token</Label>
            <Input id="token" name="token" type="password" autoComplete="off" spellCheck={false} required placeholder="github_pat_…" />
            <p className="text-[12px] leading-relaxed text-muted">
              Create a token limited to this one repository with <strong className="font-medium text-ink-2">Contents: Read-only</strong> permission.
              ROUTES uses it once to download the code and never stores it: not in the database, the job queue or logs.
              You will need to provide it again for future assessments.
            </p>
          </div>
        )}
        {mode === "zip" && (
          <div className="space-y-1.5">
            <Label htmlFor="file">Source archive (.zip, up to 100 MB)</Label>
            <Input id="file" name="file" type="file" accept=".zip,application/zip" required className="h-auto py-1.5" />
            <p className="text-[12px] text-muted">
              Dependency and build folders (node_modules, .next, dist…) are skipped. The archive is deleted when analysis finishes.
            </p>
          </div>
        )}
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={pending}>
            {pending ? (progress !== null ? `Uploading ${progress}%` : "Connecting…") : mode === "zip" ? "Upload and analyse" : "Connect and analyse"}
          </Button>
          <span className="text-[12px] text-muted">The code is analysed statically in a disposable sandbox. It is never run.</span>
        </div>
      </form>
    </div>
  );
}

function readCsrf(): string {
  const m = document.cookie.split("; ").find((c) => c.startsWith("routes_csrf="));
  return m ? decodeURIComponent(m.slice("routes_csrf=".length)) : "";
}

async function uploadZip(projectId: string, file: File, onProgress: (n: number) => void) {
  if (!readCsrf()) await fetch("/api/v1/auth/csrf", { credentials: "same-origin" });
  return new Promise<{ integration: Integration; assessment_id: string }>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/v1/projects/${projectId}/integrations/zip`);
    xhr.withCredentials = true;
    xhr.setRequestHeader("X-CSRF-Token", readCsrf());
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.onload = () => {
      let body: { error?: { code: string; message: string; details?: Record<string, string> } } | null = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as unknown as { integration: Integration; assessment_id: string });
      else reject(new ApiError(xhr.status, body?.error?.code ?? "error", body?.error?.message ?? "Upload failed.", body?.error?.details ?? {}));
    };
    xhr.onerror = () => reject(new ApiError(0, "network", "The upload could not be completed."));
    const data = new FormData();
    data.append("file", file);
    xhr.send(data);
  });
}
