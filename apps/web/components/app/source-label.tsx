import { FileArchive, Github, Lock } from "lucide-react";

import type { Integration } from "@/lib/api";

export function SourceLabel({ integration }: { integration: Integration | null }) {
  if (!integration) return <span className="text-muted">None</span>;
  if (integration.kind === "zip") {
    return (
      <span className="inline-flex items-center gap-1.5 text-ink-2">
        <FileArchive className="size-3.5 text-faint" />
        <span className="mono text-[12px]">{integration.upload_filename}</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-ink-2">
      {integration.kind === "github_private" ? <Lock className="size-3.5 text-faint" /> : <Github className="size-3.5 text-faint" />}
      <span className="mono text-[12px]">
        {integration.repo_owner}/{integration.repo_name}
        {integration.repo_ref ? `@${integration.repo_ref}` : ""}
      </span>
    </span>
  );
}
