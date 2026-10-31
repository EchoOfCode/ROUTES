"use client";

import * as React from "react";

import { KeyValues, Loading, Notice, PageBody, PageHeader, Section } from "@/components/app/layout-parts";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { api, ApiError, type User } from "@/lib/api";
import { relativeTime } from "@/lib/utils";

type Session = { id: string; created_at: string; last_seen_at: string; user_agent: string; current: boolean };

export default function SettingsPage() {
  const user = useApi<User>("/auth/me");
  const sessions = useApi<Session[]>("/auth/sessions");
  return (
    <>
      <PageHeader title="Settings" />
      <PageBody className="max-w-[860px]">
        {!user.data ? <Loading /> : <Profile user={user.data} onSaved={(u) => user.setData(u)} />}
        <PasswordForm onChanged={() => sessions.reload()} />
        <Section title="Sessions" description="Devices currently signed in to this ROUTES installation."
          actions={<Button variant="secondary" size="sm" onClick={async () => { await api("/auth/sessions/revoke-others", { method: "POST" }); sessions.reload(); }}>Sign out other sessions</Button>}>
          {sessions.data ? (
            <Table>
              <THead><TR><TH>Browser</TH><TH>Signed in</TH><TH>Last active</TH></TR></THead>
              <TBody>
                {sessions.data.map((s) => (
                  <TR key={s.id}>
                    <TD className="max-w-[420px] truncate text-[12.5px]">{s.user_agent || "Unknown"}{s.current && <span className="ml-2 text-[11px] font-semibold uppercase text-ok">This session</span>}</TD>
                    <TD className="text-muted">{relativeTime(s.created_at)}</TD>
                    <TD className="text-muted">{relativeTime(s.last_seen_at)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          ) : <Loading />}
        </Section>
        <Section title="Assessment limits" description="Fixed for this local build.">
          <KeyValues columns={3} items={[
            ["Pages per assessment", "25 HTML pages"],
            ["Assessment history", "5 per project"],
            ["ZIP upload size", "100 MB"],
            ["Crawl scope", "Exact hostname only"],
            ["Request types", "Public GET requests only"],
            ["Findings", "Static analysis (potential / inconclusive)"],
          ]} />
        </Section>
      </PageBody>
    </>
  );
}

function Profile({ user, onSaved }: { user: User; onSaved: (u: User) => void }) {
  const [name, setName] = React.useState(user.display_name);
  const [state, setState] = React.useState<"idle" | "saving" | "saved">("idle");
  return (
    <Section title="Profile">
      <form className="flex flex-wrap items-end gap-3 rounded-md border border-line bg-surface p-4" onSubmit={async (e) => {
        e.preventDefault();
        setState("saving");
        onSaved(await api<User>("/auth/me", { method: "PATCH", json: { display_name: name } }));
        setState("saved");
      }}>
        <div className="space-y-1.5"><Label>Email</Label><p className="mono flex h-9 items-center text-[13px]">{user.email}</p></div>
        <div className="min-w-[240px] flex-1 space-y-1.5">
          <Label htmlFor="display_name">Name</Label>
          <Input id="display_name" value={name} onChange={(e) => { setName(e.target.value); setState("idle"); }} maxLength={120} />
        </div>
        <Button type="submit" variant="secondary" disabled={state === "saving"}>{state === "saved" ? "Saved" : "Save"}</Button>
      </form>
    </Section>
  );
}

function PasswordForm({ onChanged }: { onChanged: () => void }) {
  const [message, setMessage] = React.useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  return (
    <Section title="Password" description="Changing your password signs out all other sessions.">
      <form className="grid gap-3 rounded-md border border-line bg-surface p-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end" onSubmit={async (e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const data = new FormData(form);
        try {
          await api("/auth/change-password", { method: "POST", json: { current_password: data.get("current"), new_password: data.get("new") } });
          form.reset();
          setMessage({ tone: "ok", text: "Password changed. Other sessions were signed out." });
          onChanged();
        } catch (err) {
          setMessage({ tone: "bad", text: err instanceof ApiError ? Object.values(err.details)[0] ?? err.message : "Could not change the password." });
        }
      }}>
        <div className="space-y-1.5"><Label htmlFor="current">Current password</Label><Input id="current" name="current" type="password" autoComplete="current-password" required /></div>
        <div className="space-y-1.5"><Label htmlFor="new">New password</Label><Input id="new" name="new" type="password" autoComplete="new-password" minLength={10} required /></div>
        <Button type="submit" variant="secondary">Change password</Button>
        {message && <Notice tone={message.tone} className="sm:col-span-3">{message.text}</Notice>}
      </form>
    </Section>
  );
}
