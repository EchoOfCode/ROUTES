"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

import { Notice } from "@/components/app/layout-parts";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError } from "@/lib/api";

export function AuthForm({ mode }: { mode: "login" | "register" }) {
  const router = useRouter();
  const params = useSearchParams();
  const [error, setError] = React.useState<ApiError | null>(null);
  const [pending, setPending] = React.useState(false);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setPending(true);
    setError(null);
    try {
      await api(`/auth/${mode}`, {
        method: "POST",
        json: {
          email: form.get("email"),
          password: form.get("password"),
          ...(mode === "register" ? { display_name: form.get("display_name") ?? "" } : {}),
        },
      });
      const next = params.get("next");
      router.replace(next && next.startsWith("/") && !next.startsWith("//") ? next : mode === "register" ? "/projects/new" : "/overview");
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "network", "Could not reach ROUTES."));
      setPending(false);
    }
  }

  const field = (name: string) => error?.details?.[name];
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <div>
        <h1 className="text-[19px] font-semibold tracking-[-0.01em]">{mode === "login" ? "Sign in" : "Create your account"}</h1>
        <p className="mt-1 text-[13px] text-muted">
          {mode === "login" ? "Use the email and password you registered with." : "Accounts are stored locally in this ROUTES installation."}
        </p>
      </div>
      {error && !Object.keys(error.details).length && <Notice tone="bad">{error.message}</Notice>}
      {mode === "register" && (
        <div className="space-y-1.5">
          <Label htmlFor="display_name">Name <span className="font-normal text-faint">(optional)</span></Label>
          <Input id="display_name" name="display_name" autoComplete="name" maxLength={120} />
        </div>
      )}
      <div className="space-y-1.5">
        <Label htmlFor="email">Email</Label>
        <Input id="email" name="email" type="email" autoComplete="email" required aria-invalid={!!field("email")} />
        {field("email") && <p className="text-[12px] text-bad">Enter a valid email address.</p>}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password" name="password" type="password" required minLength={mode === "register" ? 10 : 1}
          autoComplete={mode === "login" ? "current-password" : "new-password"} aria-invalid={!!field("password")}
        />
        {mode === "register" && !field("password") && <p className="text-[12px] text-muted">At least 10 characters.</p>}
        {field("password") && <p className="text-[12px] text-bad">{field("password")}</p>}
      </div>
      <Button type="submit" size="lg" className="w-full" disabled={pending}>
        {pending ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
      </Button>
      <p className="text-center text-[13px] text-muted">
        {mode === "login" ? (
          <>No account yet? <Link href="/register" className="font-medium text-accent hover:underline">Create one</Link></>
        ) : (
          <>Already registered? <Link href="/login" className="font-medium text-accent hover:underline">Sign in</Link></>
        )}
      </p>
      {mode === "login" && (
        <p className="text-center text-[12px] text-faint">Password recovery by email is not available in this local build.</p>
      )}
    </form>
  );
}
