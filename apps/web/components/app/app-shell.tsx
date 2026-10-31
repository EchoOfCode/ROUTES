"use client";

import { Activity, FolderKanban, LayoutGrid, LogOut, Plug, Settings, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import * as React from "react";

import { Logo } from "@/components/app/logo";
import { useApi } from "@/hooks/use-api";
import { api, type User } from "@/lib/api";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/overview", label: "Overview", icon: LayoutGrid },
  { href: "/projects", label: "Projects", icon: FolderKanban },
  { href: "/assessments", label: "Assessments", icon: Activity },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
  { href: "/integrations", label: "Integrations", icon: Plug },
  { href: "/settings", label: "Settings", icon: Settings },
];

export const UserContext = React.createContext<User | null>(null);

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { data: user } = useApi<User>("/auth/me");

  async function logout() {
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
    }
  }

  return (
    <UserContext.Provider value={user}>
      <div className="flex min-h-screen">
        <div className="w-[216px] shrink-0 border-r border-line bg-surface">
        <aside className="sticky top-0 flex h-screen flex-col">
          <div className="flex h-14 items-center px-4">
            <Link href="/overview" aria-label="ROUTES overview"><Logo /></Link>
          </div>
          <nav className="flex-1 space-y-px px-2 py-2">
            {NAV.map(({ href, label, icon: Icon }) => {
              const active = pathname === href || pathname.startsWith(`${href}/`);
              return (
                <Link
                  key={href}
                  href={href}
                  className={cn(
                    "flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] font-medium transition-colors",
                    active ? "bg-sunken text-ink" : "text-muted hover:bg-sunken/70 hover:text-ink",
                  )}
                >
                  <Icon className={cn("size-4", active ? "text-ink" : "text-faint")} strokeWidth={1.9} />
                  {label}
                </Link>
              );
            })}
          </nav>
          <div className="border-t border-line p-3">
            <div className="truncate px-1 text-[12.5px] font-medium text-ink">{user?.display_name || user?.email || " "}</div>
            {user?.display_name && <div className="truncate px-1 text-[12px] text-muted">{user.email}</div>}
            <button
              onClick={logout}
              className="mt-2 flex h-7 w-full items-center gap-2 rounded-md px-1 text-[12.5px] text-muted hover:bg-sunken hover:text-ink"
            >
              <LogOut className="size-3.5" /> Sign out
            </button>
          </div>
        </aside>
        </div>
        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </UserContext.Provider>
  );
}
