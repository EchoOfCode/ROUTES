import { Logo } from "@/components/app/logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_440px]">
      <div className="hidden flex-col justify-between border-r border-line bg-surface px-12 py-10 lg:flex">
        <Logo />
        <div className="max-w-md">
          <p className="text-[22px] font-semibold leading-snug tracking-[-0.01em] text-ink">
            Understand what your application exposes, and where it could be attacked.
          </p>
          <ul className="mt-6 space-y-3 text-[13.5px] text-ink-2">
            <li className="flex gap-3"><span className="mono text-faint">01</span>Discover public pages, forms and API endpoints of a site you own.</li>
            <li className="flex gap-3"><span className="mono text-faint">02</span>Connect its source code to map routes and database queries.</li>
            <li className="flex gap-3"><span className="mono text-faint">03</span>Review evidence-backed findings, starting with SQL injection.</li>
          </ul>
        </div>
        <p className="text-[12px] text-faint">Runs entirely on your machine. Assess only websites you own or are permitted to test.</p>
      </div>
      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-[340px]">
          <div className="mb-8 lg:hidden"><Logo /></div>
          {children}
        </div>
      </div>
    </div>
  );
}
