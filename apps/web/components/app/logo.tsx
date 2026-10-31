/** ROUTES wordmark: a small path glyph (two nodes and a bent route) + letter-spaced name. */
export function Logo({ className = "" }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
        <circle cx="3.5" cy="3.5" r="2" fill="#1a1a18" />
        <circle cx="14.5" cy="14.5" r="2" fill="#2a4fb5" />
        <path d="M3.5 5.5v4a3 3 0 0 0 3 3h5" stroke="#1a1a18" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
      <span className="text-[13px] font-bold tracking-[0.18em] text-ink">ROUTES</span>
    </span>
  );
}
