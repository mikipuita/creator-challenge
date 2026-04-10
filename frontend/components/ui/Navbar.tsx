import Link from "next/link";
import { Shield, SquareArrowOutUpRight } from "lucide-react";

export function Navbar() {
  return (
    <header className="sticky top-0 z-40 border-b border-white/5 bg-bgPrimary/70 backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
        <Link className="flex items-center gap-3" href="/">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-accentBlue/30 bg-accentBlue/10 text-accentBlue shadow-glow">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-accentBlue/80">
              DomainVitals
            </p>
            <p className="text-sm text-textSecondary">Attack Surface Console</p>
          </div>
        </Link>

        <Link
          className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-textPrimary transition hover:border-accentBlue/50 hover:bg-accentBlue/10"
          href="/"
        >
          New Scan
          <SquareArrowOutUpRight className="h-4 w-4" />
        </Link>
      </div>
    </header>
  );
}
