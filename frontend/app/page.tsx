import Link from "next/link";
import {
  BadgeCheck,
  Binary,
  Boxes,
  LockKeyhole,
  MailCheck,
  Network,
  Radar,
  ScanSearch,
  ServerCog,
  ShieldAlert
} from "lucide-react";

import { DomainScanForm } from "@/components/forms/DomainScanForm";
import { Navbar } from "@/components/ui/Navbar";

const trustChecks = [
  { label: "DNS", icon: Network },
  { label: "SSL", icon: LockKeyhole },
  { label: "Email", icon: MailCheck },
  { label: "Headers", icon: Binary },
  { label: "Ports", icon: Radar },
  { label: "Subdomains", icon: Boxes },
  { label: "Tech Stack", icon: ServerCog }
];

const steps = [
  {
    title: "Enter Your Domain",
    description: "Drop in your company domain and DomainVitals validates it before the scan begins.",
    icon: ScanSearch
  },
  {
    title: "We Run 7 Passive Recon Checks",
    description: "DNS, TLS, email, headers, Shodan, subdomains, and stack fingerprinting run in parallel.",
    icon: ShieldAlert
  },
  {
    title: "Get Your Security Report Card",
    description: "Review the grade, attacker narrative, and a step-by-step remediation plan.",
    icon: BadgeCheck
  }
];

export default function HomePage() {
  return (
    <main className="min-h-screen">
      <Navbar />

      <section className="relative overflow-hidden px-4 pb-24 pt-14 sm:px-6 sm:pb-28 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-col items-center">
          <div className="absolute left-1/2 top-28 h-72 w-72 -translate-x-1/2 rounded-full bg-accentBlue/20 blur-[120px]" />
          <div className="grid-shell relative w-full overflow-hidden rounded-[2.25rem] border border-white/6 bg-bgSecondary/60 px-6 py-14 sm:px-10 sm:py-20">
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accentBlue/60 to-transparent" />
            <div className="mx-auto max-w-4xl text-center">
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.34em] text-accentBlue/90">
                Passive Recon For Small Business Security
              </p>
              <h1 className="text-balance mt-6 text-4xl font-semibold leading-tight text-white sm:text-6xl lg:text-7xl">
                See Your Business Through a Hacker&apos;s Eyes
              </h1>
              <p className="text-balance mx-auto mt-6 max-w-2xl text-base leading-8 text-textSecondary sm:text-lg">
                DomainVitals scans your domain and tells you exactly what an attacker would find in
                plain English.
              </p>

              <DomainScanForm />
            </div>
          </div>

          <div className="panel mt-8 w-full max-w-6xl rounded-[2rem] px-5 py-5 sm:px-8">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-textSecondary">
                Checks 7 attack vectors
              </p>
              <div className="grid grid-cols-2 gap-3 sm:flex sm:flex-wrap sm:justify-end">
                {trustChecks.map(({ label, icon: Icon }) => (
                  <div
                    className="flex items-center gap-2 rounded-full border border-white/8 bg-white/[0.03] px-3 py-2 text-sm text-textSecondary"
                    key={label}
                  >
                    <Icon className="h-4 w-4 text-accentBlue" />
                    <span>{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="px-4 pb-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-accentAmber">
                How It Works
              </p>
              <h2 className="mt-3 text-3xl font-semibold text-white sm:text-4xl">
                Designed to feel like a security analyst in your corner.
              </h2>
            </div>
            <p className="max-w-2xl text-sm leading-7 text-textSecondary sm:text-base">
              DomainVitals stays passive and readable. You get a clean report card, not a pile of raw
              telemetry.
            </p>
          </div>

          <div className="mt-10 grid gap-5 lg:grid-cols-3">
            {steps.map(({ title, description, icon: Icon }, index) => (
              <div className="panel rounded-[2rem] p-6" key={title}>
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-accentBlue/20 bg-accentBlue/10 text-accentBlue">
                    <Icon className="h-5 w-5" />
                  </div>
                  <span className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-textSecondary">
                    Step {index + 1}
                  </span>
                </div>
                <h3 className="mt-6 text-2xl font-semibold text-white">{title}</h3>
                <p className="mt-4 text-sm leading-7 text-textSecondary">{description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="border-t border-white/6 px-4 py-8 sm:px-6 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 text-sm text-textSecondary sm:flex-row sm:items-center sm:justify-between">
          <p>Built for the Codex Creator Challenge</p>
          <Link className="transition hover:text-white" href="https://github.com/your-org/domainvitals">
            GitHub placeholder
          </Link>
        </div>
      </footer>
    </main>
  );
}
