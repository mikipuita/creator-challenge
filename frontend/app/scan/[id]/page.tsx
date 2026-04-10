"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { AlertTriangle, Check, ChevronRight, LoaderCircle, RotateCw } from "lucide-react";

import { LoadingPulse } from "@/components/ui/LoadingPulse";
import { Navbar } from "@/components/ui/Navbar";
import { ApiError, getScanResults } from "@/lib/api";
import { modulePresentation, summarizeProgress } from "@/lib/presentation";
import { syncScanToSessionHistory } from "@/lib/session-history";
import { ModuleResult, ScanResults } from "@/lib/types";

const MAX_POLLING_DURATION_MS = 180_000;
const SLOW_START_STORAGE_KEY = "domainvitals-slow-start";

const moduleOrder = [
  "dns",
  "subdomains",
  "ssl_tls",
  "email_security",
  "headers",
  "tech_stack",
  "open_ports"
] as const;

function moduleCardTone(status: ModuleResult["status"]): string {
  if (status === "complete") return "border-emerald-500/30 bg-emerald-500/12";
  if (status === "scanning") return "border-blue-500/40 bg-blue-500/12";
  if (status === "error") return "border-red-500/35 bg-red-500/12";
  if (status === "skipped") return "border-amber-500/35 bg-amber-500/12";
  return "border-white/8 bg-white/[0.03]";
}

function ModuleStatusCard({
  moduleKey,
  module
}: {
  moduleKey: string;
  module: ModuleResult;
}) {
  const presentation = modulePresentation[moduleKey];
  const scanning = module.status === "scanning";
  const complete = module.status === "complete";
  const error = module.status === "error";
  const skipped = module.status === "skipped";

  return (
    <div
      className={`relative h-full min-h-[13.5rem] rounded-[2rem] border px-5 py-5 transition-colors duration-300 ${moduleCardTone(module.status)}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.22em] text-textSecondary">
            {presentation.short}
          </p>
          <h3 className="mt-2 text-base font-semibold text-white">{presentation.label}</h3>
          <p className="mt-2 text-sm leading-6 text-textSecondary">{presentation.description}</p>
        </div>
        <div
          className={`status-dot mt-1 flex h-10 w-10 items-center justify-center rounded-2xl ${
            complete
              ? "bg-emerald-400/20 text-emerald-300"
              : error
                ? "bg-red-400/20 text-red-300"
                : skipped
                  ? "bg-amber-400/20 text-amber-200"
                  : scanning
                  ? "bg-blue-400/20 text-blue-300 ring-1 ring-blue-300/30"
                  : "bg-slate-500/20 text-slate-300"
          }`}
        >
          {complete ? (
            <Check className="h-5 w-5" />
          ) : error ? (
            <AlertTriangle className="h-5 w-5" />
          ) : skipped ? (
            <RotateCw className="h-5 w-5" />
          ) : (
            <RotateCw className={`h-5 w-5 ${scanning ? "animate-spin" : ""}`} />
          )}
        </div>
      </div>
      <p className="mt-4 line-clamp-3 text-xs leading-6 text-textSecondary">
        {module.error || module.note || `Status: ${module.status}`}
      </p>
    </div>
  );
}

export default function ScanPage({
  params
}: {
  params: { id: string };
}) {
  const router = useRouter();
  const [scan, setScan] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [slowStartNotice, setSlowStartNotice] = useState<string | null>(null);
  const [estimatedSecondsRemaining, setEstimatedSecondsRemaining] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    let redirectTimeout: ReturnType<typeof setTimeout> | null = null;
    let intervalId: ReturnType<typeof setInterval> | null = null;
    const startedAt = Date.now();

    if (typeof window !== "undefined") {
      const slowStart = window.sessionStorage.getItem(SLOW_START_STORAGE_KEY);
      if (slowStart === "true") {
        setSlowStartNotice("Starting up the security engine... this takes a moment on first scan.");
        window.sessionStorage.removeItem(SLOW_START_STORAGE_KEY);
      }
    }

    async function load() {
      try {
        const response = await getScanResults(params.id);
        if (cancelled) return;
        setScan(response);
        setError(null);
        syncScanToSessionHistory(response);

        const progress = summarizeProgress(response.modules);
        const finishedModules = Object.values(response.modules).filter((module) =>
          ["complete", "error", "skipped"].includes(module.status)
        ).length;
        const elapsedSeconds = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
        if (finishedModules > 0 && finishedModules < moduleOrder.length) {
          const averagePerModule = elapsedSeconds / finishedModules;
          setEstimatedSecondsRemaining(
            Math.max(8, Math.min(180, Math.round(averagePerModule * (moduleOrder.length - finishedModules))))
          );
        } else if (finishedModules === 0) {
          setEstimatedSecondsRemaining(90);
        } else {
          setEstimatedSecondsRemaining(0);
        }

        const reportReady = response.status === "completed" && Boolean(response.risk_score && response.report);

        if (reportReady) {
          setSlowStartNotice(null);
          if (intervalId) {
            clearInterval(intervalId);
          }
          redirectTimeout = setTimeout(() => {
            router.push(`/results/${params.id}`);
          }, 900);
        }

        if (Date.now() - startedAt > MAX_POLLING_DURATION_MS && response.status !== "completed") {
          if (intervalId) {
            clearInterval(intervalId);
          }
          setError("This scan is taking longer than expected. The security engine may still be waking up, so please give it another minute or retry.");
        }
      } catch (caughtError) {
        if (cancelled) return;
        if (caughtError instanceof ApiError) {
          setError(caughtError.message);
        } else {
          setError("DomainVitals could not refresh scan progress.");
        }
      } finally {
        if (!cancelled) {
          setInitialLoading(false);
        }
      }
    }

    load();
    intervalId = setInterval(load, 2000);

    return () => {
      cancelled = true;
      if (intervalId) {
        clearInterval(intervalId);
      }
      if (redirectTimeout) {
        clearTimeout(redirectTimeout);
      }
    };
  }, [params.id, router]);

  if (initialLoading) {
    return (
      <main className="min-h-screen">
        <Navbar />
        <section className="flex min-h-[calc(100vh-73px)] items-center justify-center px-4">
          <div className="panel w-full max-w-lg rounded-[2rem] p-10 text-center">
            <LoadingPulse label="Activating DomainVitals scan modules" />
          </div>
        </section>
      </main>
    );
  }

  if (error || !scan) {
    return (
      <main className="min-h-screen">
        <Navbar />
        <section className="mx-auto flex min-h-[calc(100vh-73px)] max-w-3xl items-center px-4 sm:px-6 lg:px-8">
          <div className="panel w-full rounded-[2rem] p-8">
            <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentRed">
              Scan Error
            </p>
            <h1 className="mt-4 text-3xl font-semibold text-white">We couldn&apos;t load this scan.</h1>
            <p className="mt-4 text-sm leading-7 text-textSecondary">{error}</p>
            <Link
              className="mt-8 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold transition hover:border-accentBlue hover:text-white"
              href="/"
            >
              Back to home
              <ChevronRight className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </main>
    );
  }

  const progress = summarizeProgress(scan.modules);
  const modules = moduleOrder.map((moduleKey) => ({
    key: moduleKey,
    result: scan.modules[moduleKey] ?? {
      name: moduleKey,
      status: "pending",
      findings: [],
      data: {}
    }
  }));

  return (
    <main className="min-h-screen">
      <Navbar />
      <section className="px-4 py-8 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentBlue">
                Live Recon Progress
              </p>
              <h1 className="mt-3 text-3xl font-semibold text-white sm:text-5xl">{scan.domain}</h1>
              <p className="mt-3 max-w-2xl text-sm leading-7 text-textSecondary sm:text-base">
                DomainVitals is polling each passive recon module every two seconds and will move you
                to the report as soon as the analysis finishes.
              </p>
            </div>
            <div className="panel rounded-[2rem] px-5 py-4 sm:w-72">
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-textSecondary">
                Completion
              </p>
              <p className="mt-3 text-4xl font-semibold text-white">{progress}%</p>
              <p className="mt-2 text-sm text-textSecondary">
                {estimatedSecondsRemaining === null
                  ? "Estimating time remaining..."
                  : estimatedSecondsRemaining === 0
                    ? "Wrapping up final analysis..."
                    : `Estimated time remaining: ~${estimatedSecondsRemaining}s`}
              </p>
            </div>
          </div>

          {slowStartNotice ? (
            <div className="mt-6 flex items-center gap-3 rounded-[1.5rem] border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
              <LoaderCircle className="h-4 w-4 shrink-0 animate-spin text-accentAmber" />
              <span>Waking up the server... {slowStartNotice}</span>
            </div>
          ) : null}

          <div className="mt-8 h-3 overflow-hidden rounded-full bg-white/8">
            <motion.div
              animate={{ width: `${progress}%` }}
              className="h-full rounded-full bg-gradient-to-r from-accentBlue via-blue-300 to-accentGreen"
              initial={{ width: 0 }}
              transition={{ duration: 0.6, ease: "easeOut" }}
            />
          </div>

          {progress >= 100 && !(scan.status === "completed" && scan.risk_score && scan.report) ? (
            <div className="mt-6 flex items-center gap-3 rounded-[1.5rem] border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-100">
              <LoaderCircle className="h-4 w-4 shrink-0 animate-spin text-accentBlue" />
              <span>Recon modules are done. DomainVitals is packaging the scorecard and attacker narrative now.</span>
            </div>
          ) : null}

          <div className="grid-shell panel relative mt-10 rounded-[2.5rem] px-5 py-6 sm:px-8 lg:px-10">
            <div className="grid gap-5 xl:grid-cols-3 xl:grid-rows-[minmax(13.5rem,1fr)_minmax(15rem,1fr)_minmax(13.5rem,1fr)]">
              <ModuleStatusCard module={modules[0].result} moduleKey={modules[0].key} />
              <div className="hidden xl:block" />
              <ModuleStatusCard module={modules[1].result} moduleKey={modules[1].key} />

              <ModuleStatusCard module={modules[2].result} moduleKey={modules[2].key} />
              <div className="z-10 flex min-h-[15rem] flex-col items-center justify-center rounded-[2rem] border border-accentBlue/20 bg-accentBlue/10 px-6 py-8 text-center shadow-glow">
                <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentBlue">
                  Target Domain
                </p>
                <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">{scan.domain}</h2>
                <p className="mt-4 text-sm leading-7 text-textSecondary">
                  Passive checks only. No invasive probing. No signup required.
                </p>
              </div>
              <ModuleStatusCard module={modules[3].result} moduleKey={modules[3].key} />

              <ModuleStatusCard module={modules[4].result} moduleKey={modules[4].key} />
              <ModuleStatusCard module={modules[5].result} moduleKey={modules[5].key} />
              <ModuleStatusCard module={modules[6].result} moduleKey={modules[6].key} />
            </div>
          </div>

          {scan.status === "failed" ? (
            <div className="mt-6 rounded-[2rem] border border-red-500/20 bg-red-500/10 p-5 text-sm text-red-100">
              The scan ended in a failed state. Review the module cards above for the failing
              service and try a new scan.
            </div>
          ) : null}
        </div>
      </section>
    </main>
  );
}
