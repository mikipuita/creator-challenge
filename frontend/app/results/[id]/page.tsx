"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { ArrowLeft, Download, Filter, RotateCw } from "lucide-react";

import { CategoryCard } from "@/components/ui/CategoryCard";
import { GradeDisplay } from "@/components/ui/GradeDisplay";
import { LoadingPulse } from "@/components/ui/LoadingPulse";
import { Navbar } from "@/components/ui/Navbar";
import { ScoreGauge } from "@/components/ui/ScoreGauge";
import { ApiError, getReportPdf, getScanResults } from "@/lib/api";
import {
  categoryLabel,
  findingCountBySeverity,
  findingsForCategory,
  formatDateTime,
  severityOrder
} from "@/lib/presentation";
import { ScanResults, Severity } from "@/lib/types";

const statTone: Record<Severity, string> = {
  critical: "border-red-500/25 bg-red-500/10 text-red-200",
  high: "border-orange-500/25 bg-orange-500/10 text-orange-200",
  medium: "border-amber-500/25 bg-amber-500/10 text-amber-200",
  low: "border-blue-500/25 bg-blue-500/10 text-blue-200",
  info: "border-slate-500/25 bg-slate-500/10 text-slate-200"
};

export default function ResultsPage({
  params
}: {
  params: { id: string };
}) {
  const [scan, setScan] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeSeverity, setActiveSeverity] = useState<Severity | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const response = await getScanResults(params.id);
        if (cancelled) return;
        setScan(response);
        setError(null);
      } catch (caughtError) {
        if (cancelled) return;
        if (caughtError instanceof ApiError) {
          setError(caughtError.message);
        } else {
          setError("DomainVitals could not load the report.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    load();
    const interval = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [params.id]);

  if (loading) {
    return (
      <main className="min-h-screen">
        <Navbar />
        <section className="flex min-h-[calc(100vh-73px)] items-center justify-center px-4">
          <div className="panel w-full max-w-lg rounded-[2rem] p-10 text-center">
            <LoadingPulse label="Rendering report dashboard" />
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
              Report Unavailable
            </p>
            <h1 className="mt-4 text-3xl font-semibold text-white">DomainVitals couldn&apos;t load this report.</h1>
            <p className="mt-4 text-sm leading-7 text-textSecondary">{error}</p>
          </div>
        </section>
      </main>
    );
  }

  if (scan.status !== "completed" || !scan.risk_score || !scan.report) {
    return (
      <main className="min-h-screen">
        <Navbar />
        <section className="mx-auto flex min-h-[calc(100vh-73px)] max-w-4xl items-center px-4 sm:px-6 lg:px-8">
          <div className="panel w-full rounded-[2rem] p-8">
            <LoadingPulse label="Waiting for final report" />
            <h1 className="mt-6 text-3xl font-semibold text-white">The report is still being assembled.</h1>
            <p className="mt-4 text-sm leading-7 text-textSecondary">
              DomainVitals has your scan data, but the final scorecard and attacker narrative are not
              ready yet.
            </p>
            <Link
              className="mt-8 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold transition hover:border-accentBlue hover:text-white"
              href={`/scan/${params.id}`}
            >
              Return to live scan
              <RotateCw className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </main>
    );
  }

  const visibleFindings = activeSeverity
    ? scan.findings.filter((finding) => finding.severity === activeSeverity)
    : scan.findings;

  function handleDownload() {
    setIsDownloading(true);
    void getReportPdf(params.id)
      .then(() => {
        setError(null);
      })
      .catch((caughtError) => {
        if (caughtError instanceof ApiError) {
          setError(caughtError.message);
          return;
        }
        setError("The PDF report could not be downloaded.");
      })
      .finally(() => {
        setIsDownloading(false);
      });
  }

  return (
    <main className="min-h-screen">
      <Navbar />
      <section className="px-4 py-8 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="panel rounded-[2.5rem] p-6 sm:p-8">
            <div className="flex flex-col gap-8 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
                <GradeDisplay grade={scan.risk_score.overall_grade} />
                <div>
                  <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentBlue">
                    DomainVitals Report Card
                  </p>
                  <h1 className="mt-4 text-3xl font-semibold text-white sm:text-5xl">{scan.domain}</h1>
                  <p className="mt-4 text-sm leading-7 text-textSecondary">
                    Scan completed {formatDateTime(scan.completed_at || scan.updated_at)}
                  </p>
                </div>
              </div>

              <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
                <div className="panel rounded-[2rem] px-5 py-4">
                  <ScoreGauge score={scan.risk_score.overall_score} />
                </div>
                <div className="flex flex-col gap-3">
                  <button
                    className="inline-flex items-center justify-center gap-2 rounded-full bg-accentBlue px-5 py-3 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:opacity-60"
                    disabled={isDownloading}
                    onClick={handleDownload}
                    type="button"
                  >
                    <Download className="h-4 w-4" />
                    {isDownloading ? "Preparing PDF" : "Download PDF Report"}
                  </button>
                  <Link
                    className="inline-flex items-center justify-center gap-2 rounded-full border border-white/10 bg-white/5 px-5 py-3 text-sm font-semibold transition hover:border-accentBlue hover:text-white"
                    href="/"
                  >
                    <ArrowLeft className="h-4 w-4" />
                    Scan Another Domain
                  </Link>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-textSecondary" />
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-textSecondary">
                Filter findings by severity
              </p>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
              {severityOrder.map((severity) => {
                const count = findingCountBySeverity(scan.findings, severity);
                const active = activeSeverity === severity;
                return (
                  <button
                    className={`rounded-[1.4rem] border px-4 py-4 text-left transition ${statTone[severity]} ${active ? "ring-2 ring-white/30" : "opacity-85 hover:opacity-100"}`}
                    key={severity}
                    onClick={() => setActiveSeverity((current) => (current === severity ? null : severity))}
                    type="button"
                  >
                    <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.22em]">
                      {severity}
                    </p>
                    <p className="mt-3 text-3xl font-semibold">{count}</p>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="mt-10 grid gap-6 xl:grid-cols-[minmax(0,1.45fr)_minmax(320px,0.9fr)]">
            <div className="space-y-6">
              <div className="grid gap-5 lg:grid-cols-2">
                {scan.risk_score.category_scores.map((score) => (
                  <CategoryCard
                    findings={findingsForCategory(score, visibleFindings)}
                    key={score.name}
                    score={{ ...score, name: categoryLabel(score.name) }}
                  />
                ))}
              </div>

              <div className="panel rounded-[2rem] p-6">
                <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentAmber">
                  Executive Summary
                </p>
                <p className="mt-4 text-sm leading-7 text-textSecondary sm:text-base">
                  {scan.report.executive_summary}
                </p>
              </div>
            </div>

            <div className="space-y-6">
              <motion.blockquote
                className="panel rounded-[2rem] p-6"
                initial={{ opacity: 0, x: 10 }}
                transition={{ duration: 0.3 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, amount: 0.2 }}
              >
                <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentBlue">
                  Attacker&apos;s Perspective
                </p>
                <p className="mt-5 border-l-2 border-accentBlue/40 pl-4 text-sm leading-7 text-textSecondary sm:text-base">
                  {scan.report.attacker_narrative}
                </p>
              </motion.blockquote>

              <div className="panel rounded-[2rem] p-6">
                <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-accentAmber">
                  Action Items
                </p>
                <div className="mt-5 space-y-4">
                  {scan.report.prioritized_action_items.map((item, index) => (
                    <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4" key={`${item.title}-${index}`}>
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.24em] text-textSecondary">
                            Item {index + 1}
                          </p>
                          <h3 className="mt-2 text-lg font-semibold text-white">{item.title}</h3>
                        </div>
                        <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-textSecondary">
                          {item.difficulty}
                        </span>
                      </div>
                      <p className="mt-3 text-sm leading-6 text-textSecondary">{item.rationale}</p>
                      {item.steps.length > 0 ? (
                        <ol className="mt-4 space-y-2 text-sm text-textSecondary">
                          {item.steps.map((step, stepIndex) => (
                            <li className="flex gap-3" key={`${item.title}-${stepIndex}`}>
                              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accentBlue/15 font-[family-name:var(--font-mono)] text-xs text-accentBlue">
                                {stepIndex + 1}
                              </span>
                              <span className="pt-0.5 leading-6">{step}</span>
                            </li>
                          ))}
                        </ol>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-[2rem] border border-white/8 bg-white/[0.03] p-5 text-sm leading-7 text-textSecondary">
                {scan.report.disclaimer}
              </div>
            </div>
          </div>

          {error ? (
            <div className="mt-6 rounded-[1.5rem] border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          ) : null}
        </div>
      </section>
    </main>
  );
}
