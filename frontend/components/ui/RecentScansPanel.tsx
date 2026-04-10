"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ChevronRight, Clock3, Radar } from "lucide-react";

import { formatDateTime } from "@/lib/presentation";
import {
  HISTORY_UPDATED_EVENT,
  SessionScanRecord,
  getSessionScanHistory
} from "@/lib/session-history";
import { Grade } from "@/lib/types";

const gradeTone: Record<Grade, string> = {
  A: "border-emerald-500/25 bg-emerald-500/10 text-emerald-200",
  B: "border-blue-500/25 bg-blue-500/10 text-blue-200",
  C: "border-amber-500/25 bg-amber-500/10 text-amber-200",
  D: "border-orange-500/25 bg-orange-500/10 text-orange-200",
  F: "border-red-500/25 bg-red-500/10 text-red-200"
};

function getStatusLabel(scan: SessionScanRecord): string {
  if (scan.status === "completed" && scan.overallGrade) {
    return `Report ready • Grade ${scan.overallGrade}`;
  }
  if (scan.status === "failed") {
    return "Scan needs attention";
  }
  return "Still scanning";
}

export function RecentScansPanel() {
  const [scans, setScans] = useState<SessionScanRecord[]>([]);

  useEffect(() => {
    function refreshHistory() {
      setScans(getSessionScanHistory());
    }

    refreshHistory();
    window.addEventListener(HISTORY_UPDATED_EVENT, refreshHistory);
    return () => {
      window.removeEventListener(HISTORY_UPDATED_EVENT, refreshHistory);
    };
  }, []);

  if (scans.length === 0) {
    return null;
  }

  return (
    <section className="px-4 pb-10 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl">
        <div className="panel rounded-[2rem] p-6 sm:p-8">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.28em] text-accentBlue">
                Session History
              </p>
              <h2 className="mt-3 text-2xl font-semibold text-white sm:text-3xl">
                Recent scans from this browser session.
              </h2>
            </div>
            <p className="max-w-2xl text-sm leading-7 text-textSecondary">
              Jump back into a live scan or reopen a finished report without rescanning the domain.
            </p>
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            {scans.map((scan) => {
              const destination = scan.status === "completed" ? `/results/${scan.scanId}` : `/scan/${scan.scanId}`;
              return (
                <Link
                  className="rounded-[1.6rem] border border-white/8 bg-white/[0.03] p-5 transition hover:border-accentBlue/40 hover:bg-accentBlue/5"
                  href={destination}
                  key={scan.scanId}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.22em] text-textSecondary">
                        {getStatusLabel(scan)}
                      </p>
                      <h3 className="mt-2 text-xl font-semibold text-white">{scan.domain}</h3>
                    </div>
                    {scan.overallGrade ? (
                      <span
                        className={`rounded-full border px-3 py-1 text-xs font-semibold ${gradeTone[scan.overallGrade]}`}
                      >
                        {scan.overallGrade}
                      </span>
                    ) : (
                      <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-textSecondary">
                        {scan.status}
                      </span>
                    )}
                  </div>

                  <div className="mt-4 flex flex-wrap items-center gap-3 text-sm text-textSecondary">
                    <span className="inline-flex items-center gap-2">
                      <Clock3 className="h-4 w-4" />
                      {formatDateTime(scan.completedAt ?? scan.updatedAt)}
                    </span>
                    <span className="inline-flex items-center gap-2">
                      <Radar className="h-4 w-4" />
                      {scan.findingsCount} findings
                    </span>
                  </div>

                  <div className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-accentBlue">
                    {scan.status === "completed" ? "Open report" : "Resume scan"}
                    <ChevronRight className="h-4 w-4" />
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
