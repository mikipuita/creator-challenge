"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, ShieldAlert } from "lucide-react";

import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { Finding } from "@/lib/types";

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.03]">
      <button
        className="flex w-full items-start justify-between gap-4 p-4 text-left"
        onClick={() => setExpanded((current) => !current)}
        type="button"
      >
        <div className="flex gap-3">
          <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-white/8 bg-white/5 text-accentAmber">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.22em] text-textSecondary">
                {finding.category.replaceAll("_", " ")}
              </span>
            </div>
            <h4 className="mt-2 text-base font-semibold text-white">{finding.title}</h4>
            <p className="mt-2 text-sm leading-6 text-textSecondary">{finding.description}</p>
          </div>
        </div>
        <ChevronDown
          className={`mt-1 h-5 w-5 shrink-0 text-textSecondary transition ${expanded ? "rotate-180" : ""}`}
        />
      </button>

      <AnimatePresence initial={false}>
        {expanded ? (
          <motion.div
            animate={{ height: "auto", opacity: 1 }}
            className="overflow-hidden border-t border-white/8"
            exit={{ height: 0, opacity: 0 }}
            initial={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.24, ease: "easeOut" }}
          >
            <div className="space-y-4 p-4">
              <div>
                <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.24em] text-accentBlue">
                  Why it matters
                </p>
                <p className="mt-2 text-sm leading-6 text-textSecondary">{finding.impact}</p>
              </div>

              {finding.remediation.length > 0 ? (
                <div>
                  <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.24em] text-accentBlue">
                    Fix steps
                  </p>
                  <ul className="mt-2 space-y-2 text-sm leading-6 text-textSecondary">
                    {finding.remediation.map((step) => (
                      <li key={step} className="flex gap-2">
                        <span className="mt-2 h-1.5 w-1.5 rounded-full bg-accentBlue" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
