"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown } from "lucide-react";

import { FindingCard } from "@/components/ui/FindingCard";
import { CategoryScore, Finding } from "@/lib/types";

function scoreTone(score: number): string {
  if (score >= 90) return "bg-emerald-400";
  if (score >= 80) return "bg-blue-400";
  if (score >= 70) return "bg-amber-400";
  if (score >= 60) return "bg-orange-400";
  return "bg-red-400";
}

export function CategoryCard({
  score,
  findings
}: {
  score: CategoryScore;
  findings: Finding[];
}) {
  const [expanded, setExpanded] = useState(findings.length > 0);

  return (
    <motion.div
      className="panel rounded-3xl p-5"
      initial={{ opacity: 0, y: 10 }}
      transition={{ duration: 0.25 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
    >
      <button className="w-full text-left" onClick={() => setExpanded((current) => !current)} type="button">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.24em] text-accentBlue">
              {score.name.replaceAll("_", " ")}
            </p>
            <div className="mt-3 flex items-end gap-3">
              <span className="text-3xl font-semibold text-white">{Math.round(score.score)}</span>
              <span className="pb-1 text-sm text-textSecondary">{findings.length} findings</span>
            </div>
          </div>
          <ChevronDown
            className={`mt-2 h-5 w-5 shrink-0 text-textSecondary transition ${expanded ? "rotate-180" : ""}`}
          />
        </div>
        <div className="mt-4 h-2 rounded-full bg-white/8">
          <div
            className={`h-2 rounded-full ${scoreTone(score.score)}`}
            style={{ width: `${Math.max(8, Math.min(100, score.score))}%` }}
          />
        </div>
      </button>

      <AnimatePresence initial={false}>
        {expanded ? (
          <motion.div
            animate={{ height: "auto", opacity: 1 }}
            className="overflow-hidden"
            exit={{ height: 0, opacity: 0 }}
            initial={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.24, ease: "easeOut" }}
          >
            <div className="mt-5 space-y-3">
              {findings.length > 0 ? (
                findings.map((finding) => <FindingCard finding={finding} key={`${score.name}-${finding.title}`} />)
              ) : (
                <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/8 p-4 text-sm text-emerald-200">
                  No notable issues were surfaced in this category.
                </div>
              )}
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </motion.div>
  );
}
