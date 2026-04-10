"use client";

import { motion } from "framer-motion";

export function ScoreGauge({ score }: { score: number }) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (clampedScore / 100) * circumference;
  const stroke =
    clampedScore >= 90
      ? "#10b981"
      : clampedScore >= 80
        ? "#3b82f6"
        : clampedScore >= 70
          ? "#f59e0b"
          : clampedScore >= 60
            ? "#f97316"
            : "#ef4444";

  return (
    <div className="relative flex h-40 w-40 items-center justify-center">
      <svg className="h-40 w-40 -rotate-90" viewBox="0 0 160 160">
        <circle
          cx="80"
          cy="80"
          fill="transparent"
          r={radius}
          stroke="rgba(148, 163, 184, 0.15)"
          strokeWidth="12"
        />
        <motion.circle
          animate={{ strokeDashoffset: offset }}
          cx="80"
          cy="80"
          fill="transparent"
          initial={{ strokeDashoffset: circumference }}
          r={radius}
          stroke={stroke}
          strokeDasharray={circumference}
          strokeLinecap="round"
          strokeWidth="12"
          transition={{ duration: 1.1, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.22em] text-textSecondary">
          Score
        </span>
        <span className="mt-1 text-4xl font-semibold text-white">{clampedScore}</span>
      </div>
    </div>
  );
}
