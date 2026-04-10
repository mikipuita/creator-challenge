"use client";

import { motion } from "framer-motion";

import { Grade } from "@/lib/types";

const gradeTone: Record<Grade, string> = {
  A: "from-emerald-400 to-emerald-600 text-emerald-300 shadow-[0_0_50px_rgba(16,185,129,0.35)]",
  B: "from-blue-400 to-blue-600 text-blue-300 shadow-[0_0_50px_rgba(59,130,246,0.35)]",
  C: "from-amber-300 to-amber-500 text-amber-300 shadow-[0_0_50px_rgba(245,158,11,0.28)]",
  D: "from-orange-400 to-orange-600 text-orange-300 shadow-[0_0_50px_rgba(249,115,22,0.28)]",
  F: "from-red-400 to-red-600 text-red-300 shadow-[0_0_50px_rgba(239,68,68,0.28)]"
};

export function GradeDisplay({
  grade,
  size = "lg"
}: {
  grade: Grade;
  size?: "md" | "lg";
}) {
  const sizeClass = size === "lg" ? "h-28 w-28 text-6xl sm:h-36 sm:w-36 sm:text-7xl" : "h-20 w-20 text-4xl";

  return (
    <motion.div
      animate={{ y: [0, -4, 0] }}
      className={`flex ${sizeClass} items-center justify-center rounded-[2rem] border border-white/10 bg-gradient-to-br ${gradeTone[grade]}`}
      transition={{ duration: 4, repeat: Number.POSITIVE_INFINITY, ease: "easeInOut" }}
    >
      <span className="font-[family-name:var(--font-mono)] font-semibold">{grade}</span>
    </motion.div>
  );
}
