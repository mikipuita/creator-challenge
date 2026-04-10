"use client";

import { motion } from "framer-motion";

export function LoadingPulse({
  label = "Scanning target"
}: {
  label?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex h-20 w-20 items-center justify-center">
        <motion.div
          animate={{ scale: [1, 1.35, 1], opacity: [0.4, 0.1, 0.4] }}
          className="absolute h-20 w-20 rounded-full bg-accentBlue/20"
          transition={{ duration: 2, repeat: Number.POSITIVE_INFINITY, ease: "easeInOut" }}
        />
        <motion.div
          animate={{ scale: [1, 1.18, 1], opacity: [1, 0.75, 1] }}
          className="relative h-8 w-8 rounded-full bg-accentBlue"
          transition={{ duration: 1.6, repeat: Number.POSITIVE_INFINITY, ease: "easeInOut" }}
        />
      </div>
      <p className="mt-4 font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.26em] text-textSecondary">
        {label}
      </p>
    </div>
  );
}
