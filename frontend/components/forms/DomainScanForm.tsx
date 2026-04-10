"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Globe2 } from "lucide-react";

import { ApiError, startScan, validateDomain } from "@/lib/api";

const DEMO_DOMAIN = "demo.domainvitals.io";
const SLOW_START_STORAGE_KEY = "domainvitals-slow-start";

export function DomainScanForm() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  async function submitDomain(targetDomain: string) {
    const validationError = validateDomain(targetDomain);
    if (validationError) {
      setError(validationError);
      return;
    }

    setError(null);
    setIsSubmitting(true);
    setStatusMessage(null);
    const slowStartTimer = window.setTimeout(() => {
      setStatusMessage("Starting up the security engine... this takes a moment on first scan");
    }, 5000);
    try {
      const response = await startScan(targetDomain);
      window.clearTimeout(slowStartTimer);
      if (typeof window !== "undefined") {
        if (response.slowStartDetected) {
          window.sessionStorage.setItem(SLOW_START_STORAGE_KEY, "true");
        } else {
          window.sessionStorage.removeItem(SLOW_START_STORAGE_KEY);
        }
      }
      router.push(`/scan/${response.data.scan_id}`);
    } catch (caughtError) {
      window.clearTimeout(slowStartTimer);
      if (caughtError instanceof ApiError) {
        setError(caughtError.message);
      } else {
        setError("DomainVitals could not start the scan. Please try again.");
      }
      setIsSubmitting(false);
      setStatusMessage(null);
      return;
    }
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await submitDomain(domain);
  }

  async function handleDemoClick() {
    setDomain(DEMO_DOMAIN);
    await submitDomain(DEMO_DOMAIN);
  }

  return (
    <form className="relative z-10 mt-8 w-full max-w-3xl" onSubmit={handleSubmit}>
      <div className="panel rounded-[2rem] p-3 sm:p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="flex flex-1 items-center gap-3 rounded-[1.5rem] border border-white/8 bg-black/20 px-4 py-4">
            <Globe2 className="h-5 w-5 shrink-0 text-accentBlue" />
            <input
              autoCapitalize="none"
              autoComplete="off"
              autoCorrect="off"
              className="w-full border-0 bg-transparent text-base text-white outline-none placeholder:text-textSecondary sm:text-lg"
              inputMode="url"
              onChange={(event) => setDomain(event.target.value)}
              placeholder="yourbusiness.com"
              spellCheck={false}
              type="text"
              value={domain}
            />
          </div>
          <button
            className="inline-flex items-center justify-center gap-2 rounded-[1.5rem] bg-accentBlue px-6 py-4 text-sm font-semibold text-white shadow-glow transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={isSubmitting}
            type="submit"
          >
            {isSubmitting ? "Launching Scan" : "Scan My Domain"}
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>
      <p className="mt-4 text-center font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.3em] text-textSecondary">
        Free • No signup • Results in 60 seconds
      </p>
      {isSubmitting ? (
        <p className="mt-3 text-center text-sm text-accentAmber">
          {statusMessage ?? "Preparing your scan request..."}
        </p>
      ) : null}
      <div className="mt-3 text-center">
        <button
          className="text-sm text-textSecondary transition hover:text-accentBlue disabled:cursor-not-allowed disabled:opacity-60"
          disabled={isSubmitting}
          onClick={handleDemoClick}
          type="button"
        >
          Try a demo scan &rarr;
        </button>
      </div>
      {error ? (
        <p className="mt-3 rounded-2xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </p>
      ) : null}
    </form>
  );
}
