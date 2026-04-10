"use client";

export default function GlobalError({
  error,
  reset
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body className="flex min-h-screen items-center justify-center bg-bgPrimary px-6 text-textPrimary">
        <div className="panel max-w-xl rounded-3xl p-8">
          <p className="font-[family-name:var(--font-mono)] text-sm uppercase tracking-[0.3em] text-accentRed">
            System Fault
          </p>
          <h1 className="mt-4 text-3xl font-semibold">The DomainVitals console hit an unexpected error.</h1>
          <p className="mt-3 text-sm leading-7 text-textSecondary">{error.message}</p>
          <button
            className="mt-8 rounded-full border border-borderTone bg-white/5 px-5 py-3 text-sm font-semibold transition hover:border-accentBlue hover:text-white"
            onClick={reset}
            type="button"
          >
            Reload Interface
          </button>
        </div>
      </body>
    </html>
  );
}
