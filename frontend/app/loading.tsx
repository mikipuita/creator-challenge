import { LoadingPulse } from "@/components/ui/LoadingPulse";

export default function GlobalLoading() {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="panel w-full max-w-md rounded-3xl p-10 text-center">
        <LoadingPulse label="Booting DomainVitals console" />
        <p className="mt-6 text-sm text-textSecondary">
          Aligning passive recon modules and preparing the dashboard.
        </p>
      </div>
    </main>
  );
}
