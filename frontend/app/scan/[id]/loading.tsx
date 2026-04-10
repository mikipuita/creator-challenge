import { LoadingPulse } from "@/components/ui/LoadingPulse";

export default function ScanLoading() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center">
      <LoadingPulse label="Connecting to scan telemetry" />
    </div>
  );
}
