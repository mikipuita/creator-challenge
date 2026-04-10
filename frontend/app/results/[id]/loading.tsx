import { LoadingPulse } from "@/components/ui/LoadingPulse";

export default function ResultsLoading() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center">
      <LoadingPulse label="Decrypting report layers" />
    </div>
  );
}
