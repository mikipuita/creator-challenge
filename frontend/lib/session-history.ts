import { ScanResults } from "@/lib/types";

export interface SessionScanRecord {
  scanId: string;
  domain: string;
  status: ScanResults["status"];
  createdAt: string;
  updatedAt: string;
  completedAt?: string | null;
  overallGrade?: string | null;
  overallScore?: number | null;
  findingsCount: number;
}

const STORAGE_KEY = "domainvitals-session-history";
export const HISTORY_UPDATED_EVENT = "domainvitals:history-updated";
const MAX_HISTORY_ITEMS = 8;

function canUseSessionStorage(): boolean {
  return typeof window !== "undefined";
}

function dispatchHistoryUpdated(): void {
  if (!canUseSessionStorage()) {
    return;
  }

  window.dispatchEvent(new CustomEvent(HISTORY_UPDATED_EVENT));
}

function sortHistory(records: SessionScanRecord[]): SessionScanRecord[] {
  return records
    .sort((left, right) => new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime())
    .slice(0, MAX_HISTORY_ITEMS);
}

function writeHistory(records: SessionScanRecord[]): void {
  if (!canUseSessionStorage()) {
    return;
  }

  window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(sortHistory(records)));
  dispatchHistoryUpdated();
}

export function getSessionScanHistory(): SessionScanRecord[] {
  if (!canUseSessionStorage()) {
    return [];
  }

  const raw = window.sessionStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw) as SessionScanRecord[];
    return Array.isArray(parsed) ? sortHistory(parsed) : [];
  } catch {
    return [];
  }
}

export function rememberStartedScan(scanId: string, domain: string): void {
  const now = new Date().toISOString();
  const existing = getSessionScanHistory().filter((item) => item.scanId !== scanId);

  writeHistory([
    {
      scanId,
      domain,
      status: "scanning",
      createdAt: now,
      updatedAt: now,
      findingsCount: 0
    },
    ...existing
  ]);
}

export function syncScanToSessionHistory(scan: ScanResults): void {
  const existing = getSessionScanHistory().filter((item) => item.scanId !== scan.scan_id);

  writeHistory([
    {
      scanId: scan.scan_id,
      domain: scan.domain,
      status: scan.status,
      createdAt: scan.created_at,
      updatedAt: scan.updated_at,
      completedAt: scan.completed_at,
      overallGrade: scan.risk_score?.overall_grade ?? null,
      overallScore: scan.risk_score?.overall_score ?? null,
      findingsCount: scan.findings.length
    },
    ...existing
  ]);
}
