export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ModuleStatus = "pending" | "scanning" | "complete" | "error" | "skipped";
export type ScanLifecycle = "scanning" | "completed" | "failed";
export type Grade = "A" | "B" | "C" | "D" | "F";

export interface ActionItem {
  title: string;
  category: string;
  priority: "critical" | "high" | "medium" | "low";
  difficulty: "Easy" | "Medium" | "Hard";
  rationale: string;
  steps: string[];
}

export interface ReportSection {
  title: string;
  summary: string;
  findings: string[];
  remediation_steps: string[];
}

export interface FullReport {
  executive_summary: string;
  attacker_narrative: string;
  category_breakdowns: ReportSection[];
  prioritized_action_items: ActionItem[];
  generated_at: string;
  model?: string | null;
  disclaimer: string;
}

export interface Finding {
  title: string;
  category: string;
  severity: Severity;
  description: string;
  impact: string;
  remediation: string[];
  evidence: Record<string, unknown>;
}

export interface CategoryScore {
  name: string;
  score: number;
  weight: number;
  findings_count: number;
}

export interface RiskScore {
  overall_grade: Grade;
  overall_score: number;
  category_scores: CategoryScore[];
  critical_findings_count: number;
  high_findings_count: number;
}

export interface ModuleResult {
  name: string;
  status: ModuleStatus;
  findings: Finding[];
  data: Record<string, unknown>;
  note?: string | null;
  error?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface ScanResults {
  scan_id: string;
  domain: string;
  status: ScanLifecycle;
  created_at: string;
  updated_at: string;
  completed_at?: string | null;
  modules: Record<string, ModuleResult>;
  findings: Finding[];
  risk_score?: RiskScore | null;
  report?: FullReport | null;
}

export interface StartScanResponse {
  scan_id: string;
  status: ScanLifecycle;
}
