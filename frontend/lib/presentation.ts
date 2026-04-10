import { CategoryScore, Finding, ModuleResult, Severity } from "@/lib/types";

export const modulePresentation: Record<
  string,
  {
    label: string;
    short: string;
    description: string;
  }
> = {
  dns: {
    label: "DNS Recon",
    short: "DNS",
    description: "Records, wildcards, and delegation anomalies"
  },
  subdomains: {
    label: "Subdomain Discovery",
    short: "Subdomains",
    description: "Certificate transparency and exposed naming"
  },
  ssl_tls: {
    label: "SSL/TLS",
    short: "SSL",
    description: "Certificates, expiry, and protocol posture"
  },
  email_security: {
    label: "Email Security",
    short: "Email",
    description: "SPF, DKIM, and DMARC enforcement"
  },
  headers: {
    label: "HTTP Headers",
    short: "Headers",
    description: "Browser hardening and HTTPS redirect behavior"
  },
  open_ports: {
    label: "Open Ports",
    short: "Ports",
    description: "Internet-facing services and risky exposures"
  },
  tech_stack: {
    label: "Tech Fingerprint",
    short: "Tech Stack",
    description: "Visible stack hints and version disclosure"
  }
};

export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function formatDateTime(value?: string | null): string {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit"
  }).format(date);
}

export function summarizeProgress(modules: Record<string, ModuleResult>): number {
  const values = Object.values(modules);
  if (values.length === 0) return 0;
  const complete = values.filter((module) =>
    ["complete", "error", "skipped"].includes(module.status)
  ).length;
  return Math.round((complete / values.length) * 100);
}

export function categoryLabel(name: string): string {
  return name
    .replaceAll("_", " ")
    .replace(/\bssl tls\b/i, "SSL/TLS")
    .replace(/\bapi\b/i, "API")
    .replace(/\bdns\b/i, "DNS")
    .replace(/\bhttp\b/i, "HTTP");
}

export function findingsForCategory(score: CategoryScore, findings: Finding[]): Finding[] {
  if (score.name === "dns") {
    return findings.filter((finding) => finding.category === "dns" || finding.category === "subdomains");
  }
  return findings.filter((finding) => finding.category === score.name);
}

export function findingCountBySeverity(findings: Finding[], severity: Severity): number {
  return findings.filter((finding) => finding.severity === severity).length;
}
