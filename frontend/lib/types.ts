export interface TermContribution {
  term: string;
  weight: number;
}

export interface HealthResponse {
  status: string;
  model_loaded: boolean;
  model_version?: string;
  api_version: string;
}

export interface PredictResponse {
  prediction: "SAFE" | "SUSPICIOUS" | "SPAM" | "SCAM";
  confidence: number;
  spam_probability: number;
  risk_score: number;
  risk_level: string;
  flags: string[];
  explanation: string[];
  top_terms: TermContribution[];
  score_breakdown: Record<string, number>;
  iocs?: {
    urls: string[];
    domains: string[];
    ips: string[];
    emails: string[];
  };
  url_analysis?: Array<{
    url: string;
    domain: string;
    https: boolean;
    raw_ip: boolean;
    shortened: boolean;
    punycode: boolean;
    excessive_subdomains: boolean;
    suspicious_structure: boolean;
    signals: string[];
    risk_score: number;
  }>;
  threat_intelligence?: Array<{
    url: string;
    provider: string;
    status: string;
    threat_type?: string;
    malicious_votes?: number;
    suspicious_votes?: number;
    harmless_votes?: number;
  }>;
}

export interface PageScanSummary {
  clean: number;
  suspicious: number;
  threats: number;
}

export interface NotableLink {
  url: string;
  prediction: string;
  risk_score: number;
  reason: string;
}

export interface PageScanResponse {
  scan_id: string;
  page_url: string;
  total_links_found: number;
  links_analyzed: number;
  external_links: number;
  summary: PageScanSummary;
  risk_score: number;
  risk_level: string;
  prediction: string;
  notable_links: NotableLink[];
}
