export interface EngineDetection {
  engine_name: string;
  category: string;
  result: string | null;
  method?: string | null;
}

export interface AnalysisStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout: number;
  [key: string]: number;
}

export interface AnalysisReport {
  analysis_id?: string;
  filename: string;
  status: "queued" | "in-progress" | "completed";
  sha256: string;
  file_size: number;
  is_cached?: boolean;
  stats?: AnalysisStats;
  malicious: number;
  suspicious: number;
  total_engines: number;
  verdict?: "CLEAN" | "WARNING" | "DANGER" | string;
  detections: EngineDetection[];
  analyzed_at?: string;
}

export type StepState = "idle" | "validating" | "checking_cache" | "scanning" | "completed" | "error";
