"use client";

import { useEffect, useRef, useState } from "react";
import { AnalysisProgress } from "@/components/AnalysisProgress";
import { Dropzone } from "@/components/Dropzone";
import { Header } from "@/components/Header";
import { HistorySidebar } from "@/components/HistorySidebar";
import { ReportCard } from "@/components/ReportCard";
import { AnalysisReport, StepState } from "@/types/analysis";

const STORAGE_KEY = "vt_doc_guardian_history_v1";
const POLL_INTERVAL_MS = 15000; // 15s para respeitar limite da API pública do VT (4 req/min)
const MAX_POLL_ATTEMPTS = 12; // Máximo de 3 minutos de polling

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [step, setStep] = useState<StepState>("idle");
  const [statusText, setStatusText] = useState<string>("");
  const [history, setHistory] = useState<AnalysisReport[]>(() => {
    if (typeof window !== "undefined") {
      try {
        const saved = localStorage.getItem(STORAGE_KEY);
        return saved ? JSON.parse(saved) : [];
      } catch {
        return [];
      }
    }
    return [];
  });
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);

  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);
  const pollAttemptsRef = useRef<number>(0);

  // Limpa timer se o componente for desmontado
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) {
        clearTimeout(pollTimerRef.current);
      }
    };
  }, []);

  const saveToHistory = (newReport: AnalysisReport) => {
    setHistory((prev) => {
      const filtered = prev.filter((item) => item.sha256 !== newReport.sha256);
      const updated = [{ ...newReport, analyzed_at: new Date().toISOString() }, ...filtered].slice(0, 5);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // Ignora erro de cota de localStorage
      }
      return updated;
    });
  };

  const handleClearHistory = () => {
    localStorage.removeItem(STORAGE_KEY);
    setHistory([]);
    setIsHistoryOpen(false);
  };

  const handleReset = () => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
    }
    setFile(null);
    setReport(null);
    setError(null);
    setIsUploading(false);
    setStep("idle");
    setStatusText("");
  };

  const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/+$/, "");

  const pollStatus = async (analysisId: string, currentFile: File, sha256: string) => {
    pollAttemptsRef.current += 1;

    if (pollAttemptsRef.current > MAX_POLL_ATTEMPTS) {
      setError("Tempo limite de análise excedido. Os motores do VirusTotal ainda estão processando a fila.");
      setIsUploading(false);
      setStep("error");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/status/${analysisId}`);
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || "Falha ao checar status no servidor.");
      }

      const data = await res.json();

      if (data.status === "completed") {
        const fullReport: AnalysisReport = {
          analysis_id: analysisId,
          filename: currentFile.name,
          status: "completed",
          sha256,
          file_size: currentFile.size,
          is_cached: false,
          stats: data.stats,
          malicious: data.malicious || 0,
          suspicious: data.suspicious || 0,
          total_engines: data.total_engines || 0,
          verdict: data.verdict,
          detections: data.detections || [],
        };

        setReport(fullReport);
        setStep("completed");
        setIsUploading(false);
        saveToHistory(fullReport);
      } else {
        setStep("scanning");
        setStatusText(
          `Varredura nos motores antivírus em andamento (${data.status}). Tentativa ${pollAttemptsRef.current}/${MAX_POLL_ATTEMPTS}...`
        );
        pollTimerRef.current = setTimeout(
          () => pollStatus(analysisId, currentFile, sha256),
          POLL_INTERVAL_MS
        );
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Erro desconhecido durante polling.";
      setError(message);
      setIsUploading(false);
      setStep("error");
    }
  };

  const handleStartAnalysis = async () => {
    if (!file) return;

    setIsUploading(true);
    setError(null);
    setReport(null);
    pollAttemptsRef.current = 0;

    // Etapa 1: Validação
    setStep("validating");
    setStatusText("Inspecionando assinatura estática e integridade do arquivo...");

    const formData = new FormData();
    formData.append("file", file);

    try {
      // Etapa 2: Threat Intel Hash Check
      setStep("checking_cache");
      setStatusText("Transmitindo para validação estrutural e verificação de cache global...");

      const res = await fetch(`${API_BASE}/upload`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Erro ao processar documento no backend.");
      }

      const data: AnalysisReport = await res.json();

      // Se a resposta veio instantânea pelo hash-first
      if (data.status === "completed" && data.is_cached) {
        setReport(data);
        setStep("completed");
        setIsUploading(false);
        saveToHistory(data);
        return;
      }

      // Se entrou na fila do VirusTotal
      setStep("scanning");
      setStatusText("Arquivo registrado na fila do VirusTotal. Aguardando motores antivírus...");
      pollTimerRef.current = setTimeout(
        () => pollStatus(data.analysis_id || "", file, data.sha256),
        POLL_INTERVAL_MS
      );
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Falha na comunicação com o backend.";
      setError(message);
      setIsUploading(false);
      setStep("error");
    }
  };

  return (
    <main className="min-h-screen p-6 md:p-16 max-w-4xl mx-auto flex flex-col gap-8">
      <Header
        hasHistory={history.length > 0}
        onToggleHistory={() => setIsHistoryOpen(!isHistoryOpen)}
        isHistoryOpen={isHistoryOpen}
      />

      {isHistoryOpen && history.length > 0 && (
        <HistorySidebar
          history={history}
          onSelectReport={(selected) => {
            setReport(selected);
            setFile(null);
            setIsHistoryOpen(false);
          }}
          onClearHistory={handleClearHistory}
          onClose={() => setIsHistoryOpen(false)}
        />
      )}

      {!report && (
        <section className="flex flex-col gap-6">
          <Dropzone
            selectedFile={file}
            onFileSelect={(selected) => {
              setFile(selected);
              setError(null);
            }}
            onClearFile={() => setFile(null)}
            onSubmit={handleStartAnalysis}
            isUploading={isUploading}
            disabled={isUploading}
          />

          {isUploading && (
            <AnalysisProgress step={step} statusText={statusText} />
          )}

          {error && (
            <div className="p-4 bg-red-950/40 border border-red-800 text-red-400 font-mono text-xs flex items-center justify-between">
              <span>[ERRO] {error}</span>
              <button
                type="button"
                onClick={() => setError(null)}
                className="text-zinc-400 hover:text-white uppercase ml-4"
              >
                [&times;]
              </button>
            </div>
          )}
        </section>
      )}

      {report && <ReportCard report={report} onReset={handleReset} />}
    </main>
  );
}
