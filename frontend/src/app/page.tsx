"use client";

import { useState } from "react";

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<any>(null);
  const [status, setStatus] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
      setReport(null);
      setStatus(null);
    }
  };

  const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const pollStatus = async (analysisId: string) => {
    try {
      const res = await fetch(`${API_BASE}/status/${analysisId}`);
      if (!res.ok) throw new Error("Falha ao checar status no backend");
      
      const data = await res.json();
      
      if (data.status === "completed") {
        setReport(data);
        setStatus("Concluído");
        setIsUploading(false);
      } else {
        setStatus(`Analisando arquivo... (${data.status})`);
        setTimeout(() => pollStatus(analysisId), 3000);
      }
    } catch (err: any) {
      setError(err.message);
      setIsUploading(false);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setIsUploading(true);
    setError(null);
    setStatus("Enviando...");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/upload`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Erro no upload");
      }

      const data = await res.json();
      setStatus("Upload concluído. Aguardando análise da API...");
      pollStatus(data.analysis_id);
    } catch (err: any) {
      setError(err.message);
      setIsUploading(false);
    }
  };

  return (
    <main className="min-h-screen p-8 md:p-24 max-w-4xl mx-auto flex flex-col gap-12">
      <header className="border-b border-[var(--border)] pb-8">
        <h1 className="text-2xl font-bold uppercase tracking-widest text-zinc-100 mb-2">
          VT Doc Guardian
        </h1>
        <p className="text-sm text-zinc-400 font-mono">
          Security Analysis Engine // Powered by VirusTotal
        </p>
      </header>

      <section className="bg-[#181a1f] border border-[var(--border)] p-8">
        <form onSubmit={handleUpload} className="flex flex-col gap-6">
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-zinc-500 mb-4">
              Upload Document
            </label>
            <input
              type="file"
              onChange={handleFileChange}
              disabled={isUploading}
              accept=".pdf,.ppt,.pptx,.pps,.ppsx,.odp"
              className="block w-full text-sm text-zinc-400
                file:mr-4 file:py-2 file:px-4
                file:border-0 file:text-sm file:font-mono file:font-semibold
                file:bg-zinc-800 file:text-zinc-300
                hover:file:bg-zinc-700 hover:file:cursor-pointer
                file:transition-colors"
            />
          </div>
          
          <button
            type="submit"
            disabled={!file || isUploading}
            className="self-start bg-zinc-100 text-zinc-900 font-bold px-6 py-2 text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-white transition-colors uppercase tracking-wider"
          >
            {isUploading ? "Processando..." : "Analisar Arquivo"}
          </button>
        </form>

        {status && !error && !report && (
          <div className="mt-8 pt-6 border-t border-[var(--border)]">
            <p className="font-mono text-sm text-amber-400 animate-pulse">
              &gt; {status}
            </p>
          </div>
        )}

        {error && (
          <div className="mt-8 pt-6 border-t border-[var(--border)]">
            <p className="font-mono text-sm text-red-500">
              [ERRO] {error}
            </p>
          </div>
        )}
      </section>

      {report && (
        <section className="border border-[var(--border)] bg-[#181a1f]">
          <div className="border-b border-[var(--border)] p-4 bg-[#1e2026]">
            <h2 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
              Analysis Report // {file?.name}
            </h2>
          </div>
          <div className="p-8">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono text-zinc-500 uppercase">Malicious</span>
                <span className={`text-3xl font-mono ${report.malicious > 0 ? 'text-red-500' : 'text-zinc-100'}`}>
                  {report.malicious}
                </span>
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono text-zinc-500 uppercase">Suspicious</span>
                <span className={`text-3xl font-mono ${report.suspicious > 0 ? 'text-amber-500' : 'text-zinc-100'}`}>
                  {report.suspicious}
                </span>
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono text-zinc-500 uppercase">Total Engines</span>
                <span className="text-3xl font-mono text-zinc-100">
                  {report.total_engines}
                </span>
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono text-zinc-500 uppercase">Verdict</span>
                <span className={`text-sm font-bold mt-2 ${
                  report.malicious > 0 ? 'text-red-500' : 
                  report.suspicious > 0 ? 'text-amber-500' : 'text-green-500'
                }`}>
                  {report.malicious > 0 ? 'DANGER' : 
                   report.suspicious > 0 ? 'WARNING' : 'CLEAN'}
                </span>
              </div>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
